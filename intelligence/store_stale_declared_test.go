package intelligence

// C-6 — the stale-report sweep must not touch a coordinate some live
// monitored target declares.
//
// WHY IT MATTERS, and why the test is DB-backed. The sweep refreshes by Key
// and dispatches NOTHING: refresher_stale_reports.go, refresher_recompute.go
// and refresher_coverage.go contain zero references to the alerter, and
// OnRefreshedReport has exactly one call site (the primary walk in
// refresher.go). Declared inventory is the only audience an orphan can have —
// monitored_targets carries org_id, and a declared coordinate the proxy never
// served has no package_metadata row, so the walk never visits it. The
// declared-inventory sweep diffs the stored report against a rescan of the
// single shared intelligence_reports row, so once THIS sweep has refreshed
// that row the diff is prior == next and the transition is gone.
//
// The claim is entirely about a SQL predicate against two tables, so there is
// no in-memory substitute. The monitored_targets rows are inserted with raw
// SQL on purpose rather than through internal/monitoredtargets: core cannot
// import internal, and asserting against the raw shape proves the predicate
// does not depend on the Go reader agreeing with it.

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// declaredProbeJSON is the package_set element shape, matching
// scan.PackageKey's json tags. Written out rather than imported for the
// reason in the header; a drift here is caught by the Go-side test in
// internal/monitoredtargets.
func declaredProbeJSON(eco, name, version string) string {
	return `[{"ecosystem":"` + eco + `","name":"` + name + `","version":"` + version +
		`","direct":true,"source":"package-lock.json"}]`
}

// selectedPackages pages IterateStaleReports to exhaustion and returns the
// packages it selected in one ecosystem.
//
// PAGING, NOT ONE BIG LIMIT. intelligence_reports is shared with every other
// test in this package and several of them insert stale rows; the sweep orders
// by collected_at ASC, so a single LIMIT page can be filled entirely by
// another test's older fixtures and this test would then assert against an
// empty slice — passing the "declared is absent" check vacuously and failing
// the "not-declared is present" one for a reason that has nothing to do with
// the predicate. Measured: with 5,000 unrelated stale rows present, a
// LIMIT 100 call returned none of this test's rows at all.
func selectedPackages(t *testing.T, store *Store, scope StaleReportScope, eco string) map[string]bool {
	t.Helper()
	ctx := context.Background()
	got := map[string]bool{}
	var cursor StaleReportCursor
	for page := 0; page < 200; page++ {
		rows, next, err := store.IterateStaleReports(ctx, scope, cursor, 1000)
		if err != nil {
			t.Fatalf("iterate (page %d): %v", page, err)
		}
		for _, r := range rows {
			if r.Ecosystem == eco {
				got[r.Package] = true
			}
		}
		if next.IsZero() {
			return got
		}
		cursor = next
	}
	t.Fatal("IterateStaleReports did not terminate within 200 pages of 1000 — " +
		"the keyset cursor is not advancing")
	return nil
}

func TestStaleReportScopeExcludesDeclaredCoordinates(t *testing.T) {
	db := openStaleDisclosureDB(t)
	store := NewStore(db)
	ctx := context.Background()

	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	eco := "npm-c6-" + suffix
	org := "c6-org-" + suffix
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1`, eco)
		_, _ = db.DB().Exec(`DELETE FROM monitored_targets WHERE org_id=$1`, org)
	})

	now := time.Now().UTC().Truncate(time.Second)
	// Every row is 48h old, i.e. unambiguously past the 24h bound. The ONLY
	// difference between them is whether a target declares them.
	insert := func(pkg string) {
		t.Helper()
		at := now.Add(-48 * time.Hour)
		if _, err := db.DB().ExecContext(ctx, `
			INSERT INTO intelligence_reports
			  (ecosystem, package_name, version, report, collected_at, fresh_until)
			VALUES ($1, $2, '1.0.0', '{}'::jsonb, $3, $4)
		`, eco, pkg, at, at.Add(24*time.Hour)); err != nil {
			t.Fatalf("insert %s: %v", pkg, err)
		}
	}
	declareTarget := func(repoLabel, pkg string, archived bool) {
		t.Helper()
		var archivedAt any
		if archived {
			archivedAt = now
		}
		if _, err := db.DB().ExecContext(ctx, `
			INSERT INTO monitored_targets (org_id, repo_label, branch, package_set, archived_at)
			VALUES ($1, $2, 'main', $3::jsonb, $4)
		`, org, repoLabel, declaredProbeJSON(eco, pkg, "1.0.0"), archivedAt); err != nil {
			t.Fatalf("declare %s: %v", pkg, err)
		}
	}

	insert("declared")
	insert("not-declared")
	// Declared by a target whose archived_at is SET. An archived target cannot
	// be swept (IterateDue filters archived_at IS NULL), so it has no diff
	// window to protect and must NOT shield the coordinate — otherwise a
	// cancelled subscription freezes a coordinate out of refresh forever.
	insert("declared-but-archived")

	declareTarget("repo-live", "declared", false)
	declareTarget("repo-archived", "declared-but-archived", true)

	scope := StaleReportScope{OlderThan: now.Add(-24 * time.Hour)}
	got := selectedPackages(t, store, scope, eco)

	if got["declared"] {
		t.Error("the sweep selected a coordinate a LIVE monitored target declares. " +
			"It refreshes the shared report row and dispatches nothing, so selecting " +
			"this row consumes the declared-inventory sweep's only diff window and " +
			"the customer's alert is lost (C-6).")
	}
	if !got["not-declared"] {
		t.Error("the sweep skipped a coordinate NO target declares. The anti-join is " +
			"over-matching — if this fails, the sweep has lost coverage of the 11,754 " +
			"orphans it exists to refresh, which is a far larger regression than C-6.")
	}
	if !got["declared-but-archived"] {
		t.Error("an ARCHIVED target shielded a coordinate from the sweep. Archived " +
			"targets are never swept (archived_at IS NULL in IterateDue), so there is " +
			"no window to protect and the coordinate would simply stop being refreshed.")
	}

	// The gauge and the walk MUST agree. CountStaleReports feeds
	// chainsaw_intel_stale_report_backlog and shares scope.where() with the
	// iteration precisely so an operator is never shown a backlog the sweep
	// will not work through.
	//
	// Scoped by a second predicate on ecosystem because the table is shared
	// with every other test in this package; counting globally would make the
	// assertion depend on test order.
	var scopedCount int
	pred, args := scope.where()
	args = append(args, eco)
	if err := db.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM intelligence_reports WHERE `+pred+
			` AND ecosystem = $`+strconv.Itoa(len(args)), args...).Scan(&scopedCount); err != nil {
		t.Fatalf("scoped count: %v", err)
	}
	if scopedCount != 2 {
		t.Errorf("scoped backlog count = %d, want 2 (not-declared + declared-but-archived). "+
			"CountStaleReports and IterateStaleReports share scope.where(); a mismatch "+
			"here means they have drifted and the backlog gauge is lying.", scopedCount)
	}
}

// TestStaleReportScopeExcludesDeclaredOnTheArtifactHalf covers the OTHER
// return of scope.where(). The two halves render separately, so a fix applied
// to one is not applied to the other — and the artifact half is the one that
// selects FRESH rows (a never-scanned coordinate past the cool-down), so a
// declared coordinate would be swallowed by it even while the staleness half
// correctly skipped the row.
func TestStaleReportScopeExcludesDeclaredOnTheArtifactHalf(t *testing.T) {
	db := openStaleDisclosureDB(t)
	store := NewStore(db)
	ctx := context.Background()

	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	eco := "nuget-c6a-" + suffix
	org := "c6a-org-" + suffix
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1`, eco)
		_, _ = db.DB().Exec(`DELETE FROM monitored_targets WHERE org_id=$1`, org)
	})

	now := time.Now().UTC().Truncate(time.Second)
	// 13h old: FRESH against the 24h staleness bound, stale against a 12h
	// artifact cool-down. Only the artifact half can select these.
	insert := func(pkg string) {
		t.Helper()
		at := now.Add(-13 * time.Hour)
		if _, err := db.DB().ExecContext(ctx, `
			INSERT INTO intelligence_reports
			  (ecosystem, package_name, version, report, collected_at, fresh_until)
			VALUES ($1, $2, '1.0.0', '{}'::jsonb, $3, $4)
		`, eco, pkg, at, at.Add(24*time.Hour)); err != nil {
			t.Fatalf("insert %s: %v", pkg, err)
		}
	}
	insert("declared")
	insert("not-declared")
	if _, err := db.DB().ExecContext(ctx, `
		INSERT INTO monitored_targets (org_id, repo_label, branch, package_set)
		VALUES ($1, 'repo-a', 'main', $2::jsonb)
	`, org, declaredProbeJSON(eco, "declared", "1.0.0")); err != nil {
		t.Fatalf("declare: %v", err)
	}

	scope := StaleReportScope{
		OlderThan:          now.Add(-24 * time.Hour),
		ArtifactEcosystems: []string{eco},
		ArtifactOlderThan:  now.Add(-12 * time.Hour),
	}
	got := selectedPackages(t, store, scope, eco)
	if got["declared"] {
		t.Error("the ARTIFACT half of the scope selected a declared coordinate. " +
			"scope.where() has two returns and they render independently; the " +
			"anti-join has to be on both.")
	}
	if !got["not-declared"] {
		t.Fatal("the artifact half selected nothing at all, so this test proves " +
			"nothing about the anti-join — check the 13h seed against the 12h " +
			"cool-down before reading the assertion above as a pass")
	}
}
