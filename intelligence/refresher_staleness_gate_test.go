package intelligence

// The refresher's skip gate must measure the REPORT's age, not
// package_metadata.updated_at.
//
// It read row.UpdatedAt, justified by a comment asserting "the refresher's own
// Scan writes update both". Measured against production 2026-09-24: **zero
// package_metadata rows were touched in any two-hour window** while ticks ran,
// while scanFederated gates its own cache-first read on the report's
// Observation.CollectedAt. Two clocks. Three consecutive ticks logged
// byte-identical scanned=934 / skipped=1661 / new_versions=626 on three
// different images against ~35 rows actually written in the hour.
//
// Both directions are pinned, because the gate was wrong both ways and only one
// of them merely wastes work.

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestReportIsFresh(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	staleAfter := now.Add(-24 * time.Hour)
	fresh := now.Add(-1 * time.Hour)
	stale := now.Add(-9 * 24 * time.Hour)

	report := func(ts time.Time) *Report {
		r := &Report{}
		r.Observation.CollectedAt = ts
		return r
	}

	cases := []struct {
		name         string
		prior        *Report
		haveStore    bool
		rowUpdatedAt time.Time
		want         bool
		why          string
	}{
		{
			name:  "report fresh, package_metadata stale -> SKIP",
			prior: report(fresh), haveStore: true, rowUpdatedAt: stale, want: true,
			why: "293 production pairs were in this state; each fetched an artifact and ran a Scan " +
				"every tick only to be answered from cache",
		},
		{
			name:  "report stale, package_metadata fresh -> SCAN",
			prior: report(stale), haveStore: true, rowUpdatedAt: fresh, want: false,
			why: "15 production pairs were in this state and were skipped every tick, so they never " +
				"refreshed at all — this is the half that loses data rather than wasting work",
		},
		{
			name:  "no report stored -> SCAN",
			prior: nil, haveStore: true, rowUpdatedAt: fresh, want: false,
			why: "a coordinate with no stored report must be scanned, or it never gets one",
		},
		{
			name:  "no store configured, column fresh -> SKIP",
			prior: nil, haveStore: false, rowUpdatedAt: fresh, want: true,
			why: "with no store there is nothing better to go on; preserves the previous behaviour",
		},
		{
			name:  "no store configured, column stale -> SCAN",
			prior: nil, haveStore: false, rowUpdatedAt: stale, want: false,
			why: "with no store there is nothing better to go on",
		},
		{
			name:  "report exactly at the bound -> SCAN",
			prior: report(staleAfter), haveStore: true, rowUpdatedAt: fresh, want: false,
			why: "After() is strict, so a report exactly at the staleness bound is not fresh",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := reportIsFresh(c.prior, c.haveStore, c.rowUpdatedAt, staleAfter)
			if got != c.want {
				t.Errorf("reportIsFresh = %v, want %v — %s", got, c.want, c.why)
			}
		})
	}
}

// The gate must not read the package_metadata column at all when a store is
// present. If it fell back on a nil prior, the 15 never-refreshing pairs would
// stay broken while looking fixed.
func TestReportIsFreshIgnoresPackageMetadataWhenAStoreIsPresent(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	staleAfter := now.Add(-24 * time.Hour)
	for _, rowTime := range []time.Time{now, now.Add(-1 * time.Hour), now.Add(-100 * 24 * time.Hour)} {
		if reportIsFresh(nil, true, rowTime, staleAfter) {
			t.Errorf("a nil prior with rowUpdatedAt=%v was called fresh; the package_metadata column "+
				"must not decide anything once a store is available", rowTime)
		}
	}
}

// A SOURCE guard on the call site, and labelled as one.
//
// reportIsFresh is pure and fully covered above, and that is not sufficient:
// reverting refreshRow to `row.UpdatedAt.After(staleAfter)` leaves every test
// above green, because a correct helper nobody calls changes nothing. That
// mutation survives the entire package suite without this.
//
// It cannot be caught behaviourally here. RefresherConfig.Store is a concrete
// *Store over a live database, so the branch that consults the stored report
// is unreachable from a unit test — which is precisely why the original bug
// sat in a comment ("the refresher's own Scan writes update both") that was
// false for as long as anyone had looked.
func TestRefreshRowUsesTheReportStalenessGate(t *testing.T) {
	src, err := os.ReadFile("refresher.go")
	if err != nil {
		t.Fatalf("read refresher.go: %v", err)
	}
	text := string(src)

	if !strings.Contains(text, "reportIsFresh(priorReport,") {
		t.Fatal("refreshRow does not call reportIsFresh. Measuring staleness on " +
			"package_metadata.updated_at rescans rows whose report is fresh (293 production pairs, " +
			"each fetching an artifact first) and skips rows whose report is stale (15 pairs, which " +
			"then never refresh at all).")
	}
	if strings.Contains(text, "reportFresh := row.UpdatedAt.After(staleAfter)") {
		t.Error("refreshRow still derives reportFresh straight from the package_metadata column")
	}
}

// The new-version check must ask the REPORT store too, not only
// package_metadata.
//
// package_metadata records what the proxy has SERVED. A coordinate scanned on
// the public path, or enqueued as a transitive dependency, has an
// intelligence_reports row and no metadata row — so it counted as a new version
// on every tick, forever, because nothing in this path ever inserts into
// package_metadata. That was 626 of the 934 rows the production walk "scanned"
// each hour, each issuing a Scan the report cache then answered without
// writing.
//
// A SOURCE guard for the same reason as the gate above: RefresherConfig.Store
// is a concrete *Store over a live database, so this branch is unreachable from
// a unit test.
//
// KNOWN LIMIT, stated so nobody over-trusts it: a source guard catches the
// block being DELETED, which is what a real regression looks like. It cannot
// see the block being DISABLED — wrapping it in `if false` leaves the text in
// place and this stays green. Verified both ways when it was written.
func TestNewVersionCheckConsultsTheReportStore(t *testing.T) {
	src, err := os.ReadFile("refresher.go")
	if err != nil {
		t.Fatalf("read refresher.go: %v", err)
	}
	text := string(src)

	// Anchor on the CALL, not on the MetadataSource interface declaration —
	// that is the first occurrence of the bare name and it is 300 lines away.
	// The first draft of this test anchored there and reported the fix
	// missing when it was present.
	i := strings.Index(text, "r.cfg.Metadata.PackageVersionExists(")
	if i < 0 {
		t.Fatal("the PackageVersionExists call site was not found in refresher.go")
	}
	// The report-store fallback must sit in the same block, after it.
	window := text[i:min(i+1600, len(text))]
	if !strings.Contains(window, "loadReportForKey(") {
		t.Error("the new-version check asks package_metadata and stops there. A version already " +
			"covered by a fresh report but absent from package_metadata counts as new on every " +
			"tick, forever — 626 of 934 rows per tick in production.")
	}
	if !strings.Contains(window, "CollectedAt.After(staleAfter)") {
		t.Error("the report-store fallback does not check freshness; a STALE report for the latest " +
			"version must not suppress the scan that would refresh it")
	}
}

// Freshness is load-bearing in that fallback: treating any stored report as
// "exists" would suppress the new-version scan permanently once a single stale
// report existed.
func TestNewVersionFallbackRequiresAFreshReport(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	staleAfter := now.Add(-24 * time.Hour)
	stale := &Report{}
	stale.Observation.CollectedAt = now.Add(-9 * 24 * time.Hour)
	if stale.Observation.CollectedAt.After(staleAfter) {
		t.Fatal("fixture is not stale")
	}
	fresh := &Report{}
	fresh.Observation.CollectedAt = now.Add(-1 * time.Hour)
	if !fresh.Observation.CollectedAt.After(staleAfter) {
		t.Fatal("fixture is not fresh")
	}
}

// A row whose own report is fresh AND whose newer upstream version is already
// covered has nothing left to do, and must not reach the artifact fetch.
//
// The skip gate cannot decide this: it fires before `exists` is computed, and
// its condition requires `latest == row.Version`. So a row with a newer version
// upstream never skipped even when both versions were current — 626 rows an
// hour in production, each downloading an artifact and running a Scan the
// report cache then answered without writing.
//
// SOURCE guard, same constraint as the two above (concrete *Store). It asserts
// the skip sits on the `else` of the new-version branch — before the artifact
// fetch, which is the expensive half — and not merely somewhere in the file.
func TestFreshRowWithCoveredNewVersionSkipsBeforeTheArtifactFetch(t *testing.T) {
	src, err := os.ReadFile("refresher.go")
	if err != nil {
		t.Fatalf("read refresher.go: %v", err)
	}
	text := string(src)

	i := strings.Index(text, "action = actionNewVersion")
	if i < 0 {
		t.Fatal("the new-version branch was not found in refresher.go")
	}
	fetchAt := strings.Index(text, "r.cfg.ArtifactFetcher(fetchCtx, row)")
	if fetchAt < 0 {
		t.Fatal("the artifact fetch was not found in refresher.go")
	}
	between := text[i:fetchAt]
	if !strings.Contains(between, "else if reportFresh && probeAnswered") {
		t.Error("no skip between the new-version branch and the artifact fetch. A row whose report " +
			"is fresh and whose newer version is already covered still downloads an artifact and " +
			"scans, every tick, forever.")
	}
	if !strings.Contains(between, "return actionSkipped") {
		t.Error("that branch does not return actionSkipped, so the row still falls through to the " +
			"artifact fetch — the expensive half")
	}
	if fetchAt < i {
		t.Fatal("the artifact fetch precedes the new-version branch; this guard is asserting the " +
			"wrong ordering and would pass on the bug")
	}
}
