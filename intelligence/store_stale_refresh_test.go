package intelligence

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestStaleReportScopeSelectsNeverScannedReports pins the SQL half of the
// artifact backfill against Postgres. Each row isolates one clause of the
// predicate, so deleting or loosening any clause selects a row it must not.
func TestStaleReportScopeSelectsNeverScannedReports(t *testing.T) {
	db := openStaleDisclosureDB(t)
	store := NewStore(db)
	ctx := context.Background()

	suffix := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	listed, unlisted := "nuget-bf-"+suffix, "apt-bf-"+suffix
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem IN ($1, $2)`, listed, unlisted)
	})

	now := time.Now().UTC().Truncate(time.Second)
	insert := func(eco, pkg, report string, hasScan bool, age time.Duration) {
		t.Helper()
		at := now.Add(-age)
		if _, err := db.DB().ExecContext(ctx, `
			INSERT INTO intelligence_reports
			  (ecosystem, package_name, version, report, collected_at, fresh_until, has_artifact_scan)
			VALUES ($1, $2, '1.0.0', $3::jsonb, $4, $5, $6)
		`, eco, pkg, report, at, at.Add(24*time.Hour), hasScan); err != nil {
			t.Fatalf("insert %s/%s: %v", eco, pkg, err)
		}
	}
	insert(listed, "no-section", `{}`, false, 13*time.Hour)
	insert(listed, "performed-false", `{"artifactScan":{"performed":false}}`, false, 14*time.Hour)
	// The column says false but the merged payload kept an earlier scan: a
	// bytes-less rewrite does exactly this. It must NOT be re-downloaded.
	insert(listed, "column-drifted", `{"artifactScan":{"performed":true}}`, false, 15*time.Hour)
	insert(listed, "inside-cooldown", `{}`, false, 1*time.Hour)
	insert(unlisted, "unlisted-ecosystem", `{}`, false, 13*time.Hour)

	scope := StaleReportScope{
		// Far enough back that the stale half selects none of these rows, so
		// every selection below is the artifact half's doing.
		OlderThan:          time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		ArtifactEcosystems: []string{listed},
		ArtifactOlderThan:  now.Add(-12 * time.Hour),
	}

	var got []string
	var cursor StaleReportCursor
	for page := 0; page < 10; page++ {
		rows, next, err := store.IterateStaleReports(ctx, scope, cursor, 1)
		if err != nil {
			t.Fatalf("iterate: %v", err)
		}
		for _, r := range rows {
			if r.Ecosystem == listed || r.Ecosystem == unlisted {
				got = append(got, r.Package)
			}
		}
		if next.IsZero() {
			break
		}
		cursor = next
	}

	// Oldest first, and paged one row at a time so the keyset placeholders
	// (which now start after the scope's own arguments) are exercised.
	want := []string{"performed-false", "no-section"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("selected %v, want %v", got, want)
	}

	n, err := store.CountStaleReports(ctx, scope)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n < 2 {
		t.Errorf("CountStaleReports = %d, want at least the 2 selectable rows", n)
	}

	// With the artifact half off, none of these fresh rows is in scope.
	plain := StaleReportScope{OlderThan: scope.OlderThan}
	rows, _, err := store.IterateStaleReports(ctx, plain, StaleReportCursor{}, 1000)
	if err != nil {
		t.Fatalf("iterate plain: %v", err)
	}
	for _, r := range rows {
		if r.Ecosystem == listed || r.Ecosystem == unlisted {
			t.Errorf("plain scope selected %s/%s, which is not stale", r.Ecosystem, r.Package)
		}
	}
}
