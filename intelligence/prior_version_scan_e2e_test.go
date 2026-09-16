package intelligence

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

// TestPriorVersionScan_ReadsTheRightRow is the integration half of the
// cross-version diff.
//
// The unit tests cover projectVersionDiff and the three signals. Neither can
// cover the SQL, and the SQL is where this can go quietly wrong: the query
// must return the most recently collected OTHER version of the SAME package,
// must not return the version being scanned, and must not cross package or
// ecosystem boundaries. A wrong row here does not error — it produces a diff
// against the wrong baseline, which is worse than no diff at all.
//
// Set CHAINSAW_DATABASE_URL to a throwaway Postgres to run it.
func TestPriorVersionScan_ReadsTheRightRow(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := NewStore(db)
	ctx := context.Background()
	uniq := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	pkg := "pvs-example-" + uniq
	other := "pvs-other-" + uniq
	now := time.Now().UTC().Truncate(time.Second)

	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name IN ($1,$2)`, pkg, other)
	})

	seed := func(name, version string, collected time.Time, shell bool) {
		r := &Report{Identity: IdentitySection{Ecosystem: "npm", Package: name, Version: version}}
		r.Observation.CollectedAt = collected
		r.Observation.FreshUntil = collected.Add(24 * time.Hour)
		r.Scan = ArtifactScanSection{Performed: true, ShellAccess: shell}
		if err := store.Upsert(ctx, "", r); err != nil {
			t.Fatalf("seed %s@%s: %v", name, version, err)
		}
	}

	// Three versions of our package, plus a decoy package scanned most
	// recently of all — if the query forgets its package filter, the decoy
	// is what it will return.
	seed(pkg, "1.0.0", now.Add(-72*time.Hour), false)
	seed(pkg, "1.1.0", now.Add(-48*time.Hour), true) // most recent OTHER
	seed(pkg, "2.0.0", now.Add(-24*time.Hour), false)
	seed(other, "9.9.9", now.Add(-1*time.Hour), true)

	scan, version, err := store.PriorVersionScan(ctx, Key{Ecosystem: "npm", Package: pkg, Version: "2.0.0"})
	if err != nil {
		t.Fatalf("PriorVersionScan: %v", err)
	}
	if scan == nil {
		t.Fatal("no prior version returned; three rows exist for this package")
	}
	if version != "1.1.0" {
		t.Errorf("prior version = %q, want 1.1.0 (the most recently collected OTHER version)", version)
	}
	if !scan.Performed || !scan.ShellAccess {
		t.Errorf("prior scan facts not returned: Performed=%v ShellAccess=%v", scan.Performed, scan.ShellAccess)
	}

	// Must never return the version being scanned.
	if _, v, _ := store.PriorVersionScan(ctx, Key{Ecosystem: "npm", Package: pkg, Version: "1.1.0"}); v == "1.1.0" {
		t.Error("returned the version being scanned as its own prior version")
	}

	// A package we hold exactly one version of has no prior — and that must
	// be (nil, "", nil), not an error and not a zero-valued scan, because
	// projectVersionDiff keys the whole safety property on a nil prior.
	single := "pvs-single-" + uniq
	t.Cleanup(func() { _, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE package_name=$1`, single) })
	seed(single, "1.0.0", now, true)
	s2, v2, err := store.PriorVersionScan(ctx, Key{Ecosystem: "npm", Package: single, Version: "1.0.0"})
	if err != nil {
		t.Fatalf("single-version lookup errored: %v", err)
	}
	if s2 != nil || v2 != "" {
		t.Errorf("single-version package returned a prior: scan=%v version=%q", s2, v2)
	}

	// Ecosystem must be part of the key.
	if _, v, _ := store.PriorVersionScan(ctx, Key{Ecosystem: "pypi", Package: pkg, Version: "2.0.0"}); v != "" {
		t.Errorf("crossed an ecosystem boundary: got prior %q for pypi/%s", v, pkg)
	}
}
