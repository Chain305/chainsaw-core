package intelligence

// Store-level tests for the matcher-staleness DISCLOSURE on the list surfaces.
//
// The contract under test is deliberately the opposite of the one
// Report.MatcherStale() drives on the detail path. There, a superseded row is
// a cache MISS and the coordinate 404s so the page can rescan. Here, a
// superseded row is RETURNED and MARKED, because the alternative — an epoch
// predicate in the WHERE clause — empties the entire package inventory for as
// long as a recompute takes, and the refresher only walks coordinates that
// have a package_metadata row, so anything indexed by the CLI lockfile
// scanner, `intel scan`, transitive fan-out or a public lookup would never
// come back at all.

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

// openStaleDisclosureDB opens the test database for the disclosure tests.
//
// Separate from requireIntelDB (store_tenancy_test.go) for one reason: a
// skipped test still reports its package as "ok", so a run that silently
// skipped every database assertion is indistinguishable from a run that
// passed them. CHAINSAW_TEST_REQUIRE_DB turns the skip into a failure, so a
// run that was MEANT to exercise Postgres cannot quietly prove nothing.
func openStaleDisclosureDB(t *testing.T) *pgstore.Store {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if dsn == "" {
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != "" {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but CHAINSAW_DATABASE_URL is empty — " +
				"this run was supposed to exercise Postgres and would otherwise have " +
				"skipped while still reporting the package ok")
		}
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	pg, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	return pg
}

// TestMatcherEpochJSONPathMatchesTheSQL pins the JSONB path the list queries
// read against the struct tags that produce it. Store.Search and Store.Facets
// dig the epoch out with `report->'observation'->>'matcherEpoch'`; a rename of
// either tag would leave that expression reading SQL NULL forever, which
// COALESCEs to 0 and would silently mark the entire cache stale. No database
// needed — this is a contract between two literals.
func TestMatcherEpochJSONPathMatchesTheSQL(t *testing.T) {
	t.Parallel()

	blob, err := json.Marshal(&Report{
		Observation: ObservationSection{MatcherEpoch: 7},
	})
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	obs, ok := decoded["observation"].(map[string]any)
	if !ok {
		t.Fatalf("report JSON has no \"observation\" object; the SQL "+
			"report->'observation'->>'matcherEpoch' reads NULL for every row. keys=%v",
			keysOf(decoded))
	}
	epoch, ok := obs["matcherEpoch"]
	if !ok {
		t.Fatalf("observation has no \"matcherEpoch\" key; the SQL reads NULL for "+
			"every row and COALESCEs to 0, marking the whole cache stale. keys=%v",
			keysOf(obs))
	}
	if n, _ := epoch.(float64); int(n) != 7 {
		t.Fatalf("matcherEpoch decoded as %v, want 7", epoch)
	}

	// The zero epoch is dropped by `omitempty`, which is exactly why the SQL
	// wraps the extract in COALESCE(..., 0): a row written before the field
	// existed carries no key, and must read as epoch 0 — below every real
	// epoch, therefore always stale.
	zeroBlob, err := json.Marshal(&Report{Observation: ObservationSection{}})
	if err != nil {
		t.Fatalf("marshal zero report: %v", err)
	}
	var zeroDecoded map[string]any
	if err := json.Unmarshal(zeroBlob, &zeroDecoded); err != nil {
		t.Fatalf("unmarshal zero report: %v", err)
	}
	zeroObs, _ := zeroDecoded["observation"].(map[string]any)
	if _, present := zeroObs["matcherEpoch"]; present {
		t.Error("matcherEpoch is now emitted at zero — harmless, but the COALESCE in " +
			"Store.Search/Store.Facets is no longer load-bearing for new rows; " +
			"legacy rows still need it, so do not remove it")
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestSearchAndFacetsDiscloseMatcherStaleRows is the core assertion: a row at
// CurrentMatcherEpoch-1 and a row with no epoch key at all are BOTH returned
// by Search alongside a current row, each flagged correctly, and Facets counts
// all three in Total while counting the two superseded ones in StalePending.
func TestSearchAndFacetsDiscloseMatcherStaleRows(t *testing.T) {
	db := openStaleDisclosureDB(t)
	store := NewStore(db)
	ctx := context.Background()

	// intelligence_reports is universal (no org_id), so isolate on a
	// per-run ecosystem and delete it on the way out. Search can then be
	// scoped with q.Ecosystem and see only this test's rows.
	eco := "npm-stale-" + strings.ReplaceAll(
		time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1`, eco)
	})

	collectedAt := time.Now().UTC().Truncate(time.Second)
	mkReport := func(pkg string, epoch int, trust int) *Report {
		return &Report{
			Identity:    IdentitySection{Ecosystem: eco, Package: pkg, Version: "1.0.0"},
			SupplyChain: SupplyChainSection{MalwareStatus: "clean", TrustScore: trust},
			Observation: ObservationSection{
				CollectedAt:  collectedAt,
				FreshUntil:   collectedAt.Add(24 * time.Hour),
				MatcherEpoch: epoch,
			},
		}
	}

	// Facet counts span the whole table, so assert on the DELTA rather than
	// on absolute numbers — a shared database legitimately holds other rows.
	before, err := store.Facets(ctx, "org-test")
	if err != nil {
		t.Fatalf("facets before: %v", err)
	}

	if err := store.Upsert(ctx, "org-test", mkReport("pkg-current", CurrentMatcherEpoch, 80)); err != nil {
		t.Fatalf("upsert current: %v", err)
	}
	if err := store.Upsert(ctx, "org-test", mkReport("pkg-stale", CurrentMatcherEpoch-1, 30)); err != nil {
		t.Fatalf("upsert stale: %v", err)
	}
	// A row whose report JSONB carries no observation.matcherEpoch key at
	// all — every row written before the field existed. Inserted raw so the
	// case is pinned regardless of what CurrentMatcherEpoch happens to be
	// (at epoch 1, CurrentMatcherEpoch-1 is 0 and omitempty produces this
	// shape anyway; at epoch 2+ it would not, and the NULL path would stop
	// being covered).
	if _, err := db.DB().ExecContext(ctx, `
		INSERT INTO intelligence_reports
		  (ecosystem, package_name, version, report, collected_at, fresh_until, trust_score)
		VALUES ($1, 'pkg-legacy', '1.0.0', $2::jsonb, $3, $4, 50)
	`, eco, `{"observation":{"collectedAt":"2020-01-01T00:00:00Z"}}`,
		collectedAt, collectedAt.Add(24*time.Hour)); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	rows, err := store.Search(ctx, SearchQuery{Ecosystem: eco, Limit: 100})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	got := map[string]bool{}
	for _, r := range rows.Rows {
		got[r.Package] = r.MatcherStale
	}
	if len(got) != 3 {
		t.Fatalf("Search returned %d rows for ecosystem %s, want 3 — a matcher-stale "+
			"row must be disclosed, never dropped. got=%v", len(got), eco, got)
	}
	for pkg, wantStale := range map[string]bool{
		"pkg-current": false,
		"pkg-stale":   true,
		"pkg-legacy":  true,
	} {
		stale, present := got[pkg]
		if !present {
			t.Errorf("%s missing from Search results entirely", pkg)
			continue
		}
		if stale != wantStale {
			t.Errorf("%s: MatcherStale=%v, want %v", pkg, stale, wantStale)
		}
	}

	// The stale rows must keep their data. Disclosure marks a value; it does
	// not blank it, or the UI has nothing to render as provisional.
	for _, r := range rows.Rows {
		if r.Package == "pkg-stale" && r.TrustScore != 30 {
			t.Errorf("pkg-stale TrustScore=%d, want 30 — the stale row kept its place "+
				"in the sort and the filter, so it must keep its value too", r.TrustScore)
		}
	}

	after, err := store.Facets(ctx, "org-test")
	if err != nil {
		t.Fatalf("facets after: %v", err)
	}
	if delta := after.Total - before.Total; delta != 3 {
		t.Errorf("Facets Total delta = %d, want 3 — every row still counts in the "+
			"bucket totals, stale or not, or the sidebar stops reconciling with the table",
			delta)
	}
	if delta := after.StalePending - before.StalePending; delta != 2 {
		t.Errorf("Facets StalePending delta = %d, want 2 (pkg-stale + pkg-legacy)", delta)
	}
	// StalePending is a companion, not a subtraction: the trust buckets still
	// include the stale rows. pkg-current(80)=high, pkg-legacy(50)=medium,
	// pkg-stale(30)=low — one new row in each bucket.
	for _, want := range []struct {
		key   string
		delta int
	}{{"low", 1}, {"medium", 1}, {"high", 1}} {
		if d := bucketDelta(before.TrustBuckets, after.TrustBuckets, want.key); d != want.delta {
			t.Errorf("trust bucket %q delta = %d, want %d — stale rows must stay in "+
				"the buckets they were counted in before the disclosure landed",
				want.key, d, want.delta)
		}
	}
}

func bucketDelta(before, after []FacetBucket, key string) int {
	find := func(bs []FacetBucket) int {
		for _, b := range bs {
			if b.Key == key {
				return b.Count
			}
		}
		return 0
	}
	return find(after) - find(before)
}

// TestSearchKeepsEveryRowAcrossAnEpochBump simulates the exact failure mode
// the epoch predicate was rejected for. CurrentMatcherEpoch is a compile-time
// constant, so the bump is modelled the other way round: every seeded row's
// persisted epoch is rewritten downwards, which is indistinguishable from the
// constant moving up. The row SET must be identical before and after — only
// the flags may change.
func TestSearchKeepsEveryRowAcrossAnEpochBump(t *testing.T) {
	db := openStaleDisclosureDB(t)
	store := NewStore(db)
	ctx := context.Background()
	eco := "npm-bump-" + strings.ReplaceAll(
		time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1`, eco)
	})

	collectedAt := time.Now().UTC().Truncate(time.Second)
	for _, pkg := range []string{"alpha", "beta", "gamma"} {
		if err := store.Upsert(ctx, "org-test", &Report{
			Identity:    IdentitySection{Ecosystem: eco, Package: pkg, Version: "1.0.0"},
			SupplyChain: SupplyChainSection{MalwareStatus: "clean", TrustScore: 70},
			Observation: ObservationSection{
				CollectedAt:  collectedAt,
				FreshUntil:   collectedAt.Add(24 * time.Hour),
				MatcherEpoch: CurrentMatcherEpoch,
			},
		}); err != nil {
			t.Fatalf("upsert %s: %v", pkg, err)
		}
	}

	beforeRows, err := store.Search(ctx, SearchQuery{Ecosystem: eco, Limit: 100})
	if err != nil {
		t.Fatalf("search before bump: %v", err)
	}
	if len(beforeRows.Rows) != 3 {
		t.Fatalf("seeded 3 rows, Search returned %d", len(beforeRows.Rows))
	}
	for _, r := range beforeRows.Rows {
		if r.MatcherStale {
			t.Fatalf("%s was written at CurrentMatcherEpoch but reports MatcherStale", r.Package)
		}
	}
	beforeSet := coordinateSet(beforeRows.Rows)

	// The bump. Every row is now behind the current epoch.
	if _, err := db.DB().ExecContext(ctx, `
		UPDATE intelligence_reports
		SET report = jsonb_set(report, '{observation,matcherEpoch}', to_jsonb($2::int))
		WHERE ecosystem = $1
	`, eco, CurrentMatcherEpoch-1); err != nil {
		t.Fatalf("simulate epoch bump: %v", err)
	}

	afterRows, err := store.Search(ctx, SearchQuery{Ecosystem: eco, Limit: 100})
	if err != nil {
		t.Fatalf("search after bump: %v", err)
	}
	afterSet := coordinateSet(afterRows.Rows)
	if len(afterSet) != len(beforeSet) {
		t.Fatalf("an epoch bump changed the row count: %d before, %d after. "+
			"This is the failure the WHERE-clause fix was rejected for — the whole "+
			"inventory disappears until a recompute walks it, and coordinates with no "+
			"package_metadata row are never walked at all",
			len(beforeSet), len(afterSet))
	}
	for coord := range beforeSet {
		if !afterSet[coord] {
			t.Errorf("%s vanished from the list after the epoch bump", coord)
		}
	}
	// Every row is now stale and must say so — a bump that changes nothing
	// visible would mean the flag is not actually being read from the row.
	for _, r := range afterRows.Rows {
		if !r.MatcherStale {
			t.Errorf("%s survived the bump but reports MatcherStale=false; the flag is "+
				"not reading the persisted epoch", r.Package)
		}
	}

	// Sorting still works on the stale rows — they keep their place in the
	// ordering rather than sinking to the end or being skipped.
	sorted, err := store.Search(ctx, SearchQuery{Ecosystem: eco, Sort: "trust_desc", Limit: 100})
	if err != nil {
		t.Fatalf("search sorted after bump: %v", err)
	}
	if len(sorted.Rows) != 3 {
		t.Errorf("trust_desc sort after bump returned %d rows, want 3", len(sorted.Rows))
	}
	// And so does the trust-score filter, which reads the same denormalised
	// column the stale verdict came from.
	minTrust := 60
	filtered, err := store.Search(ctx, SearchQuery{Ecosystem: eco, MinTrustScore: &minTrust, Limit: 100})
	if err != nil {
		t.Fatalf("search filtered after bump: %v", err)
	}
	if len(filtered.Rows) != 3 {
		t.Errorf("minTrust=60 after bump returned %d rows, want 3 — a stale row is "+
			"still filterable, it is just labelled", len(filtered.Rows))
	}
}

func coordinateSet(rows []SearchRow) map[string]bool {
	out := map[string]bool{}
	for _, r := range rows {
		out[r.Ecosystem+"/"+r.Package+"@"+r.Version] = true
	}
	return out
}
