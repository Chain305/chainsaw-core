package intelligence

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
)

// mkTransitiveFixture seeds one row with a DIRECT CVE and one with a
// TRANSITIVE-ONLY CVE, in a per-run ecosystem, and returns that ecosystem.
//
// The transitive row deliberately carries max_cvss NULL. That is the whole
// point of the fixture and the assertion below defends it.
func mkTransitiveFixture(t *testing.T, ctx context.Context, store *Store) string {
	t.Helper()
	eco := "npm-transcve-" + strings.ReplaceAll(
		time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	collectedAt := time.Now().UTC().Truncate(time.Second)

	base := func(pkg string) *Report {
		return &Report{
			Identity:    IdentitySection{Ecosystem: eco, Package: pkg, Version: "1.0.0"},
			SupplyChain: SupplyChainSection{MalwareStatus: "clean", TrustScore: 60},
			Observation: ObservationSection{
				CollectedAt:  collectedAt,
				FreshUntil:   collectedAt.Add(24 * time.Hour),
				MatcherEpoch: CurrentMatcherEpoch,
			},
		}
	}

	// Direct: a CVE on the package itself. Populates max_cvss.
	direct := base("pkg-direct")
	direct.Vulnerabilities = VulnSection{
		IsVulnerable: true, CVSSScore: 9.8, CVEs: []string{"CVE-2024-0001"},
	}
	if err := store.Upsert(ctx, "org-test", direct); err != nil {
		t.Fatalf("upsert direct: %v", err)
	}

	// Transitive-only: NO CVE of its own (so max_cvss stays NULL), but its
	// resolved closure carries one. This is the row the direct-only facet
	// could not see.
	transitive := base("pkg-transitive")
	transitive.Risk = &risk.Evaluation{
		Resolution: risk.Resolution{
			TransitiveSeverity: risk.TransitiveSeverity{CriticalCount: 1},
		},
	}
	if err := store.Upsert(ctx, "org-test", transitive); err != nil {
		t.Fatalf("upsert transitive: %v", err)
	}
	return eco
}

// assertFixtureCanDetectTheDefect is the fixture-adequacy control, and it is
// the most important part of these tests.
//
// The trivially-passing edit on a facet test is to give the transitive row a
// max_cvss too (or to drop it and assert a delta of 1). Both rows then satisfy
// the OLD direct-only predicate, the deltas still come out right, and the test
// passes against the UNFIXED code — proving nothing.
//
// So: hardcode the OLD predicate verbatim and require that exactly ONE row in
// this ecosystem satisfies it. Any edit that makes the fixture visible to the
// direct-only expression fails here, before the real assertions run.
func assertFixtureCanDetectTheDefect(t *testing.T, ctx context.Context, store *Store, eco string) {
	t.Helper()
	var directVisible int
	// NOTE: this string is the pre-D8-2 predicate ON PURPOSE. Do not
	// refactor it to use hasCVEExpr — the whole point is to measure the
	// fixture against the OLD behaviour.
	err := store.sql.DB().QueryRowContext(ctx, `
		SELECT COUNT(*) FROM intelligence_reports
		 WHERE ecosystem=$1 AND max_cvss IS NOT NULL AND max_cvss > 0
	`, eco).Scan(&directVisible)
	if err != nil {
		t.Fatalf("fixture control query: %v", err)
	}
	if directVisible != 1 {
		t.Fatalf("fixture control: %d row(s) visible to the OLD direct-only predicate, want exactly 1.\n"+
			"This fixture contains no row invisible to the direct-only predicate, so it CANNOT "+
			"detect D8-2. Do not 'fix' this by giving pkg-transitive a max_cvss — that is the "+
			"edit this control exists to reject.", directVisible)
	}
}

// TestFacetsCountTransitiveOnlyCVE — H1. The has-CVE facet must include a
// package whose only CVEs come from its dependency closure. Measured on the
// production corpus, that population (423) was LARGER than the direct one
// (339), so the facet was under-reporting by more than it reported.
func TestFacetsCountTransitiveOnlyCVE(t *testing.T) {
	db := openStaleDisclosureDB(t)
	store := NewStore(db)
	ctx := context.Background()

	before, err := store.Facets(ctx, "org-test")
	if err != nil {
		t.Fatalf("facets before: %v", err)
	}

	eco := mkTransitiveFixture(t, ctx, store)
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1`, eco)
	})
	assertFixtureCanDetectTheDefect(t, ctx, store, eco)

	after, err := store.Facets(ctx, "org-test")
	if err != nil {
		t.Fatalf("facets after: %v", err)
	}

	// Deltas, not absolutes: intelligence_reports is universal and a shared
	// database legitimately holds other rows.
	if got := after.HasCVE - before.HasCVE; got != 2 {
		t.Errorf("HasCVE delta = %d, want 2 (one direct + one transitive-only). "+
			"A delta of 1 means the facet is still direct-only.", got)
	}
	if got := after.TransitiveOnlyCVE - before.TransitiveOnlyCVE; got != 1 {
		t.Errorf("TransitiveOnlyCVE delta = %d, want 1. Without this disclosure the "+
			"HasCVE number moves with nothing on the wire explaining why.", got)
	}
}

// TestFacetAndFilterAgreeOnTransitiveCVE — H2. The sidebar count and the list
// it filters are two halves of one contract; fixing one and not the other
// gives an operator a number that does not match the rows beneath it.
func TestFacetAndFilterAgreeOnTransitiveCVE(t *testing.T) {
	db := openStaleDisclosureDB(t)
	store := NewStore(db)
	ctx := context.Background()

	eco := mkTransitiveFixture(t, ctx, store)
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1`, eco)
	})
	assertFixtureCanDetectTheDefect(t, ctx, store, eco)

	res, err := store.Search(ctx, SearchQuery{Ecosystem: eco, OnlyHasCVE: true, Limit: 100})
	if err != nil {
		t.Fatalf("search: %v", err)
	}

	// Assert on NAMES, not the count. A count-only assertion is satisfied
	// by a filter returning two WRONG rows.
	var got []string
	for _, r := range res.Rows {
		got = append(got, r.Package)
	}
	sort.Strings(got)
	want := []string{"pkg-direct", "pkg-transitive"}
	if len(got) != len(want) {
		t.Fatalf("OnlyHasCVE returned %v, want %v — if pkg-transitive is missing, the "+
			"filter is still direct-only while the facet counts it", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OnlyHasCVE returned %v, want %v", got, want)
		}
	}
}

// TestFacetsTolerateNullRiskEvaluation — H5. A row written before risk-V2 has
// risk_evaluation NULL entirely. The JSONB extract must read as "no
// transitive CVE", not error and not panic.
func TestFacetsTolerateNullRiskEvaluation(t *testing.T) {
	db := openStaleDisclosureDB(t)
	store := NewStore(db)
	ctx := context.Background()

	eco := "npm-nullrisk-" + strings.ReplaceAll(
		time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1`, eco)
	})
	collectedAt := time.Now().UTC().Truncate(time.Second)

	before, err := store.Facets(ctx, "org-test")
	if err != nil {
		t.Fatalf("facets before: %v", err)
	}

	// RAW INSERT, deliberately. Seeding this through Store.Upsert would
	// write a well-formed risk_evaluation blob, so the NULL column path —
	// the one a cast could fail on — would never be exercised and this test
	// would pass without touching the code it is meant to cover.
	if _, err := db.DB().ExecContext(ctx, `
		INSERT INTO intelligence_reports
		  (ecosystem, package_name, version, report, collected_at, fresh_until, trust_score)
		VALUES ($1, 'pkg-legacy', '1.0.0', $2::jsonb, $3, $4, 50)
	`, eco, `{"observation":{"collectedAt":"2020-01-01T00:00:00Z"}}`,
		collectedAt, collectedAt.Add(24*time.Hour)); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	after, err := store.Facets(ctx, "org-test")
	if err != nil {
		t.Fatalf("facets after a NULL risk_evaluation row: %v — the JSONB extract in "+
			"transitiveCVEExpr must tolerate the column being NULL outright", err)
	}
	if got := after.HasCVE - before.HasCVE; got != 0 {
		t.Errorf("HasCVE delta = %d, want 0 for a row with no CVE and no risk evaluation", got)
	}
	if got := after.TransitiveOnlyCVE - before.TransitiveOnlyCVE; got != 0 {
		t.Errorf("TransitiveOnlyCVE delta = %d, want 0", got)
	}
}
