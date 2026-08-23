package pgstore

// Tests for the opt-in unevaluable-coordinate cleanup
// (migrate_unevaluable_coordinates.go).
//
// The DB-backed case needs a real Postgres via CHAINSAW_DATABASE_URL, and it
// runs against a PRIVATE scratch database on that server rather than the
// shared one — see requireCleanupDB for why a globally-scoped DELETE cannot
// share a database with a concurrently-running package. Because the database
// is private, the counts are asserted exactly rather than as deltas.
//
// Unlike its neighbours this test does NOT silently skip when the DSN is unset
// and CHAINSAW_TEST_REQUIRE_DB is set: a cleanup that deletes rows is exactly
// the thing that must not report "ok" having asserted nothing.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// productionRule mirrors what intelligence.UnevaluableCoordinateRule()
// returns. It is spelled out here rather than imported because pgstore cannot
// import core/intelligence (the dependency runs the other way) — which is the
// same reason the rule is a parameter in the first place.
func productionRule() UnevaluableCoordinateRule {
	return UnevaluableCoordinateRule{
		UnresolvedPropertyMarker: "${",
		MavenFamilyEcosystems:    []string{"maven", "gradle", "maven-hosted"},
		MavenNonVersions:         []string{"metadata", "release", "latest"},
	}
}

// TestUnevaluableCoordinateRuleRejectsEmptyMarker is the single most important
// unit case in this file. Postgres `strpos(version, ”)` returns 1 for EVERY
// row, so a rule with a blank marker would select the whole table. Both entry
// points must refuse it rather than default it.
func TestUnevaluableCoordinateRuleRejectsEmptyMarker(t *testing.T) {
	t.Parallel()

	for _, marker := range []string{"", "   "} {
		rule := UnevaluableCoordinateRule{
			UnresolvedPropertyMarker: marker,
			MavenFamilyEcosystems:    []string{"maven"},
			MavenNonVersions:         []string{"metadata"},
		}
		if _, err := rule.normalized(); err == nil {
			t.Fatalf("normalized() with marker %q returned no error — an empty marker "+
				"makes strpos match every row", marker)
		}
	}
}

// TestUnevaluableCoordinatePredicate pins the SQL fragment and its argument
// order, including the case where an under-populated rule must NARROW the
// match rather than widen it.
func TestUnevaluableCoordinatePredicate(t *testing.T) {
	t.Parallel()

	full, err := productionRule().normalized()
	if err != nil {
		t.Fatalf("normalized: %v", err)
	}
	pred, args := full.unevaluablePredicate()
	if len(args) != 1+3+3 {
		t.Fatalf("args = %v, want marker + 3 ecosystems + 3 non-versions", args)
	}
	if args[0] != "${" {
		t.Fatalf("args[0] = %v, want the marker first", args[0])
	}
	for _, want := range []string{"version IS NULL", "btrim(version) = ''", "strpos(version, ?)",
		"lower(btrim(ecosystem)) IN", "lower(btrim(version)) IN"} {
		if !strings.Contains(pred, want) {
			t.Errorf("predicate %q is missing %q", pred, want)
		}
	}

	// No Maven non-versions declared → the Maven clause must vanish entirely,
	// not degenerate into "any maven-family row".
	narrow, err := UnevaluableCoordinateRule{
		UnresolvedPropertyMarker: "${",
		MavenFamilyEcosystems:    []string{"maven"},
	}.normalized()
	if err != nil {
		t.Fatalf("normalized narrow: %v", err)
	}
	narrowPred, narrowArgs := narrow.unevaluablePredicate()
	if strings.Contains(narrowPred, "ecosystem") {
		t.Errorf("predicate with an empty MavenNonVersions list still references ecosystem: %q", narrowPred)
	}
	if len(narrowArgs) != 1 {
		t.Errorf("narrow args = %v, want just the marker", narrowArgs)
	}
}

// TestPurgeUnevaluableCoordinatesNoStore covers the no-DB guards so the
// package runs something for this migration without a database fixture.
func TestPurgeUnevaluableCoordinatesNoStore(t *testing.T) {
	t.Parallel()

	var nilStore *Store
	n, err := nilStore.PurgeUnevaluableCoordinates(context.Background(), productionRule())
	if err != nil {
		t.Fatalf("nil store purge: unexpected error: %v", err)
	}
	if n != 0 {
		t.Fatalf("nil store purge: expected 0 rows, got %d", n)
	}
	counts, err := nilStore.UnevaluableCoordinateCounts(context.Background(), productionRule())
	if err != nil {
		t.Fatalf("nil store counts: unexpected error: %v", err)
	}
	if len(counts) != 0 {
		t.Fatalf("nil store counts: expected none, got %v", counts)
	}
}

// requireCleanupDB gates the DB-backed case, and hands back a PRIVATE scratch
// database rather than the shared CHAINSAW_DATABASE_URL.
//
// The private database is not fastidiousness: PurgeUnevaluableCoordinates is
// deliberately unscoped — it deletes every unevaluable row in the table, which
// is what an operator wants — and `go test ./core/intelligence/... ./core/pgstore/...`
// runs those two packages CONCURRENTLY against one DSN. core/intelligence's
// TestUpsert_MarksUnevaluableCoordinate inserts a `${commons.lang3.version}`
// fixture and then reads it back; a global DELETE landing between those two
// steps would fail a test in a package this one never touches. Isolating the
// purge is the only way to make the assertions here exact AND leave the
// neighbour alone.
//
// CHAINSAW_TEST_REQUIRE_DB turns every skip on this path into a hard failure,
// including the CREATEDB check — provisionScratchDatabase skips internally
// when the role cannot create a database, and a run that was meant to exercise
// Postgres must not report "ok" having asserted nothing.
func requireCleanupDB(t *testing.T) *Store {
	t.Helper()
	strict := os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != ""
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		if strict {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but CHAINSAW_DATABASE_URL is empty — " +
				"this test was supposed to run against Postgres")
		}
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping unevaluable-coordinate cleanup test")
	}
	if strict {
		requireCreateDB(t, dsn)
	}
	scratch, drop := provisionScratchDatabase(t, dsn)
	t.Cleanup(drop)

	store, err := Open(scratch)
	if err != nil {
		t.Fatalf("open scratch store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// requireCreateDB fails loudly under strict mode when the test role cannot
// create a database, so provisionScratchDatabase's internal t.Skipf cannot
// silently swallow a required run.
func requireCreateDB(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("CHAINSAW_TEST_REQUIRE_DB is set but the DSN will not open: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("CHAINSAW_TEST_REQUIRE_DB is set but Postgres is unreachable: %v", err)
	}
	var canCreate bool
	if err := db.QueryRow(
		`SELECT rolcreatedb OR rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&canCreate); err != nil {
		t.Fatalf("CHAINSAW_TEST_REQUIRE_DB is set but the CREATEDB privilege check failed: %v", err)
	}
	if !canCreate {
		t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but the test role lacks CREATEDB — " +
			"this test needs a private database because the purge is global")
	}
}

// TestPurgeUnevaluableCoordinates is the load-bearing case. In one fixture it
// asserts:
//
//  1. the three production shapes go — `${…}`, the synthetic `metadata`
//     marker, and an empty version;
//  2. `metadata` goes for every Maven-family ecosystem name, INCLUDING the
//     repo-name leak "maven-hosted";
//  3. a normal coordinate stays;
//  4. a docker image tagged "latest" stays — the Maven-family scope is what
//     stops the cleanup eating real inventory;
//  5. an unevaluable row carrying is_malicious = TRUE is RETAINED, and the
//     dry run reports it as such;
//  6. the dry run counts exactly the rows the purge then removes;
//  7. a second run removes nothing.
func TestPurgeUnevaluableCoordinates(t *testing.T) {
	store := requireCleanupDB(t)
	ctx := context.Background()
	rule := productionRule()
	nonce := fmt.Sprintf("%d", time.Now().UnixNano())

	type fixture struct {
		eco       string
		pkg       string
		version   string
		malicious bool
		wantGone  bool
		why       string
	}
	fixtures := []fixture{
		{eco: "maven", pkg: "org.slf4j:slf4j-api-purge-" + nonce, version: "${slf4jVersion}",
			wantGone: true, why: "unresolved property, the production shape"},
		{eco: "gradle", pkg: "com.google.code.findbugs:jsr305-purge-" + nonce, version: "${jsr305.version}",
			wantGone: true, why: "unresolved property under gradle"},
		{eco: "maven", pkg: "com.t_est.upload:t-est-maven-purge-" + nonce, version: "metadata",
			wantGone: true, why: "synthetic maven-metadata.xml marker"},
		{eco: "maven-hosted", pkg: "com.t_est.upload:hosted-purge-" + nonce, version: "metadata",
			wantGone: true, why: "the repo-name-as-ecosystem leak is in the Maven family list"},
		{eco: "maven", pkg: "com.example:release-purge-" + nonce, version: "RELEASE",
			wantGone: true, why: "Maven meta-version, matched case-insensitively"},
		{eco: "npm", pkg: "empty-version-purge-" + nonce, version: "",
			wantGone: true, why: "an empty version names nothing, in any ecosystem"},

		{eco: "maven", pkg: "org.apache.commons:commons-lang3-purge-" + nonce, version: "3.12.0",
			wantGone: false, why: "an ordinary, evaluable coordinate"},
		{eco: "docker", pkg: "library/nginx-purge-" + nonce, version: "latest",
			wantGone: false, why: "\"latest\" is an ordinary docker tag; the Maven scope is what saves it"},
		{eco: "maven", pkg: "com.evil:malware-purge-" + nonce, version: "${evil.version}",
			malicious: true, wantGone: false, why: "a malware verdict is retained even on a junk coordinate"},
	}

	del := func() {
		for _, f := range fixtures {
			if _, err := store.DB().ExecContext(ctx,
				`DELETE FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
				f.eco, f.pkg, f.version); err != nil {
				t.Logf("cleanup %s/%s: %v", f.eco, f.pkg, err)
			}
		}
	}
	del()
	t.Cleanup(del)

	at := time.Now().UTC()
	for _, f := range fixtures {
		if _, err := store.DB().ExecContext(ctx, `
			INSERT INTO intelligence_reports
			  (ecosystem, package_name, version, report, collected_at, fresh_until, is_malicious, warning_count)
			VALUES ($1,$2,$3,$4,$5,$6,$7,0)`,
			f.eco, f.pkg, f.version, `{}`, at, at.Add(time.Hour), f.malicious); err != nil {
			t.Fatalf("insert fixture %s/%s@%s: %v", f.eco, f.pkg, f.version, err)
		}
	}

	// -- 6. the dry run sizes exactly what the purge will do ---------------
	before, err := store.UnevaluableCoordinateCounts(ctx, rule)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	deletableBefore, retainedBefore := 0, 0
	for _, c := range before {
		deletableBefore += c.Deletable
		retainedBefore += c.Retained
	}
	// Exact, not a lower bound: the scratch database contains nothing but
	// these fixtures, so a predicate that matched one row too many would show
	// up here rather than hiding inside a ">=".
	if deletableBefore != 6 {
		t.Fatalf("dry run reported %d deletable rows, want exactly the 6 unevaluable "+
			"fixtures: %+v", deletableBefore, before)
	}
	if retainedBefore != 1 {
		t.Fatalf("dry run reported %d retained rows, want exactly the 1 malicious row — "+
			"the retention must be visible in the dry run, not silent: %+v",
			retainedBefore, before)
	}

	// -- the purge ---------------------------------------------------------
	removed, err := store.PurgeUnevaluableCoordinates(ctx, rule)
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if removed != int64(deletableBefore) {
		t.Fatalf("purge removed %d rows but the dry run counted %d deletable — "+
			"the count and the delete must enumerate the same population", removed, deletableBefore)
	}

	// -- 1..5. row-by-row ---------------------------------------------------
	for _, f := range fixtures {
		present := rowExists(t, store.DB(), f.eco, f.pkg, f.version)
		switch {
		case f.wantGone && present:
			t.Errorf("%s/%s@%q survived the purge, want removed (%s)", f.eco, f.pkg, f.version, f.why)
		case !f.wantGone && !present:
			t.Errorf("%s/%s@%q was removed by the purge, want retained (%s)", f.eco, f.pkg, f.version, f.why)
		}
	}

	// -- 7. a second run is a no-op ----------------------------------------
	after, err := store.UnevaluableCoordinateCounts(ctx, rule)
	if err != nil {
		t.Fatalf("second dry run: %v", err)
	}
	deletableAfter, retainedAfter := 0, 0
	for _, c := range after {
		deletableAfter += c.Deletable
		retainedAfter += c.Retained
	}
	if deletableAfter != 0 {
		t.Errorf("second dry run reports %d deletable rows, want 0: %+v", deletableAfter, after)
	}
	if retainedAfter != retainedBefore {
		t.Errorf("retained count changed across the purge: %d → %d; retained rows must be untouched",
			retainedBefore, retainedAfter)
	}
	second, err := store.PurgeUnevaluableCoordinates(ctx, rule)
	if err != nil {
		t.Fatalf("second purge: %v", err)
	}
	if second != 0 {
		t.Errorf("second purge removed %d rows, want 0 — re-running must be a no-op", second)
	}

	// A malformed rule must never reach the database.
	if _, err := store.PurgeUnevaluableCoordinates(ctx, UnevaluableCoordinateRule{}); err == nil {
		t.Error("purge with an empty rule returned no error — a blank marker would match every row")
	}
}

func rowExists(t *testing.T, db *sql.DB, eco, pkg, version string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(
		`SELECT count(*) FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
		eco, pkg, version).Scan(&n); err != nil {
		t.Fatalf("probe %s/%s@%s: %v", eco, pkg, version, err)
	}
	return n > 0
}
