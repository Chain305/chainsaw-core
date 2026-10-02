package intelligence

// DB-backed proof for A-3's selective backfill: a scope that selects ONLY the
// coordinates whose artifact holds an analysis from a superseded version of one
// named analyzer, and drives the EXISTING stale-report sweep to do it.

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"
)

// seedAnalysedCoordinate inserts a report row with a digest plus one
// artifact_analyses row at the given analyzer version. Returns the package name.
func seedAnalysedCoordinate(t *testing.T, f *analysisFixture, eco, pkg, digest, analyzer string, version int) {
	t.Helper()
	ctx := context.Background()
	// collected_at is NOW: these rows must be FRESH, so the ordinary staleness
	// half of the scope cannot select them. Otherwise "selects only X's rows"
	// would be untestable — every row would qualify twice.
	at := time.Now().UTC()

	// THE DIGEST GOES IN THE REPORT JSONB AND THE COLUMN IS LEFT NULL, so this
	// seed exercises the JSONB FALLBACK arm of reportArtifactSHAExpr.
	//
	// That is the shape of every row written before artifact_sha256 became
	// real — the column's old source, Scan.ScannedArtifactSHA, is a field no
	// provider assigns, so it was NULL corpus-wide — and rows gain the column
	// only as they re-upsert. Keeping the fallback arm under test is what stops
	// the backfill silently skipping the pre-migration majority.
	//
	// The COLUMN arm is covered separately by
	// TestStaleAnalyzerScopeSelectsOnTheColumnAlone, which seeds the
	// post-migration shape. Both arms need a test: whichever one is dropped,
	// the other keeps this file green.
	body := `{}`
	if digest != "" {
		body = `{"artifact":{"digests":{"sha256":"` + digest + `"}}}`
	}
	if _, err := f.db.DB().ExecContext(ctx, `
		INSERT INTO intelligence_reports
		  (ecosystem, package_name, version, report, collected_at, fresh_until)
		VALUES ($1, $2, '1.0.0', $3::jsonb, $4, $5)
	`, eco, pkg, body, at, at.Add(24*time.Hour)); err != nil {
		t.Fatalf("seed report %s: %v", pkg, err)
	}
	if analyzer == "" {
		return
	}
	if err := f.store.SaveArtifactAnalysis(ctx, ArtifactAnalysisKey{
		SHA256: digest, Ecosystem: eco, Analyzer: analyzer, Version: version,
	}, PartialReport{Scan: &ArtifactScanSection{Performed: true}}); err != nil {
		t.Fatalf("seed analysis %s: %v", pkg, err)
	}
}

// TestStaleAnalyzerScopeSelectsOnlyThatAnalyzersRows is assertion (3).
//
// Four coordinates, all FRESH so the staleness half selects none of them:
//
//	stale-x    — analysis from analyzer X at version 1, current is 2  -> SELECTED
//	current-x  — analysis from analyzer X already at version 2        -> not
//	stale-y    — analysis from a DIFFERENT analyzer at version 1      -> not
//	no-digest  — a report with no artifact_sha256 at all              -> not
//
// The last two are the assertions that matter. "stale-y" is the whole measure:
// bumping X must not select Y's rows, which is what a global matcher epoch
// cannot express. "no-digest" guards the NULL case — without the
// `artifact_sha256 IS NOT NULL` guard a NULL-vs-NULL comparison in the EXISTS
// could match anything.
func TestStaleAnalyzerScopeSelectsOnlyThatAnalyzersRows(t *testing.T) {
	f := newAnalysisFixture(t, "backfill")
	ctx := context.Background()

	uniq := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	eco := "npm-a3-" + uniq
	analyzerX := "x-" + uniq
	analyzerY := "y-" + uniq

	digestStaleX := strings.Repeat("a", 64)
	digestCurrentX := strings.Repeat("b", 64)
	digestStaleY := strings.Repeat("c", 64)

	t.Cleanup(func() {
		_, _ = f.db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1`, eco)
		_, _ = f.db.DB().Exec(`DELETE FROM artifact_analyses WHERE analyzer IN ($1,$2)`,
			analyzerX, analyzerY)
	})

	seedAnalysedCoordinate(t, f, eco, "stale-x", digestStaleX, analyzerX, 1)
	seedAnalysedCoordinate(t, f, eco, "current-x", digestCurrentX, analyzerX, 2)
	seedAnalysedCoordinate(t, f, eco, "stale-y", digestStaleY, analyzerY, 1)
	seedAnalysedCoordinate(t, f, eco, "no-digest", "", "", 0)

	scope, err := StaleAnalyzerScope(analyzerX, 2)
	if err != nil {
		t.Fatalf("StaleAnalyzerScope: %v", err)
	}

	// Scoped to this test's ecosystem, because the table is shared with every
	// other test in the package and a global count would depend on test order.
	pred, args := scope.where()
	args = append(args, eco)
	rows, err := f.db.DB().QueryContext(ctx,
		`SELECT package_name FROM intelligence_reports WHERE `+pred+
			` AND ecosystem = $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		t.Fatalf("select scope: %v", err)
	}
	defer func() { _ = rows.Close() }()

	got := map[string]bool{}
	for rows.Next() {
		var pkg string
		if err := rows.Scan(&pkg); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[pkg] = true
	}

	if !got["stale-x"] {
		t.Fatal("the scope selected NOTHING for the analyzer whose version moved, so " +
			"nothing below is a real assertion. Check the seed before reading the " +
			"exclusions as passes.")
	}
	if got["current-x"] {
		t.Error("selected current-x: its analysis is already at the current version. " +
			"The predicate is `< currentVersion`; selecting it would make every " +
			"backfill sweep re-derive the whole corpus forever.")
	}
	if got["stale-y"] {
		t.Error("selected stale-y: that is a DIFFERENT analyzer's superseded row. " +
			"This is A-3's entire measure — bumping X must select X's rows only. " +
			"Selecting Y's too is the global-epoch behaviour this replaces.")
	}
	if got["no-digest"] {
		t.Error("selected no-digest: that report has no artifact_sha256, so no " +
			"analysis can belong to it. The `artifact_sha256 IS NOT NULL` guard " +
			"in the EXISTS half is missing or ineffective.")
	}
	if len(got) != 1 {
		t.Errorf("scope selected %v, want exactly {stale-x}", analysisScopeKeys(got))
	}

	// The gauge must agree with the selection, for the same reason
	// CountStaleReports shares scope.where() with the iteration: an operator
	// shown a backlog the sweep will not work through cannot tell a finished
	// backfill from a broken one.
	n, err := f.store.CountStaleAnalyses(ctx, analyzerX, 2)
	if err != nil {
		t.Fatalf("CountStaleAnalyses: %v", err)
	}
	if n < 1 {
		t.Errorf("CountStaleAnalyses = %d with a superseded row seeded, want >= 1. "+
			"This counter's failure mode is reporting ZERO while work remains — the "+
			"shape of the epoch-15 drain being called complete with 3,843 rows left.", n)
	}
}

// TestStaleAnalyzerScopeRejectsAnUnknownAnalyzer: a typo must be an error, not
// a scope that quietly selects nothing and reads as "nothing to do".
func TestStaleAnalyzerScopeRejectsAnUnknownAnalyzer(t *testing.T) {
	if _, err := StaleAnalyzerScope("", 2); err == nil {
		t.Error("an empty analyzer name produced a usable scope")
	}
	if _, err := StaleAnalyzerScope("x", AnalyzerNotCacheable); err == nil {
		t.Error("a non-cacheable version produced a usable scope; a scope built on " +
			"version 0 would select every analysed row in the corpus")
	}
}

// TestStaleAnalyzerScopeDoesNotDisturbTheOtherHalves: the staleness half must
// behave exactly as before when the analyzer fields are unset. where() was
// restructured from two returns into one, and this is the regression guard for
// that refactor.
func TestStaleAnalyzerScopeDoesNotDisturbTheOtherHalves(t *testing.T) {
	cutoff := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	plain, args := StaleReportScope{OlderThan: cutoff}.where()
	if !strings.HasPrefix(plain, "collected_at < $1 AND ") {
		t.Errorf("staleness-only scope rendered %q; the single-half shape changed", plain)
	}
	if len(args) != 1 {
		t.Errorf("staleness-only scope args = %d, want 1", len(args))
	}
	if strings.Contains(plain, "artifact_analyses") {
		t.Error("a scope with no analyzer set referenced artifact_analyses")
	}

	withArtifact, args := StaleReportScope{
		OlderThan:          cutoff,
		ArtifactEcosystems: []string{"npm"},
		ArtifactOlderThan:  cutoff,
	}.where()
	if !strings.Contains(withArtifact, " OR ") {
		t.Error("the artifact half did not OR into the predicate")
	}
	if !strings.Contains(withArtifact, declaredCoordinateAntiJoin) {
		t.Error("the declared-coordinate anti-join is missing from the two-half " +
			"predicate. It is ANDed once onto the whole disjunction now; losing it " +
			"lets the sweep eat monitorsweep's diff window, which is C-6.")
	}
	if len(args) != 3 {
		t.Errorf("two-half scope args = %d, want 3 (olderThan, artifactOlderThan, eco)", len(args))
	}
}

// analysisScopeKeys is local to this file: the package already has a keysOf
// for a different map shape.
func analysisScopeKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestStaleAnalyzerScopeSelectsOnTheColumnAlone covers the COLUMN arm of
// reportArtifactSHAExpr — the post-migration shape, and the only arm that
// survives a metadata-only rescan.
//
// `report` is replaced wholesale on every upsert and mergeReportPayload
// preserves Digests.Actual and .Verified but NOT .SHA256, so a byte-scanned
// row that is later Tier-1 refreshed keeps the column and loses the JSON key.
// Without this arm the backfill would lose exactly those rows — and they are
// the common case once the corpus has turned over once.
func TestStaleAnalyzerScopeSelectsOnTheColumnAlone(t *testing.T) {
	f := newAnalysisFixture(t, "colarm")
	ctx := context.Background()

	uniq := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	eco := "npm-colarm-" + uniq
	analyzer := "ca-" + uniq
	digest := strings.Repeat("d", 64)

	t.Cleanup(func() {
		_, _ = f.db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1`, eco)
		_, _ = f.db.DB().Exec(`DELETE FROM artifact_analyses WHERE analyzer=$1`, analyzer)
	})

	// Column set, report JSONB carrying NO digest: a row that was byte-scanned
	// and has since been metadata-refreshed.
	at := time.Now().UTC()
	if _, err := f.db.DB().ExecContext(ctx, `
		INSERT INTO intelligence_reports
		  (ecosystem, package_name, version, report, collected_at, fresh_until, artifact_sha256)
		VALUES ($1, 'col-only', '1.0.0', '{}'::jsonb, $2, $3, $4)
	`, eco, at, at.Add(24*time.Hour), digest); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := f.store.SaveArtifactAnalysis(ctx, ArtifactAnalysisKey{
		SHA256: digest, Ecosystem: eco, Analyzer: analyzer, Version: 1,
	}, PartialReport{Scan: &ArtifactScanSection{Performed: true}}); err != nil {
		t.Fatalf("seed analysis: %v", err)
	}

	scope, err := StaleAnalyzerScope(analyzer, 2)
	if err != nil {
		t.Fatalf("StaleAnalyzerScope: %v", err)
	}
	pred, args := scope.where()
	args = append(args, eco)
	var n int
	if err := f.db.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM intelligence_reports WHERE `+pred+
			` AND ecosystem = $`+strconv.Itoa(len(args)), args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("scope selected %d rows, want 1. The row carries its digest in the "+
			"artifact_sha256 COLUMN and not in the report JSONB, which is what every "+
			"row looks like after a metadata-only rescan. If reportArtifactSHAExpr "+
			"reads only the JSON path, the backfill loses them.", n)
	}
}
