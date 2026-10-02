package intelligence

// DB-backed proof for A-3: artifact_analyses reuse, per-analyzer version
// invalidation, Ephemeral isolation, and org-lessness.
//
// Run with a throwaway Postgres:
//
//	CHAINSAW_DATABASE_URL='postgres://...' go test ./core/intelligence/ -run ArtifactAnalys
//
// Every test here FAILS rather than skips when the sweep it depends on selects
// nothing, so a green run cannot mean "the fixture missed".

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

// countingAnalyzer is a byte-reading provider with a settable analyzer
// version and a run counter. The counter is the whole measurement: "reuse
// worked" means the provider did not run a second time.
type countingAnalyzer struct {
	name    string
	version int32
	config  atomic.Value // string; "" means "reads no configuration"
	runs    int64
	partial PartialReport
}

func (c *countingAnalyzer) Name() string         { return c.name }
func (c *countingAnalyzer) Signal() SignalMask   { return 0 }
func (c *countingAnalyzer) Tier() int            { return 2 }
func (c *countingAnalyzer) NeedsArtifact() bool  { return true }
func (c *countingAnalyzer) Supports(string) bool { return true }
func (c *countingAnalyzer) AnalyzerVersion() int { return int(atomic.LoadInt32(&c.version)) }
func (c *countingAnalyzer) setVersion(v int32)   { atomic.StoreInt32(&c.version, v) }
func (c *countingAnalyzer) setConfig(s string)   { c.config.Store(s) }
func (c *countingAnalyzer) AnalyzerConfigFingerprint() string {
	if v, ok := c.config.Load().(string); ok {
		return v
	}
	return ""
}
func (c *countingAnalyzer) runCount() int64 { return atomic.LoadInt64(&c.runs) }
func (c *countingAnalyzer) Run(context.Context, Request, *Report) (PartialReport, error) {
	atomic.AddInt64(&c.runs, 1)
	return c.partial, nil
}

func openAnalysisDB(t *testing.T) *pgstore.Store {
	t.Helper()
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// analysisFixture is one coordinate plus two cacheable analyzers over one
// artifact, wired into a real DefaultService against a real store.
type analysisFixture struct {
	db     *pgstore.Store
	store  *Store
	svc    *DefaultService
	alpha  *countingAnalyzer
	beta   *countingAnalyzer
	key    Key
	bytes  []byte
	digest string
}

func newAnalysisFixture(t *testing.T, tag string) *analysisFixture {
	t.Helper()
	db := openAnalysisDB(t)
	store := NewStore(db)

	uniq := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	key := Key{Ecosystem: "npm", Package: tag + "-" + uniq, Version: "1.0.0"}
	// Distinct bytes per fixture so parallel/ordered tests cannot share a
	// digest and read each other's rows.
	body := []byte("artifact-" + tag + "-" + uniq)

	alpha := &countingAnalyzer{name: "alpha-" + tag, version: 1,
		partial: PartialReport{Scan: &ArtifactScanSection{Performed: true, HasInstallScript: true}}}
	beta := &countingAnalyzer{name: "beta-" + tag, version: 1,
		partial: PartialReport{Scan: &ArtifactScanSection{Performed: true, MinifiedCode: true}}}

	svc := New(Config{Store: store, Providers: []Provider{alpha, beta}})
	t.Cleanup(func() { _ = svc.Close() })

	digest := fullArtifactSHA256(context.Background(), &ArtifactHandle{Bytes: body})
	if digest == "" {
		t.Fatal("fixture digest is empty, so every assertion below would pass " +
			"vacuously — fullArtifactSHA256 refused these bytes")
	}

	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2`,
			key.Ecosystem, key.Package)
		_, _ = db.DB().Exec(`DELETE FROM artifact_analyses WHERE artifact_sha256=$1`, digest)
	})

	return &analysisFixture{db: db, store: store, svc: svc,
		alpha: alpha, beta: beta, key: key, bytes: body, digest: digest}
}

// scan forces a fan-out: a 1ns staleness bound makes any stored row stale and
// AllowStale=false refuses to serve it, which is the same pair refreshAsync
// uses. Without it the SECOND scan would return the cached intelligence_reports
// row and never reach the analyzer cache at all — the test would pass while
// proving nothing.
func (f *analysisFixture) scan(t *testing.T, ephemeral bool) *Report {
	t.Helper()
	rep, err := f.svc.Scan(context.Background(), Request{
		Key:      f.key,
		Artifact: &ArtifactHandle{Bytes: f.bytes},
		Options: Options{
			AllowStale:   false,
			MaxStaleness: time.Nanosecond,
			Ephemeral:    ephemeral,
		},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if rep == nil {
		t.Fatal("scan returned a nil report")
	}
	return rep
}

// scanAs repeats scan against a different ecosystem on the SAME bytes. Used to
// prove the analysis rows are ecosystem-scoped.
func (f *analysisFixture) scanAs(t *testing.T, ecosystem string) *Report {
	t.Helper()
	key := f.key
	key.Ecosystem = ecosystem
	t.Cleanup(func() {
		_, _ = f.db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2`,
			ecosystem, key.Package)
	})
	rep, err := f.svc.Scan(context.Background(), Request{
		Key:      key,
		Artifact: &ArtifactHandle{Bytes: f.bytes},
		Options:  Options{AllowStale: false, MaxStaleness: time.Nanosecond},
	})
	if err != nil {
		t.Fatalf("scan as %s: %v", ecosystem, err)
	}
	return rep
}

func (f *analysisFixture) rows(t *testing.T) int {
	t.Helper()
	n, err := f.store.analysisRowCount(context.Background(), f.digest)
	if err != nil {
		t.Fatalf("count analysis rows: %v", err)
	}
	return n
}

// TestArtifactAnalysisReuseSkipsReanalysis is assertion (1): the second scan of
// the same bytes does not re-run the analyzers.
func TestArtifactAnalysisReuseSkipsReanalysis(t *testing.T) {
	f := newAnalysisFixture(t, "reuse")

	first := f.scan(t, false)
	if f.alpha.runCount() != 1 || f.beta.runCount() != 1 {
		t.Fatalf("first scan: alpha=%d beta=%d, want 1 and 1 — the fan-out did not run, "+
			"so nothing below is a reuse test", f.alpha.runCount(), f.beta.runCount())
	}
	if len(first.Observation.ReusedAnalyzers) != 0 {
		t.Errorf("first scan reported reuse %v on an empty cache", first.Observation.ReusedAnalyzers)
	}
	if got := f.rows(t); got != 2 {
		t.Fatalf("artifact_analyses rows after first scan = %d, want 2 (one per analyzer)", got)
	}

	second := f.scan(t, false)
	if f.alpha.runCount() != 1 || f.beta.runCount() != 1 {
		t.Errorf("second scan re-ran the analyzers: alpha=%d beta=%d, want 1 and 1. "+
			"The stored analysis for these exact bytes at the current version was not reused.",
			f.alpha.runCount(), f.beta.runCount())
	}
	reused := strings.Join(second.Observation.ReusedAnalyzers, ",")
	if !strings.Contains(reused, f.alpha.name) || !strings.Contains(reused, f.beta.name) {
		t.Errorf("ReusedAnalyzers = %v, want both analyzers", second.Observation.ReusedAnalyzers)
	}

	// The facts must still be ON the report — reuse that loses the facts is
	// worse than no reuse, and the run counter alone cannot tell the two apart.
	if !second.Scan.Performed || !second.Scan.HasInstallScript || !second.Scan.MinifiedCode {
		t.Errorf("reused scan lost facts: performed=%v installScript=%v minified=%v",
			second.Scan.Performed, second.Scan.HasInstallScript, second.Scan.MinifiedCode)
	}
	// TierComplete must still report 2. A reused Tier-2 analyzer completed its
	// tier; reporting 1 would make the UI poll forever.
	if second.Observation.TierComplete != 2 {
		t.Errorf("TierComplete = %d on a fully reused scan, want 2",
			second.Observation.TierComplete)
	}
}

// TestArtifactAnalysisVersionBumpRerunsOnlyThatAnalyzer is assertion (2), and
// it is the one that carries A-3's measure: an analyzer upgrade reworks its own
// rows and nothing else.
func TestArtifactAnalysisVersionBumpRerunsOnlyThatAnalyzer(t *testing.T) {
	f := newAnalysisFixture(t, "bump")

	f.scan(t, false)
	if f.alpha.runCount() != 1 || f.beta.runCount() != 1 {
		t.Fatalf("seed scan: alpha=%d beta=%d, want 1 and 1", f.alpha.runCount(), f.beta.runCount())
	}

	f.alpha.setVersion(2)
	f.scan(t, false)

	if f.alpha.runCount() != 2 {
		t.Errorf("alpha ran %d times, want 2: its version moved 1 -> 2, so its cached "+
			"row is from a superseded generation and must not be reused", f.alpha.runCount())
	}
	if f.beta.runCount() != 1 {
		t.Errorf("beta ran %d times, want 1: its version did not change, so bumping "+
			"ALPHA must not invalidate it. This is the whole point of a per-analyzer "+
			"version instead of a global epoch.", f.beta.runCount())
	}
	// Three rows: alpha@1 (kept, still valid for a rollback), alpha@2, beta@1.
	if got := f.rows(t); got != 3 {
		t.Errorf("artifact_analyses rows = %d, want 3 (alpha@1, alpha@2, beta@1). "+
			"A bump must ADD a generation, not replace one — the old row is what "+
			"makes a rollback to the previous binary free.", got)
	}
}

// TestArtifactAnalysisEphemeralNeverTouchesTheTable is assertion (4).
func TestArtifactAnalysisEphemeralNeverTouchesTheTable(t *testing.T) {
	f := newAnalysisFixture(t, "ephem")

	rep := f.scan(t, true)
	if f.alpha.runCount() != 1 || f.beta.runCount() != 1 {
		t.Fatalf("ephemeral scan: alpha=%d beta=%d, want 1 and 1 — providers must still run",
			f.alpha.runCount(), f.beta.runCount())
	}
	if got := f.rows(t); got != 0 {
		t.Fatalf("an Ephemeral scan WROTE %d artifact_analyses rows. Caller-supplied "+
			"bytes carry a caller-asserted coordinate and must never reach shared "+
			"state — that is what Options.Ephemeral exists to prevent.", got)
	}
	if len(rep.Observation.ReusedAnalyzers) != 0 {
		t.Errorf("ephemeral scan reported reuse %v; it must not READ the table either",
			rep.Observation.ReusedAnalyzers)
	}

	// And the read direction, proven against a populated cache: seed the table
	// from a non-ephemeral scan, then assert an ephemeral scan still re-runs.
	f.scan(t, false)
	if got := f.rows(t); got != 2 {
		t.Fatalf("seed scan wrote %d rows, want 2 — the read half of this test needs "+
			"a populated cache to prove anything", got)
	}
	before := f.alpha.runCount()
	f.scan(t, true)
	if f.alpha.runCount() != before+1 {
		t.Errorf("an Ephemeral scan REUSED a stored analysis (alpha runs %d -> %d). "+
			"It must analyse the bytes it carries, never a row the shared cache holds.",
			before, f.alpha.runCount())
	}
}

// TestArtifactAnalysesHasNoOrgColumn is assertion (5). The L-02 federation
// decision is that a fact about a coordinate is not a fact about a tenant;
// this table goes one level lower — a fact about BYTES — so the same rule is
// even less negotiable here.
func TestArtifactAnalysesHasNoOrgColumn(t *testing.T) {
	db := openAnalysisDB(t)
	rows, err := db.DB().Query(`
		SELECT column_name FROM information_schema.columns
		 WHERE table_name = 'artifact_analyses'`)
	if err != nil {
		t.Fatalf("read columns: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		cols = append(cols, c)
	}
	if len(cols) == 0 {
		t.Fatal("artifact_analyses has no columns, so this test proves nothing — " +
			"the migration did not run against this database")
	}
	for _, c := range cols {
		if strings.Contains(c, "org") {
			t.Errorf("artifact_analyses has column %q. An analysis result is a fact "+
				"about bytes and bytes have no tenant; partitioning it per-org would "+
				"reintroduce exactly what L-02 closed. Columns: %v", c, cols)
		}
	}
}

// TestArtifactAnalysisConfigChangeRerunsOnlyThatAnalyzer is the regression test
// for the defect the thresholds had: an operator-configurable input that the
// cache key did not carry.
//
// trivial_package and too_many_files resolve a threshold from the environment
// at construction, and capability reads its lane flag inside Run. Before
// analyzer_config was a key component, the partial computed under the old
// setting was served for those bytes indefinitely — and nothing evicts the
// table, so there was no self-heal.
func TestArtifactAnalysisConfigChangeRerunsOnlyThatAnalyzer(t *testing.T) {
	f := newAnalysisFixture(t, "config")
	f.alpha.setConfig("loc=10")
	f.beta.setConfig("")

	f.scan(t, false)
	if f.alpha.runCount() != 1 || f.beta.runCount() != 1 {
		t.Fatalf("seed scan: alpha=%d beta=%d, want 1 and 1", f.alpha.runCount(), f.beta.runCount())
	}

	// Same bytes, same version, DIFFERENT threshold.
	f.alpha.setConfig("loc=250")
	f.scan(t, false)

	if f.alpha.runCount() != 2 {
		t.Errorf("alpha ran %d times, want 2: its config fingerprint changed, so the "+
			"cached partial was computed under a threshold this process no longer "+
			"uses and must not be reused", f.alpha.runCount())
	}
	if f.beta.runCount() != 1 {
		t.Errorf("beta ran %d times, want 1: changing ALPHA's configuration must not "+
			"invalidate another analyzer", f.beta.runCount())
	}
	// alpha@loc=10, alpha@loc=250, beta@"" — the old row survives, so reverting
	// the threshold reuses it instead of re-deriving the corpus again.
	if got := f.rows(t); got != 3 {
		t.Errorf("artifact_analyses rows = %d, want 3 (alpha at two configs, beta at "+
			"one). A config change must ADD a row, not replace one.", got)
	}
}

// TestArtifactAnalysisIsEcosystemScoped proves the ecosystem is part of the
// key and not merely a stored column.
//
// This was R3 in the design and it was NOT implemented in the first cut: the
// column was written and never compared. installscripts branches npm vs pip
// and capability picks a per-ecosystem scanner, so identical bytes published to
// two ecosystems are two different analyses, and serving one for the other is
// the wrong parser's facts.
func TestArtifactAnalysisIsEcosystemScoped(t *testing.T) {
	f := newAnalysisFixture(t, "ecoscope")

	f.scan(t, false) // npm
	if f.alpha.runCount() != 1 {
		t.Fatalf("seed scan: alpha=%d, want 1", f.alpha.runCount())
	}
	if got := f.rows(t); got != 2 {
		t.Fatalf("seed wrote %d rows, want 2 — without a populated cache this test "+
			"cannot distinguish a miss from an empty table", got)
	}

	// Same bytes, same analyzers, same versions — different ecosystem.
	f.scanAs(t, "pypi")

	if f.alpha.runCount() != 2 {
		t.Errorf("alpha ran %d times, want 2: the stored analysis was produced for npm "+
			"and this scan is pypi. Reusing it serves the wrong ecosystem's parser "+
			"output.", f.alpha.runCount())
	}
	if got := f.rows(t); got != 4 {
		t.Errorf("artifact_analyses rows = %d, want 4 (two analyzers x two "+
			"ecosystems)", got)
	}
}
