package intelligence

// Tests for the matcher-epoch recompute sweep.
//
// The defect these pin is not "the sweep computes the wrong thing" — it is
// "there was no sweep, and the backlog was structurally undrainable". So the
// load-bearing assertions are about REACH (a row with no package_metadata row
// is picked up), about the sweep still having a caller, and about the backlog
// being observable. A test that only proved the sweep works when called would
// have passed on the day the defect shipped.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/metadata"
)

// fakeRecomputeSource is the in-memory RecomputeSource. It models the one
// property that matters for the sweep's control flow: a coordinate leaves the
// backlog once it has been recomputed, and stays if it has not.
type fakeRecomputeSource struct {
	mu   sync.Mutex
	rows []MatcherStaleRow
	// iterErr, when non-nil, is returned by the first IterateMatcherStale.
	iterErr error
	// countErr, when non-nil, is returned by CountMatcherStale.
	countErr error
	// pages records the (cursor, limit) of every page requested, so a test
	// can assert the sweep pages rather than re-reading page one forever.
	pages []string
}

func (f *fakeRecomputeSource) IterateMatcherStale(ctx context.Context, after MatcherStaleCursor, limit int) ([]MatcherStaleRow, MatcherStaleCursor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.iterErr != nil {
		err := f.iterErr
		f.iterErr = nil
		return nil, MatcherStaleCursor{}, err
	}
	f.pages = append(f.pages, fmt.Sprintf("%d/%s@%s:%d", after.Epoch, after.Ecosystem, after.Version, limit))

	// Find the first row strictly after the cursor, in the same order the
	// real query promises: epoch ASC, then the primary key.
	start := 0
	if !after.IsZero() {
		for i, r := range f.rows {
			if r.Epoch > after.Epoch ||
				(r.Epoch == after.Epoch && r.Ecosystem+"\x00"+r.Package+"\x00"+r.Version >
					after.Ecosystem+"\x00"+after.Package+"\x00"+after.Version) {
				start = i
				break
			}
			start = i + 1
		}
	}
	end := start + limit
	if end > len(f.rows) {
		end = len(f.rows)
	}
	page := append([]MatcherStaleRow(nil), f.rows[start:end]...)
	if len(page) < limit {
		return page, MatcherStaleCursor{}, nil
	}
	last := page[len(page)-1]
	return page, MatcherStaleCursor{
		Epoch: last.Epoch, Ecosystem: last.Ecosystem,
		Package: last.Package, Version: last.Version,
	}, nil
}

func (f *fakeRecomputeSource) CountMatcherStale(ctx context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.countErr != nil {
		return 0, f.countErr
	}
	return len(f.rows), nil
}

// newSweepRefresher builds a refresher whose PRIMARY walk is empty, so every
// Scan the test observes came from the sweep and nothing else.
func newSweepRefresher(t *testing.T, svc Service, src RecomputeSource, budget int) *Refresher {
	t.Helper()
	ref := NewRefresher(RefresherConfig{
		Service:          svc,
		Metadata:         &fakeMetadataSource{},
		Recompute:        src,
		Concurrency:      2,
		PageSize:         10,
		RecomputeMaxRows: budget,
	})
	if ref == nil {
		t.Fatal("NewRefresher returned nil")
	}
	return ref
}

// TestRecomputeSweepReachesRowsWithNoPackageMetadata is the core assertion.
//
// The primary walk iterates package_metadata; these coordinates have no row
// there, which before the sweep existed meant they could never be recomputed
// no matter how many epochs shipped. The refresher below is configured with an
// EMPTY package_metadata source precisely to model that.
func TestRecomputeSweepReachesRowsWithNoPackageMetadata(t *testing.T) {
	resetRecomputeMetrics()
	src := &fakeRecomputeSource{rows: []MatcherStaleRow{
		{Ecosystem: "npm", Package: "lodash", Version: "4.17.21", Epoch: CurrentMatcherEpoch - 1},
		{Ecosystem: "pypi", Package: "requests", Version: "2.31.0", Epoch: CurrentMatcherEpoch - 1},
	}}
	svc := &fakeService{}
	ref := newSweepRefresher(t, svc, src, 100)

	summary := ref.RunOnce(context.Background())

	if summary.Scanned != 0 {
		t.Fatalf("primary walk scanned %d rows; the fixture has no package_metadata "+
			"rows at all, so any scan here means the test is not measuring the sweep",
			summary.Scanned)
	}
	if summary.Recompute.Recomputed != 2 {
		t.Fatalf("sweep recomputed %d coordinates, want 2 — a row with no "+
			"package_metadata row must still be reachable, or every coordinate "+
			"minted by the lockfile scanner, `intel scan`, transitive fan-out or "+
			"cache-warm reports MatcherStale forever. summary=%+v",
			summary.Recompute.Recomputed, summary.Recompute)
	}
	if summary.Recompute.Backlog != 2 {
		t.Errorf("sweep sampled backlog %d, want 2", summary.Recompute.Backlog)
	}

	got := map[string]string{}
	svc.mu.Lock()
	for _, req := range svc.seen {
		got[req.Key.Ecosystem+"/"+req.Key.Package+"@"+req.Key.Version] = req.Options.RefreshReason
		if req.Options.AllowStale {
			t.Errorf("%s scanned with AllowStale=true; the sweep must never be "+
				"allowed to serve back the row it is retiring", req.Key.Package)
		}
	}
	svc.mu.Unlock()
	for _, want := range []string{"npm/lodash@4.17.21", "pypi/requests@2.31.0"} {
		reason, ok := got[want]
		if !ok {
			t.Errorf("%s was never scanned by the sweep; seen=%v", want, got)
			continue
		}
		if reason != RefreshReasonMatcherEpoch {
			t.Errorf("%s scanned with RefreshReason %q, want %q — the row has to be "+
				"attributable to the sweep after an epoch bump",
				want, reason, RefreshReasonMatcherEpoch)
		}
	}
}

// TestRecomputeSweepDrivesTheBacklogMetrics pins the observability half. A
// backlog that can silently stop draining again is the same defect, so the
// gauge and the counter must both move without anyone loading a dashboard.
func TestRecomputeSweepDrivesTheBacklogMetrics(t *testing.T) {
	resetRecomputeMetrics()
	if got := RecomputeBacklog(); got != 0 {
		t.Fatalf("reset left backlog at %v", got)
	}
	src := &fakeRecomputeSource{rows: []MatcherStaleRow{
		{Ecosystem: "npm", Package: "a", Version: "1", Epoch: 0},
		{Ecosystem: "npm", Package: "b", Version: "1", Epoch: 0},
		{Ecosystem: "npm", Package: "c", Version: "1", Epoch: 0},
	}}
	ref := newSweepRefresher(t, &fakeService{}, src, 100)

	ref.RunOnce(context.Background())

	if got := RecomputeBacklog(); got != 3 {
		t.Errorf("chainsaw_intel_recompute_backlog reader = %v, want 3 — the gauge's "+
			"only producer is the sweep's per-tick sample", got)
	}
	if got := RecomputeSweptTotal(); got != 3 {
		t.Errorf("chainsaw_intel_recompute_swept_total reader = %d, want 3", got)
	}

	// A second tick over an already-drained backlog must leave the counter
	// alone — a counter that keeps climbing on an empty backlog would make
	// the "flat backlog, zero rate" alert unreachable.
	src.mu.Lock()
	src.rows = nil
	src.mu.Unlock()
	ref.RunOnce(context.Background())
	if got := RecomputeBacklog(); got != 0 {
		t.Errorf("backlog gauge = %v after the backlog emptied, want 0", got)
	}
	if got := RecomputeSweptTotal(); got != 3 {
		t.Errorf("swept counter = %d after an empty sweep, want it to hold at 3", got)
	}
}

// TestRecomputeSweepSamplesTheBacklogEvenWhenDisabledBudgetIsZero: the gauge
// must be produced on every tick, including ticks that do no work. An operator
// staring at a 3,000-deep backlog needs the number to keep arriving.
func TestRecomputeSweepSamplesBacklogBeforeSpendingBudget(t *testing.T) {
	resetRecomputeMetrics()
	src := &fakeRecomputeSource{rows: []MatcherStaleRow{
		{Ecosystem: "npm", Package: "a", Version: "1", Epoch: 0},
		{Ecosystem: "npm", Package: "b", Version: "1", Epoch: 0},
		{Ecosystem: "npm", Package: "c", Version: "1", Epoch: 0},
	}}
	ref := newSweepRefresher(t, &fakeService{}, src, 1)

	summary := ref.RunOnce(context.Background())

	if summary.Recompute.Backlog != 3 {
		t.Errorf("backlog sampled as %d, want the full 3 — the sample must be the "+
			"whole backlog, not the slice this tick can afford",
			summary.Recompute.Backlog)
	}
	if summary.Recompute.Recomputed != 1 {
		t.Errorf("recomputed %d, want 1 (the budget)", summary.Recompute.Recomputed)
	}
	if !summary.Recompute.Truncated {
		t.Error("Truncated=false on a budget-capped sweep; an operator cannot tell " +
			"a paced drain from a finished one")
	}
}

// TestRecomputeSweepHonoursTheDisabledGate — the opt-out has to actually opt
// out, and the polarity has to be such that the ZERO value is enabled.
func TestRecomputeSweepHonoursTheDisabledGate(t *testing.T) {
	resetRecomputeMetrics()
	src := &fakeRecomputeSource{rows: []MatcherStaleRow{
		{Ecosystem: "npm", Package: "a", Version: "1", Epoch: 0},
	}}
	svc := &fakeService{}
	ref := NewRefresher(RefresherConfig{
		Service:           svc,
		Metadata:          &fakeMetadataSource{},
		Recompute:         src,
		Concurrency:       1,
		PageSize:          10,
		RecomputeDisabled: true,
	})
	ref.RunOnce(context.Background())
	if svc.scans.Load() != 0 {
		t.Fatalf("sweep ran with RecomputeDisabled=true (%d scans)", svc.scans.Load())
	}

	// And the zero value is ON. This is the property that makes a
	// hand-constructed RefresherConfig safe: forgetting the field must not
	// silently reproduce the undrainable backlog.
	svc2 := &fakeService{}
	on := NewRefresher(RefresherConfig{
		Service:     svc2,
		Metadata:    &fakeMetadataSource{},
		Recompute:   &fakeRecomputeSource{rows: []MatcherStaleRow{{Ecosystem: "npm", Package: "a", Version: "1"}}},
		Concurrency: 1,
		PageSize:    10,
	})
	on.RunOnce(context.Background())
	if svc2.scans.Load() != 1 {
		t.Fatalf("a RefresherConfig with no recompute fields set did %d sweep scans, "+
			"want 1 — the zero value must be ON", svc2.scans.Load())
	}
}

// TestRecomputeSweepPagesRatherThanRepeatingPageOne. The rows the sweep fails
// to recompute stay in the backlog; with OFFSET-style paging (or no cursor at
// all) a failing row would be handed back on every page and the sweep would
// burn its whole budget on one coordinate.
func TestRecomputeSweepPagesRatherThanRepeatingPageOne(t *testing.T) {
	resetRecomputeMetrics()
	rows := make([]MatcherStaleRow, 0, 7)
	for i := 0; i < 7; i++ {
		rows = append(rows, MatcherStaleRow{
			Ecosystem: "npm", Package: fmt.Sprintf("pkg%d", i), Version: "1", Epoch: 0,
		})
	}
	src := &fakeRecomputeSource{rows: rows}
	// Every Scan fails, so no row ever leaves the backlog.
	svc := &fakeService{onScan: func(Request) error { return errors.New("upstream down") }}
	ref := NewRefresher(RefresherConfig{
		Service:          svc,
		Metadata:         &fakeMetadataSource{},
		Recompute:        src,
		Concurrency:      1,
		PageSize:         3,
		RecomputeMaxRows: 7,
	})

	summary := ref.RunOnce(context.Background())

	if summary.Recompute.Failed != 7 {
		t.Errorf("Failed=%d, want 7", summary.Recompute.Failed)
	}
	if summary.Recompute.Recomputed != 0 {
		t.Errorf("Recomputed=%d on an all-failing sweep, want 0", summary.Recompute.Recomputed)
	}
	if got := RecomputeSweptTotal(); got != 0 {
		t.Errorf("swept counter = %d after every Scan failed; a counter that counts "+
			"attempts rather than successes makes the stall alert unreachable", got)
	}
	seen := map[string]int{}
	svc.mu.Lock()
	for _, req := range svc.seen {
		seen[req.Key.Package]++
	}
	svc.mu.Unlock()
	if len(seen) != 7 {
		t.Fatalf("sweep visited %d distinct coordinates, want 7 — a failing row was "+
			"re-served instead of paged past. visits=%v", len(seen), seen)
	}
	for pkg, n := range seen {
		if n != 1 {
			t.Errorf("%s visited %d times in one sweep, want 1", pkg, n)
		}
	}
}

// TestRecomputeSweepRunsAfterThePrimaryWalk. Order matters for budget: the
// package_metadata walk lifts whatever it covers out of the backlog first, so
// the sweep's capped budget is spent on the coordinates nothing else reaches.
func TestRecomputeSweepRunsAfterThePrimaryWalk(t *testing.T) {
	resetRecomputeMetrics()
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	meta := &fakeMetadataSource{rows: []metadata.PackageMetadataRow{{
		OrgID: "org1",
		PackageMetadata: metadata.PackageMetadata{
			Repository: "npmjs", Package: "walked", Version: "1.0.0",
			UpdatedAt: now.Add(-48 * time.Hour),
		},
	}}}
	src := &fakeRecomputeSource{rows: []MatcherStaleRow{
		{Ecosystem: "npm", Package: "swept", Version: "1.0.0", Epoch: CurrentMatcherEpoch - 1},
	}}
	svc := &fakeService{}
	ref := NewRefresher(RefresherConfig{
		Service: svc, Metadata: meta, Recompute: src,
		Concurrency: 1, PageSize: 10, MaxStaleness: 24 * time.Hour,
		EcosystemResolver: func(string) string { return "npm" },
	})
	ref.now = func() time.Time { return now }

	summary := ref.RunOnce(context.Background())

	if summary.Scanned != 1 || summary.Recompute.Recomputed != 1 {
		t.Fatalf("want 1 walked + 1 swept, got scanned=%d recomputed=%d",
			summary.Scanned, summary.Recompute.Recomputed)
	}
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if len(svc.seen) != 2 {
		t.Fatalf("expected 2 scans, got %d", len(svc.seen))
	}
	if svc.seen[0].Key.Package != "walked" {
		t.Errorf("first scan was %q; the primary walk must run before the sweep so "+
			"the sweep's capped budget goes to coordinates the walk cannot reach",
			svc.seen[0].Key.Package)
	}
	if svc.seen[1].Key.Package != "swept" {
		t.Errorf("second scan was %q, want the swept coordinate", svc.seen[1].Key.Package)
	}
}

// TestRecomputeSweepDegradesWithoutASource: no Store and no injected source
// means no sweep, not a panic. Same degradation contract the primary walk
// gives a nil Store.
func TestRecomputeSweepDegradesWithoutASource(t *testing.T) {
	resetRecomputeMetrics()
	svc := &fakeService{}
	ref := NewRefresher(RefresherConfig{
		Service: svc, Metadata: &fakeMetadataSource{}, Concurrency: 1, PageSize: 10,
	})
	summary := ref.RunOnce(context.Background())
	if summary.Recompute != (RecomputeSummary{}) {
		t.Fatalf("expected a zero RecomputeSummary with no source, got %+v", summary.Recompute)
	}
}

// TestRecomputeSweepIsCalledFromRunOnce is the dead-code guard.
//
// This tree has been bitten repeatedly by a correct function with no caller —
// SafeUpgradeVersion, backfillRepositoryGuides, ReapplyKnownFixAfterTransitive,
// and typosquat.PopularGitHubActions, each of which passed its own unit tests
// while doing nothing in production. A behavioural test on the sweep proves
// only that the sweep works WHEN CALLED, which is exactly the assurance those
// four also had.
//
// The sweep is deliberately a phase of RunOnce rather than a new exported
// worker, so the thing to pin is that RunOnce still calls it: RunOnce's own
// production wiring (Run -> cmd/chainsaw-proxy/init_server.go, plus the admin
// refresh endpoint) is already established and tested elsewhere. Written as a
// source assertion in the shape of core/policy's
// TestEveryMaxPrecedenceQueryExcludesExceptionSentinels, because the failure
// being guarded is a DELETION, and no behavioural test fails when the caller
// is removed — every sweep test above would go on passing while production
// stopped sweeping.
func TestRecomputeSweepIsCalledFromRunOnce(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile(filepath.Clean("refresher.go"))
	if err != nil {
		t.Fatalf("read refresher.go: %v", err)
	}
	text := string(src)

	// Isolate RunOnce's body: from its signature to the next top-level func.
	start := strings.Index(text, "func (r *Refresher) RunOnce(ctx context.Context) TickSummary {")
	if start < 0 {
		t.Fatal("RunOnce is no longer declared in refresher.go with the expected " +
			"signature — re-point this guard at wherever the tick now lives, and " +
			"confirm the sweep is still called from it")
	}
	body := text[start:]
	if next := regexp.MustCompile(`\nfunc `).FindStringIndex(body[1:]); next != nil {
		body = body[:next[0]+1]
	}

	if !strings.Contains(body, "r.recomputeStaleOnce(ctx)") {
		t.Fatal("RunOnce no longer calls r.recomputeStaleOnce(ctx).\n" +
			"The matcher-epoch backlog is drained by nothing else. package_metadata " +
			"— the primary walk's source — is written only by the proxy download " +
			"path, the internal-package upload handler and the CocoaPods trunk " +
			"handler, so every report row minted by the CLI lockfile scanner, " +
			"`intel scan`, the scan worker, transitive fan-out, cache-warm, the " +
			"publish pre-run, MCP, the admin scan endpoint or the refresher's own " +
			"new-version discovery becomes permanently stale without this call. " +
			"Every other test in this file would still pass.")
	}

	// The sweep must also still be wired into the summary, or the tick log
	// and the admin endpoint report a drain that is not happening.
	if !strings.Contains(body, "Recompute:") {
		t.Error("RunOnce no longer reports the sweep in its TickSummary; the admin " +
			"refresh endpoint and the tick log lose the only per-tick evidence " +
			"that the backlog is draining")
	}
}

// TestRecomputeSQLAgreesWithTheFacetsPredicate. The pill says "3,171 pending"
// and the sweep is supposed to drain exactly those rows. If the two
// expressions ever diverge, the pill counts a population the sweep does not
// visit and never reaches zero however long the sweep runs — which reads to an
// operator exactly like the original defect.
func TestRecomputeSQLAgreesWithTheFacetsPredicate(t *testing.T) {
	t.Parallel()

	normalise := func(s string) string {
		return strings.Join(strings.Fields(s), " ")
	}
	want := normalise(matcherEpochExpr)

	for _, file := range []string{"store.go", "store_recompute.go"} {
		src, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		// Every place the tree digs the epoch out of the JSONB blob.
		hits := regexp.MustCompile(`COALESCE\(NULLIF\(report->'observation'->>'matcherEpoch',\s*''\)::int,\s*0\)`).
			FindAllString(string(src), -1)
		if len(hits) == 0 {
			t.Errorf("%s: no matcher-epoch JSONB extraction found — either the "+
				"spelling changed (update this guard AND every other copy) or a "+
				"reader lost its epoch predicate", file)
		}
		for _, h := range hits {
			if normalise(h) != want {
				t.Errorf("%s: epoch expression %q differs from the shared "+
					"matcherEpochExpr %q. The backlog COUNT and the backlog WALK "+
					"must agree on what 'pending' means.", file, normalise(h), want)
			}
		}
	}
}
