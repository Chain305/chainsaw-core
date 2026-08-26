package intelligence

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
)

// ---- fakes -----------------------------------------------------------

type fakeCoverageSource struct {
	rows  []CoverageStaleRow
	count int
	pages int
}

func (f *fakeCoverageSource) IterateCoverageStale(_ context.Context, after CoverageStaleCursor, limit int) ([]CoverageStaleRow, CoverageStaleCursor, error) {
	f.pages++
	start := 0
	if !after.IsZero() {
		for i, r := range f.rows {
			if r.Ecosystem == after.Ecosystem && r.Package == after.Package && r.Version == after.Version {
				start = i + 1
				break
			}
		}
	}
	end := start + limit
	if end > len(f.rows) {
		end = len(f.rows)
	}
	page := f.rows[start:end]
	if len(page) < limit {
		return page, CoverageStaleCursor{}, nil
	}
	last := page[len(page)-1]
	return page, CoverageStaleCursor{
		Resolved: last.Resolved, Ecosystem: last.Ecosystem,
		Package: last.Package, Version: last.Version,
	}, nil
}

func (f *fakeCoverageSource) CountCoverageStale(context.Context) (int, error) { return f.count, nil }

// coverageFakeStore serves reports and records every Upsert, so a test can
// assert not just the outcome but whether a write happened at all.
type coverageFakeStore struct {
	mu      sync.Mutex
	reports map[string]*Report
	upserts []string
}

func newCoverageFakeStore() *coverageFakeStore {
	return &coverageFakeStore{reports: map[string]*Report{}}
}

func ckey(eco, pkg, ver string) string { return eco + "/" + pkg + "@" + ver }

func (s *coverageFakeStore) put(r *Report) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reports[ckey(r.Identity.Ecosystem, r.Identity.Package, r.Identity.Version)] = r
}

func (s *coverageFakeStore) Get(_ context.Context, _ string, k Key) (*Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.reports[ckey(k.Ecosystem, k.Package, k.Version)]
	if !ok {
		return nil, ErrNotFound
	}
	return r, nil
}

func (s *coverageFakeStore) ListVersions(_ context.Context, _, eco, name string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, r := range s.reports {
		if r.Identity.Ecosystem == eco && r.Identity.Package == name {
			out = append(out, r.Identity.Version)
		}
	}
	return out, nil
}

func (s *coverageFakeStore) Upsert(_ context.Context, _ string, r *Report) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upserts = append(s.upserts, ckey(r.Identity.Ecosystem, r.Identity.Package, r.Identity.Version))
	s.reports[ckey(r.Identity.Ecosystem, r.Identity.Package, r.Identity.Version)] = r
	return nil
}

func (s *coverageFakeStore) upsertCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.upserts)
}

func newCoverageRefresher(t *testing.T, src CoverageRecomputeSource, store CoverageReportStore, budget int) *Refresher {
	t.Helper()
	ref := NewRefresher(RefresherConfig{
		Service:                  &fakeService{},
		Metadata:                 &fakeMetadataSource{},
		Coverage:                 src,
		CoverageStore:            store,
		Concurrency:              2,
		PageSize:                 10,
		CoverageRecomputeMaxRows: budget,
		RecomputeDisabled:        true,
	})
	if ref == nil {
		t.Fatal("NewRefresher returned nil")
	}
	return ref
}

// parentWithDep builds a root declaring one direct dep, already scored,
// carrying a coverage record that says the dep was NOT resolved.
func parentWithDep(depName string, resolved int) *Report {
	r := newReport("npm", "parent", "1.0.0")
	r.Dependencies.Direct = []DependencyRef{{Ecosystem: "npm", Name: depName, Constraint: "1.0.0"}}
	ComputeTrustScore(r)
	r.SupplyChain.TransitiveCoverage = &TransitiveCoverage{
		Resolved: resolved, Total: 1, Complete: false, MaxDepth: 5,
	}
	return r
}

// ---- tests -----------------------------------------------------------

// THE CORE ASSERTION.
//
// A parent scored before its dependency was in cache keeps that verdict
// forever: the scanner runs the tree overlay BEFORE it enqueues dependency
// scans, so a cold first scan persists a direct-only rollup and nothing goes
// back once the child arrives. Measured in production: 122 rows serving a
// verdict strictly better than their warmed tree warrants.
func TestCoverageSweepReRollsAParentOnceItsChildArrives(t *testing.T) {
	resetCoverageMetrics()
	store := newCoverageFakeStore()

	parent := parentWithDep("badlib", 0)
	before := parent.Risk.Verdict
	store.put(parent)

	// The child arrives AFTER the parent was scored — malicious, so the
	// rollup must move.
	child := newReport("npm", "badlib", "1.0.0")
	child.SupplyChain.MalwareStatus = "malicious"
	child.SupplyChain.MalwareID = "OSV-MAL-TEST"
	ComputeTrustScore(child)
	store.put(child)

	src := &fakeCoverageSource{
		rows:  []CoverageStaleRow{{Ecosystem: "npm", Package: "parent", Version: "1.0.0", Resolved: 0}},
		count: 1,
	}
	sum := newCoverageRefresher(t, src, store, 100).recomputeCoverageOnce(context.Background())

	if sum.Improved != 1 {
		t.Fatalf("Improved = %d, want 1 (backlog=%d examined=%d failed=%d)",
			sum.Improved, sum.Backlog, sum.Examined, sum.Failed)
	}
	after, _ := store.Get(context.Background(), "", Key{Ecosystem: "npm", Package: "parent", Version: "1.0.0"})
	if after.Risk.Verdict == before {
		t.Errorf("parent verdict unchanged (%s) after its malicious child warmed", before)
	}
	if sum.VerdictChanged != 1 {
		t.Errorf("VerdictChanged = %d, want 1", sum.VerdictChanged)
	}
	if after.SupplyChain.TransitiveCoverage.Resolved != 1 {
		t.Errorf("coverage not updated: resolved = %d, want 1",
			after.SupplyChain.TransitiveCoverage.Resolved)
	}
	if after.Observation.RefreshReason != RefreshReasonCoverageRecompute {
		t.Errorf("RefreshReason = %q, want %q — the row must be attributable to this sweep",
			after.Observation.RefreshReason, RefreshReasonCoverageRecompute)
	}
}

// THE CHURN GUARD, which is the part most likely to be got wrong.
//
// The backlog predicate is "the last walk was incomplete". A row whose
// dependencies are simply not in the estate stays incomplete forever. Without
// a gate on the closure having actually grown, the sweep rewrites the same
// rows every tick — churning the table, bumping updated_at, and reporting
// steady progress while changing nothing.
func TestCoverageSweepDoesNotRewriteRowsThatDidNotImprove(t *testing.T) {
	resetCoverageMetrics()
	store := newCoverageFakeStore()
	store.put(parentWithDep("neverarrives", 0)) // child deliberately absent

	src := &fakeCoverageSource{
		rows:  []CoverageStaleRow{{Ecosystem: "npm", Package: "parent", Version: "1.0.0", Resolved: 0}},
		count: 1,
	}
	ref := newCoverageRefresher(t, src, store, 100)

	for tick := 0; tick < 3; tick++ {
		sum := ref.recomputeCoverageOnce(context.Background())
		if sum.Improved != 0 {
			t.Fatalf("tick %d: Improved = %d, want 0 — nothing warmed", tick, sum.Improved)
		}
	}
	if n := store.upsertCount(); n != 0 {
		t.Errorf("sweep wrote %d times across 3 ticks with no new dependency data; "+
			"it must not churn rows whose closure did not grow", n)
	}
	if CoverageSweptTotal() == 0 {
		t.Error("swept counter did not move — the test did not exercise the sweep")
	}
	if CoverageImprovedTotal() != 0 {
		t.Errorf("improved counter = %d, want 0", CoverageImprovedTotal())
	}
}

// The disabled gate must actually disable.
func TestCoverageSweepHonoursTheDisabledGate(t *testing.T) {
	resetCoverageMetrics()
	store := newCoverageFakeStore()
	store.put(parentWithDep("badlib", 0))
	src := &fakeCoverageSource{
		rows:  []CoverageStaleRow{{Ecosystem: "npm", Package: "parent", Version: "1.0.0"}},
		count: 1,
	}
	ref := NewRefresher(RefresherConfig{
		Service:                   &fakeService{},
		Metadata:                  &fakeMetadataSource{},
		Coverage:                  src,
		CoverageStore:             store,
		Concurrency:               2,
		PageSize:                  10,
		CoverageRecomputeDisabled: true,
		RecomputeDisabled:         true,
	})
	if sum := ref.recomputeCoverageOnce(context.Background()); sum.Examined != 0 || sum.Backlog != 0 {
		t.Errorf("disabled sweep did work: %+v", sum)
	}
	if store.upsertCount() != 0 {
		t.Error("disabled sweep wrote to the store")
	}
}

// The backlog gauge is sampled even when the sweep finds nothing to do — a
// sweep reporting no work while the backlog is thousands deep is exactly the
// state an operator needs to see.
func TestCoverageSweepSamplesBacklogEvenWithNoRows(t *testing.T) {
	resetCoverageMetrics()
	src := &fakeCoverageSource{rows: nil, count: 4321}
	sum := newCoverageRefresher(t, src, newCoverageFakeStore(), 100).
		recomputeCoverageOnce(context.Background())
	if sum.Backlog != 4321 {
		t.Errorf("Backlog = %d, want 4321", sum.Backlog)
	}
	if CoverageBacklog() != 4321 {
		t.Errorf("gauge = %v, want 4321", CoverageBacklog())
	}
}

// Pagination must advance. A keyset walk that fails to move re-serves page
// one forever, burning the whole budget on the same rows while reporting
// progress.
func TestCoverageSweepPagesRatherThanRepeatingPageOne(t *testing.T) {
	resetCoverageMetrics()
	store := newCoverageFakeStore()
	rows := make([]CoverageStaleRow, 0, 25)
	for i := 0; i < 25; i++ {
		p := newReport("npm", "p"+string(rune('a'+i)), "1.0.0")
		ComputeTrustScore(p)
		p.SupplyChain.TransitiveCoverage = &TransitiveCoverage{Total: 1, Complete: false}
		store.put(p)
		rows = append(rows, CoverageStaleRow{Ecosystem: "npm", Package: p.Identity.Package, Version: "1.0.0"})
	}
	src := &fakeCoverageSource{rows: rows, count: len(rows)}
	sum := newCoverageRefresher(t, src, store, 100).recomputeCoverageOnce(context.Background())
	if sum.Examined != 25 {
		t.Errorf("Examined = %d, want 25 — the walk did not reach every row", sum.Examined)
	}
	if src.pages < 3 {
		t.Errorf("pages served = %d; a 25-row walk at PageSize 10 must page at least 3 times", src.pages)
	}
}

// The sweep must be reached from RunOnce, or it never runs in production.
// Source-level: RunOnce needs a metadata walk and a live store to drive
// behaviourally, and this assertion is about wiring, not behaviour.
func TestCoverageSweepIsCalledFromRunOnce(t *testing.T) {
	b, err := os.ReadFile("refresher.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, "r.recomputeCoverageOnce(ctx)") {
		t.Fatal("RunOnce does not call recomputeCoverageOnce — the coverage sweep " +
			"is dead code and partial rollups are never corrected")
	}
	// Ordering matters: it must run AFTER the epoch sweep, so this tick's
	// own Scans have already warmed dependency rows.
	iw := strings.Index(src, "r.recomputeStaleOnce(ctx)")
	ic := strings.Index(src, "r.recomputeCoverageOnce(ctx)")
	if iw < 0 || ic < 0 || ic < iw {
		t.Errorf("coverage sweep must run after the matcher-epoch sweep "+
			"(offsets epoch=%d coverage=%d); running first would re-evaluate "+
			"against the cache as it was before this tick warmed it", iw, ic)
	}
}

// A matcher-stale row belongs to the epoch sweep, which fixes it with a
// real Scan. Re-rolling it here would derive a rollup from facts already
// known to be wrong, and churn a row the improvement gate cannot help.
func TestCoverageSweepSkipsMatcherStaleRows(t *testing.T) {
	resetCoverageMetrics()
	store := newCoverageFakeStore()

	parent := parentWithDep("badlib", 0)
	parent.Observation.MatcherEpoch = CurrentMatcherEpoch - 1 // superseded
	store.put(parent)

	// A child that WOULD improve the closure, so the only reason to skip
	// is the stale epoch.
	child := newReport("npm", "badlib", "1.0.0")
	child.SupplyChain.MalwareStatus = "malicious"
	child.SupplyChain.MalwareID = "OSV-MAL-TEST"
	child.Observation.MatcherEpoch = CurrentMatcherEpoch
	ComputeTrustScore(child)
	store.put(child)

	src := &fakeCoverageSource{
		rows:  []CoverageStaleRow{{Ecosystem: "npm", Package: "parent", Version: "1.0.0"}},
		count: 1,
	}
	sum := newCoverageRefresher(t, src, store, 100).recomputeCoverageOnce(context.Background())
	if sum.Improved != 0 {
		t.Errorf("Improved = %d, want 0 — a matcher-stale row is the epoch sweep's job", sum.Improved)
	}
	if n := store.upsertCount(); n != 0 {
		t.Errorf("sweep wrote %d matcher-stale rows; it must leave them to the epoch sweep", n)
	}
}
