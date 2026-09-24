package intelligence

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// chainProvider hands every coordinate a single direct dependency that
// points one step further down an infinite chain: depth-0 depends on
// depth-1, depth-1 on depth-2, and so on. Nothing is ever cached, which
// is the state a cold corpus is actually in.
//
// It exists to answer one question that cache_warm.go's header asserts
// an answer to: "we do NOT recurse beyond one level -- the next Scan of
// the parent triggers the next layer naturally."
type chainProvider struct {
	mu       sync.Mutex
	seen     map[string]int
	maxDepth int
	stopAt   int
	done     chan struct{}
	closed   bool
}

func newChainProvider(stopAt int) *chainProvider {
	return &chainProvider{seen: map[string]int{}, stopAt: stopAt, done: make(chan struct{})}
}

func (p *chainProvider) Name() string         { return "chain" }
func (p *chainProvider) Signal() SignalMask   { return SignalMalware }
func (p *chainProvider) Tier() int            { return 1 }
func (p *chainProvider) NeedsArtifact() bool  { return false }
func (p *chainProvider) Supports(string) bool { return true }

func (p *chainProvider) Run(_ context.Context, req Request, _ *Report) (PartialReport, error) {
	var depth int
	if _, err := fmt.Sscanf(req.Key.Package, "dep-%d", &depth); err != nil {
		depth = 0
	}
	p.mu.Lock()
	p.seen[req.Key.Package] = depth
	if depth > p.maxDepth {
		p.maxDepth = depth
	}
	reached := p.maxDepth >= p.stopAt && !p.closed
	if reached {
		p.closed = true
	}
	p.mu.Unlock()
	if reached {
		close(p.done)
	}
	return PartialReport{
		Dependencies: &DependenciesSection{
			Direct: []DependencyRef{{
				Ecosystem:  "npm",
				Name:       fmt.Sprintf("dep-%d", depth+1),
				Constraint: "1.0.0", // pinned, so the warmer will take it
			}},
		},
	}, nil
}

func (p *chainProvider) depth() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.maxDepth
}

// TestWarmDirectDeps_DoesNotRecurse pins maxWarmDepth. A warm Scan is a FULL Scan, and scanner.go fires
// WarmDirectDeps at the end of every fresh fan-out -- so unless
// something stops it, warming recurses the whole dependency tree on a
// cold cache, with no depth limit and no GLOBAL concurrency limit
// (cacheWarmConcurrency is a per-call semaphore).
//
// Documented bound: one level. So from `root`, the deepest package the
// provider should ever see is `dep-1`.
func TestWarmDirectDeps_DoesNotRecurse(t *testing.T) {
	const stopAt = 6 // far past the documented bound of 1
	prov := newChainProvider(stopAt)
	svc := New(Config{Providers: []Provider{prov}})
	defer svc.Close()

	if _, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "npm", Package: "root", Version: "1.0.0"},
		OrgID: "org",
	}); err != nil {
		t.Fatalf("root Scan: %v", err)
	}

	select {
	case <-prov.done:
		t.Fatalf("cache-warm recursed to depth %d; maxWarmDepth is %d (deepest expected: dep-%d). "+
			"Every level is a full Scan that schedules WarmDirectDeps again, so losing this "+
			"bound restores an exponential fan-out: 50 scans exhausted the database pool and "+
			"shed 503s onto the public read path on 2026-09-14. See docs/PLANS_INTELLIGENCE.md.",
			prov.depth(), maxWarmDepth, maxWarmDepth)
	case <-time.After(3 * time.Second):
		if d := prov.depth(); d > maxWarmDepth {
			t.Fatalf("cache-warm recursed to depth %d; maxWarmDepth is %d", d, maxWarmDepth)
		}
		if d := prov.depth(); d < maxWarmDepth {
			t.Fatalf("cache-warm reached depth %d but maxWarmDepth is %d -- warming is not "+
				"happening at all, which is a different bug from warming too much", d, maxWarmDepth)
		}
	}
}

// TestWarmDirectDeps_GlobalBudgetCapsConcurrency pins globalCacheWarmBudget.
//
// cacheWarmConcurrency is a PER-CALL semaphore — `make(chan struct{}, 4)`
// constructed inside each WarmDirectDeps invocation — so it bounds one
// parent's fan-out and nothing else. N concurrent parents gave 4N
// concurrent warm Scans, and each Scan in its fan-out holds a pooled
// database connection (core/xreplicaflight/pg.go). The process-wide
// budget is therefore the number that actually bounds what a burst of
// public scan requests can cost the database pool.
//
// The budget is acquired NON-BLOCKINGLY on purpose: warming is
// best-effort (the next Scan of the parent warms the layer anyway), so
// under pressure the right move is to skip and count it, never to park
// goroutines. That is what makes this a bound rather than a queue.
func TestWarmDirectDeps_GlobalBudgetCapsConcurrency(t *testing.T) {
	release := make(chan struct{})
	prov := &warmTrackingProvider{blockOn: release}
	svc := New(Config{Providers: []Provider{prov}})
	defer svc.Close()

	const parents = 12
	const depsPerParent = 10 // 120 targets, far past the global budget

	before := WarmSkippedForBudget()

	var wg sync.WaitGroup
	for p := 0; p < parents; p++ {
		deps := make([]DependencyRef, 0, depsPerParent)
		for d := 0; d < depsPerParent; d++ {
			deps = append(deps, DependencyRef{
				Ecosystem:  "npm",
				Name:       fmt.Sprintf("p%d-d%d", p, d),
				Constraint: "1.0.0",
			})
		}
		parent := &Report{
			Identity:     IdentitySection{Ecosystem: "npm", Package: fmt.Sprintf("parent-%d", p), Version: "1.0.0"},
			Dependencies: DependenciesSection{Direct: deps},
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			WarmDirectDeps(context.Background(), parent, svc)
		}()
	}
	wg.Wait()

	// Let the scheduled warm Scans pile up against the budget.
	time.Sleep(400 * time.Millisecond)
	peak := int(atomic.LoadInt64(&prov.maxInflt))
	close(release)

	if peak > globalCacheWarmConcurrency {
		t.Fatalf("peak concurrent warm scans %d exceeds globalCacheWarmConcurrency %d; "+
			"the per-call cacheWarmConcurrency semaphore is not a process ceiling and "+
			"each in-flight scan pins a database connection", peak, globalCacheWarmConcurrency)
	}
	if peak == 0 {
		t.Fatalf("no warm scans ran at all; this test cannot bound what never happened")
	}
	if skipped := WarmSkippedForBudget() - before; skipped == 0 {
		t.Fatalf("offered %d targets against a budget of %d but nothing was recorded as "+
			"skipped; the budget must be observable or a silent stall looks like idleness",
			parents*depsPerParent, globalCacheWarmConcurrency)
	}
}
