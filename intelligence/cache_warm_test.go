package intelligence

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// warmTrackingProvider records every Scan it sees so tests can assert
// exactly which (eco, name, version) triples were warmed. It is also
// used to observe in-flight concurrency by blocking on a release channel
// when configured to do so.
type warmTrackingProvider struct {
	mu       sync.Mutex
	seen     []Key
	inflight int64
	maxInflt int64
	blockOn  chan struct{} // when non-nil, Run waits for a send
	hold     time.Duration
}

func (p *warmTrackingProvider) Name() string         { return "warm-tracker" }
func (p *warmTrackingProvider) Signal() SignalMask   { return SignalMalware }
func (p *warmTrackingProvider) Tier() int            { return 1 }
func (p *warmTrackingProvider) NeedsArtifact() bool  { return false }
func (p *warmTrackingProvider) Supports(string) bool { return true }
func (p *warmTrackingProvider) Run(ctx context.Context, req Request, _ *Report) (PartialReport, error) {
	now := atomic.AddInt64(&p.inflight, 1)
	defer atomic.AddInt64(&p.inflight, -1)
	for {
		// CAS update of the max-inflight high-water mark.
		old := atomic.LoadInt64(&p.maxInflt)
		if now <= old || atomic.CompareAndSwapInt64(&p.maxInflt, old, now) {
			break
		}
	}
	p.mu.Lock()
	p.seen = append(p.seen, req.Key)
	p.mu.Unlock()
	if p.blockOn != nil {
		select {
		case <-p.blockOn:
		case <-ctx.Done():
			return PartialReport{}, ctx.Err()
		}
	}
	if p.hold > 0 {
		select {
		case <-time.After(p.hold):
		case <-ctx.Done():
			return PartialReport{}, ctx.Err()
		}
	}
	return PartialReport{}, nil
}

func (p *warmTrackingProvider) keys() []Key {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Key, len(p.seen))
	copy(out, p.seen)
	return out
}

func TestWarmDirectDeps_PinnedDepsOnly(t *testing.T) {
	prov := &warmTrackingProvider{}
	svc := New(Config{Providers: []Provider{prov}})
	defer svc.Close()

	parent := &Report{
		Identity: IdentitySection{
			Ecosystem: "rubygems",
			Package:   "rails",
			Version:   "7.0.0",
		},
		Dependencies: DependenciesSection{
			Direct: []DependencyRef{
				{Name: "actionpack", Constraint: "7.0.0"},      // pinned
				{Name: "activesupport", Constraint: "= 7.0.0"}, // pinned
				{Name: "activerecord", Constraint: ">= 6.0"},   // range — skip
			},
		},
	}

	WarmDirectDeps(context.Background(), parent, svc)
	waitForSeen(t, prov, 2, 2*time.Second)

	got := prov.keys()
	names := make(map[string]string, len(got))
	for _, k := range got {
		names[k.Package] = k.Version
	}
	if v := names["actionpack"]; v != "7.0.0" {
		t.Fatalf("actionpack: got version %q, want 7.0.0", v)
	}
	if v := names["activesupport"]; v != "7.0.0" {
		t.Fatalf("activesupport: got version %q, want 7.0.0", v)
	}
	if _, ok := names["activerecord"]; ok {
		t.Fatalf("activerecord should not have been warmed (range constraint)")
	}
}

func TestWarmDirectDeps_ConcurrencyCap(t *testing.T) {
	release := make(chan struct{})
	prov := &warmTrackingProvider{blockOn: release}
	svc := New(Config{Providers: []Provider{prov}})
	defer svc.Close()

	deps := make([]DependencyRef, 0, 20)
	for i := 0; i < 20; i++ {
		// Distinct names so the dedup map doesn't collapse them. Version
		// is a pinned 1.0.N so all are warmed.
		deps = append(deps, DependencyRef{
			Name:       depName(i),
			Constraint: "1.0." + warmItoa(i),
		})
	}
	parent := &Report{
		Identity:     IdentitySection{Ecosystem: "npm", Package: "parent", Version: "1.0.0"},
		Dependencies: DependenciesSection{Direct: deps},
	}

	WarmDirectDeps(context.Background(), parent, svc)

	// Let goroutines reach Run() and block on `release`. The cap should
	// hold maxInflt at exactly cacheWarmConcurrency.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&prov.inflight) >= int64(cacheWarmConcurrency) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Give any over-cap goroutines a chance to misbehave.
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt64(&prov.maxInflt); got > int64(cacheWarmConcurrency) {
		close(release)
		t.Fatalf("concurrency cap exceeded: maxInflt=%d, cap=%d", got, cacheWarmConcurrency)
	}
	// Drain the rest.
	close(release)
	waitForSeen(t, prov, 20, 5*time.Second)
}

func TestWarmDirectDeps_AlreadyWarming_Dedup(t *testing.T) {
	release := make(chan struct{})
	prov := &warmTrackingProvider{blockOn: release}
	svc := New(Config{Providers: []Provider{prov}})
	defer svc.Close()

	parent := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "parent", Version: "1.0.0"},
		Dependencies: DependenciesSection{
			Direct: []DependencyRef{
				{Name: "lodash", Constraint: "4.17.21"},
				{Name: "react", Constraint: "18.2.0"},
			},
		},
	}

	// First call schedules two warms; second call (before any complete)
	// must not double-fire the same keys.
	WarmDirectDeps(context.Background(), parent, svc)
	// Wait for both first-call goroutines to be in-flight (blocked).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&prov.inflight) == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := atomic.LoadInt64(&prov.inflight); got != 2 {
		close(release)
		t.Fatalf("expected 2 in-flight before second call, got %d", got)
	}

	WarmDirectDeps(context.Background(), parent, svc)
	// Give the second call a moment to (mis)schedule.
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt64(&prov.inflight); got != 2 {
		close(release)
		t.Fatalf("dedup failed: in-flight became %d after second call, want 2", got)
	}

	close(release)
	waitForSeen(t, prov, 2, 2*time.Second)
	if got := len(prov.keys()); got != 2 {
		t.Fatalf("expected 2 distinct Scans, got %d", got)
	}
}

func TestWarmDirectDeps_NoDeps_NoOp(t *testing.T) {
	prov := &warmTrackingProvider{}
	svc := New(Config{Providers: []Provider{prov}})
	defer svc.Close()

	parent := &Report{
		Identity:     IdentitySection{Ecosystem: "npm", Package: "leaf", Version: "1.0.0"},
		Dependencies: DependenciesSection{},
	}
	WarmDirectDeps(context.Background(), parent, svc)
	// No goroutines should have been spawned. Give them a chance anyway.
	time.Sleep(50 * time.Millisecond)
	if got := len(prov.keys()); got != 0 {
		t.Fatalf("expected 0 Scans, got %d", got)
	}

	// nil parent must also be safe.
	WarmDirectDeps(context.Background(), nil, svc)
	WarmDirectDeps(context.Background(), parent, nil)
}

func TestWarmDirectDeps_DisabledViaEnv(t *testing.T) {
	t.Setenv(cacheWarmEnvDisabled, "1")
	prov := &warmTrackingProvider{}
	svc := New(Config{Providers: []Provider{prov}})
	defer svc.Close()

	parent := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "parent", Version: "1.0.0"},
		Dependencies: DependenciesSection{
			Direct: []DependencyRef{
				{Name: "lodash", Constraint: "4.17.21"},
			},
		},
	}
	WarmDirectDeps(context.Background(), parent, svc)
	time.Sleep(50 * time.Millisecond)
	if got := len(prov.keys()); got != 0 {
		t.Fatalf("env-disabled warm should have no scans, got %d", got)
	}
}

func TestWarmDirectDeps_FreshScanTriggersWarm(t *testing.T) {
	// Inject the Direct deps via a fake registry-metadata-style provider
	// so the parent Scan emits a report with Dependencies.Direct populated.
	// The scanner.go hook then fires WarmDirectDeps in the background.
	parentProv := &fakeProvider{
		name:   "fake-registrymetadata",
		signal: SignalMalware, // any signal that's in the default mask
		partial: PartialReport{
			Dependencies: &DependenciesSection{
				Direct: []DependencyRef{
					{Name: "lodash", Constraint: "4.17.21"},
				},
			},
		},
	}
	svc := New(Config{Providers: []Provider{parentProv}})
	defer svc.Close()

	_, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "npm", Package: "parent", Version: "1.0.0"},
		OrgID: "org",
	})
	if err != nil {
		t.Fatalf("parent Scan err: %v", err)
	}

	// The warm-up runs in svc.bg. Wait for the inner Scan to call the
	// fake provider a SECOND time (first call was the parent itself).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt64(&parentProv.runs) >= 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected warm-up Scan to fire; got %d total runs", atomic.LoadInt64(&parentProv.runs))
}

func TestPinnedVersion(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"1.2.3", "1.2.3"},
		{"  1.2.3  ", "1.2.3"},
		{"==1.2.3", "1.2.3"},
		{"= 1.2.3", "1.2.3"},
		{"=1.2.3", "1.2.3"},
		{"v1.2.3", "1.2.3"},
		{"1.2.3-rc.1", "1.2.3-rc.1"},
		{"^1.2.3", ""},
		{"~1.2.3", ""},
		{">=1.0.0", ""},
		{"<2.0", ""},
		{"1.2.3 - 2.0", ""},
		{"1.x", ""},
		{"*", ""},
		{"1.2.3 || 2.0", ""},
		{"", ""},
		{"latest", ""}, // no digit
		{"1, 2", ""},   // comma
		{"1.X", ""},    // wildcard segment, capital
	}
	for _, tc := range cases {
		if got := pinnedVersion(tc.in); got != tc.want {
			t.Errorf("pinnedVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// waitForSeen blocks until prov has recorded at least `want` keys or
// `timeout` elapses; fails the test on timeout.
func waitForSeen(t *testing.T, prov *warmTrackingProvider, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(prov.keys()) >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d Scans; saw %d", want, len(prov.keys()))
}

// depName returns a distinct-per-i package name so tests don't collide
// in the in-flight dedup map.
func depName(i int) string {
	return "dep-" + warmItoa(i)
}

// warmItoa is a tiny strconv.Itoa replacement that avoids the import
// bloat in this test file (which doesn't otherwise need strconv).
func warmItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
