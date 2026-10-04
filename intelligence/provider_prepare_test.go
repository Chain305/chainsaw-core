package intelligence

import (
	"context"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
	"github.com/chain305/chainsaw-core/upstreamhttp"
)

// preparingFake waits in Prepare (the limiter queue) and then needs most of
// its timeout to run (the fetches).
type preparingFake struct {
	fakeProvider
	queue time.Duration
}

func (p *preparingFake) Prepare(ctx context.Context, _ Request) context.Context {
	select {
	case <-time.After(p.queue):
	case <-ctx.Done():
	}
	return ctx
}

// The provider's timeout starts after Prepare: queue wait no longer eats the
// budget the fetches run under. 2.5s queued + 1s of fetching failed at the
// 3s default before.
func TestScan_ProviderTimeoutStartsAfterPrepare(t *testing.T) {
	ok := true
	p := &preparingFake{
		fakeProvider: fakeProvider{
			name:    "queued-registry",
			signal:  SignalMalware,
			delay:   time.Second,
			partial: PartialReport{People: &PeopleSection{TrustedPublisher: &ok}},
		},
		queue: DefaultProviderTimeout - 500*time.Millisecond,
	}
	svc := New(Config{Providers: []Provider{p}})
	report, err := svc.Scan(context.Background(), Request{Key: Key{Ecosystem: "npm", Package: "json5", Version: "1.0.2"}})
	if err != nil {
		t.Fatal(err)
	}
	if report.People.TrustedPublisher == nil {
		t.Fatalf("the queue wait ate the provider budget: %+v", report.Observation.ProviderTimings)
	}
	for _, pt := range report.Observation.ProviderTimings {
		if pt.Provider == "queued-registry" && pt.Duration < p.queue {
			t.Fatalf("the provider timing must include the queue wait: %v", pt.Duration)
		}
	}
}

// Every successful run makes these requests to the ecosystem's primary
// host, so Prepare pays for them before the clock starts.
func TestRegistryMetadataFixedRequests(t *testing.T) {
	p := newRegistryMetadataProvider()
	for eco, want := range map[string]int{"npm": 1, "pypi": 3, "rubygems": 3, "cargo": 4, "maven": 2, "go": 4, "nuget": 0} {
		if _, n := p.fixedRequests(eco); n != want {
			t.Errorf("%s: %d fixed requests, want %d", eco, n, want)
		}
	}
	// On the shared limited client it returns a context carrying the paid
	// tokens (a local limiter wait; nothing is fetched).
	if got := p.Prepare(context.Background(), Request{Key: Key{Ecosystem: "pypi"}}); got == context.Background() {
		t.Fatal("Prepare paid for nothing on the shared client")
	}
	// A provider not on the shared limited client (tests, httptest) has no
	// bucket to queue on.
	other := &registryMetadataProvider{endpoints: defaultRegistryEndpoints()}
	ctx := context.Background()
	if got := other.Prepare(ctx, Request{Key: Key{Ecosystem: "pypi"}}); got != ctx {
		t.Fatal("Prepare must leave the context alone off the shared client")
	}
}

// A scan someone may be waiting on (proxy install, public lookup) queues for
// its registry tokens at most prepayForegroundWait; work nobody waits on
// (refresher, dependency scans, cache warm-up) up to prepayBackgroundWait.
func TestPrepayWaitCaps(t *testing.T) {
	if prepayForegroundWait != 2*time.Second || prepayBackgroundWait != 15*time.Second {
		t.Fatalf("caps are %v / %v, want 2s / 15s", prepayForegroundWait, prepayBackgroundWait)
	}
	bg := context.Background()
	for name, tc := range map[string]struct {
		ctx  context.Context
		want time.Duration
	}{
		"install or public lookup": {bg, prepayForegroundWait},
		"dependency scan":          {upstreamhttp.WithBackground(bg), prepayBackgroundWait},
		"refresher":                {httpclient.WithEgressCaller(bg, httpclient.EgressCallerRefresh), prepayBackgroundWait},
		"refresher sub-caller":     {httpclient.WithEgressCaller(bg, httpclient.EgressCallerRefreshDocument), prepayBackgroundWait},
	} {
		if got := prepayWait(tc.ctx); got != tc.want {
			t.Errorf("%s: cap %v, want %v", name, got, tc.want)
		}
	}
}
