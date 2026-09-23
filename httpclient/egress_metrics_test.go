package httpclient

// The first version of this counter lived inside one provider and measured
// NOTHING in production: the refresher scanned 2,075 rows and the counter
// stayed at zero, because the upstream work also flows through the
// latest-version prober, the artifact fetcher and the wave4 providers. The
// lesson is in these tests — assert on the client the package actually hands
// out, not on the function you happened to instrument.

import (
	"net/http"
	"net/http/httptest"
	"sync"

	"github.com/chain305/chainsaw-core/config"
	"testing"
)

func recorded(t *testing.T) (*sync.Mutex, map[string]int) {
	t.Helper()
	var mu sync.Mutex
	got := map[string]int{}
	SetEgressRecorder(func(host string, outcome EgressOutcome) {
		mu.Lock()
		defer mu.Unlock()
		got[host+"/"+string(outcome)]++
	})
	t.Cleanup(func() { SetEgressRecorder(nil) })
	return &mu, got
}

// New() is the general constructor.
func TestNewClientCountsEgress(t *testing.T) {
	mu, got := recorded(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := New()
	for i := 0; i < 3; i++ {
		resp, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if got["127.0.0.1/ok"] != 3 {
		t.Errorf("expected 3 ok requests on 127.0.0.1, got %+v", got)
	}
}

// Factory.NewClient is the OTHER constructor — artifact downloads use it, and
// they are the bulk of upstream byte volume. Missing it is how the first
// attempt undercounted.
func TestFactoryClientCountsEgress(t *testing.T) {
	mu, got := recorded(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := NewFactory(config.HTTPClientConfig{}).NewClient(config.RemoteConfig{})
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()

	mu.Lock()
	defer mu.Unlock()
	if got["127.0.0.1/rate_limited"] != 1 {
		t.Errorf("Factory client did not count a 429: %+v", got)
	}
}

func TestOutcomeClassification(t *testing.T) {
	for _, c := range []struct {
		status int
		want   EgressOutcome
	}{
		{200, EgressOK}, {204, EgressOK},
		{404, EgressNotFound},
		{429, EgressRateLimited},
		{403, EgressForbidden}, // distinct from 429: retrying never fixes a 403
		{500, EgressServerError}, {503, EgressServerError},
		{301, EgressOther}, {418, EgressOther},
	} {
		if got := outcomeForStatus(c.status); got != c.want {
			t.Errorf("outcomeForStatus(%d) = %q, want %q", c.status, got, c.want)
		}
	}
}

// A transport failure must still be counted — a connection refused by a
// rate-limiting upstream costs us, and is exactly what we want to see.
func TestTransportErrorCounted(t *testing.T) {
	mu, got := recorded(t)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing is listening now

	resp, err := New().Get(url)
	if err == nil {
		resp.Body.Close()
		t.Skip("the port was reused by something else; cannot exercise the transport path")
	}
	mu.Lock()
	defer mu.Unlock()
	if got["127.0.0.1/transport_error"] != 1 {
		t.Errorf("transport failure not counted: %+v", got)
	}
}

// Wrapping twice would double every count.
func TestEgressCountingIsIdempotent(t *testing.T) {
	inner := http.DefaultTransport
	once := withEgressCounting(inner)
	twice := withEgressCounting(once)
	if once != twice {
		t.Error("withEgressCounting wrapped an already-wrapped transport; counts would double")
	}
}

// Nil recorder must be free and safe — this sits on every outbound request.
func TestNilRecorderSafe(t *testing.T) {
	SetEgressRecorder(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	resp, err := New().Get(srv.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
}

// A 403 from an object store that answers a MISSING object with 403 must not be
// reported as "forbidden". The metric misled its own author within two hours of
// shipping: 15 of 15 requests to static.crates.io read `forbidden`, which sent
// me looking for a User-Agent or IP block that did not exist — the crates
// simply were not there. Verified live with our own UA: serde-1.0.219.crate
// 200, serde-99.99.99.crate 403.
func TestAmbiguous403HostsAreNotReportedAsForbidden(t *testing.T) {
	for _, host := range []string{"static.crates.io", "rubygems.org"} {
		if got := outcomeFor(host, 403); got != EgressAbsentOrForbidden {
			t.Errorf("outcomeFor(%q, 403) = %q, want %q — this host answers a missing "+
				"object with 403, so %q asserts a block that may not exist",
				host, got, EgressAbsentOrForbidden, EgressForbidden)
		}
	}
}

// The distinction must NOT be destroyed for every other host. 403 from a
// registry API is a config problem retrying will never fix, and
// plan_upstream_rate_limits turns on telling it apart from 429 throttling.
func TestOrdinaryHosts403StaysForbidden(t *testing.T) {
	for _, host := range []string{"repo1.maven.org", "registry.npmjs.org", "api.github.com"} {
		if got := outcomeFor(host, 403); got != EgressForbidden {
			t.Errorf("outcomeFor(%q, 403) = %q, want %q", host, got, EgressForbidden)
		}
	}
	// And a genuine 403 block on an ambiguous host must still be VISIBLE —
	// folding these into not_found would hide it on the one path where a block
	// cannot otherwise be seen.
	if outcomeFor("static.crates.io", 403) == EgressNotFound {
		t.Error("an ambiguous 403 was folded into not_found; a genuine block there becomes invisible")
	}
}

// Every other status must be host-independent, or the host lookup has leaked
// into paths it has no business touching.
func TestOutcomeForIsHostIndependentExcept403(t *testing.T) {
	for _, status := range []int{200, 404, 429, 500, 503, 302} {
		want := outcomeForStatus(status)
		for _, host := range []string{"static.crates.io", "rubygems.org", "repo1.maven.org"} {
			if got := outcomeFor(host, status); got != want {
				t.Errorf("outcomeFor(%q, %d) = %q, want %q (host must only matter for 403)",
					host, status, got, want)
			}
		}
	}
}

// stub403 answers every request 403 without a network, so the request URL can
// name a REAL ambiguous-403 host.
type stub403 struct{}

func (stub403) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusForbidden,
		Body:       http.NoBody,
		Header:     http.Header{},
	}, nil
}

// The wiring, not the mapper. Correcting outcomeFor and then not calling it from
// RoundTrip leaves the metric exactly as misleading as before, and the mapper's
// own unit tests all stay green — the failure mode CLAUDE.md §3 is about. This
// is the test that goes red when the call site drops the host argument; without
// it, that mutation survives the whole package suite.
func TestRoundTripPassesHostToTheOutcomeMapper(t *testing.T) {
	mu, got := recorded(t)

	rt := withEgressCounting(stub403{})
	for _, host := range []string{"static.crates.io", "repo1.maven.org"} {
		req, err := http.NewRequest(http.MethodGet, "https://"+host+"/whatever", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		if _, err := rt.RoundTrip(req); err != nil {
			t.Fatalf("round trip: %v", err)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if n := got["static.crates.io/"+string(EgressAbsentOrForbidden)]; n != 1 {
		t.Errorf("static.crates.io recorded %q %d times, want 1 — RoundTrip is not passing the "+
			"host to the outcome mapper, so a missing crate still reads as a block. recorded=%v",
			EgressAbsentOrForbidden, n, got)
	}
	if n := got["repo1.maven.org/"+string(EgressForbidden)]; n != 1 {
		t.Errorf("repo1.maven.org recorded %q %d times, want 1 — an ordinary host's 403 must "+
			"stay forbidden. recorded=%v", EgressForbidden, n, got)
	}
}
