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
