package intelligence

// The counter exists because declared_inventory D-2 could not be answered:
// per-coordinate refresh cost is upstream fetches, and nothing counted them.

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestUpstreamHostLabelIsBounded(t *testing.T) {
	// The endpoint carries a package NAME, which is attacker-influenced. If it
	// reached the label, Prometheus cardinality would be driven by input we do
	// not control — so anything unparseable collapses to "unknown" rather than
	// passing the raw string through.
	for _, c := range []struct{ in, want string }{
		{"https://registry.npmjs.org/express", "registry.npmjs.org"},
		{"https://proxy.golang.org/rsc.io/quote/@v/v1.5.2.info", "proxy.golang.org"},
		{"https://repo1.maven.org/maven2/org/x/y/1.0/y-1.0.pom", "repo1.maven.org"},
		{"https://registry.npmjs.org:443/express", "registry.npmjs.org"}, // port stripped
		{"not a url at all", "unknown"},
		{"", "unknown"},
		{"://bad", "unknown"},
		{"/relative/only", "unknown"},
	} {
		if got := upstreamHost(c.in); got != c.want {
			t.Errorf("upstreamHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestOutcomeForStatus(t *testing.T) {
	for _, c := range []struct {
		status int
		want   UpstreamFetchOutcome
	}{
		{200, UpstreamFetchOK},
		{204, UpstreamFetchOK},
		{404, UpstreamFetchNotFound},
		{429, UpstreamFetchRateLimited},
		// GitHub answers a spent rate limit with 403, not 429, and GitHub is
		// the upstream most likely to be limited here.
		{403, UpstreamFetchRateLimited},
		{500, UpstreamFetchServerError},
		{503, UpstreamFetchServerError},
		{301, UpstreamFetchOther},
		{418, UpstreamFetchOther},
	} {
		if got := outcomeForStatus(c.status); got != c.want {
			t.Errorf("outcomeForStatus(%d) = %q, want %q", c.status, got, c.want)
		}
	}
}

// TestFetchCountsEveryAttempt is the property D-2 depends on: a retry is a
// second real request against a rate-limited upstream, so it must be counted
// separately. Counting logical fetches would under-report exactly when an
// upstream is unhealthy, which is when the number matters most.
func TestFetchCountsEveryAttempt(t *testing.T) {
	var mu sync.Mutex
	got := map[string]int{}
	SetUpstreamFetchRecorder(func(host string, outcome UpstreamFetchOutcome) {
		mu.Lock()
		defer mu.Unlock()
		got[host+"/"+string(outcome)]++
	})
	defer SetUpstreamFetchRecorder(nil)

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		http.Error(w, "boom", http.StatusInternalServerError) // retryable
	}))
	defer srv.Close()

	p := &registryMetadataProvider{client: srv.Client(), now: func() time.Time { return time.Unix(0, 0).UTC() }}
	_, _ = p.fetchJSON(t.Context(), srv.URL+"/pkg", "application/json", &struct{}{})

	mu.Lock()
	defer mu.Unlock()
	total := 0
	for _, n := range got {
		total += n
	}
	if total != hits {
		t.Errorf("counted %d attempts but the server saw %d requests: %+v", total, hits, got)
	}
	if hits < 2 {
		t.Fatalf("server saw %d requests; the 5xx path should have retried, so this is not "+
			"exercising the per-attempt property", hits)
	}
	if got["127.0.0.1/server_error"] != hits {
		t.Errorf("expected %d server_error attempts on 127.0.0.1, got %+v", hits, got)
	}
}

// A nil recorder must be free and safe — it sits on the fetch hot path.
func TestRecordUpstreamFetchNilSafe(t *testing.T) {
	SetUpstreamFetchRecorder(nil)
	recordUpstreamFetch("https://registry.npmjs.org/x", UpstreamFetchOK) // must not panic
}
