package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
)

type mavenEdgeRT struct{ hits atomic.Int32 }

func (rt *mavenEdgeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.hits.Add(1)
	h := http.Header{"Retry-After": {"600"}}
	return &http.Response{StatusCode: http.StatusTooManyRequests, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

// A proxied Maven install during a Sonatype block fails fast with an
// upstream-unavailable 503 and a Retry-After, instead of sending the edge one
// more request it holds against us. The proxy's remote clients are built by
// httpclient (repository builder -> Factory.NewClient), so they share the
// process-wide stand-off with the refresher and registry metadata.
func TestProxiedMavenInstallHonoursTheSonatypeStandoff(t *testing.T) {
	httpclient.ResetSonatypeStandoff()
	t.Cleanup(httpclient.ResetSonatypeStandoff)
	rt := &mavenEdgeRT{}
	client := httpclient.New(httpclient.WithTransport(func(*http.Transport) http.RoundTripper { return rt }))
	base, _ := url.Parse("https://repo.maven.apache.org/maven2/")
	remote := RemoteDefinition{BaseURL: base, Client: client}
	f := &facet{format: "maven", logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// The first install meets the block: one request, not retried.
	resp, err := f.fetchWithRetry(context.Background(), remote, "org/a/b/1/b-1.pom", http.Header{})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || rt.hits.Load() != 1 {
		t.Fatalf("first install: status %d hits %d, want the 429 once", resp.StatusCode, rt.hits.Load())
	}

	// Every later install, on either hostname, is answered without the edge.
	for _, host := range []string{"https://repo.maven.apache.org/maven2/", "https://repo1.maven.org/maven2/"} {
		base, _ := url.Parse(host)
		start := time.Now()
		resp, err := f.fetchWithRetry(context.Background(), RemoteDefinition{BaseURL: base, Client: client}, "org/c/d/2/d-2.jar", http.Header{})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
			t.Fatalf("%s during the stand-off: status %d, want 503 with Retry-After", host, resp.StatusCode)
		}
		if time.Since(start) > 50*time.Millisecond {
			t.Fatalf("%s: the stand-off answer took %v; it must fail fast, not walk the retry backoff", host, time.Since(start))
		}
	}
	if n := rt.hits.Load(); n != 1 {
		t.Fatalf("the edge was asked %d times, want 1", n)
	}
}
