package upstreamhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
)

func freshSonatypeEdge(t *testing.T) {
	t.Helper()
	old := sonatypeEdge
	sonatypeEdge = &sonatypeEdgeState{}
	httpclient.ResetSonatypeStandoff()
	t.Cleanup(func() { sonatypeEdge = old; httpclient.ResetSonatypeStandoff() })
}

// One bucket for Maven Central, whichever client asks and under whichever
// hostname. Before, each limiter instance kept its own bucket per hostname,
// so a token spent on repo1.maven.org by one client left another client's
// repo.maven.apache.org bucket full.
func TestSonatypeEdgeIsOneBucketAcrossClientsAndHostnames(t *testing.T) {
	freshSonatypeEdge(t)
	cfg := Config{HostLimits: map[string]float64{"repo1.maven.org": 1, "repo.maven.apache.org": 1}, Burst: 1}
	a, b := NewInProcessHostLimiter(cfg), NewInProcessHostLimiter(cfg)
	if err := a.Wait(context.Background(), "repo1.maven.org"); err != nil {
		t.Fatal(err)
	}
	// The next token is ~1s away. With 700ms left, a separate bucket would
	// grant at once; the shared one has to refuse.
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	if err := b.Wait(ctx, "REPO.maven.apache.org"); !errors.Is(err, ErrRateLimitedLocally) {
		t.Fatalf("second client on the other hostname: err = %v, want the shared bucket to refuse", err)
	}
	// Other hosts keep their own per-instance buckets.
	if err := b.Wait(ctx, "registry.npmjs.org"); err != nil {
		t.Fatalf("an unrelated host was throttled by the Maven bucket: %v", err)
	}
}

type countingRT struct {
	calls  atomic.Int32
	status int
	header http.Header
}

func (rt *countingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.calls.Add(1)
	return &http.Response{StatusCode: rt.status, Header: rt.header.Clone(), Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

func sonatypeGet(t *testing.T, c *Client, url string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	return resp, err
}

// A 429 from Maven Central stops EVERY client asking either hostname until
// its Retry-After, and is not retried: asking again inside a block is what
// lengthens it.
func TestSonatype429StandsOffHostWide(t *testing.T) {
	freshSonatypeEdge(t)
	rt := &countingRT{status: http.StatusTooManyRequests, header: http.Header{"Retry-After": {"120"}}}
	cfg := Config{HostLimits: map[string]float64{"repo1.maven.org": 1000}, Burst: 10, MaxRetries: 3, RetryBaseDelay: time.Millisecond}
	first := New(cfg, WithBaseClient(&http.Client{Transport: rt}))
	other := New(cfg, WithBaseClient(&http.Client{Transport: rt}))

	resp, err := sonatypeGet(t, first, "https://repo1.maven.org/maven2/a/b/1/b-1.pom")
	if err != nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("first request: resp=%v err=%v, want the 429 returned", resp, err)
	}
	if n := rt.calls.Load(); n != 1 {
		t.Fatalf("a Maven Central 429 was retried: %d requests, want 1", n)
	}
	if got := httpclient.SonatypeStandoff(); got < 110*time.Second || got > 121*time.Second {
		t.Fatalf("stand-off ends in %v, want the Retry-After of 120s", got)
	}

	_, err = sonatypeGet(t, other, "https://repo.maven.apache.org/maven2/c/d/2/d-2.pom")
	if !errors.Is(err, ErrUpstreamStandoff) || !errors.Is(err, ErrRateLimitedLocally) {
		t.Fatalf("another client on the other hostname: err = %v, want ErrUpstreamStandoff (wrapping ErrRateLimitedLocally)", err)
	}
	if _, err := other.Prepay(context.Background(), "repo1.maven.org", 1, 0); !errors.Is(err, ErrUpstreamStandoff) {
		t.Fatalf("prepay during a stand-off: err = %v, want ErrUpstreamStandoff", err)
	}
	if n := rt.calls.Load(); n != 1 {
		t.Fatalf("the edge was asked again during the stand-off: %d requests, want 1", n)
	}
}

// Every other host keeps the ordinary retry behaviour and no stand-off.
func TestNonSonatype429IsNotAStandoff(t *testing.T) {
	freshSonatypeEdge(t)
	rt := &countingRT{status: http.StatusTooManyRequests}
	c := New(Config{Burst: 10, MaxRetries: 2, RetryBaseDelay: time.Millisecond}, WithBaseClient(&http.Client{Transport: rt}))
	if _, err := sonatypeGet(t, c, "https://registry.npmjs.org/left-pad"); err != nil {
		t.Fatal(err)
	}
	if n := rt.calls.Load(); n != 3 {
		t.Fatalf("npm 429: %d requests, want 3 (1 + MaxRetries)", n)
	}
	if httpclient.SonatypeStandoff() != 0 {
		t.Fatal("a non-Maven 429 started the Maven stand-off")
	}
}
