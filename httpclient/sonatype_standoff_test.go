package httpclient

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type sonatypeFakeRT struct {
	hits   atomic.Int32
	status int
	header http.Header
}

func (rt *sonatypeFakeRT) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.hits.Add(1)
	return &http.Response{StatusCode: rt.status, Header: rt.header.Clone(), Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

func sonatypeClient(rt http.RoundTripper) *http.Client {
	return New(WithTransport(func(*http.Transport) http.RoundTripper { return rt }))
}

// Any client this package builds starts the stand-off on a Maven Central 429
// and, while it holds, answers every client's request to either hostname
// locally with a 503 and a Retry-After, without touching the network.
func TestSonatypeStandoffIsSharedByEveryClient(t *testing.T) {
	ResetSonatypeStandoff()
	t.Cleanup(ResetSonatypeStandoff)
	rt := &sonatypeFakeRT{status: http.StatusTooManyRequests, header: http.Header{"Retry-After": {"120"}}}
	installs, refresher := sonatypeClient(rt), sonatypeClient(rt)

	resp, err := installs.Get("https://repo1.maven.org/maven2/a/b/1/b-1.pom")
	if err != nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("first request: %v %v", resp, err)
	}
	resp.Body.Close()
	if left := SonatypeStandoff(); left < 110*time.Second || left > 121*time.Second {
		t.Fatalf("stand-off left %v, want the Retry-After of 120s", left)
	}

	start := time.Now()
	resp, err = refresher.Get("https://repo.maven.apache.org/maven2/c/d/2/d-2.pom")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get(SonatypeStandoffHeader) == "" || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("during the stand-off: status %d headers %v, want a local 503 with Retry-After", resp.StatusCode, resp.Header)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("the stand-off answer must be immediate")
	}
	if n := rt.hits.Load(); n != 1 {
		t.Fatalf("the edge was asked %d times, want 1: nothing goes out during a stand-off", n)
	}
	// Other hosts are untouched.
	rt.status = http.StatusOK
	if resp, err := refresher.Get("https://registry.npmjs.org/left-pad"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("an unrelated host was held by the Maven stand-off: %v %v", resp, err)
	}
}

func TestSonatypeStandoffIsCappedAndDefaulted(t *testing.T) {
	for _, tc := range []struct {
		name       string
		retryAfter string
		lo, hi     time.Duration
	}{
		{"a day-long Retry-After is capped", "86400", sonatypeStandoffMax - time.Minute, sonatypeStandoffMax},
		{"no Retry-After takes the default", "", sonatypeStandoffDefault - 5*time.Second, sonatypeStandoffDefault},
		{"an HTTP-date Retry-After is honoured", time.Now().Add(10 * time.Minute).UTC().Format(http.TimeFormat), 9 * time.Minute, 10 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ResetSonatypeStandoff()
			t.Cleanup(ResetSonatypeStandoff)
			h := http.Header{}
			if tc.retryAfter != "" {
				h.Set("Retry-After", tc.retryAfter)
			}
			if !ObserveSonatypeResponse("repo1.maven.org", &http.Response{StatusCode: http.StatusTooManyRequests, Header: h}) {
				t.Fatal("a Maven Central 429 did not start a stand-off")
			}
			if got := SonatypeStandoff(); got < tc.lo || got > tc.hi {
				t.Fatalf("stand-off left %v, want between %v and %v", got, tc.lo, tc.hi)
			}
		})
	}
}

// Outside a stand-off nothing changes: no wait, the request goes out.
func TestNoSonatypeStandoffNoChange(t *testing.T) {
	ResetSonatypeStandoff()
	rt := &sonatypeFakeRT{status: http.StatusOK}
	resp, err := sonatypeClient(rt).Get("https://repo1.maven.org/maven2/a/b/1/b-1.pom")
	if err != nil || resp.StatusCode != http.StatusOK || rt.hits.Load() != 1 {
		t.Fatalf("got %v %v hits=%d", resp, err, rt.hits.Load())
	}
	if ObserveSonatypeResponse("registry.npmjs.org", &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}}) || SonatypeStandoff() != 0 {
		t.Fatal("a non-Maven 429 started the Maven stand-off")
	}
}
