package provenance

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
)

// TestNuGetRejectsOversizedPackage — HEAD with Content-Length exceeding
// the 50 MiB cap must surface StatusUnavailable (not StatusFailed) so the
// caller can still render a row.
func TestNuGetRejectsOversizedPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", "2147483648") // 2 GiB
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	over, err := headContentTooLarge(context.Background(), srv.Client(), srv.URL, 50<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !over {
		t.Error("want headContentTooLarge to return true for 2 GiB response")
	}
}

func TestHeadContentTooLargeUnderLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Small response: 10 bytes, no explicit Content-Length → Go may
		// send chunked. Set it explicitly.
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	over, err := headContentTooLarge(context.Background(), srv.Client(), srv.URL, 50<<20)
	if err != nil {
		t.Fatal(err)
	}
	if over {
		t.Error("small Content-Length should not be flagged oversized")
	}
}

// TestFetchNuGetTrustPoolFailsLoudlyOnEmpty — if every cert fetch fails we
// must return an error, not a nil-err empty pool (which would later fail
// silently inside VerifyWithChain with "unknown authority").
func TestFetchNuGetTrustPoolFailsLoudlyOnEmpty(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/index.json") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"signingCertificates":[
				{"contentUrl":"` + base + `/cert1.cer"},
				{"contentUrl":"` + base + `/cert2.cer"}
			]}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	base = srv.URL

	// We can't easily redirect the hardcoded index URL; instead drive
	// fetchNuGetTrustPool with an empty index from our test server by
	// stubbing the index to return zero signingCertificates — that's a
	// separate failure mode. The "all certs fail" path is what we want.
	//
	// Use an alternate helper wired for this test: call
	// fetchNuGetTrustPoolFrom(indexURL) for dependency injection.
	_, err := fetchNuGetTrustPoolFrom(context.Background(), srv.Client(), srv.URL+"/index.json")
	if err == nil {
		t.Fatal("want error when all cert fetches fail, got nil")
	}
	if !strings.Contains(err.Error(), "no nuget trust") {
		t.Errorf("want 'no nuget trust' in error, got: %v", err)
	}
}

func TestNugetTrustCacheRetriesAfterBackoff(t *testing.T) {
	fake := clockwork.NewFakeClock()
	calls := 0
	boom := errors.New("fetch fail")
	want := x509.NewCertPool()
	c := &nugetTrustCache{
		clock: fake,
		loader: func(ctx context.Context) (*x509.CertPool, error) {
			calls++
			if calls == 1 {
				return nil, boom
			}
			return want, nil
		},
	}

	if _, err := c.get(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("first call: want %v, got %v", boom, err)
	}

	// Within backoff: cached error, no re-invoke.
	fake.Advance(5 * time.Second)
	if _, err := c.get(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("cached-fail: want %v, got %v", boom, err)
	}
	if calls != 1 {
		t.Fatalf("cached-fail: loader should not re-run, got %d", calls)
	}

	// Past backoff: retry and succeed.
	fake.Advance(nugetTrustBackoff + time.Second)
	got, err := c.get(context.Background())
	if err != nil {
		t.Fatalf("post-backoff: want success, got %v", err)
	}
	if got != want {
		t.Fatalf("post-backoff: want %p, got %p", want, got)
	}

	// Cached for TTL.
	fake.Advance(nugetTrustTTL - time.Second)
	if got, _ := c.get(context.Background()); got != want {
		t.Fatalf("cached-success: want %p, got %p", want, got)
	}
	if calls != 2 {
		t.Fatalf("cached-success: loader should not re-run, got %d", calls)
	}

	// Past TTL: refresh.
	fake.Advance(2 * time.Second)
	if _, err := c.get(context.Background()); err != nil {
		t.Fatalf("post-TTL: want success, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("post-TTL: want loader invoked 3x total, got %d", calls)
	}
}
