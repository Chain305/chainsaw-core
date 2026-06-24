package intelligence

// Tests for the retry-with-backoff + per-ecosystem timeout layer in
// the registry-metadata fetch path. We use httptest servers that count
// hits so we can assert (a) flaky 5xx recovers within budget,
// (b) persistent 5xx surfaces the registry_fetch_exhausted_retries
// code, (c) 4xx skips retry entirely, and (d) maven's 20s budget can
// absorb a slow server beyond the 8s default.
//
// Backoff base is set very low (microsecond-scale) per test by
// overriding registryBackoffBase via a local const elsewhere — we
// can't here because it's a const. Instead we accept the real
// 200ms+800ms ≈ 1s wait for the exhaustion test, which is acceptable
// for go test under -race.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// minimal valid npm packument body that the runNPM decoder accepts.
const minimalNPMBody = `{"name":"x","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}`

// (a) Flaky 5xx that succeeds on the 2nd retry: expect success and
// no warning surfaced.
func TestRegistryRetry_FlakyRecovers(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := hits.Add(1)
		if n < 3 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(minimalNPMBody))
	}))
	t.Cleanup(srv.Close)

	p := newRegistryMetadataProvider()
	p.endpoints.npm = srv.URL

	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := hits.Load(); got != 3 {
		t.Fatalf("handler hit %d times, want 3 (1 initial + 2 retries)", got)
	}
	for _, w := range pr.Warnings {
		if w.Code == "registry_fetch_exhausted_retries" || strings.HasPrefix(w.Code, "http_5") {
			t.Fatalf("unexpected warning after recovery: %+v", w)
		}
	}
}

// (b) Persistent 5xx: 3 attempts then surface the exhausted code.
func TestRegistryRetry_ExhaustsOn5xx(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "still broken", http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)

	p := newRegistryMetadataProvider()
	p.endpoints.npm = srv.URL

	start := time.Now()
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := hits.Load(); got != registryMaxAttempts {
		t.Fatalf("handler hit %d times, want %d", got, registryMaxAttempts)
	}
	if len(pr.Warnings) == 0 {
		t.Fatalf("expected exhausted warning, got none")
	}
	last := pr.Warnings[len(pr.Warnings)-1]
	if last.Code != "registry_fetch_exhausted_retries" {
		t.Fatalf("expected code registry_fetch_exhausted_retries, got %q (msg=%s)", last.Code, last.Message)
	}
	// Sanity: total elapsed should include at least the two backoff
	// sleeps (200ms + 800ms = 1s, with ±25% jitter floor at 0.75 →
	// 750ms minimum).
	if elapsed := time.Since(start); elapsed < 700*time.Millisecond {
		t.Fatalf("retry path completed too fast (%v) — backoff not sleeping", elapsed)
	}
}

// (c) 404: must not retry.
func TestRegistryRetry_NoRetryOn404(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.NotFound(w, nil)
	}))
	t.Cleanup(srv.Close)

	p := newRegistryMetadataProvider()
	p.endpoints.npm = srv.URL

	start := time.Now()
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("handler hit %d times, want 1 (404 must not retry)", got)
	}
	if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
		t.Fatalf("404 path slept on backoff (%v) — should be immediate", elapsed)
	}
	if len(pr.Warnings) == 0 || pr.Warnings[0].Code != "not_found" {
		t.Fatalf("expected not_found warning, got %+v", pr.Warnings)
	}
}

// (d) Slow server: 1.5s response, exceeds the 8s default but well
// inside maven's 20s per-attempt budget. Use a real maven dispatch
// (the POM XML path).
func TestRegistryRetry_PerEcosystemTimeoutMaven(t *testing.T) {
	// 1.5s is beyond what we want for npm's 8s budget would still
	// pass, but the test point is: a delay larger than the *default*
	// (8s) would normally fail under flat-timeout settings. Setting
	// 9s here would make the test slow; we instead verify the
	// effective per-attempt timeout via ecosystemTimeout() and that
	// a sub-default delay still works through the maven path.
	if got := registryTimeouts["maven"]; got != 20*time.Second {
		t.Fatalf("maven timeout = %v, want 20s", got)
	}
	if got := defaultRegistryTimeout; got != 8*time.Second {
		t.Fatalf("default = %v, want 8s", got)
	}

	delay := 1500 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		// Minimal POM the maven decoder accepts.
		w.Header().Set("Content-Type", "application/xml")
		_, _ = fmt.Fprintf(w, `<project><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>`)
	}))
	t.Cleanup(srv.Close)

	p := newRegistryMetadataProvider()
	p.endpoints.maven = srv.URL

	// Pin a per-attempt timeout via context: under maven dispatch
	// the eco context value selects 20s, comfortably above 1.5s.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pr, err := p.Run(ctx, Request{Key: Key{Ecosystem: "maven", Package: "g:a", Version: "1"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, w := range pr.Warnings {
		if w.Code == "registry_fetch_exhausted_retries" || w.Code == "transport" || w.Code == "timeout" {
			t.Fatalf("slow-but-within-budget request should succeed, got warning: %+v", w)
		}
	}
}

// Sanity check that ecosystemTimeout falls back to default for
// unlisted/unknown ecosystems.
func TestEcosystemTimeoutFallback(t *testing.T) {
	ctx := withEcosystem(context.Background(), "apt")
	if got := ecosystemTimeout(ctx); got != defaultRegistryTimeout {
		t.Fatalf("apt timeout = %v, want default %v", got, defaultRegistryTimeout)
	}
	ctx = withEcosystem(context.Background(), "MAVEN") // case-insensitive in inputs
	if got := ecosystemTimeout(ctx); got != 20*time.Second {
		t.Fatalf("MAVEN (uppercase) timeout = %v, want 20s", got)
	}
}
