package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// TestFetchWithRetryHonoursRetryAfter pins the retry budget against a
// throttling upstream. Every attempt is a real request that registries count
// against the limit that produced the 429, so a retry the server has already
// said it will refuse is pure cost.
func TestFetchWithRetryHonoursRetryAfter(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		retryAfter string
		wantHits   int32
	}{
		// Verified by deletion: removing the Retry-After check in
		// fetchWithRetry makes both of these hit the upstream 3 times.
		{"429 with a long Retry-After is not retried", http.StatusTooManyRequests, "30", 1},
		{"503 with an HTTP-date Retry-After is not retried", http.StatusServiceUnavailable,
			time.Now().Add(time.Hour).UTC().Format(http.TimeFormat), 1},
		// No hint, or a hint shorter than our own backoff: the short retries
		// still run, so a transient blip does not reach the customer.
		{"429 without Retry-After is retried", http.StatusTooManyRequests, "", 3},
		{"503 without Retry-After is retried", http.StatusServiceUnavailable, "", 3},
		{"garbage Retry-After is ignored", http.StatusTooManyRequests, "soon", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			base, _ := url.Parse(srv.URL + "/")
			f := &facet{
				format: "npm",
				logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			remote := RemoteDefinition{BaseURL: base, Client: srv.Client()}

			resp, err := f.fetchWithRetry(context.Background(), remote, "left-pad", http.Header{})
			if err != nil {
				t.Fatalf("fetchWithRetry: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if got := hits.Load(); got != tc.wantHits {
				t.Errorf("upstream hit %d times, want %d", got, tc.wantHits)
			}
		})
	}
}

func TestRetryAfterParsing(t *testing.T) {
	now := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	for header, want := range map[string]time.Duration{
		"5":                             5 * time.Second,
		" 120 ":                         2 * time.Minute,
		"Fri, 25 Sep 2026 00:01:00 GMT": time.Minute,
	} {
		if got, ok := retryAfter(header, now); !ok || got != want {
			t.Errorf("retryAfter(%q) = %v, %v; want %v, true", header, got, ok, want)
		}
	}
	for _, header := range []string{"", "0", "-3", "soon", "Thu, 24 Sep 2026 23:00:00 GMT"} {
		if got, ok := retryAfter(header, now); ok {
			t.Errorf("retryAfter(%q) = %v, true; want ok=false", header, got)
		}
	}
}
