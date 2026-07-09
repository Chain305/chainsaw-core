package upstreamhttp

import (
	"net/http"
	"testing"
	"time"
)

// TestParseRetryAfter_Seconds covers the integer-seconds form, which
// is what npm / pypi / crates actually emit.
func TestParseRetryAfter_Seconds(t *testing.T) {
	d, ok := parseRetryAfter("5", time.Unix(0, 0))
	if !ok {
		t.Fatal("parseRetryAfter(5) ok=false, want true")
	}
	if d != 5*time.Second {
		t.Fatalf("parseRetryAfter(5) = %v, want 5s", d)
	}
}

// TestParseRetryAfter_HTTPDate covers the RFC 7231 HTTP-date form. We
// pin the clock 10 seconds before the header's instant so the
// computed delay is deterministic.
func TestParseRetryAfter_HTTPDate(t *testing.T) {
	now := time.Date(2099, time.December, 31, 23, 59, 49, 0, time.UTC)
	// IMF-fixdate form — the canonical HTTP-date layout per RFC 7231.
	header := "Fri, 31 Dec 2099 23:59:59 GMT"
	d, ok := parseRetryAfter(header, now)
	if !ok {
		t.Fatalf("parseRetryAfter HTTP-date ok=false, want true (header=%q)", header)
	}
	if d != 10*time.Second {
		t.Fatalf("parseRetryAfter HTTP-date = %v, want 10s", d)
	}
}

// TestParseRetryAfter_PastDate rejects a Retry-After that has already
// elapsed. The caller should fall through to exponential backoff in
// that case rather than retrying immediately and hammering the server.
func TestParseRetryAfter_PastDate(t *testing.T) {
	now := time.Date(2099, time.December, 31, 23, 59, 59, 0, time.UTC)
	header := "Fri, 31 Dec 2099 23:59:49 GMT" // 10s in the past
	if _, ok := parseRetryAfter(header, now); ok {
		t.Fatal("parseRetryAfter past-date ok=true, want false")
	}
}

// TestParseRetryAfter_EmptyAndGarbage tolerates missing / unparseable
// headers. Returns (0, false) so the caller knows to use exponential
// backoff.
func TestParseRetryAfter_EmptyAndGarbage(t *testing.T) {
	for _, h := range []string{"", "   ", "banana", "0", "-5"} {
		if _, ok := parseRetryAfter(h, time.Unix(0, 0)); ok {
			t.Fatalf("parseRetryAfter(%q) ok=true, want false", h)
		}
	}
}

// TestComputeBackoff_RespectsRetryAfter asserts that a valid
// Retry-After preempts the exponential ladder entirely.
func TestComputeBackoff_RespectsRetryAfter(t *testing.T) {
	cfg := DefaultConfig()
	resp := &http.Response{Header: http.Header{"Retry-After": []string{"3"}}}
	got := computeBackoff(cfg, resp, 0, time.Unix(0, 0))
	if got != 3*time.Second {
		t.Fatalf("backoff with Retry-After:3 = %v, want 3s", got)
	}
}

// TestComputeBackoff_CappedByMaxBackoff protects against a hostile
// upstream. A Retry-After: 86400 must be capped at MaxBackoff.
func TestComputeBackoff_CappedByMaxBackoff(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBackoff = 2 * time.Second
	resp := &http.Response{Header: http.Header{"Retry-After": []string{"86400"}}}
	got := computeBackoff(cfg, resp, 0, time.Unix(0, 0))
	if got != 2*time.Second {
		t.Fatalf("backoff with Retry-After:86400 and cap=2s = %v, want 2s", got)
	}
}

// TestComputeBackoff_ExponentialFallback covers the no-Retry-After
// path: 1s → 2s → 4s, capped by MaxBackoff.
func TestComputeBackoff_ExponentialFallback(t *testing.T) {
	cfg := Config{
		RetryBaseDelay: time.Second,
		MaxBackoff:     time.Minute,
	}
	for attempt, want := range map[int]time.Duration{
		0: 1 * time.Second,
		1: 2 * time.Second,
		2: 4 * time.Second,
	} {
		got := computeBackoff(cfg, nil, attempt, time.Unix(0, 0))
		if got != want {
			t.Errorf("computeBackoff attempt=%d = %v, want %v", attempt, got, want)
		}
	}
}
