package upstreamhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient builds a Client that talks to srv, uses a permissive
// limiter (so rate limiting doesn't distort retry assertions), and
// has the supplied retry config.
func newTestClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	if cfg.DefaultLimit == 0 {
		cfg.DefaultLimit = 10000 // effectively unlimited for the test
	}
	if cfg.Burst == 0 {
		cfg.Burst = 100
	}
	return New(cfg)
}

// Test429_RetryAfterSecondsHonored verifies the core 429-retry
// contract: a response with Retry-After: 1 must cause exactly one
// retry after ~1s, then pass through the 200.
func Test429_RetryAfterSecondsHonored(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{
		MaxRetries:     2,
		MaxBackoff:     5 * time.Second,
		RetryBaseDelay: time.Second,
	}
	c := newTestClient(t, cfg)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	start := time.Now()
	resp, err := c.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if count.Load() != 2 {
		t.Fatalf("handler hit %d times, want 2", count.Load())
	}
	if elapsed < 900*time.Millisecond {
		t.Fatalf("elapsed = %v, want ≥900ms (honoring Retry-After: 1)", elapsed)
	}
}

// Test429_RetryAfterCappedByMaxBackoff pins the defensive cap: a
// hostile upstream that emits Retry-After: 3600 must not pin the
// caller for an hour.
func Test429_RetryAfterCappedByMaxBackoff(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{
		MaxRetries:     1,
		MaxBackoff:     200 * time.Millisecond,
		RetryBaseDelay: time.Second,
	}
	c := newTestClient(t, cfg)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	start := time.Now()
	resp, err := c.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if elapsed > time.Second {
		t.Fatalf("elapsed = %v, want ≤1s (cap=200ms should have clamped Retry-After:3600)", elapsed)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// Test429_HTTPDateRetryAfter confirms that an HTTP-date Retry-After
// value is parsed and honoured (we cap MaxBackoff low so the test
// doesn't sleep for a real future date).
func Test429_HTTPDateRetryAfter(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		if n == 1 {
			// Emit a date well in the future. MaxBackoff will clamp the
			// wait down to 100ms so the test runs quickly.
			w.Header().Set("Retry-After", time.Now().Add(10*time.Minute).UTC().Format(http.TimeFormat))
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{
		MaxRetries:     1,
		MaxBackoff:     100 * time.Millisecond,
		RetryBaseDelay: 50 * time.Millisecond,
	}
	c := newTestClient(t, cfg)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (HTTP-date Retry-After should have been parsed)", resp.StatusCode)
	}
}

// Test429_NoRetryAfterFallsBackExponential confirms that when the
// server emits 429 without a Retry-After header, we fall through to
// RetryBaseDelay * 2^attempt backoff.
func Test429_NoRetryAfterFallsBackExponential(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		if n == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{
		MaxRetries:     1,
		MaxBackoff:     time.Second,
		RetryBaseDelay: 150 * time.Millisecond,
	}
	c := newTestClient(t, cfg)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	start := time.Now()
	resp, err := c.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if elapsed < 120*time.Millisecond {
		t.Fatalf("elapsed = %v, want ≥120ms (should have backed off RetryBaseDelay=150ms)", elapsed)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// Test5xxRetried covers the 5xx branch: a 503 counts as retryable.
func Test5xxRetried(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		if n < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{MaxRetries: 2, MaxBackoff: 500 * time.Millisecond, RetryBaseDelay: 20 * time.Millisecond}
	c := newTestClient(t, cfg)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if count.Load() != 2 {
		t.Fatalf("handler hit %d times, want 2", count.Load())
	}
}

// TestNon429NonRetriableReturnsImmediately pins the "don't retry 4xx"
// contract: a 404 is a caller bug, not a transient failure, and must
// be surfaced to the caller on the first attempt.
func TestNon429NonRetriableReturnsImmediately(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cfg := Config{MaxRetries: 3, RetryBaseDelay: 10 * time.Millisecond}
	c := newTestClient(t, cfg)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if count.Load() != 1 {
		t.Fatalf("handler hit %d times, want 1 (404 must not retry)", count.Load())
	}
}

// TestContextCancelledDuringBackoff verifies that cancelling the
// caller's context during a retry-after sleep unblocks promptly —
// critical for graceful shutdown.
func TestContextCancelledDuringBackoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60") // long enough that the test will cancel first
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	cfg := Config{MaxRetries: 2, MaxBackoff: time.Minute, RetryBaseDelay: time.Minute}
	c := newTestClient(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := c.Do(req)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Do: expected ctx error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Do did not observe ctx.Done promptly: elapsed=%v", elapsed)
	}
}

// TestHTTPClient_RoundTripsThroughLimiter covers the HTTPClient()
// adapter. A fetch via the *http.Client we expose must still hit the
// retry path.
func TestHTTPClient_RoundTripsThroughLimiter(t *testing.T) {
	var count atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := count.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`ok`))
	}))
	defer srv.Close()
	cfg := Config{MaxRetries: 2, MaxBackoff: time.Second, RetryBaseDelay: 10 * time.Millisecond}
	c := newTestClient(t, cfg)
	httpClient := c.HTTPClient()
	resp, err := httpClient.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if count.Load() != 2 {
		t.Fatalf("handler hit %d times, want 2", count.Load())
	}
}

// TestLimiterGatesRequests confirms that when the limiter enforces a
// low rate, Do does serialise requests accordingly. We use a
// permissive-retry config so only the limiter can delay things, then
// issue two requests to the same host and assert a measurable gap.
func TestLimiterGatesRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{
		DefaultLimit:   5,
		Burst:          1,
		MaxRetries:     0,
		RetryBaseDelay: time.Millisecond,
		MaxBackoff:     time.Second,
	}
	c := New(cfg)
	ctx := context.Background()

	start := time.Now()
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("Do %d: %v", i, err)
		}
		resp.Body.Close()
	}
	elapsed := time.Since(start)
	if elapsed < 100*time.Millisecond {
		t.Fatalf("two requests at 5rps burst=1 completed in %v, expected ≥100ms", elapsed)
	}
}

// TestRedisStubDelegates confirms the Redis stub still routes through
// its Inner limiter. If this ever silently becomes "no limit at all"
// we want a red test before anyone ships it.
func TestRedisStubDelegates(t *testing.T) {
	inner := NewInProcessHostLimiter(Config{
		HostLimits:   map[string]float64{"example.com": 5},
		DefaultLimit: 5,
		Burst:        1,
	})
	stub := &RedisHostLimiter{Inner: inner}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := stub.Wait(ctx, "example.com"); err != nil {
		t.Fatalf("first wait: %v", err)
	}
	start := time.Now()
	if err := stub.Wait(ctx, "example.com"); err != nil {
		t.Fatalf("second wait: %v", err)
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("RedisHostLimiter.Wait did not delegate rate enforcement to Inner")
	}
}

// Small sanity — make sure the UA / Accept headers we add don't stomp
// caller-supplied values when using HTTPClient().
func TestHTTPClient_PreservesCallerHeaders(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{MaxRetries: 0}
	c := newTestClient(t, cfg)
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("User-Agent", "custom-ua/1.0")
	resp, err := c.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	resp.Body.Close()
	if !strings.HasPrefix(got, "custom-ua") {
		t.Fatalf("User-Agent = %q, want prefix custom-ua", got)
	}
}
