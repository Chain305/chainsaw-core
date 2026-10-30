package upstreamhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A burst of best-effort background work (the dependency enqueuer's child
// scans, cache warm-up) must not queue the bucket so deep that a foreground
// scan's 3s provider budget is spent waiting for a token: that is how a
// small packument like json5 came back "the registry fetch was cancelled"
// in prod and was served Unknown for 24h (2026-10-04). Background takes at
// most backgroundShare of a host's rate, so foreground keeps the rest.
func TestInProcessHostLimiter_BackgroundBurstDoesNotStarveForeground(t *testing.T) {
	l := NewInProcessHostLimiter(Config{HostLimits: map[string]float64{"registry.example": 15}, Burst: 5})
	bg, cancelBG := context.WithTimeout(WithBackground(context.Background()), 30*time.Second)
	defer cancelBG()
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ { // ~4s of the whole host budget
		wg.Add(1)
		go func() { defer wg.Done(); _ = l.Wait(bg, "registry.example") }()
	}
	time.Sleep(50 * time.Millisecond) // let the burst reserve

	fg, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	if err := l.Wait(fg, "registry.example"); err != nil {
		t.Fatalf("foreground refused behind a background burst: %v", err)
	}
	if waited := time.Since(start); waited > time.Second {
		t.Fatalf("foreground waited %v behind a background burst; its whole budget is 3s", waited)
	}
	cancelBG()
	wg.Wait()
}

// A token granted with too little of the deadline left to make the request
// is refused up front, as a local rate limit, instead of being spent on a
// request that is cancelled mid-flight and reported as a registry outage.
func TestInProcessHostLimiter_RefusesAWaitThatLeavesNoTimeToFetch(t *testing.T) {
	l := NewInProcessHostLimiter(Config{HostLimits: map[string]float64{"slow.example": 1}, Burst: 1})
	if err := l.Wait(context.Background(), "slow.example"); err != nil {
		t.Fatal(err)
	}
	// Next token is ~1s away; the caller has 1.2s, so it would get the
	// token with ~0.2s left.
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := l.Wait(ctx, "slow.example")
	if !errors.Is(err, ErrRateLimitedLocally) {
		t.Fatalf("err = %v, want ErrRateLimitedLocally", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("the refusal must be immediate, not after the wait")
	}
	// And the refused reservation is given back: a caller with time to
	// spare still gets the next token about 1s out, not 2s.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	start = time.Now()
	if err := l.Wait(ctx2, "slow.example"); err != nil {
		t.Fatal(err)
	}
	if waited := time.Since(start); waited > 1500*time.Millisecond {
		t.Fatalf("a refused reservation was not cancelled: next caller waited %v", waited)
	}
}

// The floor applies to a WAIT. A free token is granted however little of the
// deadline is left: the fetch costs the limiter nothing, and refusing it
// failed a late sequential fetch that the caller still had time to make.
func TestInProcessHostLimiter_FreeTokenIsNotRefusedLate(t *testing.T) {
	l := NewInProcessHostLimiter(Config{HostLimits: map[string]float64{"late.example": 5}, Burst: 1})
	ctx, cancel := context.WithTimeout(context.Background(), minFetchAfterWait/2)
	defer cancel()
	if err := l.Wait(ctx, "late.example"); err != nil {
		t.Fatalf("a free token with %v left was refused: %v", minFetchAfterWait/2, err)
	}
}

// Prepay queues for a caller's fixed requests before its short fetch
// deadline starts; Waits on the returned context then spend those credits
// instead of queueing, and only for the host they were paid on.
func TestInProcessHostLimiter_PrepaidTokensSkipTheQueue(t *testing.T) {
	l := NewInProcessHostLimiter(Config{HostLimits: map[string]float64{"pypi.example": 2, "other.example": 2}, Burst: 1})
	paid, err := l.Prepay(context.Background(), "pypi.example", 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The bucket is now empty for ~0.5s; three prepaid requests under a
	// 300ms deadline still go straight through.
	fetch, cancel := context.WithTimeout(paid, 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := l.Wait(fetch, "PYPI.example"); err != nil {
			t.Fatalf("prepaid request %d queued: %v", i+1, err)
		}
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("prepaid requests waited on the bucket")
	}
	if err := l.Wait(fetch, "pypi.example"); err == nil {
		t.Fatal("a fourth request has no credit and must queue on the empty bucket")
	}
	if takeCredit(paid, "other.example") {
		t.Fatal("credits are per host")
	}
}

// Prepay's maxWait caps the queueing, not the work after it: under a
// saturated bucket a capped prepay gives up within the cap, and the returned
// context keeps the caller's own deadline. Uncapped, it waits for its tokens.
func TestInProcessHostLimiter_PrepayWaitIsCapped(t *testing.T) {
	l := NewInProcessHostLimiter(Config{HostLimits: map[string]float64{"busy.example": 1}, Burst: 1})
	if err := l.Wait(context.Background(), "busy.example"); err != nil { // drain
		t.Fatal(err)
	}
	start := time.Now()
	ctx, err := l.Prepay(context.Background(), "busy.example", 3, 300*time.Millisecond)
	if err == nil {
		t.Fatal("three tokens at 1/s cannot be paid in 300ms")
	}
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Fatalf("capped prepay took %v, cap 300ms", took)
	}
	if _, has := ctx.Deadline(); has {
		t.Fatal("the cap leaked into the returned context's deadline")
	}

	slow := NewInProcessHostLimiter(Config{HostLimits: map[string]float64{"busy.example": 2}, Burst: 1})
	if err := slow.Wait(context.Background(), "busy.example"); err != nil {
		t.Fatal(err)
	}
	long, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	paid, err := slow.Prepay(long, "busy.example", 2, 0)
	if err != nil {
		t.Fatalf("an uncapped prepay waits for its tokens: %v", err)
	}
	if !takeCredit(paid, "busy.example") || !takeCredit(paid, "busy.example") {
		t.Fatal("both tokens should be credited")
	}
}

// A 429 pauses background requests to that host for its Retry-After, so a
// dependency walk stops asking a host that is already pushing back, while
// foreground requests keep their own retry handling (I13-1).
func TestClient_429PausesBackgroundForThatHost(t *testing.T) {
	t.Setenv("CHAINSAW_ALLOW_PRIVATE_UPSTREAMS", "1")
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	l := NewInProcessHostLimiter(Config{})
	c := New(Config{}, WithLimiter(l), WithMaxRetries(0))
	do := func(ctx context.Context) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		resp, err := c.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	bg := WithBackground(context.Background())

	if err := do(context.Background()); err != nil { // the 429
		t.Fatal(err)
	}
	if err := do(bg); !errors.Is(err, ErrBackgroundPaused) {
		t.Fatalf("background after a 429 = %v, want ErrBackgroundPaused", err)
	}
	if err := do(context.Background()); err != nil {
		t.Fatalf("foreground refused after a 429: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream saw %d requests, want 2 (the paused background one never left)", hits.Load())
	}
	host := strings.TrimPrefix(srv.URL, "http://")
	host = host[:strings.LastIndex(host, ":")]
	if err := l.Wait(WithBackground(context.Background()), "other."+host); err != nil {
		t.Fatalf("the pause leaked to another host: %v", err)
	}
	l.mu.Lock()
	until := l.pausedUntil[host]
	l.mu.Unlock()
	if d := time.Until(until); d < 50*time.Second || d > 61*time.Second {
		t.Fatalf("pause is %v, want the 60s Retry-After", d)
	}
}

func TestSharedLimiterIsOneInstance(t *testing.T) {
	if SharedLimiter() != SharedLimiter() {
		t.Fatal("SharedLimiter returned two limiters; host budgets would add up")
	}
}

// An install fetch made outside the limiter is charged to the host's
// background bucket without waiting: background work then waits, while a
// foreground lookup does not (J.4 I13-1).
func TestChargeSlowsBackgroundNotForeground(t *testing.T) {
	l := NewInProcessHostLimiter(Config{HostLimits: map[string]float64{"registry.example": 3}, Burst: 3})
	start := time.Now()
	for i := 0; i < 5; i++ {
		l.Charge("registry.example") // never blocks
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("Charge blocked")
	}
	fg, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start = time.Now()
	if err := l.Wait(fg, "registry.example"); err != nil || time.Since(start) > 100*time.Millisecond {
		t.Fatalf("foreground waited %v (err %v) after install charges", time.Since(start), err)
	}
	bg, cancelBG := context.WithTimeout(WithBackground(context.Background()), 500*time.Millisecond)
	defer cancelBG()
	if err := l.Wait(bg, "registry.example"); err == nil {
		t.Fatal("background was not held back by the install charges")
	}
}
