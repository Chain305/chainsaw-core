package upstreamhttp

import (
	"context"
	"errors"
	"sync"
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
