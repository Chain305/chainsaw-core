package xreplicaflight

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

// TestNoopFlightAlwaysRunsFn exercises the zero-cost default: every
// caller is a leader, peek is never invoked. This is the single-
// replica default, so bit-identical behaviour here is load-bearing.
func TestNoopFlightAlwaysRunsFn(t *testing.T) {
	t.Parallel()
	var nf NoopFlight
	var ranFn, ranPeek bool
	got, err := nf.Do(
		context.Background(),
		"any-key",
		time.Second,
		func(ctx context.Context) (any, error) { ranFn = true; return "leader", nil },
		func(ctx context.Context) (any, error) { ranPeek = true; return "follower", nil },
	)
	if err != nil {
		t.Fatalf("noop Do returned error: %v", err)
	}
	if got != "leader" {
		t.Fatalf("expected leader result, got %v", got)
	}
	if !ranFn {
		t.Fatalf("expected fn to run")
	}
	if ranPeek {
		t.Fatalf("peek must never be invoked on noop path")
	}
}

// TestHashKeyStable locks in the hashKey invariant that equal inputs
// produce equal outputs (so lock namespaces align across processes)
// and different inputs mostly produce different outputs (so unrelated
// keys don't false-contend).
func TestHashKeyStable(t *testing.T) {
	t.Parallel()
	hi1, lo1 := hashKey("npm|lodash|4.17.21")
	hi2, lo2 := hashKey("npm|lodash|4.17.21")
	if hi1 != hi2 || lo1 != lo2 {
		t.Fatalf("hashKey not deterministic: (%d,%d) vs (%d,%d)", hi1, lo1, hi2, lo2)
	}
	hi3, lo3 := hashKey("npm|lodash|4.17.22")
	if hi1 == hi3 && lo1 == lo3 {
		t.Fatalf("hashKey collision on trivially distinct inputs")
	}
}

// openTestDB skip-gates on CHAINSAW_DATABASE_URL, matching the pattern
// used by internal/policy/store_test.go.
func openTestDB(t *testing.T) *pgstore.Store {
	t.Helper()
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping PG flight test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestPGFlight_CoalescesSameKey — two goroutines race for the same
// lock. fn must run exactly once; the follower gets peek's result.
func TestPGFlight_CoalescesSameKey(t *testing.T) {
	db := openTestDB(t)
	f := NewPG(db.DB(), nil)

	key := "xflight-test-" + time.Now().Format("20060102150405.000000000")
	var fnRuns int32
	var cached atomic.Value // stored by the leader, read by the follower

	// Leader's fn sleeps briefly so the follower has time to contend.
	leaderFn := func(ctx context.Context) (any, error) {
		atomic.AddInt32(&fnRuns, 1)
		time.Sleep(200 * time.Millisecond)
		cached.Store("leader-result")
		return "leader-result", nil
	}
	// Follower's peek returns whatever the leader stashed in `cached`.
	// If the follower arrived before cached was set, peek returns nil
	// (mapped to ErrLeaderCrashed by waitAndPeek) — but with the sleep
	// above + advisory-lock ordering, the follower's peek always fires
	// AFTER the leader's Store.
	peek := func(ctx context.Context) (any, error) {
		if v := cached.Load(); v != nil {
			return v, nil
		}
		return nil, nil
	}

	var wg sync.WaitGroup
	results := make([]any, 2)
	errs := make([]error, 2)
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			defer wg.Done()
			// Stagger slightly so caller 0 wins the lock deterministically.
			if i == 1 {
				time.Sleep(50 * time.Millisecond)
			}
			results[i], errs[i] = f.Do(context.Background(), key, 5*time.Second, leaderFn, peek)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d errored: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&fnRuns); got != 1 {
		t.Fatalf("fn ran %d times, expected exactly 1 (cross-replica singleflight broken)", got)
	}
	if results[0] != "leader-result" || results[1] != "leader-result" {
		t.Fatalf("results mismatch: %v / %v", results[0], results[1])
	}
}

// TestPGFlight_DifferentKeysRunConcurrently verifies that the 64-bit
// lock namespace is wide enough that unrelated keys don't serialize.
func TestPGFlight_DifferentKeysRunConcurrently(t *testing.T) {
	db := openTestDB(t)
	f := NewPG(db.DB(), nil)

	// Both fn's sleep 300ms. If the locks are distinct, total wall
	// time < 600ms (they run in parallel). If something has serialized
	// them, total > 600ms. We allow generous slack for CI jitter.
	const sleep = 300 * time.Millisecond
	fn := func(ctx context.Context) (any, error) {
		time.Sleep(sleep)
		return "ok", nil
	}
	peek := func(ctx context.Context) (any, error) { return "peeked", nil }

	t0 := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)
	ts := time.Now().Format("20060102150405.000000000")
	for i, key := range []string{"xflight-keyA-" + ts, "xflight-keyB-" + ts} {
		go func(i int, key string) {
			defer wg.Done()
			if _, err := f.Do(context.Background(), key, 2*time.Second, fn, peek); err != nil {
				t.Errorf("goroutine %d: %v", i, err)
			}
		}(i, key)
	}
	wg.Wait()
	elapsed := time.Since(t0)
	if elapsed > 2*sleep {
		t.Fatalf("distinct keys appear serialized: elapsed=%v (expected ~%v, serialized=%v)", elapsed, sleep, 2*sleep)
	}
}

// TestPGFlight_FollowerTimesOut exercises the statement_timeout path:
// a follower with a tiny timeout gets ErrFlightTimeout.
func TestPGFlight_FollowerTimesOut(t *testing.T) {
	db := openTestDB(t)
	f := NewPG(db.DB(), nil)

	key := "xflight-timeout-" + time.Now().Format("20060102150405.000000000")

	// Leader holds the lock for a long time.
	leaderReady := make(chan struct{})
	leaderDone := make(chan struct{})
	go func() {
		_, _ = f.Do(context.Background(), key, 5*time.Second,
			func(ctx context.Context) (any, error) {
				close(leaderReady)
				time.Sleep(2 * time.Second)
				return "leader-done", nil
			},
			func(ctx context.Context) (any, error) { return "x", nil },
		)
		close(leaderDone)
	}()
	<-leaderReady
	// Small gap so the advisory lock is definitely held before the
	// follower attempts.
	time.Sleep(50 * time.Millisecond)

	_, err := f.Do(context.Background(), key, 100*time.Millisecond,
		func(ctx context.Context) (any, error) { return "fn-ran", nil },
		func(ctx context.Context) (any, error) { return "peeked", nil },
	)
	if !errors.Is(err, ErrFlightTimeout) {
		t.Fatalf("expected ErrFlightTimeout, got %v", err)
	}
	<-leaderDone
}

// TestPGFlight_ContextCancelAbortsWait verifies ctx cancellation
// propagates into the blocking advisory-lock wait.
func TestPGFlight_ContextCancelAbortsWait(t *testing.T) {
	db := openTestDB(t)
	f := NewPG(db.DB(), nil)

	key := "xflight-cancel-" + time.Now().Format("20060102150405.000000000")

	leaderReady := make(chan struct{})
	leaderDone := make(chan struct{})
	go func() {
		_, _ = f.Do(context.Background(), key, 5*time.Second,
			func(ctx context.Context) (any, error) {
				close(leaderReady)
				time.Sleep(2 * time.Second)
				return "leader-done", nil
			},
			func(ctx context.Context) (any, error) { return "x", nil },
		)
		close(leaderDone)
	}()
	<-leaderReady
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := f.Do(ctx, key, 5*time.Second,
		func(ctx context.Context) (any, error) { return "fn-ran", nil },
		func(ctx context.Context) (any, error) { return "peeked", nil },
	)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected error from cancelled ctx, got nil")
	}
	if elapsed > 1*time.Second {
		t.Fatalf("ctx cancel did not abort wait promptly: elapsed=%v", elapsed)
	}
	<-leaderDone
}

// TestPGFlight_LeaderCrashedSignalsToRetry covers the edge case where
// the leader released the lock without persisting anything. Our peek
// returns nil and Do should surface ErrLeaderCrashed so the caller
// knows to retry rather than treat it as a normal empty cache hit.
func TestPGFlight_LeaderCrashedSignalsToRetry(t *testing.T) {
	db := openTestDB(t)
	f := NewPG(db.DB(), nil)

	key := "xflight-crashed-" + time.Now().Format("20060102150405.000000000")

	leaderReady := make(chan struct{})
	leaderDone := make(chan struct{})
	go func() {
		// Leader fn errors out WITHOUT stashing anything in the cache —
		// simulating a mid-scan crash/abort. The commit path still
		// releases the lock so followers unblock.
		_, _ = f.Do(context.Background(), key, 5*time.Second,
			func(ctx context.Context) (any, error) {
				close(leaderReady)
				time.Sleep(200 * time.Millisecond)
				return nil, errors.New("leader failed mid-scan")
			},
			func(ctx context.Context) (any, error) { return "x", nil },
		)
		close(leaderDone)
	}()
	<-leaderReady

	_, err := f.Do(context.Background(), key, 5*time.Second,
		func(ctx context.Context) (any, error) { return "fn-ran", nil },
		func(ctx context.Context) (any, error) { return nil, nil }, // empty cache
	)
	if !errors.Is(err, ErrLeaderCrashed) {
		t.Fatalf("expected ErrLeaderCrashed, got %v", err)
	}
	<-leaderDone
}
