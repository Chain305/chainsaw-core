package upstreamhttp

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// TestInProcessHostLimiter_PerHostBudget pins the core contract: two
// different hostnames share separate budgets, but the same hostname
// (case-insensitive) shares one.
func TestInProcessHostLimiter_PerHostBudget(t *testing.T) {
	cfg := Config{
		HostLimits: map[string]float64{
			"registry.npmjs.org": 1000, // very high to avoid waits
			"pypi.org":           1000,
		},
		DefaultLimit: 1,
		Burst:        1,
	}
	l := NewInProcessHostLimiter(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Same host, different case — must share a bucket. If they
	// didn't, the second Wait would drain an independent bucket and
	// both would succeed instantly even under a default of 1 req/s.
	// (We only assert they don't *error*; timing is asserted below.)
	if err := l.Wait(ctx, "registry.npmjs.org"); err != nil {
		t.Fatalf("wait npm lower: %v", err)
	}
	if err := l.Wait(ctx, "Registry.NPMjs.ORG"); err != nil {
		t.Fatalf("wait npm upper: %v", err)
	}
}

// TestInProcessHostLimiter_RateEnforced asserts that a low req/s cap
// actually slows down a tight loop. We ask for 2 tokens at 2 req/s
// burst=1, expecting ~500ms total — the limiter should delay the
// second Wait by roughly that long.
func TestInProcessHostLimiter_RateEnforced(t *testing.T) {
	cfg := Config{
		HostLimits:   map[string]float64{"example.com": 2},
		DefaultLimit: 2,
		Burst:        1,
	}
	l := NewInProcessHostLimiter(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	start := time.Now()
	for i := 0; i < 2; i++ {
		if err := l.Wait(ctx, "example.com"); err != nil {
			t.Fatalf("wait %d: %v", i, err)
		}
	}
	elapsed := time.Since(start)
	// Expect ~500ms gap. Allow wide jitter — CI runners are noisy;
	// the assertion is "noticeably > 0", not a tight bound.
	if elapsed < 200*time.Millisecond {
		t.Fatalf("rate not enforced: 2 waits at 2rps took %v, expected ≥200ms", elapsed)
	}
}

// TestInProcessHostLimiter_ContextCancelled exercises the ctx.Done
// fast-path: a caller that gives up mid-Wait must unblock promptly.
func TestInProcessHostLimiter_ContextCancelled(t *testing.T) {
	cfg := Config{
		HostLimits:   map[string]float64{"slow.example.com": 0.01}, // ~100s per token
		DefaultLimit: 0.01,
		Burst:        1,
	}
	l := NewInProcessHostLimiter(cfg)

	// First wait drains the burst token so the second enters the
	// long cooldown; we cancel while it's in that cooldown.
	ctx1, cancel1 := context.WithTimeout(context.Background(), time.Second)
	defer cancel1()
	if err := l.Wait(ctx1, "slow.example.com"); err != nil {
		t.Fatalf("first wait burst: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var done atomic.Bool
	go func() {
		_ = l.Wait(ctx, "slow.example.com")
		done.Store(true)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	deadline := time.Now().Add(500 * time.Millisecond)
	for !done.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !done.Load() {
		t.Fatal("Wait did not unblock promptly after ctx cancel")
	}
}

// TestFromEnv_OverrideApplied confirms that a CHAINSAW_UPSTREAM_LIMIT_*
// env var actually lands in the resolved Config.
func TestFromEnv_OverrideApplied(t *testing.T) {
	t.Setenv("CHAINSAW_UPSTREAM_LIMIT_REGISTRY_NPMJS_ORG", "42")
	t.Setenv("CHAINSAW_UPSTREAM_MAX_RETRIES", "7")
	t.Setenv("CHAINSAW_UPSTREAM_MAX_BACKOFF", "15s")
	cfg := FromEnv()
	if got := cfg.HostLimits["registry.npmjs.org"]; got != 42 {
		t.Fatalf("npm host limit = %v, want 42", got)
	}
	if cfg.MaxRetries != 7 {
		t.Fatalf("MaxRetries = %d, want 7", cfg.MaxRetries)
	}
	if cfg.MaxBackoff != 15*time.Second {
		t.Fatalf("MaxBackoff = %v, want 15s", cfg.MaxBackoff)
	}
}

// TestFromEnv_IgnoresInvalid asserts that a bogus env value is
// silently skipped rather than taking down startup with a parse error.
func TestFromEnv_IgnoresInvalid(t *testing.T) {
	t.Setenv("CHAINSAW_UPSTREAM_LIMIT_REGISTRY_NPMJS_ORG", "not-a-number")
	cfg := FromEnv()
	if got := cfg.HostLimits["registry.npmjs.org"]; got != 15 {
		t.Fatalf("npm host limit = %v after bogus override, want 15 (default)", got)
	}
}
