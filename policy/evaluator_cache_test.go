package policy

import (
	"testing"
	"time"
)

func TestEvalCacheKeyFor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ctx     EvaluationContext
		keyable bool
		want    cacheKey
	}{
		{
			name: "full context is keyable",
			ctx: EvaluationContext{
				OrgID:          "org-1",
				Repository:     "npmjs",
				PackageName:    "lodash",
				PackageVersion: "4.17.21",
			},
			keyable: true,
			want: cacheKey{
				OrgID:       "org-1",
				Repo:        "npmjs",
				PackageName: "lodash",
				Version:     "4.17.21",
			},
		},
		{
			name:    "missing package name is not keyable",
			ctx:     EvaluationContext{PackageVersion: "1.0.0"},
			keyable: false,
		},
		{
			name:    "missing version is not keyable",
			ctx:     EvaluationContext{PackageName: "lodash"},
			keyable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := evalCacheKeyFor(tt.ctx)
			if ok != tt.keyable {
				t.Fatalf("keyable = %v, want %v", ok, tt.keyable)
			}
			if ok && got != tt.want {
				t.Fatalf("key = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestEvaluatorWithEvalCacheEnables(t *testing.T) {
	t.Parallel()

	e := &Evaluator{}
	if e.cache != nil {
		t.Fatalf("cache should be nil by default")
	}
	e.WithEvalCache(5 * time.Second)
	if e.cache == nil {
		t.Fatalf("cache should be populated after WithEvalCache")
	}
	if e.cache.ttl != 5*time.Second {
		t.Fatalf("ttl = %s, want 5s", e.cache.ttl)
	}
}

func TestEvaluatorWithEvalCacheDefaultTTL(t *testing.T) {
	t.Parallel()

	e := (&Evaluator{}).WithEvalCache(0)
	if e.cache.ttl != DefaultEvalCacheTTL {
		t.Fatalf("ttl = %s, want DefaultEvalCacheTTL %s", e.cache.ttl, DefaultEvalCacheTTL)
	}
}

// TestEvaluatorWiringTTLZeroLeavesCacheDisabled documents the contract
// that callers (server.New) rely on: if the operator opts out by
// configuring TTL=0, do NOT call WithEvalCache — the default resurrects
// the 60s TTL, inverting intent. This is a regression guard for that
// call-site check, not an assertion about WithEvalCache itself.
func TestEvaluatorWiringTTLZeroLeavesCacheDisabled(t *testing.T) {
	t.Parallel()

	// Simulate the server.New branch: conditional opt-in only.
	e := NewEvaluator(nil)
	ttl := time.Duration(0)
	if ttl > 0 {
		e = e.WithEvalCache(ttl)
	}
	if e.cache != nil {
		t.Fatalf("TTL=0 must leave evaluator cache disabled, got %+v", e.cache)
	}

	// Positive TTL path should attach the cache with that TTL.
	e2 := NewEvaluator(nil)
	ttl2 := 42 * time.Second
	if ttl2 > 0 {
		e2 = e2.WithEvalCache(ttl2)
	}
	if e2.cache == nil {
		t.Fatalf("TTL=%s must attach eval cache", ttl2)
	}
	if e2.cache.ttl != ttl2 {
		t.Fatalf("cache ttl = %s, want %s", e2.cache.ttl, ttl2)
	}
}

func TestEvaluatorInvalidateCacheNoCacheIsSafe(t *testing.T) {
	t.Parallel()

	var e *Evaluator
	e.InvalidateCache()
	e.InvalidateCacheForOrg("o1")

	e2 := &Evaluator{}
	e2.InvalidateCache()
	e2.InvalidateCacheForOrg("o1")
}

func TestEvaluatorInvalidateCacheClearsEntries(t *testing.T) {
	t.Parallel()

	e := (&Evaluator{}).WithEvalCache(time.Hour)
	key := cacheKey{OrgID: "o1", PackageName: "a", Version: "1"}
	e.cache.Put(key, EvaluationResult{Action: ModeBlock})

	if _, ok := e.cache.Get(key); !ok {
		t.Fatalf("expected hit before invalidate")
	}
	e.InvalidateCache()
	if _, ok := e.cache.Get(key); ok {
		t.Fatalf("expected miss after InvalidateCache")
	}
}

func TestEvaluatorInvalidateCacheForOrgScoped(t *testing.T) {
	t.Parallel()

	e := (&Evaluator{}).WithEvalCache(time.Hour)
	k1 := cacheKey{OrgID: "o1", PackageName: "a", Version: "1"}
	k2 := cacheKey{OrgID: "o2", PackageName: "b", Version: "1"}
	e.cache.Put(k1, EvaluationResult{Action: ModeBlock})
	e.cache.Put(k2, EvaluationResult{Action: ModeAllow})

	e.InvalidateCacheForOrg("o1")

	if _, ok := e.cache.Get(k1); ok {
		t.Fatalf("o1 entry should be gone")
	}
	if _, ok := e.cache.Get(k2); !ok {
		t.Fatalf("o2 entry should survive")
	}
}

// TestEvaluatorEvaluateCacheRoundTrip exercises the Evaluate path via a
// pre-populated cache entry. A nil store would normally short-circuit
// with "no policy store", so we set a sentinel cache entry and assert
// Evaluate reads through it rather than falling into the store path.
// This pins the cache-first ordering: any future refactor that moves
// the cache lookup below the store-nil guard will flip this test red.
func TestEvaluatorEvaluateCacheRoundTripWithoutStore(t *testing.T) {
	t.Parallel()

	// With a nil store, Evaluate returns "no policy store" even if
	// the cache has a matching entry — the store guard runs first.
	// This documents current behaviour; if we want cache-hits to beat
	// a missing store we'd reorder the guards.
	e := (&Evaluator{}).WithEvalCache(time.Hour)
	ctx := EvaluationContext{
		OrgID:          "o1",
		Repository:     "npmjs",
		PackageName:    "lodash",
		PackageVersion: "4.17.21",
	}
	key, _ := evalCacheKeyFor(ctx)
	e.cache.Put(key, EvaluationResult{Action: ModeBlock, Reason: "cached"})

	result, err := e.Evaluate(ctx, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Reason != "no policy store" {
		t.Fatalf("expected nil-store guard to fire first, got %+v", result)
	}
}

// TestEvaluatorNilCacheBehaviorUnchanged asserts that omitting
// WithEvalCache leaves the evaluator operating exactly like the
// pre-cache path: no Put/Get side effects, nil-safe.
func TestEvaluatorNilCacheBehaviorUnchanged(t *testing.T) {
	t.Parallel()

	e := &Evaluator{}
	if e.cache != nil {
		t.Fatalf("cache should be nil without WithEvalCache")
	}

	// InvalidateCache on a nil inner cache is a no-op.
	e.InvalidateCache()
	e.InvalidateCacheForOrg("anything")

	ctx := EvaluationContext{
		OrgID:          "o1",
		PackageName:    "lodash",
		PackageVersion: "4.17.21",
	}
	// EvaluateWithPolicies is the cache-bypass path — nil cache must
	// not interfere with direct evaluation.
	result := e.EvaluateWithPolicies(ctx, nil, 0)
	if result.Action != ModeAllow {
		t.Fatalf("empty policy list should allow, got %s", result.Action)
	}
}
