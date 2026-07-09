package policy

import (
	"testing"
	"time"
)

// scopedBlockPolicy is a Mode=Block policy targeted at a single client
// via Scope.TargetClient. It matches any package (empty Identifier
// fields → match-all) so the verdict is driven purely by whether the
// requester's ClientID is in scope.
func scopedBlockPolicy(id, clientID string) Policy {
	return Policy{
		ID:         id,
		Precedence: 100,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		Scope:      Scope{TargetClient: []string{clientID}},
	}
}

// TestScopeFingerprint pins the fingerprint contract: order-independent
// on groups, and distinct requesters produce distinct fingerprints.
func TestScopeFingerprint(t *testing.T) {
	t.Parallel()

	// Group order must not matter.
	a := scopeFingerprint("client-a", []string{"g1", "g2"}, "1.2.3.4", "US")
	b := scopeFingerprint("client-a", []string{"g2", "g1"}, "1.2.3.4", "US")
	if a != b {
		t.Fatalf("group order changed fingerprint: %q vs %q", a, b)
	}

	// Different client → different fingerprint.
	if scopeFingerprint("client-a", nil, "", "") == scopeFingerprint("client-b", nil, "", "") {
		t.Fatalf("distinct client_ids must not share a fingerprint")
	}
	// Different country → different fingerprint.
	if scopeFingerprint("c", nil, "", "US") == scopeFingerprint("c", nil, "", "DE") {
		t.Fatalf("distinct countries must not share a fingerprint")
	}
	// Different IP → different fingerprint.
	if scopeFingerprint("c", nil, "1.1.1.1", "") == scopeFingerprint("c", nil, "2.2.2.2", "") {
		t.Fatalf("distinct IPs must not share a fingerprint")
	}
}

// TestEvalCacheKeyForScopeAware documents the three key shapes:
//   - non-scoped, non-grace org → exact four-field key (Scope empty),
//     byte-identical to the pre-B1 behaviour;
//   - scoped org → key carries a scope fingerprint;
//   - grace org → not cacheable.
func TestEvalCacheKeyForScopeAware(t *testing.T) {
	t.Parallel()

	ctx := EvaluationContext{
		OrgID:          "org-1",
		Repository:     "npmjs",
		PackageName:    "lodash",
		PackageVersion: "4.17.21",
		ClientID:       "client-a",
	}

	// Non-scoped, non-grace: exact four-field key, empty Scope.
	k, ok := evalCacheKeyFor(ctx, policyMeta{})
	if !ok {
		t.Fatalf("expected keyable")
	}
	if k.Scope != "" {
		t.Fatalf("non-scoped key must have empty Scope, got %q", k.Scope)
	}
	if (k != cacheKey{OrgID: "org-1", Repo: "npmjs", PackageName: "lodash", Version: "4.17.21"}) {
		t.Fatalf("non-scoped key regressed: %+v", k)
	}

	// Scoped org: fingerprint present.
	ks, ok := evalCacheKeyFor(ctx, policyMeta{hasScopedPolicies: true})
	if !ok {
		t.Fatalf("expected keyable (scoped)")
	}
	if ks.Scope == "" {
		t.Fatalf("scoped org key must carry a scope fingerprint")
	}

	// Grace org: not cacheable regardless of scope.
	if _, ok := evalCacheKeyFor(ctx, policyMeta{hasGracePolicies: true}); ok {
		t.Fatalf("grace org must bypass the cache (not keyable)")
	}
	if _, ok := evalCacheKeyFor(ctx, policyMeta{hasScopedPolicies: true, hasGracePolicies: true}); ok {
		t.Fatalf("grace org must bypass the cache even when scoped")
	}
}

// TestEvaluateScopedNoCrossClientLeak is the B1 regression: with a
// scope-targeted block for client A only, repeated Evaluate calls for
// the SAME (org,repo,pkg,version) must return BLOCK for client A and
// ALLOW for client B. A scope-blind cache would freeze whichever
// verdict was computed first and serve it to the other client.
func TestEvaluateScopedNoCrossClientLeak(t *testing.T) {
	t.Parallel()

	policies := []Policy{scopedBlockPolicy("scoped-block-a", "client-a")}
	e := (&Evaluator{}).WithEvalCache(time.Hour)
	e.listOverride = func() ([]Policy, error) { return policies, nil }

	base := EvaluationContext{
		OrgID:          "org-1",
		Repository:     "npmjs",
		PackageName:    "lodash",
		PackageVersion: "4.17.21",
	}
	ctxA := base
	ctxA.ClientID = "client-a"
	ctxB := base
	ctxB.ClientID = "client-b"

	// Prime the cache with A first (BLOCK), then B (must still ALLOW),
	// then repeat both to prove the cached rows are per-scope.
	order := []struct {
		name string
		ctx  EvaluationContext
		want Mode
	}{
		{"A first (block, primes cache)", ctxA, ModeBlock},
		{"B (must not inherit A's block)", ctxB, ModeAllow},
		{"A repeat (cache hit, still block)", ctxA, ModeBlock},
		{"B repeat (cache hit, still allow)", ctxB, ModeAllow},
	}
	for _, tc := range order {
		res, err := e.Evaluate(tc.ctx, 0)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if res.Action != tc.want {
			t.Fatalf("%s: action = %s, want %s", tc.name, res.Action, tc.want)
		}
	}

	// Prove B came from a distinct cache entry (or none), never from
	// A's: the two scope fingerprints must differ, so both rows coexist.
	meta := policyMeta{hasScopedPolicies: true}
	kA, _ := evalCacheKeyFor(ctxA, meta)
	kB, _ := evalCacheKeyFor(ctxB, meta)
	if kA == kB {
		t.Fatalf("A and B must not share a cache key: %+v", kA)
	}
	if _, ok := e.cache.Get(kA); !ok {
		t.Fatalf("client A verdict should be cached")
	}
	if _, ok := e.cache.Get(kB); !ok {
		t.Fatalf("client B verdict should be cached under a distinct key")
	}
}

// TestEvaluateScopedByCountry mirrors the leak test but varies only the
// RequestingCountry, confirming the fingerprint covers geo scope too.
func TestEvaluateScopedByCountry(t *testing.T) {
	t.Parallel()

	// Block only requesters from DE.
	pol := Policy{
		ID:         "geo-block-de",
		Precedence: 100,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		Scope:      Scope{TargetRequestingCountry: []string{"DE"}},
	}
	e := (&Evaluator{}).WithEvalCache(time.Hour)
	e.listOverride = func() ([]Policy, error) { return []Policy{pol}, nil }

	base := EvaluationContext{
		OrgID:          "org-1",
		Repository:     "npmjs",
		PackageName:    "lodash",
		PackageVersion: "4.17.21",
		ClientID:       "client-a",
	}
	de := base
	de.RequestingCountry = "DE"
	us := base
	us.RequestingCountry = "US"

	for _, tc := range []struct {
		name string
		ctx  EvaluationContext
		want Mode
	}{
		{"DE blocks (primes)", de, ModeBlock},
		{"US allows (no leak)", us, ModeAllow},
		{"DE repeat (cache hit)", de, ModeBlock},
		{"US repeat (cache hit)", us, ModeAllow},
	} {
		res, err := e.Evaluate(tc.ctx, 0)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if res.Action != tc.want {
			t.Fatalf("%s: action = %s, want %s", tc.name, res.Action, tc.want)
		}
	}
}

// TestEvaluateNonScopedKeyUnchanged asserts the no-regression contract:
// an org with only global, non-grace policies stores exactly one cache
// entry under the four-field key with an EMPTY Scope, regardless of how
// many distinct clients hit the same coordinate.
func TestEvaluateNonScopedKeyUnchanged(t *testing.T) {
	t.Parallel()

	// A global (empty-scope) block for the package.
	pol := Policy{
		ID:         "global-block",
		Precedence: 100,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
	}
	e := (&Evaluator{}).WithEvalCache(time.Hour)
	e.listOverride = func() ([]Policy, error) { return []Policy{pol}, nil }

	base := EvaluationContext{
		OrgID:          "org-1",
		Repository:     "npmjs",
		PackageName:    "lodash",
		PackageVersion: "4.17.21",
	}
	for _, client := range []string{"client-a", "client-b", "client-c"} {
		c := base
		c.ClientID = client
		res, err := e.Evaluate(c, 0)
		if err != nil {
			t.Fatalf("client %s: unexpected error: %v", client, err)
		}
		if res.Action != ModeBlock {
			t.Fatalf("client %s: want block, got %s", client, res.Action)
		}
	}

	// Three distinct clients, one shared four-field cache entry.
	if got := e.cache.size(); got != 1 {
		t.Fatalf("non-scoped org must share one cache entry across clients, got %d", got)
	}
	k, _ := evalCacheKeyFor(base, policyMeta{})
	if k.Scope != "" {
		t.Fatalf("non-scoped key must have empty Scope")
	}
	if _, ok := e.cache.Get(k); !ok {
		t.Fatalf("expected the shared four-field entry to be present")
	}
}

// TestEvaluateGraceBoundaryNotFrozen is the second B1 deliverable: a
// grace-mode org bypasses the cache, so two calls straddling the window
// boundary return the correct (non-frozen) verdicts. With a scope-blind
// cache the first (in-window, downgraded) verdict would be frozen and
// served after the window elapsed.
func TestEvaluateGraceBoundaryNotFrozen(t *testing.T) {
	t.Parallel()

	// Window: policy created 5 days ago, 7-day grace → boundary is 2
	// days from now. A pre-existing, non-malicious package is downgraded
	// to monitor while in-window and blocked once elapsed.
	createdAt := time.Now().Add(-5 * 24 * time.Hour)
	grace := 7
	pol := blockAfterGracePolicy("grace-1", createdAt, &grace)

	e := (&Evaluator{}).
		WithEvalCache(time.Hour).
		WithGraceMode(staticFlag(true), &recordingPreexisting{seen: true})
	e.listOverride = func() ([]Policy, error) { return []Policy{pol}, nil }

	ctx := graceCtx()

	// In-window: pre-existing + not malware/vuln → downgrade to monitor.
	res, err := e.Evaluate(ctx, 0)
	if err != nil {
		t.Fatalf("in-window: unexpected error: %v", err)
	}
	if res.Action != ModeMonitor {
		t.Fatalf("in-window grace should downgrade to monitor, got %s", res.Action)
	}

	// A grace org must never cache: the entry that would freeze the
	// boundary verdict must not exist.
	if e.cache.size() != 0 {
		t.Fatalf("grace org must bypass the cache, found %d entries", e.cache.size())
	}

	// Now move the policy's creation back so the window has elapsed and
	// re-evaluate. Because grace bypasses the cache, the second call is
	// recomputed live and must BLOCK — not serve the frozen monitor.
	elapsed := blockAfterGracePolicy("grace-1", time.Now().Add(-30*24*time.Hour), &grace)
	e.listOverride = func() ([]Policy, error) { return []Policy{elapsed}, nil }
	// meta is unaffected (still a grace policy); no invalidation needed
	// to prove the cache-bypass, but reset to mirror a real edit.
	e.InvalidateCache()

	res2, err := e.Evaluate(ctx, 0)
	if err != nil {
		t.Fatalf("post-window: unexpected error: %v", err)
	}
	if res2.Action != ModeBlock {
		t.Fatalf("post-window grace should enforce block (non-frozen), got %s", res2.Action)
	}
}
