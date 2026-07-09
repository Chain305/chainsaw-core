package policy

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultEvalCacheTTL is the default expiry for evalCache entries when
// callers do not supply a TTL via NewEvaluatorWithCache / the evaluator
// config. 60s balances freshness against the common read-heavy workload:
// a package pulled thousands of times within a minute gets one
// evaluation instead of thousands, and a policy edit is picked up
// within a minute even without the invalidation bus wiring.
const DefaultEvalCacheTTL = 60 * time.Second

// cacheKey identifies a memoised evaluation. The four-field shape
// mirrors the subset of EvaluationContext that drives policy matching
// — org, repo (ecosystem/source), package name, and version. Other
// fields (client IP, country, groups) would bloat the key with little
// hit-rate gain in the pull-through proxy hot path.
//
// Scope is the B1 escape hatch: it stays EMPTY for the common case
// (orgs with only global, non-grace policies) so the key is
// byte-identical to the historical four-field shape and hit-rate is
// unchanged. It is populated with scopeFingerprint(ctx) ONLY when the
// org has at least one scope-targeted policy — see evalCacheKeyFor.
// Without this, a verdict computed for one requester (client_id / group
// / IP / country) would be served to another, since matchesScope gates
// on those fields but the flat key ignored them (B1 leak).
type cacheKey struct {
	OrgID       string
	Repo        string
	PackageName string
	Version     string
	Scope       string
}

// policyMeta caches per-policy-set booleans that decide HOW a cache key
// is built, so the hot path avoids re-scanning the whole policy list on
// every request. Recomputed from the policy list and reset on the same
// Invalidate bus that clears the eval cache (see Evaluator.metaFor and
// InvalidateCache), so a policy edit that adds/removes a scoped or
// grace policy is picked up together with the cache flush.
//
//   - hasScopedPolicies: any enabled policy carries a non-empty Scope
//     (client / group / repo / IP / country target). When true, the
//     cache key is extended with a scope fingerprint so requesters with
//     different scope identity don't share a cached verdict.
//   - hasGracePolicies: any enabled policy is ModeBlockAfterGrace. Grace
//     resolution depends on `now` vs the window and per-request
//     SeenBefore, both un-cacheable — when true the key builder reports
//     not-cacheable so grace verdicts are always computed live.
type policyMeta struct {
	hasScopedPolicies bool
	hasGracePolicies  bool
}

// scopeFingerprint returns a stable string identifying the scope-facing
// identity of a request: ClientID, its sorted ClientGroups, the
// RequestingIP, and the RequestingCountry — exactly the fields
// matchesScope keys on. Sorting ClientGroups makes the fingerprint
// order-independent so two requests with the same group set (in any
// order) share a cache entry. Sep bytes that cannot appear inside the
// component values keep the concatenation unambiguous.
func scopeFingerprint(clientID string, groups []string, ip, country string) string {
	sorted := append([]string(nil), groups...)
	sort.Strings(sorted)
	var b strings.Builder
	b.WriteString(clientID)
	b.WriteByte('|')
	b.WriteString(strings.Join(sorted, ","))
	b.WriteByte('|')
	b.WriteString(ip)
	b.WriteByte('|')
	b.WriteString(country)
	return b.String()
}

type cacheEntry struct {
	result    EvaluationResult
	expiresAt time.Time
}

// evalCache is a map+RWMutex TTL cache. sync.Map was considered but
// rejected: we need a bulk Invalidate that swaps the underlying map
// atomically, and sync.Map has no primitive for "drop everything"
// without iterating. RWMutex over a plain map is the simpler choice
// for a read-heavy load where writes are invalidations and puts, not
// per-key contention.
type evalCache struct {
	mu      sync.RWMutex
	entries map[cacheKey]cacheEntry
	ttl     time.Duration
}

func newEvalCache(ttl time.Duration) *evalCache {
	if ttl <= 0 {
		ttl = DefaultEvalCacheTTL
	}
	return &evalCache{
		entries: make(map[cacheKey]cacheEntry),
		ttl:     ttl,
	}
}

func (c *evalCache) Get(k cacheKey) (EvaluationResult, bool) {
	if c == nil {
		return EvaluationResult{}, false
	}
	c.mu.RLock()
	entry, ok := c.entries[k]
	c.mu.RUnlock()
	if !ok {
		return EvaluationResult{}, false
	}
	if time.Now().After(entry.expiresAt) {
		return EvaluationResult{}, false
	}
	return entry.result, true
}

func (c *evalCache) Put(k cacheKey, r EvaluationResult) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries[k] = cacheEntry{
		result:    r,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// Invalidate drops every entry. Called on any policy change so the
// cache cannot serve decisions made against stale policy snapshots.
// A fresh map is allocated rather than iterating-and-deleting so the
// old map can be reclaimed in one GC cycle.
func (c *evalCache) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.entries = make(map[cacheKey]cacheEntry)
	c.mu.Unlock()
}

// InvalidateOrg drops every entry belonging to orgID. Used when the
// invalidation bus delivers a per-org message (invalidation.go publishes
// on chainsaw.policy.invalidate.<orgID>) so one tenant's edit does not
// wipe another tenant's hot set.
func (c *evalCache) InvalidateOrg(orgID string) {
	if c == nil {
		return
	}
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		c.Invalidate()
		return
	}
	c.mu.Lock()
	for k := range c.entries {
		if k.OrgID == orgID {
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()
}

// computePolicyMeta scans a policy list once and derives the two
// booleans that steer cache-key construction (see policyMeta). Only
// enabled policies count — a disabled scoped/grace policy never
// evaluates, so it must not perturb the cache-key shape for everyone
// else. Cheap: O(policies), run on cache-cold or right after the store
// List that a cache miss already performs.
func computePolicyMeta(policies []Policy) policyMeta {
	var m policyMeta
	for i := range policies {
		p := policies[i]
		if p.Status != StatusEnabled {
			continue
		}
		if !p.Scope.isEmpty() {
			m.hasScopedPolicies = true
		}
		if p.Mode == ModeBlockAfterGrace {
			m.hasGracePolicies = true
		}
		if m.hasScopedPolicies && m.hasGracePolicies {
			break // both set — nothing more to learn
		}
	}
	return m
}

// size returns the current entry count. Test-only helper — not part
// of the public surface.
func (c *evalCache) size() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
