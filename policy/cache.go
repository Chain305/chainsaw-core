package policy

import (
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
// hit-rate gain in the pull-through proxy hot path; when those become
// load-bearing for eviction the key can grow.
type cacheKey struct {
	OrgID       string
	Repo        string
	PackageName string
	Version     string
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
