package policy

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestEvalCacheHitMissExpiry(t *testing.T) {
	t.Parallel()

	c := newEvalCache(50 * time.Millisecond)
	key := cacheKey{OrgID: "o1", Repo: "npm", PackageName: "lodash", Version: "4.17.21"}

	if _, ok := c.Get(key); ok {
		t.Fatalf("expected miss on empty cache")
	}

	want := EvaluationResult{Action: ModeBlock, Reason: "blocked by policy: p1"}
	c.Put(key, want)

	got, ok := c.Get(key)
	if !ok {
		t.Fatalf("expected hit immediately after Put")
	}
	if got.Action != want.Action || got.Reason != want.Reason {
		t.Fatalf("cache returned %+v, want %+v", got, want)
	}

	time.Sleep(75 * time.Millisecond)
	if _, ok := c.Get(key); ok {
		t.Fatalf("expected miss after TTL expiry")
	}
}

func TestEvalCacheDefaultTTL(t *testing.T) {
	t.Parallel()

	c := newEvalCache(0)
	if c.ttl != DefaultEvalCacheTTL {
		t.Fatalf("ttl = %s, want %s", c.ttl, DefaultEvalCacheTTL)
	}
}

func TestEvalCacheInvalidate(t *testing.T) {
	t.Parallel()

	c := newEvalCache(time.Hour)
	k1 := cacheKey{OrgID: "o1", PackageName: "a", Version: "1"}
	k2 := cacheKey{OrgID: "o2", PackageName: "b", Version: "2"}
	c.Put(k1, EvaluationResult{Action: ModeAllow})
	c.Put(k2, EvaluationResult{Action: ModeBlock})

	if c.size() != 2 {
		t.Fatalf("size = %d, want 2", c.size())
	}

	c.Invalidate()
	if c.size() != 0 {
		t.Fatalf("size after Invalidate = %d, want 0", c.size())
	}
	if _, ok := c.Get(k1); ok {
		t.Fatalf("expected miss after Invalidate")
	}
}

func TestEvalCacheInvalidateOrg(t *testing.T) {
	t.Parallel()

	c := newEvalCache(time.Hour)
	k1 := cacheKey{OrgID: "o1", PackageName: "a", Version: "1"}
	k2 := cacheKey{OrgID: "o1", PackageName: "b", Version: "2"}
	k3 := cacheKey{OrgID: "o2", PackageName: "c", Version: "3"}
	c.Put(k1, EvaluationResult{Action: ModeAllow})
	c.Put(k2, EvaluationResult{Action: ModeAllow})
	c.Put(k3, EvaluationResult{Action: ModeBlock})

	c.InvalidateOrg("o1")

	if _, ok := c.Get(k1); ok {
		t.Fatalf("expected o1 miss after InvalidateOrg")
	}
	if _, ok := c.Get(k2); ok {
		t.Fatalf("expected o1 miss after InvalidateOrg")
	}
	if _, ok := c.Get(k3); !ok {
		t.Fatalf("expected o2 to survive InvalidateOrg")
	}
}

func TestEvalCacheInvalidateOrgEmptyWipesAll(t *testing.T) {
	t.Parallel()

	c := newEvalCache(time.Hour)
	c.Put(cacheKey{OrgID: "o1", PackageName: "a", Version: "1"}, EvaluationResult{})
	c.Put(cacheKey{OrgID: "o2", PackageName: "b", Version: "2"}, EvaluationResult{})

	c.InvalidateOrg("   ")
	if c.size() != 0 {
		t.Fatalf("size = %d, want 0", c.size())
	}
}

func TestEvalCacheNilReceiverSafe(t *testing.T) {
	t.Parallel()

	var c *evalCache
	if _, ok := c.Get(cacheKey{}); ok {
		t.Fatalf("nil cache should miss")
	}
	c.Put(cacheKey{}, EvaluationResult{})
	c.Invalidate()
	c.InvalidateOrg("o1")
	if c.size() != 0 {
		t.Fatalf("nil cache size should be 0")
	}
}

func TestEvalCacheConcurrentAccess(t *testing.T) {
	t.Parallel()

	c := newEvalCache(time.Hour)
	const workers = 16
	const ops = 500

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				k := cacheKey{
					OrgID:       fmt.Sprintf("o%d", id%4),
					PackageName: fmt.Sprintf("pkg-%d", i%8),
					Version:     fmt.Sprintf("v%d", i%4),
				}
				if i%5 == 0 {
					c.Invalidate()
					continue
				}
				if i%7 == 0 {
					c.InvalidateOrg(k.OrgID)
					continue
				}
				c.Put(k, EvaluationResult{Action: ModeAllow})
				_, _ = c.Get(k)
			}
		}(w)
	}
	wg.Wait()
}
