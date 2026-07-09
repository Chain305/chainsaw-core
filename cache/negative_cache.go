package cache

import (
	"context"
	"strings"
	"sync"
	"time"
)

const defaultMaxSize = 50_000

// NegativeCache replicates the "negative cache" behaviour from Nexus' NegativeCacheHandler.
type NegativeCache struct {
	ttl     time.Duration
	maxSize int
	entries map[string]time.Time
	mu      sync.RWMutex

	evictOnce sync.Once
	cancel    context.CancelFunc
}

// NewNegativeCache constructs a cache with the provided ttl.
// An optional maxSize caps the number of entries (default 10 000).
func NewNegativeCache(ttl time.Duration, maxSize ...int) *NegativeCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	ms := defaultMaxSize
	if len(maxSize) > 0 && maxSize[0] > 0 {
		ms = maxSize[0]
	}
	return &NegativeCache{
		ttl:     ttl,
		maxSize: ms,
		entries: make(map[string]time.Time),
	}
}

// Remember records a logical path that returned 404.
func (c *NegativeCache) Remember(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.purgeExpiredLocked()
	}
	if len(c.entries) >= c.maxSize {
		c.evictOldestLocked()
	}

	c.entries[path] = time.Now().UTC().Add(c.ttl)
}

// Hit returns true when the logical path is still cached as missing.
func (c *NegativeCache) Hit(path string) bool {
	c.mu.RLock()
	expiry, ok := c.entries[path]
	c.mu.RUnlock()
	if !ok {
		return false
	}
	if time.Now().UTC().After(expiry) {
		c.mu.Lock()
		delete(c.entries, path)
		c.mu.Unlock()
		return false
	}
	return true
}

// Forget removes a cached negative entry so it can be re-fetched immediately.
func (c *NegativeCache) Forget(path string) {
	if c == nil || path == "" {
		return
	}
	c.mu.Lock()
	delete(c.entries, path)
	c.mu.Unlock()
}

// ForgetMatching removes cached entries that satisfy the matcher.
func (c *NegativeCache) ForgetMatching(match func(path string) bool) int {
	if c == nil || match == nil {
		return 0
	}
	removed := 0
	c.mu.Lock()
	for path := range c.entries {
		if match(path) {
			delete(c.entries, path)
			removed++
		}
	}
	c.mu.Unlock()
	return removed
}

// Len returns the current number of cached entries.
func (c *NegativeCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// StartEviction launches a background goroutine that periodically purges expired
// entries. It is safe to call multiple times; only the first call starts the loop.
// The goroutine stops when ctx is cancelled.
func (c *NegativeCache) StartEviction(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	c.evictOnce.Do(func() {
		ctx, c.cancel = context.WithCancel(ctx)
		go c.evictionLoop(ctx, interval)
	})
}

// Close stops the background eviction goroutine, if one was started.
func (c *NegativeCache) Close() {
	c.mu.RLock()
	fn := c.cancel
	c.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

func (c *NegativeCache) evictionLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			c.purgeExpiredLocked()
			c.mu.Unlock()
		}
	}
}

// purgeExpiredLocked deletes all entries whose expiry is in the past.
// Caller must hold c.mu (write lock).
func (c *NegativeCache) purgeExpiredLocked() {
	now := time.Now().UTC()
	for k, exp := range c.entries {
		if now.After(exp) {
			delete(c.entries, k)
		}
	}
}

// evictOldestLocked removes entries with the earliest expiry times until the
// cache is at 90% capacity. Uses a single pass to find the N oldest entries.
// Caller must hold c.mu (write lock).
func (c *NegativeCache) evictOldestLocked() {
	evictCount := len(c.entries) - (c.maxSize * 9 / 10)
	if evictCount <= 0 {
		return
	}

	// Collect the N oldest entries in a single pass using a small slice.
	type kv struct {
		key string
		exp time.Time
	}
	oldest := make([]kv, 0, evictCount)
	for k, exp := range c.entries {
		if len(oldest) < evictCount {
			oldest = append(oldest, kv{k, exp})
			continue
		}
		// Find the newest entry in our oldest set and replace if current is older.
		maxIdx := 0
		for i := 1; i < len(oldest); i++ {
			if oldest[i].exp.After(oldest[maxIdx].exp) {
				maxIdx = i
			}
		}
		if exp.Before(oldest[maxIdx].exp) {
			oldest[maxIdx] = kv{k, exp}
		}
	}
	for _, e := range oldest {
		delete(c.entries, e.key)
	}
}

// ScopedKey builds a cache key that isolates entries by tenant when provided.
func ScopedKey(scope, path string) string {
	scope = strings.TrimSpace(scope)
	path = strings.TrimSpace(path)
	if scope == "" || path == "" {
		return path
	}
	return scope + "::" + path
}
