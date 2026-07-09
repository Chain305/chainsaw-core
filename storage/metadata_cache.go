package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chain305/chainsaw-core/cache"
)

const (
	defaultMetaCacheSize = 10_000

	// MetadataInvalidationChannel is the pub/sub channel on which
	// metadata-cache invalidation messages are exchanged between
	// instances. When an instance writes to its local MetadataCache
	// (Put or Invalidate) it also publishes a JSON-encoded
	// [metadataInvalidationMessage] on this channel; peers subscribe
	// and drop their matching local entry so the next Get re-reads
	// from the meta store (which is already shared across instances).
	MetadataInvalidationChannel = "chainsaw:metadata:invalidate"
)

type metaCacheEntry struct {
	meta       ContentMetadata
	accessedAt int64 // unix nano, updated on read
}

// metadataInvalidationMessage is the wire format for cross-instance
// invalidation broadcasts. InstanceID lets receivers ignore their own
// echoes when the pub/sub backend fans messages back to the publisher
// (Redis PUB/SUB does).
type metadataInvalidationMessage struct {
	BlobPath   string `json:"blob_path"`
	OrgID      string `json:"org_id,omitempty"`
	InstanceID string `json:"instance_id,omitempty"`
}

// MetadataCache is a bounded in-memory cache for ContentMetadata that avoids
// repeated disk reads and JSON unmarshalling for hot artifacts.
//
// When a shared [cache.Cache] has been registered via
// [SetMetadataInvalidationBus], Put and Invalidate also publish a
// cross-instance invalidation message so peers drop their local
// copies. Incoming invalidations are delivered by a single subscriber
// goroutine started by [StartMetadataInvalidationSubscriber].
type MetadataCache struct {
	entries map[string]*metaCacheEntry
	mu      sync.RWMutex
	maxSize int
	hits    atomic.Int64
	misses  atomic.Int64
}

// NewMetadataCache creates a metadata cache with the given max entry count.
// Any cache registered with [SetMetadataInvalidationBus] is applied
// automatically — callers don't need to wire pub/sub per instance.
func NewMetadataCache(maxSize int) *MetadataCache {
	if maxSize <= 0 {
		maxSize = defaultMetaCacheSize
	}
	c := &MetadataCache{
		entries: make(map[string]*metaCacheEntry, maxSize),
		maxSize: maxSize,
	}
	registerMetadataCache(c)
	return c
}

// Get returns cached metadata for the given blob path, or false on miss.
func (c *MetadataCache) Get(blobPath string) (ContentMetadata, bool) {
	c.mu.RLock()
	entry, ok := c.entries[blobPath]
	c.mu.RUnlock()
	if !ok {
		c.misses.Add(1)
		return ContentMetadata{}, false
	}
	// Update access time (racy but acceptable for approximate LRU).
	entry.accessedAt = time.Now().UnixNano()
	c.hits.Add(1)
	return entry.meta, true
}

// Put stores metadata in the cache, evicting stale entries if at capacity.
// Put also publishes a cross-instance invalidation when a shared bus is
// registered — peers drop their local copy so the next Get re-reads the
// (now shared) meta store.
func (c *MetadataCache) Put(blobPath string, meta ContentMetadata) {
	c.mu.Lock()
	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}
	c.entries[blobPath] = &metaCacheEntry{
		meta:       meta,
		accessedAt: time.Now().UnixNano(),
	}
	c.mu.Unlock()
	publishMetadataInvalidation(blobPath)
}

// Invalidate removes a single entry from the cache. Like Put, it also
// publishes a cross-instance invalidation when a shared bus is registered.
func (c *MetadataCache) Invalidate(blobPath string) {
	c.mu.Lock()
	delete(c.entries, blobPath)
	c.mu.Unlock()
	publishMetadataInvalidation(blobPath)
}

// invalidateLocal drops the entry without publishing. Used by the
// subscriber goroutine to apply remote invalidations without echoing
// them back into a loop.
func (c *MetadataCache) invalidateLocal(blobPath string) {
	c.mu.Lock()
	delete(c.entries, blobPath)
	c.mu.Unlock()
}

// evictLocked removes ~10% of entries with the oldest access times.
// Caller must hold c.mu write lock.
func (c *MetadataCache) evictLocked() {
	target := c.maxSize * 9 / 10
	for len(c.entries) > target {
		var oldestKey string
		var oldestTime int64
		first := true
		for k, e := range c.entries {
			if first || e.accessedAt < oldestTime {
				oldestKey = k
				oldestTime = e.accessedAt
				first = false
			}
		}
		delete(c.entries, oldestKey)
	}
}

// ---- Cross-instance invalidation bus ------------------------------

// metadataBus guards the package-level cross-instance invalidation
// plumbing. A single bus is shared by every MetadataCache in the
// process; instances register themselves on construction and are
// looked up when an inbound invalidation arrives.
//
// The design deliberately avoids per-repo subscriptions: chainsaw
// can easily have >50 MetadataCache instances (one per repo × org)
// and one Redis PUB/SUB subscription per instance would be wasteful.
// Blob paths are globally unique so a single subscriber can fan out
// to every registered cache.
var metadataBus = struct {
	mu         sync.RWMutex
	c          cache.Cache
	channel    string
	instanceID string
	caches     []*MetadataCache
}{
	channel:    MetadataInvalidationChannel,
	instanceID: newInstanceID(),
}

func newInstanceID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Non-crypto fallback — time-derived is fine because we only
		// need to distinguish our own publishes from peers'.
		return "inst-" + time.Now().Format("150405.000000000")
	}
	return "inst-" + hex.EncodeToString(b[:])
}

func registerMetadataCache(c *MetadataCache) {
	metadataBus.mu.Lock()
	metadataBus.caches = append(metadataBus.caches, c)
	metadataBus.mu.Unlock()
}

// SetMetadataInvalidationBus attaches a shared cache to the pub/sub
// invalidation path. When non-nil, every subsequent Put / Invalidate
// on any [MetadataCache] in the process publishes an invalidation
// message on the given channel. Passing channel == "" uses the
// default [MetadataInvalidationChannel]. Pass nil cache to disable.
func SetMetadataInvalidationBus(c cache.Cache, channel string) {
	metadataBus.mu.Lock()
	metadataBus.c = c
	if channel != "" {
		metadataBus.channel = channel
	}
	metadataBus.mu.Unlock()
}

// MetadataInvalidationInstanceID returns the per-process instance ID
// used to filter out the publisher's own invalidation echoes. Exposed
// primarily for tests that want to simulate remote messages.
func MetadataInvalidationInstanceID() string {
	metadataBus.mu.RLock()
	defer metadataBus.mu.RUnlock()
	return metadataBus.instanceID
}

func publishMetadataInvalidation(blobPath string) {
	metadataBus.mu.RLock()
	c := metadataBus.c
	channel := metadataBus.channel
	instanceID := metadataBus.instanceID
	metadataBus.mu.RUnlock()
	if c == nil || blobPath == "" {
		return
	}
	msg := metadataInvalidationMessage{
		BlobPath:   blobPath,
		InstanceID: instanceID,
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return
	}
	// Publish is best-effort — errors are not fatal for the local
	// write (the peer's TTL will eventually expire the stale entry).
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.Publish(ctx, channel, payload)
}

// StartMetadataInvalidationSubscriber spawns a goroutine that
// subscribes to the invalidation channel and drops matching entries
// from every registered MetadataCache. It reconnects on dropped
// subscriptions with exponential backoff capped at 30s. Returns
// immediately; stops when ctx is cancelled.
//
// Calling it without first calling [SetMetadataInvalidationBus] is a
// no-op — the subscriber exits immediately.
// StartMetadataInvalidationSubscriber spawns the invalidation-listener
// goroutine and blocks just long enough to either (a) confirm the first
// Subscribe() attempt succeeded or (b) prove the bus is disabled. This
// tiny synchronous window closes a race where a caller Publishes an
// event between StartMetadataInvalidationSubscriber returning and the
// goroutine completing its first Subscribe — messages published into
// that window would otherwise be silently dropped.
func StartMetadataInvalidationSubscriber(ctx context.Context, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	ready := make(chan struct{})
	go runMetadataInvalidationSubscriber(ctx, logger, ready)
	// Don't block forever if the subscriber can't make progress (bus
	// missing, ctx cancelled) — worst case we publish into the void,
	// same outcome the caller already tolerates for a missing bus.
	select {
	case <-ready:
	case <-ctx.Done():
	case <-time.After(500 * time.Millisecond):
	}
}

func runMetadataInvalidationSubscriber(ctx context.Context, logger *slog.Logger, ready chan<- struct{}) {
	backoff := 100 * time.Millisecond
	const maxBackoff = 30 * time.Second
	firstAttempt := true
	signalReady := func() {
		if firstAttempt {
			firstAttempt = false
			close(ready)
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			signalReady()
			return
		}
		metadataBus.mu.RLock()
		c := metadataBus.c
		channel := metadataBus.channel
		metadataBus.mu.RUnlock()
		if c == nil {
			signalReady()
			return
		}
		sub, cancel, err := c.Subscribe(ctx, channel)
		if err != nil {
			logger.Warn("metadata invalidation subscribe failed",
				"channel", channel,
				"error", err,
				"retry_in", backoff,
			)
			signalReady()
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}
		// Successful connection — reset backoff so the next reconnect
		// starts fast, and let the caller proceed.
		backoff = 100 * time.Millisecond
		signalReady()
		consumeMetadataInvalidations(ctx, sub, logger)
		cancel()
		// consume returned — either ctx cancelled or the channel was
		// closed (connection drop). Loop reconnects.
		if err := ctx.Err(); err != nil {
			return
		}
		if !sleepCtx(ctx, backoff) {
			return
		}
		backoff = nextBackoff(backoff, maxBackoff)
	}
}

func consumeMetadataInvalidations(ctx context.Context, sub <-chan []byte, logger *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case payload, ok := <-sub:
			if !ok {
				return
			}
			applyMetadataInvalidation(payload, logger)
		}
	}
}

func applyMetadataInvalidation(payload []byte, logger *slog.Logger) {
	var msg metadataInvalidationMessage
	if err := json.Unmarshal(payload, &msg); err != nil {
		if logger != nil {
			logger.Debug("metadata invalidation: malformed payload", "error", err)
		}
		return
	}
	if msg.BlobPath == "" {
		return
	}
	metadataBus.mu.RLock()
	selfID := metadataBus.instanceID
	caches := append([]*MetadataCache(nil), metadataBus.caches...)
	metadataBus.mu.RUnlock()
	// Ignore our own echoes so we don't wipe entries we just wrote.
	if msg.InstanceID != "" && msg.InstanceID == selfID {
		return
	}
	for _, c := range caches {
		c.invalidateLocal(msg.BlobPath)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func nextBackoff(cur, max time.Duration) time.Duration {
	next := cur * 2
	if next > max {
		return max
	}
	return next
}
