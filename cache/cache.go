// Package cache provides a byte-oriented [Cache] abstraction that
// supports both an in-process default ([MemoryCache]) and an
// optional Redis-protocol backend ([RedisCache], wired up in Phase 2).
//
// The existing typed caches in this package ([NegativeCache] and the
// metadata cache in internal/storage) keep their public APIs and
// continue to default to in-memory storage. They are layered on top
// of the generic [Cache] interface so multi-instance deployments can
// switch them to a shared Redis without touching call sites.
//
// Default behaviour: with no `CHAINSAW_CACHE_TYPE` env var set the
// in-process [MemoryCache] is selected and the new abstraction is
// invisible to callers.
package cache

import (
	"context"
	"errors"
	"time"
)

// ErrCacheMiss is the canonical "key not found" sentinel. Callers
// should compare errors with [errors.Is] rather than equality so
// implementations may wrap it with backend-specific context.
var ErrCacheMiss = errors.New("cache: key not found")

// Cache is the byte-oriented cache abstraction. Backends are free to
// store the bytes verbatim; serialization is the caller's concern
// (typed wrappers JSON-encode their value before [Cache.Set] and
// decode after [Cache.Get]).
//
// All methods accept a context. Backends that don't support
// cancellation (memory) treat it as a no-op.
type Cache interface {
	// Get returns the bytes stored at key. The boolean is true on hit.
	// On miss returns (nil, false, nil) — never (nil, false, ErrCacheMiss).
	// A non-nil error indicates a backend failure (network, parse, …).
	Get(ctx context.Context, key string) ([]byte, bool, error)

	// Set stores value at key with the given TTL. A zero TTL means
	// "no expiry"; backends that require a TTL (eg some Redis configs)
	// document their floor.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes one or more keys. Missing keys are not an error.
	Delete(ctx context.Context, keys ...string) error

	// Exists checks whether key is present.
	Exists(ctx context.Context, key string) (bool, error)

	// SetAdd / SetMembers / SetRemove maintain a Redis-style set
	// (unordered, unique members). Used by JWT revocation tracking
	// and similar.
	SetAdd(ctx context.Context, key string, members ...string) error
	SetMembers(ctx context.Context, key string) ([]string, error)
	SetRemove(ctx context.Context, key string, members ...string) error

	// Publish broadcasts a message to subscribers of channel. Used for
	// cache-invalidation messages between instances.
	Publish(ctx context.Context, channel string, msg []byte) error

	// Subscribe returns a channel of inbound messages for the given
	// pubsub channel and a cancellation function the caller invokes
	// to stop receiving. The returned channel is closed when the
	// cancellation function runs or the underlying connection drops.
	Subscribe(ctx context.Context, channel string) (<-chan []byte, func(), error)

	// Close releases backend resources.
	Close() error
}
