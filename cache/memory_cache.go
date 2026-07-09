package cache

import (
	"context"
	"sync"
	"time"
)

// MemoryCache is the in-process [Cache] implementation. It is the
// default backend and matches the prior (single-instance) behaviour
// of every typed cache it backs. Pub/Sub is local-only — Publish
// fans out to subscribers within the same process.
type MemoryCache struct {
	mu       sync.RWMutex
	entries  map[string]memoryEntry
	sets     map[string]map[string]struct{}
	channels map[string][]chan []byte

	closed bool
}

type memoryEntry struct {
	value     []byte
	expiresAt time.Time // zero = no expiry
}

// NewMemoryCache constructs an in-memory cache. The garbage-collection
// goroutine is lazy — entries are checked for expiry on read.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		entries:  make(map[string]memoryEntry),
		sets:     make(map[string]map[string]struct{}),
		channels: make(map[string][]chan []byte),
	}
}

// Get returns the bytes stored at key.
func (m *MemoryCache) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.RLock()
	entry, ok := m.entries[key]
	m.mu.RUnlock()
	if !ok {
		return nil, false, nil
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		m.mu.Lock()
		// Re-check inside the write lock — another reader may have
		// refreshed the entry between our RUnlock and Lock.
		if cur, stillOk := m.entries[key]; stillOk && !cur.expiresAt.IsZero() && time.Now().After(cur.expiresAt) {
			delete(m.entries, key)
		}
		m.mu.Unlock()
		return nil, false, nil
	}
	// Defensive copy so callers can't mutate cached bytes.
	out := make([]byte, len(entry.value))
	copy(out, entry.value)
	return out, true, nil
}

// Set stores value at key with the given TTL.
func (m *MemoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	stored := make([]byte, len(value))
	copy(stored, value)
	entry := memoryEntry{value: stored}
	if ttl > 0 {
		entry.expiresAt = time.Now().Add(ttl)
	}
	m.mu.Lock()
	m.entries[key] = entry
	m.mu.Unlock()
	return nil
}

// Delete removes the named keys.
func (m *MemoryCache) Delete(_ context.Context, keys ...string) error {
	m.mu.Lock()
	for _, k := range keys {
		delete(m.entries, k)
	}
	m.mu.Unlock()
	return nil
}

// Exists reports whether key is present and unexpired.
func (m *MemoryCache) Exists(ctx context.Context, key string) (bool, error) {
	_, ok, err := m.Get(ctx, key)
	return ok, err
}

// SetAdd records the named members in the set at key.
func (m *MemoryCache) SetAdd(_ context.Context, key string, members ...string) error {
	m.mu.Lock()
	set, ok := m.sets[key]
	if !ok {
		set = make(map[string]struct{}, len(members))
		m.sets[key] = set
	}
	for _, member := range members {
		set[member] = struct{}{}
	}
	m.mu.Unlock()
	return nil
}

// SetMembers returns every member of the set at key.
func (m *MemoryCache) SetMembers(_ context.Context, key string) ([]string, error) {
	m.mu.RLock()
	set := m.sets[key]
	out := make([]string, 0, len(set))
	for member := range set {
		out = append(out, member)
	}
	m.mu.RUnlock()
	return out, nil
}

// SetRemove removes the named members from the set at key.
func (m *MemoryCache) SetRemove(_ context.Context, key string, members ...string) error {
	m.mu.Lock()
	if set, ok := m.sets[key]; ok {
		for _, member := range members {
			delete(set, member)
		}
		if len(set) == 0 {
			delete(m.sets, key)
		}
	}
	m.mu.Unlock()
	return nil
}

// Publish delivers msg to every subscriber of channel. Slow
// subscribers do not block the publisher — if a subscriber's buffered
// channel is full the message is dropped silently for that subscriber
// (matches Redis Pub/Sub at-most-once semantics).
//
// The send is wrapped in a panic recover so a concurrent Close (which
// closes the subscriber channel) cannot crash the publisher — the
// dropped message is the same outcome a slow-consumer drop already has.
func (m *MemoryCache) Publish(_ context.Context, channel string, msg []byte) error {
	m.mu.RLock()
	subs := append([]chan []byte(nil), m.channels[channel]...)
	m.mu.RUnlock()
	for _, ch := range subs {
		payload := make([]byte, len(msg))
		copy(payload, msg)
		func(c chan []byte, p []byte) {
			defer func() { _ = recover() }()
			select {
			case c <- p:
			default:
				// drop on full buffer
			}
		}(ch, payload)
	}
	return nil
}

// Subscribe returns a buffered channel that receives every message
// published to the named pubsub channel. The returned cancel func
// unregisters the subscription and closes the receive channel.
func (m *MemoryCache) Subscribe(_ context.Context, channel string) (<-chan []byte, func(), error) {
	ch := make(chan []byte, 16)
	m.mu.Lock()
	m.channels[channel] = append(m.channels[channel], ch)
	m.mu.Unlock()

	cancel := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		subs := m.channels[channel]
		for i, existing := range subs {
			if existing == ch {
				m.channels[channel] = append(subs[:i], subs[i+1:]...)
				break
			}
		}
		if len(m.channels[channel]) == 0 {
			delete(m.channels, channel)
		}
		// Closing the channel must happen exactly once and only after
		// it has been removed from the registry, so a concurrent
		// publisher won't send on it.
		defer func() { _ = recover() }()
		close(ch)
	}
	return ch, cancel, nil
}

// Close drops all entries. Subscriber channels remain open — the
// caller is responsible for invoking the cancel func returned from
// Subscribe to drain them. (Closing channels here would race with a
// concurrent Publish.) Subsequent Publish/Set/Subscribe calls become
// no-ops or short-circuit reads.
func (m *MemoryCache) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	// Drop the channel registry so future Publish calls fan out to
	// nothing — subscribers' channels are intentionally left open
	// so any in-flight publisher goroutine can complete its send
	// without panicking.
	m.channels = map[string][]chan []byte{}
	m.entries = make(map[string]memoryEntry)
	m.sets = make(map[string]map[string]struct{})
	return nil
}

// Compile-time interface assertion.
var _ Cache = (*MemoryCache)(nil)
