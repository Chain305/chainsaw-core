package storage

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/cache"
)

// resetMetadataBus restores the package-level bus state between tests so
// a bus/subscriber from one test doesn't bleed into the next. Tests that
// register their own Cache must call this during cleanup.
func resetMetadataBus(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		metadataBus.mu.Lock()
		metadataBus.c = nil
		metadataBus.channel = MetadataInvalidationChannel
		metadataBus.caches = nil
		metadataBus.mu.Unlock()
	})
	metadataBus.mu.Lock()
	metadataBus.c = nil
	metadataBus.channel = MetadataInvalidationChannel
	metadataBus.caches = nil
	metadataBus.mu.Unlock()
}

// TestMetadataCacheBasicPutGet covers the non-pub/sub behaviour that
// existed before H7 — the new hooks must not regress local-only use.
func TestMetadataCacheBasicPutGet(t *testing.T) {
	resetMetadataBus(t)
	c := NewMetadataCache(32)
	c.Put("/blob/a", ContentMetadata{LogicalPath: "foo/a"})
	got, ok := c.Get("/blob/a")
	if !ok || got.LogicalPath != "foo/a" {
		t.Fatalf("get after put: ok=%v meta=%+v", ok, got)
	}
	c.Invalidate("/blob/a")
	if _, ok := c.Get("/blob/a"); ok {
		t.Fatal("expected entry to be gone after Invalidate")
	}
}

// TestMetadataCacheInvalidationOverBus is the headline test: a peer's
// invalidation message (injected directly into the shared cache) must
// wipe our local copy. Uses the in-memory cache as the shared bus.
func TestMetadataCacheInvalidationOverBus(t *testing.T) {
	resetMetadataBus(t)
	bus := cache.NewMemoryCache()
	defer bus.Close()
	SetMetadataInvalidationBus(bus, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMetadataInvalidationSubscriber(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))

	mc := NewMetadataCache(32)
	mc.Put("/blob/x", ContentMetadata{LogicalPath: "foo/x"})
	// Sanity: the local Put should be present AND have been published.
	if _, ok := mc.Get("/blob/x"); !ok {
		t.Fatal("local Put should be visible")
	}

	// Simulate a peer by publishing directly with a different instance ID.
	peerMsg := metadataInvalidationMessage{
		BlobPath:   "/blob/x",
		InstanceID: "peer-xyz",
	}
	payload, _ := json.Marshal(peerMsg)
	if err := bus.Publish(ctx, MetadataInvalidationChannel, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}

	if !waitForInvalidation(mc, "/blob/x", 2*time.Second) {
		t.Fatal("peer invalidation never applied")
	}
}

// TestMetadataCacheOwnEchoIgnored ensures we don't wipe our own entries
// when the pub/sub backend fans our messages back to us (Redis does).
func TestMetadataCacheOwnEchoIgnored(t *testing.T) {
	resetMetadataBus(t)
	bus := cache.NewMemoryCache()
	defer bus.Close()
	SetMetadataInvalidationBus(bus, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMetadataInvalidationSubscriber(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))

	mc := NewMetadataCache(32)
	mc.Put("/blob/y", ContentMetadata{LogicalPath: "foo/y"})

	// Wait long enough that the (self-published) invalidation would
	// have been consumed by the subscriber. It must be ignored.
	time.Sleep(200 * time.Millisecond)
	if _, ok := mc.Get("/blob/y"); !ok {
		t.Fatal("self-echoed invalidation should not wipe our own Put")
	}
}

// TestMetadataCacheInvalidateAlsoPublishes ensures local Invalidate
// also broadcasts so peers drop their entries.
func TestMetadataCacheInvalidateAlsoPublishes(t *testing.T) {
	resetMetadataBus(t)
	bus := cache.NewMemoryCache()
	defer bus.Close()
	SetMetadataInvalidationBus(bus, "")

	// Raw subscriber — not the MetadataCache one — so we can observe
	// what's actually on the wire.
	sub, cancelSub, err := bus.Subscribe(context.Background(), MetadataInvalidationChannel)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer cancelSub()

	mc := NewMetadataCache(32)
	mc.Put("/blob/z", ContentMetadata{LogicalPath: "foo/z"})
	mc.Invalidate("/blob/z")

	// Drain two messages (Put + Invalidate) with a timeout.
	deadline := time.After(2 * time.Second)
	gotPaths := map[string]int{}
	for i := 0; i < 2; i++ {
		select {
		case payload := <-sub:
			var msg metadataInvalidationMessage
			if err := json.Unmarshal(payload, &msg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			gotPaths[msg.BlobPath]++
			if msg.InstanceID != MetadataInvalidationInstanceID() {
				t.Fatalf("expected own instance ID on outbound message, got %q", msg.InstanceID)
			}
		case <-deadline:
			t.Fatal("timed out waiting for published messages")
		}
	}
	if gotPaths["/blob/z"] != 2 {
		t.Fatalf("expected 2 publishes for /blob/z, got %v", gotPaths)
	}
}

// TestMetadataCacheNoBusIsNoop exercises the fast path — when no bus is
// registered, Put/Invalidate must not block or error, and nothing is
// published anywhere.
func TestMetadataCacheNoBusIsNoop(t *testing.T) {
	resetMetadataBus(t)
	mc := NewMetadataCache(32)
	// These must not panic or deadlock even with no bus attached.
	mc.Put("/blob/none", ContentMetadata{LogicalPath: "x"})
	mc.Invalidate("/blob/none")
}

// TestMetadataCacheFanoutToMultipleInstances ensures every registered
// cache drops the key when an invalidation arrives — simulates N repo
// caches in the same process.
func TestMetadataCacheFanoutToMultipleInstances(t *testing.T) {
	resetMetadataBus(t)
	bus := cache.NewMemoryCache()
	defer bus.Close()
	SetMetadataInvalidationBus(bus, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMetadataInvalidationSubscriber(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))

	caches := make([]*MetadataCache, 5)
	for i := range caches {
		caches[i] = NewMetadataCache(16)
		caches[i].Put("/blob/shared", ContentMetadata{LogicalPath: "foo"})
	}

	peerMsg := metadataInvalidationMessage{BlobPath: "/blob/shared", InstanceID: "peer-42"}
	payload, _ := json.Marshal(peerMsg)
	if err := bus.Publish(ctx, MetadataInvalidationChannel, payload); err != nil {
		t.Fatalf("publish: %v", err)
	}

	for i, c := range caches {
		if !waitForInvalidation(c, "/blob/shared", 2*time.Second) {
			t.Fatalf("cache %d still has key after peer invalidation", i)
		}
	}
}

// TestMetadataCacheSubscriberExitsOnCtxCancel ensures the background
// goroutine shuts down cleanly so Close during shutdown doesn't leak.
func TestMetadataCacheSubscriberExitsOnCtxCancel(t *testing.T) {
	resetMetadataBus(t)
	bus := cache.NewMemoryCache()
	defer bus.Close()
	SetMetadataInvalidationBus(bus, "")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runMetadataInvalidationSubscriber(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), make(chan struct{}))
		close(done)
	}()

	// Give it a moment to subscribe then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber didn't exit within 2s of ctx cancel")
	}
}

// TestMetadataCacheMalformedPayloadIgnored — a bad message on the bus
// must not wipe entries or crash the subscriber.
func TestMetadataCacheMalformedPayloadIgnored(t *testing.T) {
	resetMetadataBus(t)
	bus := cache.NewMemoryCache()
	defer bus.Close()
	SetMetadataInvalidationBus(bus, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMetadataInvalidationSubscriber(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))

	mc := NewMetadataCache(32)
	mc.Put("/blob/keep", ContentMetadata{LogicalPath: "foo"})

	if err := bus.Publish(ctx, MetadataInvalidationChannel, []byte("not json")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, ok := mc.Get("/blob/keep"); !ok {
		t.Fatal("bad payload should not have wiped unrelated entries")
	}
}

// TestMetadataCacheConcurrentAccess stress-tests concurrent Put /
// Invalidate / inbound-invalidation under the race detector. The
// previous implementation had no bus so this is new coverage.
func TestMetadataCacheConcurrentAccess(t *testing.T) {
	resetMetadataBus(t)
	bus := cache.NewMemoryCache()
	defer bus.Close()
	SetMetadataInvalidationBus(bus, "")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMetadataInvalidationSubscriber(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))

	mc := NewMetadataCache(128)
	var wg sync.WaitGroup
	// Writers
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				mc.Put("/blob/concurrent", ContentMetadata{LogicalPath: "v"})
				mc.Invalidate("/blob/concurrent")
			}
		}(w)
	}
	// Remote invalidations
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			peerMsg := metadataInvalidationMessage{BlobPath: "/blob/concurrent", InstanceID: "peer"}
			payload, _ := json.Marshal(peerMsg)
			_ = bus.Publish(ctx, MetadataInvalidationChannel, payload)
		}
	}()
	wg.Wait()
}

func waitForInvalidation(mc *MetadataCache, key string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, ok := mc.Get(key); !ok {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}
