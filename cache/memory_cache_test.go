package cache

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryCacheGetSet(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()
	if err := c.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, ok, err := c.Get(ctx, "k")
	if err != nil || !ok || string(got) != "v" {
		t.Fatalf("unexpected get: %q %v %v", got, ok, err)
	}
	// Defensive copy: mutating the returned slice must not corrupt the cache.
	got[0] = 'x'
	got2, _, _ := c.Get(ctx, "k")
	if string(got2) != "v" {
		t.Fatalf("cache corrupted by caller mutation: %q", got2)
	}
}

func TestMemoryCacheTTL(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()
	_ = c.Set(ctx, "k", []byte("v"), 20*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	_, ok, _ := c.Get(ctx, "k")
	if ok {
		t.Fatal("expected entry to expire")
	}
}

func TestMemoryCachePubSub(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()
	ctx := context.Background()
	out, cancel, err := c.Subscribe(ctx, "topic")
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer cancel()
	if err := c.Publish(ctx, "topic", []byte("hi")); err != nil {
		t.Fatalf("publish: %v", err)
	}
	select {
	case msg := <-out:
		if string(msg) != "hi" {
			t.Fatalf("unexpected payload: %q", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber didn't receive message")
	}
}

func TestMemoryCacheConcurrentPublishClose(t *testing.T) {
	// Stress test the publish-vs-close race that bug 9 fixed.
	c := NewMemoryCache()
	ctx := context.Background()
	_, cancel, _ := c.Subscribe(ctx, "topic")
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = c.Publish(ctx, "topic", []byte("x"))
		}
	}()
	time.Sleep(time.Millisecond)
	_ = c.Close() // race with publishers
	wg.Wait()
}

func TestMemoryCacheFactoryDefault(t *testing.T) {
	c, err := New(Config{}, nil)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	if _, ok := c.(*MemoryCache); !ok {
		t.Fatalf("default factory must return *MemoryCache, got %T", c)
	}
}
