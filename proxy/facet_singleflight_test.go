package proxy

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCoalescedWaitersGetTheirOwnResponse pins the fix for a process crash:
// singleflight hands every coalesced waiter the same *Response, and the
// server then writes per-request headers into it. Two concurrent installs
// of one package wrote the shared map at once and the runtime aborted with
// "fatal error: concurrent map writes" (8 parallel npm packs, 2026-10-21).
//
// Verified by deletion: returning result.Val.(*Response) directly from
// awaitFetch makes this fail on the shared Headers map.
func TestCoalescedWaitersGetTheirOwnResponse(t *testing.T) {
	const waiters = 6
	release := make(chan struct{})
	var hits atomic.Int32
	f, _ := newRevalidationFacet(t, &freshStorage{}, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"undici"}`))
	})

	responses := make([]*Response, waiters)
	var wg sync.WaitGroup
	for i := range waiters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := f.Get(context.Background(), &Request{LogicalPath: "undici", Method: http.MethodGet, Header: http.Header{}})
			if err != nil {
				t.Errorf("waiter %d: %v", i, err)
				return
			}
			responses[i] = resp
		}()
	}
	// ponytail: a sleep lets the waiters join the flight; the hit count
	// below proves they did, so a slow machine fails loudly, not silently.
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream saw %d fetches, want 1: the waiters did not coalesce, so this test proves nothing", got)
	}
	for i, resp := range responses {
		if resp == nil {
			t.Fatalf("waiter %d got no response", i)
		}
		resp.Headers.Set("X-Waiter", string(rune('a'+i)))
	}
	for i, resp := range responses {
		if got, want := resp.Headers.Get("X-Waiter"), string(rune('a'+i)); got != want {
			t.Errorf("waiter %d sees X-Waiter=%q, want %q: the Headers map is shared between waiters", i, got, want)
		}
		if i > 0 && resp.Content == responses[0].Content {
			t.Errorf("waiter %d shares the CachedContent struct with waiter 0", i)
		}
	}
}
