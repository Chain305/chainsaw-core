package policy

import (
	"sync/atomic"
	"testing"
	"time"
)

// One org's slow policy load used to hold the cache's write lock for the
// whole DB call, so every other org's cached read waited behind it.
func TestCachedStoreSlowLoadDoesNotBlockOtherOrgs(t *testing.T) {
	release := make(chan struct{})
	c := &CachedStore{cache: map[string]cachedEntry{
		"org-b": {policies: []Policy{{ID: "b1"}}, loadedAt: time.Now()},
	}, ttl: time.Minute}
	c.load = func(orgID string) ([]Policy, error) {
		<-release
		return []Policy{{ID: orgID}}, nil
	}
	go func() { _, _ = c.ListPolicies("org-a") }()
	time.Sleep(20 * time.Millisecond) // let org-a's load start

	done := make(chan struct{})
	go func() {
		_, _ = c.ListPolicies("org-b")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("cached read for org-b blocked behind org-a's in-flight load")
	}
	close(release)
}

// A load that began before an Invalidate must not write its (now stale)
// result back into the cache, and concurrent misses share one load.
func TestCachedStoreLoadRacingInvalidateIsNotCached(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	c := &CachedStore{cache: map[string]cachedEntry{}, ttl: time.Minute}
	c.load = func(string) ([]Policy, error) {
		n := calls.Add(1)
		if n == 1 {
			<-release
			return []Policy{{ID: "stale"}}, nil
		}
		return []Policy{{ID: "fresh"}}, nil
	}
	first := make(chan []Policy, 2)
	for i := 0; i < 2; i++ {
		go func() { p, _ := c.ListPolicies("org-a"); first <- p }()
	}
	time.Sleep(20 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent misses made %d loads, want 1", got)
	}
	c.localInvalidate("org-a") // a policy edit lands mid-load
	close(release)
	<-first
	<-first

	got, err := c.ListPolicies("org-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "fresh" {
		t.Fatalf("after invalidate during load got %+v, want a fresh reload (the stale result must not be cached)", got)
	}
}
