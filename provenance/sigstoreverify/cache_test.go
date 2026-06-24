package sigstoreverify

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
)

func TestBundleCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c, err := NewBundleCache(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewBundleCache: %v", err)
	}
	bundle := []byte(`{"bundle":"x"}`)
	artifact := make([]byte, 32)
	want := Identity{
		SourceRepo: "https://github.com/foo/bar",
		BuilderID:  "https://github.com/foo/bar/.github/workflows/release.yml@refs/tags/v1",
		Issuer:     "https://token.actions.githubusercontent.com",
	}
	if err := c.Put(bundle, artifact, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, _, fresh, ok := c.Get(bundle, artifact)
	if !ok {
		t.Fatal("Get: ok=false after Put")
	}
	if !fresh {
		t.Error("Get: fresh=false within TTL")
	}
	if got != want {
		t.Errorf("Get: got %+v, want %+v", got, want)
	}
}

func TestBundleCacheStaleAfterTTL(t *testing.T) {
	dir := t.TempDir()
	fake := clockwork.NewFakeClock()
	c := &BundleCache{dir: dir, ttl: time.Hour, clock: fake}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bundle := []byte("b")
	artifact := make([]byte, 32)
	if err := c.Put(bundle, artifact, Identity{SourceRepo: "r"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, _, fresh, ok := c.Get(bundle, artifact); !ok || !fresh {
		t.Fatalf("immediately after Put: ok=%v fresh=%v", ok, fresh)
	}
	fake.Advance(2 * time.Hour)
	got, _, fresh, ok := c.Get(bundle, artifact)
	if !ok {
		t.Fatal("expected stale entry to still be returned")
	}
	if fresh {
		t.Error("expected stale=true past TTL")
	}
	if got.SourceRepo != "r" {
		t.Errorf("got %+v, want SourceRepo=r", got)
	}
}

func TestBundleCacheKeyIncludesArtifact(t *testing.T) {
	c, err := NewBundleCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte("same-bundle")
	a1 := make([]byte, 32)
	a2 := make([]byte, 32)
	a2[0] = 1
	if err := c.Put(bundle, a1, Identity{SourceRepo: "one"}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := c.Get(bundle, a2); ok {
		t.Fatal("entry leaked across artifact digests")
	}
}

func TestBundleCacheNilSafe(t *testing.T) {
	var c *BundleCache
	if _, _, _, ok := c.Get(nil, nil); ok {
		t.Error("nil cache returned ok=true")
	}
	if err := c.Put(nil, nil, Identity{}); err != nil {
		t.Errorf("nil cache Put returned err: %v", err)
	}
}

func TestBundleCacheCorruptEntryIgnored(t *testing.T) {
	dir := t.TempDir()
	c, err := NewBundleCache(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte("b")
	artifact := make([]byte, 32)
	path := c.path(bundle, artifact)
	if err := os.WriteFile(path, []byte("{not-valid-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := c.Get(bundle, artifact); ok {
		t.Error("corrupt entry should report ok=false")
	}
}

func TestVerifyWithCacheServesFreshHit(t *testing.T) {
	cache, err := NewBundleCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte("b")
	artifact := make([]byte, 32)
	want := Identity{SourceRepo: "https://github.com/cached/repo"}
	if err := cache.Put(bundle, artifact, want); err != nil {
		t.Fatal(err)
	}
	// Verifier with nil trusted root would fail any live call — proves
	// fresh hits short-circuit before ever touching it.
	v := &Verifier{}
	got, err := v.VerifyWithCache(cache, bundle, artifact)
	if err != nil {
		t.Fatalf("VerifyWithCache: %v", err)
	}
	if got.Identity != want {
		t.Errorf("Identity = %+v, want %+v", got.Identity, want)
	}
	if got.CacheStale {
		t.Error("CacheStale=true on fresh hit")
	}
}

func TestVerifyWithCacheStaleFallbackOnLiveError(t *testing.T) {
	dir := t.TempDir()
	fake := clockwork.NewFakeClock()
	cache := &BundleCache{dir: dir, ttl: time.Hour, clock: fake}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Put a too-short artifact digest so live Verify will reject ("want
	// 32 bytes") — simulates a transient live failure for the test.
	bundle := []byte(`{"x":1}`)
	artifact := make([]byte, 16) // wrong length on purpose
	staleID := Identity{SourceRepo: "https://github.com/stale/repo"}
	// Pre-populate the cache directly so we know the Get key matches.
	c := &BundleCache{dir: dir, ttl: time.Hour, clock: fake}
	if err := c.Put(bundle, artifact, staleID); err != nil {
		t.Fatal(err)
	}
	fake.Advance(2 * time.Hour) // make the entry stale

	v := &Verifier{}
	got, err := v.VerifyWithCache(cache, bundle, artifact)
	if err != nil {
		t.Fatalf("VerifyWithCache should serve stale, got err: %v", err)
	}
	if !got.CacheStale {
		t.Error("CacheStale=false; want true on live-error fallback")
	}
	if got.Identity != staleID {
		t.Errorf("Identity = %+v, want %+v", got.Identity, staleID)
	}
	if got.LiveError == nil {
		t.Error("LiveError nil; want the live-verify error")
	}
}

func TestVerifyWithCacheLiveErrorNoCacheReturnsError(t *testing.T) {
	cache, err := NewBundleCache(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{}
	_, err = v.VerifyWithCache(cache, []byte(`{}`), make([]byte, 16))
	if err == nil {
		t.Fatal("expected error when live fails and no cache entry exists")
	}
}

func TestNewBundleCacheRequiresDir(t *testing.T) {
	if _, err := NewBundleCache("", time.Hour); err == nil {
		t.Error("expected error for empty dir")
	}
}

func TestNewBundleCacheDefaultsTTL(t *testing.T) {
	c, err := NewBundleCache(filepath.Join(t.TempDir(), "sub"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if c.ttl != DefaultBundleTTL {
		t.Errorf("ttl = %v, want %v", c.ttl, DefaultBundleTTL)
	}
}

func TestVerifyWithCacheNilCache(t *testing.T) {
	v := &Verifier{}
	_, err := v.VerifyWithCache(nil, []byte(`{}`), make([]byte, 16))
	// nil cache → fall through to plain Verify, which fails on the bad
	// artifact digest. We just want to confirm we don't panic and we
	// surface the underlying error.
	if err == nil {
		t.Fatal("want error from underlying Verify")
	}
	if !errors.Is(err, err) { // sanity
		t.Fatal("error should be returnable")
	}
}
