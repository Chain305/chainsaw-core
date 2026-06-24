package sigstoreverify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
)

// DefaultBundleTTL is how long a successful Sigstore bundle verification is
// trusted before we re-verify against Rekor/Fulcio. 24h matches the
// granularity at which Sigstore's transparency log signatures rotate in
// practice; shorter is fine, longer should be paired with a documented
// risk acceptance.
const DefaultBundleTTL = 24 * time.Hour

// BundleCache is an on-disk store of recent successful Sigstore bundle
// verifications, keyed by sha256(bundleJSON || artifactSHA256). It exists
// to (a) avoid re-running the full Sigstore verify pipeline for every
// scan of an unchanged artifact and (b) preserve a "last-known-good"
// answer that can be served when Rekor/Fulcio is unreachable.
//
// Entries past TTL are still returned by Get with fresh=false; callers
// decide whether to use the stale answer (the typical use case is the
// online-with-cache fallback in VerifyWithCache).
type BundleCache struct {
	dir   string
	ttl   time.Duration
	clock clockwork.Clock
	mu    sync.Mutex // serializes writes to a given file path
}

// NewBundleCache opens (or creates) a cache directory. The directory is
// created with 0o700 permissions because cached entries embed signer
// identities that callers may treat as sensitive. Returns an error only if
// the directory cannot be created.
func NewBundleCache(dir string, ttl time.Duration) (*BundleCache, error) {
	if dir == "" {
		return nil, errors.New("cache dir is required")
	}
	if ttl <= 0 {
		ttl = DefaultBundleTTL
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &BundleCache{
		dir:   dir,
		ttl:   ttl,
		clock: clockwork.NewRealClock(),
	}, nil
}

// cacheEntry is the on-disk JSON representation of a cached verification.
type cacheEntry struct {
	Identity   Identity  `json:"identity"`
	VerifiedAt time.Time `json:"verifiedAt"`
}

// Get looks up a previously cached verification result.
//
//   - ok=false: no entry exists (or the on-disk entry is unreadable).
//   - ok=true, fresh=true: entry exists and is within TTL.
//   - ok=true, fresh=false: entry exists but is past TTL ("stale").
//
// Stale entries are returned because the live-verification path treats
// them as a last-known-good fallback when Rekor/Fulcio is unreachable.
func (c *BundleCache) Get(bundleJSON, artifactSHA256 []byte) (id Identity, verifiedAt time.Time, fresh, ok bool) {
	if c == nil {
		return Identity{}, time.Time{}, false, false
	}
	path := c.path(bundleJSON, artifactSHA256)
	data, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, time.Time{}, false, false
	}
	var e cacheEntry
	if err := json.Unmarshal(data, &e); err != nil {
		return Identity{}, time.Time{}, false, false
	}
	fresh = c.clock.Now().Sub(e.VerifiedAt) < c.ttl
	return e.Identity, e.VerifiedAt, fresh, true
}

// Put stores a successful verification result. Errors are returned but
// callers typically log-and-continue: a cache write failure should not
// fail an otherwise-successful verification.
func (c *BundleCache) Put(bundleJSON, artifactSHA256 []byte, id Identity) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e := cacheEntry{Identity: id, VerifiedAt: c.clock.Now()}
	data, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal cache entry: %w", err)
	}
	path := c.path(bundleJSON, artifactSHA256)
	tmp, err := os.CreateTemp(c.dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// path returns the on-disk path for a given (bundle, artifact) pair. The
// key includes the artifact digest so the same bundle replayed against a
// different artifact never silently reuses the cached identity.
func (c *BundleCache) path(bundleJSON, artifactSHA256 []byte) string {
	h := sha256.New()
	h.Write(bundleJSON)
	h.Write(artifactSHA256)
	return filepath.Join(c.dir, hex.EncodeToString(h.Sum(nil))+".json")
}

// VerifyResult is the output of VerifyWithCache. It mirrors what Verify
// returns plus enough metadata for the policy engine to decide whether to
// honor a stale answer.
type VerifyResult struct {
	Identity   Identity
	VerifiedAt time.Time
	// CacheStale is true when the result was served from the cache past
	// its TTL because the live verifier returned an error. Callers can
	// surface this as a warning and policy can refuse stale data via
	// the ForbidCacheStale condition.
	CacheStale bool
	// LiveError, when non-nil, is the error from the live verifier on
	// the path that produced this result. Only set alongside
	// CacheStale=true so the caller can log why the live path failed.
	LiveError error
}

// VerifyWithCache runs the full Sigstore verify pipeline with a cache
// in front and a stale-fallback behind. The semantics are:
//
//  1. Cache hit and fresh: return cached identity, no network.
//  2. Cache miss or stale: run live Verify.
//     - Live success: update cache, return.
//     - Live failure with stale entry: return stale entry with
//     CacheStale=true and LiveError set.
//     - Live failure with no entry: return error.
//
// If cache is nil, behaves like a plain Verify call (no caching, no
// fallback).
func (v *Verifier) VerifyWithCache(cache *BundleCache, bundleJSON, artifactSHA256 []byte) (*VerifyResult, error) {
	if cache != nil {
		if id, verifiedAt, fresh, ok := cache.Get(bundleJSON, artifactSHA256); ok && fresh {
			return &VerifyResult{Identity: id, VerifiedAt: verifiedAt}, nil
		}
	}
	id, err := v.Verify(bundleJSON, artifactSHA256)
	if err == nil {
		now := time.Now()
		if cache != nil {
			// Best-effort cache write; verification result stands
			// regardless of write success.
			_ = cache.Put(bundleJSON, artifactSHA256, *id)
		}
		return &VerifyResult{Identity: *id, VerifiedAt: now}, nil
	}
	if cache != nil {
		if staleID, staleAt, _, ok := cache.Get(bundleJSON, artifactSHA256); ok {
			return &VerifyResult{
				Identity:   staleID,
				VerifiedAt: staleAt,
				CacheStale: true,
				LiveError:  err,
			}, nil
		}
	}
	return nil, err
}
