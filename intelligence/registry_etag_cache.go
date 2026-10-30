package intelligence

import (
	"net/http"
	"os"
	"strconv"
	"sync"
)

// Conditional GETs for registry documents (docs/REPORTS.md
// #backend-perf-load-test-2026-10-29 J.4 I13-4).
//
// The refresher refetches the same registry documents (npm packuments, PyPI
// JSON, ...) on every pass, and most have not changed. A successful answer
// carrying an ETag is kept here with its headers; the next fetch of the
// same URL sends If-None-Match, and a 304 replays the kept body through the
// same decode as a 200. The analyzers run on the same bytes either way, so
// nothing here depends on an analyzer epoch: it saves download bytes, not
// parsing.
//
// Bounded by CHAINSAW_REGISTRY_ETAG_CACHE_MB (default 64; 0 turns it off),
// with a single document capped at a quarter of that. Same shape as
// maven_pom_cache.go: at the cap the whole map is dropped, since a wrong
// eviction only costs one full download.
type etagEntry struct {
	etag   string
	body   []byte
	header http.Header
}

var etagCache = struct {
	sync.Mutex
	m     map[string]etagEntry
	bytes int64
	limit int64 // -1 until read from the environment
}{m: map[string]etagEntry{}, limit: -1}

func etagCacheLimit() int64 {
	if etagCache.limit < 0 {
		mb := int64(64)
		if v, err := strconv.ParseInt(os.Getenv("CHAINSAW_REGISTRY_ETAG_CACHE_MB"), 10, 64); err == nil && v >= 0 {
			mb = v
		}
		etagCache.limit = mb << 20
	}
	return etagCache.limit
}

// etagEntryMax is the largest single document kept; 0 when the cache is off.
func etagEntryMax() int64 {
	etagCache.Lock()
	defer etagCache.Unlock()
	return etagCacheLimit() / 4
}

func etagCacheKey(endpoint, accept string) string { return accept + "\x00" + endpoint }

func etagCacheGet(key string) (etagEntry, bool) {
	etagCache.Lock()
	defer etagCache.Unlock()
	e, ok := etagCache.m[key]
	return e, ok
}

func etagCachePut(key string, e etagEntry) {
	etagCache.Lock()
	defer etagCache.Unlock()
	limit := etagCacheLimit()
	size := int64(len(e.body))
	if e.etag == "" || size > limit/4 {
		return
	}
	if old, ok := etagCache.m[key]; ok {
		etagCache.bytes -= int64(len(old.body))
	}
	if etagCache.bytes+size > limit {
		etagCache.m, etagCache.bytes = map[string]etagEntry{}, 0
	}
	etagCache.m[key] = e
	etagCache.bytes += size
}

// etagCacheDrop forgets key, for a document that stopped decoding.
func etagCacheDrop(key string) {
	etagCache.Lock()
	defer etagCache.Unlock()
	if old, ok := etagCache.m[key]; ok {
		etagCache.bytes -= int64(len(old.body))
		delete(etagCache.m, key)
	}
}
