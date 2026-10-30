package intelligence

import (
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/provenance"
)

// A bounded cache of Go module proxy @v/{ver}.info answers, across scans
// (docs/REPORTS.md#backend-perf-load-test-2026-10-29 J.4 I13-2).
//
// The refresher rescans every Go row every 1-7 days and each pass refetched
// the same .info. For a canonical version the answer is immutable: the
// checksum database pins a version's content, and the proxy serves the
// version's commit time and origin. Only a successful answer for a canonical
// version whose Version field equals the request is kept; a query such as a
// branch name resolves to whatever is newest and is never cached, and a 404
// is never cached (the version may be published later).
//
// Same shape as maven_pom_cache.go: keyed by URL (so by endpoint), a
// generation reset at the cap, a TTL as a backstop.
const (
	goInfoCacheMax = 8192
	// goInfoCacheTTL outlives the cold refresh window (~7 d), so a cold row
	// usually still hits on its next pass.
	goInfoCacheTTL = 8 * 24 * time.Hour
)

type goModuleInfo struct {
	Version string `json:"Version"`
	Time    string `json:"Time"`
	Origin  struct {
		URL  string `json:"URL"`
		Ref  string `json:"Ref"`
		Hash string `json:"Hash"`
	} `json:"Origin"`
}

type goInfoCacheEntry struct {
	info    goModuleInfo
	expires time.Time
}

var (
	goInfoCacheMu sync.Mutex
	goInfoCache   = map[string]goInfoCacheEntry{}
)

func goInfoCacheGet(infoURL string) (goModuleInfo, bool) {
	goInfoCacheMu.Lock()
	defer goInfoCacheMu.Unlock()
	e, ok := goInfoCache[infoURL]
	if !ok || time.Now().After(e.expires) {
		return goModuleInfo{}, false
	}
	return e.info, true
}

func goInfoCachePut(infoURL, requested string, info goModuleInfo) {
	if canonical, ok := provenance.CanonicalGoVersion(requested); !ok || canonical != requested || info.Version != requested {
		return
	}
	goInfoCacheMu.Lock()
	defer goInfoCacheMu.Unlock()
	if len(goInfoCache) >= goInfoCacheMax {
		goInfoCache = map[string]goInfoCacheEntry{}
	}
	goInfoCache[infoURL] = goInfoCacheEntry{info: info, expires: time.Now().Add(goInfoCacheTTL)}
}
