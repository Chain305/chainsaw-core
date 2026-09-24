package intelligence

// A bounded, expiring cache for fetched POMs.
//
// WHY THIS EXISTS, AND WHY IT WAS PREVIOUSLY REFUSED. The parent-licence walk
// (`inheritMavenLicense`) documents a deliberate decision not to cache across
// packages: "A cache spanning packages would have to live on the provider,
// which is process-lifetime, unbounded and stale-prone; deliberately not done."
//
// Each of those three objections is answered here rather than waved away:
//
//   - **Unbounded** — capped at mavenPOMCacheMax entries.
//   - **Stale-prone** — every entry expires. A *released* Maven coordinate is
//     immutable, so the TTL is belt-and-braces rather than the main defence,
//     but it bounds the damage if a repository ever serves a mutated POM.
//   - **Process-lifetime** — still true, and now harmless: bounded size plus a
//     TTL means the worst case is a fixed, small amount of memory holding
//     documents that cannot legitimately change.
//
// The cost of NOT having it, measured by the ecosystem sweep on 2026-09-23:
// every Apache Commons artifact re-fetches `commons-parent`, every Spring
// artifact re-fetches its BOM, and so on. Parent POMs are the highest-
// multiplier immutable re-fetch in the product, and they go to
// repo1.maven.org — which is the host already rejecting the majority of our
// requests with 429.
//
// Keyed by ENDPOINT as well as coordinate. The repository base URL is
// configurable (and the google-maven fallback is a second host), so a
// coordinate alone does not identify a document — two providers pointed at
// different repositories would otherwise serve each other's POMs. Found by
// core's own parent-walk suite, where two tests share a guava-parent
// coordinate across two httptest servers.
//
// Eviction is a generation reset rather than an LRU: at the cap the whole map
// is dropped. Crude, but O(1), needs no per-entry bookkeeping, and for a cache
// of immutable documents the only cost of a wrong eviction is one refetch.
// hashicorp/golang-lru is available but only as an INDIRECT dependency, and
// promoting it would change go.mod and the standalone-build gate for a
// 40-line need.

import (
	"strings"
	"sync"
	"time"
)

const (
	// mavenPOMCacheMax bounds the entry count. A large refresh cycle touches a
	// few thousand coordinates but only a few hundred DISTINCT parents, which
	// is the population this holds.
	mavenPOMCacheMax = 512
	// mavenPOMCacheTTL expires entries. Long, because the documents are
	// immutable; finite, because "immutable" is a convention and not enforced.
	mavenPOMCacheTTL = time.Hour
)

type mavenPOMCacheEntry struct {
	pom     *mavenPOM
	expires time.Time
}

var (
	mavenPOMCacheMu sync.Mutex
	mavenPOMCache   = map[string]mavenPOMCacheEntry{}
)

// mavenVersionIsMutable reports whether a version names a document that can
// change under the same coordinate, and so must never be cached. A -SNAPSHOT
// is republished in place; LATEST / RELEASE are Maven 2 meta-versions that
// resolve to whatever was published last; a range (`[1.0,2.0)`) is not one
// version at all. Ranges are already refused by isSafeMavenCoordinateSegment
// before a URL is built, so they are listed here only so this guard does not
// depend on that one.
func mavenVersionIsMutable(version string) bool {
	v := strings.ToUpper(strings.TrimSpace(version))
	return strings.Contains(v, "SNAPSHOT") || v == "LATEST" || v == "RELEASE" ||
		strings.ContainsAny(v, "[](),")
}

// mavenPOMCacheKey namespaces a coordinate by the repository it came from.
func mavenPOMCacheKey(endpoint, group, artifact, version string) string {
	return endpoint + "\x00" + mavenCoordKey(group, artifact, version)
}

// lookupMavenPOM returns a cached POM for the coordinate, if one is live.
func lookupMavenPOM(endpoint, group, artifact, version string) (*mavenPOM, bool) {
	key := mavenPOMCacheKey(endpoint, group, artifact, version)
	mavenPOMCacheMu.Lock()
	defer mavenPOMCacheMu.Unlock()
	e, ok := mavenPOMCache[key]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.pom, true
}

// storeMavenPOM caches a successfully fetched POM. A mutable version (see
// mavenVersionIsMutable) is never cached. A FAILED fetch is never cached: a
// negative entry would turn one transient upstream error into an hour of
// missing licence inheritance across every child of that parent, which is
// worse than the refetch it saves.
func storeMavenPOM(endpoint, group, artifact, version string, pom *mavenPOM) {
	if pom == nil || mavenVersionIsMutable(version) {
		return
	}
	key := mavenPOMCacheKey(endpoint, group, artifact, version)
	mavenPOMCacheMu.Lock()
	defer mavenPOMCacheMu.Unlock()
	if len(mavenPOMCache) >= mavenPOMCacheMax {
		mavenPOMCache = make(map[string]mavenPOMCacheEntry, mavenPOMCacheMax)
	}
	mavenPOMCache[key] = mavenPOMCacheEntry{pom: pom, expires: time.Now().Add(mavenPOMCacheTTL)}
}

// resetMavenPOMCacheForTest clears the cache so tests do not leak into
// each other through process-lifetime state.
func resetMavenPOMCacheForTest() {
	mavenPOMCacheMu.Lock()
	defer mavenPOMCacheMu.Unlock()
	mavenPOMCache = map[string]mavenPOMCacheEntry{}
}
