package intelligence

// Parent POMs are the highest-multiplier immutable re-fetch in the product:
// every Apache Commons artifact walks to commons-parent, and that walk goes to
// repo1.maven.org — the host already rejecting most of our requests with 429.
//
// Caching across packages was previously refused as "process-lifetime,
// unbounded and stale-prone". These tests pin the answers to the second and
// third objections, so the refusal cannot be re-applied to this cache.

import (
	"testing"
	"time"
)

func TestMavenPOMCacheRoundTrips(t *testing.T) {
	resetMavenPOMCacheForTest()
	t.Cleanup(resetMavenPOMCacheForTest)

	const ep = "https://repo1.maven.org/maven2"
	want := &mavenPOM{GroupID: "org.apache.commons", ArtifactID: "commons-parent", Version: "54"}
	storeMavenPOM(ep, "org.apache.commons", "commons-parent", "54", want)

	got, ok := lookupMavenPOM(ep, "org.apache.commons", "commons-parent", "54")
	if !ok || got != want {
		t.Fatalf("cache miss on a coordinate just stored (ok=%v)", ok)
	}
	// A different version is a different coordinate.
	if _, ok := lookupMavenPOM(ep, "org.apache.commons", "commons-parent", "55"); ok {
		t.Error("version 55 hit an entry stored for 54")
	}
}

// Objection 1: unbounded. It is capped.
func TestMavenPOMCacheIsBounded(t *testing.T) {
	resetMavenPOMCacheForTest()
	t.Cleanup(resetMavenPOMCacheForTest)

	for i := 0; i < mavenPOMCacheMax*3; i++ {
		storeMavenPOM("https://r", "g", "a", string(rune('a'+i%26))+time.Now().Format("150405.000000000"), &mavenPOM{})
	}
	mavenPOMCacheMu.Lock()
	n := len(mavenPOMCache)
	mavenPOMCacheMu.Unlock()
	if n > mavenPOMCacheMax {
		t.Errorf("cache holds %d entries, cap is %d — the original objection to caching "+
			"across packages was that it would be unbounded", n, mavenPOMCacheMax)
	}
}

// Objection 2: stale-prone. Entries expire.
func TestMavenPOMCacheExpires(t *testing.T) {
	resetMavenPOMCacheForTest()
	t.Cleanup(resetMavenPOMCacheForTest)

	key := mavenPOMCacheKey("https://r", "g", "a", "1")
	mavenPOMCacheMu.Lock()
	mavenPOMCache[key] = mavenPOMCacheEntry{pom: &mavenPOM{}, expires: time.Now().Add(-time.Second)}
	mavenPOMCacheMu.Unlock()

	if _, ok := lookupMavenPOM("https://r", "g", "a", "1"); ok {
		t.Error("an expired entry was served; entries must expire so a mutated POM cannot " +
			"be pinned for the process lifetime")
	}
}

// A failed fetch must never be cached: a negative entry would turn one
// transient upstream error into an hour of missing licence inheritance across
// every child of that parent.
func TestMavenPOMCacheDoesNotStoreNil(t *testing.T) {
	resetMavenPOMCacheForTest()
	t.Cleanup(resetMavenPOMCacheForTest)

	storeMavenPOM("https://r", "g", "a", "1", nil)
	if _, ok := lookupMavenPOM("https://r", "g", "a", "1"); ok {
		t.Error("a nil POM was cached — a transient failure would suppress licence " +
			"inheritance for every child of this parent until the TTL expired")
	}
}

// Two repositories serving the same coordinate must not share a cache entry.
// The base URL is configurable and the google-maven fallback is a second host,
// so the coordinate alone does not identify a document. Core's own parent-walk
// suite caught this: two tests reuse a guava-parent coordinate across two
// httptest servers, and the second saw zero fetches.
func TestMavenPOMCacheIsKeyedByEndpoint(t *testing.T) {
	resetMavenPOMCacheForTest()
	t.Cleanup(resetMavenPOMCacheForTest)

	storeMavenPOM("https://repo-a", "g", "a", "1", &mavenPOM{GroupID: "from-a"})
	if _, ok := lookupMavenPOM("https://repo-b", "g", "a", "1"); ok {
		t.Fatal("a POM cached for repo-a was served to a provider pointed at repo-b; " +
			"the cache must be namespaced by repository or it serves the wrong document")
	}
	got, ok := lookupMavenPOM("https://repo-a", "g", "a", "1")
	if !ok || got.GroupID != "from-a" {
		t.Fatalf("repo-a lost its own entry (ok=%v)", ok)
	}
}
