package intelligence

// The parent-POM cache, pinned end to end through runMaven against a server
// that counts requests. maven_pom_cache_test.go pins the map in isolation;
// these pin that the parent walk actually routes through it, and that the
// things it must never hold (a failure, a 404, a mutable version, another
// repository's document) are never served from it.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// parentCacheServer serves POM fixtures and counts .pom requests by path.
// failWith, when non-zero, answers every request for failPath with that
// status instead of the document.
type parentCacheServer struct {
	mu       sync.Mutex
	hits     map[string]int
	body     map[string]string
	failPath string
	failWith atomic.Int32
}

func newParentCacheServer(t *testing.T, poms ...pomFixture) (*parentCacheServer, string) {
	t.Helper()
	s := &parentCacheServer{hits: map[string]int{}, body: map[string]string{}}
	for _, f := range poms {
		s.body[f.path()] = f.xml()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits[r.URL.Path]++
		doc, ok := s.body[r.URL.Path]
		s.mu.Unlock()
		if r.URL.Path == s.failPath {
			if code := s.failWith.Load(); code != 0 {
				w.WriteHeader(int(code))
				return
			}
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(doc))
	}))
	t.Cleanup(srv.Close)
	return s, srv.URL
}

func (s *parentCacheServer) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[path]
}

func parentCacheProvider(base string) *registryMetadataProvider {
	p := newRegistryMetadataProvider()
	p.endpoints = defaultRegistryEndpoints()
	p.endpoints.maven = base
	p.endpoints.mavenGoogle = ""
	p.endpoints.github = base
	p.endpoints.gitlab = base
	p.endpoints.bitbucket = base
	p.endpoints.codeberg = base
	p.endpoints.depsdev = base
	return p
}

var (
	cacheParent = pomFixture{group: "org.example.cache", artifact: "house-parent", version: "54",
		licenses: []string{"Apache-2.0"}}
	cacheChildA = pomFixture{group: "org.example.cache", artifact: "lib-a", version: "1.0",
		parent: "org.example.cache:house-parent:54"}
	cacheChildB = pomFixture{group: "org.example.cache", artifact: "lib-b", version: "2.0",
		parent: "org.example.cache:house-parent:54"}
)

// Two scans of two different artifacts sharing a parent fetch it once.
func TestMavenParentPOMFetchedOnceAcrossScans(t *testing.T) {
	srv, base := newParentCacheServer(t, cacheParent, cacheChildA, cacheChildB)
	p := parentCacheProvider(base)

	if got := runMavenLicense(t, p, "org.example.cache:lib-a", "1.0"); got != "Apache-2.0" {
		t.Fatalf("lib-a licence = %q, want Apache-2.0 inherited from the parent", got)
	}
	if got := runMavenLicense(t, p, "org.example.cache:lib-b", "2.0"); got != "Apache-2.0" {
		t.Fatalf("lib-b licence = %q, want Apache-2.0 served from the cached parent", got)
	}
	if n := srv.count(cacheParent.path()); n != 1 {
		t.Errorf("shared parent fetched %d times across two scans, want 1", n)
	}
}

// A parent that fails with 503 is asked again on the next scan: a failure
// is never cached.
func TestMavenParentPOMFailureIsNotCached(t *testing.T) {
	srv, base := newParentCacheServer(t, cacheParent, cacheChildA, cacheChildB)
	srv.failPath = cacheParent.path()
	srv.failWith.Store(http.StatusServiceUnavailable)
	p := parentCacheProvider(base)

	pr, err := p.runMaven(context.Background(), "org.example.cache:lib-a", "1.0")
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarning(pr.Warnings, WarnLicenseUnavailable) {
		t.Fatalf("first scan: a 503 parent must leave the licence unknown; warnings=%+v", pr.Warnings)
	}
	first := srv.count(cacheParent.path())

	srv.failWith.Store(0)
	if got := runMavenLicense(t, p, "org.example.cache:lib-b", "2.0"); got != "Apache-2.0" {
		t.Fatalf("second scan licence = %q, want Apache-2.0 — the earlier 503 was served from cache", got)
	}
	if n := srv.count(cacheParent.path()); n <= first {
		t.Errorf("parent requests %d -> %d: the second scan did not re-ask after a failure", first, n)
	}
}

// A parent 404 is not cached either: re-asking costs nothing, and caching it
// would hide a parent published later.
func TestMavenParentPOM404IsNotCached(t *testing.T) {
	orphan := pomFixture{group: "org.example.cache", artifact: "orphan", version: "1.0",
		parent: "org.example.cache:absent-parent:1"}
	srv, base := newParentCacheServer(t, orphan)
	p := parentCacheProvider(base)
	missing := pomFixture{group: "org.example.cache", artifact: "absent-parent", version: "1"}.path()

	for i := 0; i < 2; i++ {
		runMavenLicense(t, p, "org.example.cache:orphan", "1.0")
	}
	if n := srv.count(missing); n != 2 {
		t.Errorf("404 parent fetched %d times across two scans, want 2 (a 404 must not be cached)", n)
	}
}

// Different repository bases never share an entry — neither a different
// repo1 base nor the same repo1 base with a different google fallback.
func TestMavenParentPOMCacheIsPerRepository(t *testing.T) {
	srvA, baseA := newParentCacheServer(t, cacheParent, cacheChildA)
	srvB, baseB := newParentCacheServer(t, cacheParent, cacheChildA)

	runMavenLicense(t, parentCacheProvider(baseA), "org.example.cache:lib-a", "1.0")
	runMavenLicense(t, parentCacheProvider(baseB), "org.example.cache:lib-a", "1.0")
	if a, b := srvA.count(cacheParent.path()), srvB.count(cacheParent.path()); a != 1 || b != 1 {
		t.Errorf("parent fetches: repo A=%d, repo B=%d; want 1 each — one base was served the other's document", a, b)
	}

	// Same repo1, different fallback host: the fallback's document is
	// stored under the base, so these must not share either.
	p2 := parentCacheProvider(baseA)
	p2.endpoints.mavenGoogle = baseB
	runMavenLicense(t, p2, "org.example.cache:lib-a", "1.0")
	if a := srvA.count(cacheParent.path()); a != 2 {
		t.Errorf("repo A parent fetched %d times, want 2 — a provider with a different google fallback shared the entry", a)
	}
}

// A -SNAPSHOT parent is republished in place, so it is never cached.
func TestMavenParentPOMSnapshotIsNotCached(t *testing.T) {
	parent := pomFixture{group: "org.example.cache", artifact: "snap-parent", version: "1.0-SNAPSHOT",
		licenses: []string{"MIT"}}
	child := pomFixture{group: "org.example.cache", artifact: "snap-child", version: "1.0",
		parent: "org.example.cache:snap-parent:1.0-SNAPSHOT"}
	srv, base := newParentCacheServer(t, parent, child)
	p := parentCacheProvider(base)

	for i := 0; i < 2; i++ {
		if got := runMavenLicense(t, p, "org.example.cache:snap-child", "1.0"); got != "MIT" {
			t.Fatalf("scan %d licence = %q, want MIT", i, got)
		}
	}
	if n := srv.count(parent.path()); n != 2 {
		t.Errorf("SNAPSHOT parent fetched %d times across two scans, want 2 (a mutable version must not be cached)", n)
	}
	for _, v := range []string{"1.0-SNAPSHOT", "LATEST", "RELEASE", "[1.0,2.0)"} {
		if !mavenVersionIsMutable(v) {
			t.Errorf("mavenVersionIsMutable(%q) = false", v)
		}
	}
	if mavenVersionIsMutable("54") {
		t.Error(`mavenVersionIsMutable("54") = true — a released version must be cacheable`)
	}
}

func hasWarning(ws []Warning, code string) bool {
	for _, w := range ws {
		if w.Code == code {
			return true
		}
	}
	return false
}
