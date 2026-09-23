package intelligence

// Version-less coordinates must resolve to the latest version in EVERY
// ecosystem, not just the four that had resolvers.
//
// Reported from production 2026-09-23: /pkg/maven/org.apache.neethi:neethi
// renders "is not indexed yet" while /pkg/npm/express resolves. Measured
// against the live public surface, the split is exactly
// latestResolvableEcosystems:
//
//	resolved     npm, pypi, cargo, rubygems
//	NOT INDEXED  maven, gradle, go, composer
//
// The default arm of ResolveLatestVersionEx returns LatestUnknown for those,
// so the page has no version to scan and shows the empty state. This is the
// same list that made the Go artifact fix dead code, which is a second reason
// to close it rather than special-case Maven.

import (
	"context"
	"net/http"
	"testing"
)

func TestResolveLatest_MavenAndGradle(t *testing.T) {
	withStubLatestRegistries(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Maven Central's maven-metadata.xml. <release> is the newest
		// non-snapshot and is what a version-less coordinate means; <latest>
		// can point at a SNAPSHOT, which must never be served as "latest".
		_, _ = w.Write([]byte(`<metadata>
  <groupId>org.apache.neethi</groupId>
  <artifactId>neethi</artifactId>
  <versioning>
    <latest>3.2.1-SNAPSHOT</latest>
    <release>3.2.0</release>
    <versions><version>3.1.1</version><version>3.2.0</version></versions>
  </versioning>
</metadata>`))
	}))
	for _, eco := range []string{"maven", "gradle"} {
		got := ResolveLatestVersion(context.Background(), eco, "org.apache.neethi:neethi")
		if got != "3.2.0" {
			t.Errorf("%s = %q, want 3.2.0 (the <release>, never the SNAPSHOT <latest>)", eco, got)
		}
	}
}

func TestResolveLatest_Go(t *testing.T) {
	withStubLatestRegistries(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Version":"v1.8.1","Time":"2023-01-01T00:00:00Z"}`))
	}))
	if got := ResolveLatestVersion(context.Background(), "go", "github.com/gorilla/mux"); got != "v1.8.1" {
		t.Errorf("go = %q, want v1.8.1", got)
	}
}

func TestResolveLatest_Composer(t *testing.T) {
	withStubLatestRegistries(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// packagist p2: newest first, and dev branches must be skipped.
		_, _ = w.Write([]byte(`{"packages":{"monolog/monolog":[
			{"version":"dev-main"},{"version":"3.5.0"},{"version":"3.4.0"}]}}`))
	}))
	if got := ResolveLatestVersion(context.Background(), "composer", "monolog/monolog"); got != "3.5.0" {
		t.Errorf("composer = %q, want 3.5.0 (dev-main must be skipped)", got)
	}
}

// A registry that answers with no usable version must yield "" rather than a
// guess. "" routes to LatestUnknown, which the caller renders as "we could not
// determine", not as "this package does not exist".
func TestResolveLatest_EmptyAnswersAreNotGuesses(t *testing.T) {
	withStubLatestRegistries(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"packages":{}}`))
	}))
	for _, eco := range []string{"maven", "gradle", "go", "composer"} {
		if got := ResolveLatestVersion(context.Background(), eco, "x"); got != "" {
			t.Errorf("%s invented %q from an empty answer", eco, got)
		}
	}
}
