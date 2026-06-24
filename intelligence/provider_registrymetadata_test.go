package intelligence

// Unit tests for the registry-metadata provider. Stubs each registry
// with an httptest.Server so the tests are offline-safe and
// deterministic. Coverage focuses on the three most-travelled fetchers
// (npm, pypi, cargo) plus the XML path (maven). The remaining
// ecosystems share the same shared-helpers plumbing so a smoke test
// on these four is sufficient to catch regressions in the HTTP
// wrapping, response decoding, and field mapping.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func newStubProvider(t *testing.T, mux *http.ServeMux) (*registryMetadataProvider, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	p := newRegistryMetadataProvider()
	p.endpoints = registryEndpoints{
		npm:               srv.URL,
		pypi:              srv.URL,
		maven:             srv.URL,
		cargo:             srv.URL,
		rubygems:          srv.URL,
		nuget:             srv.URL,
		nugetRegistration: srv.URL,
		composer:          srv.URL,
		goproxy:           srv.URL,
		cocoapods:         srv.URL,
		cocoapodsCDN:      srv.URL,
		pub:               srv.URL,
		huggingface:       srv.URL,
		docker:            srv.URL,
		depsdev:           srv.URL,
		github:            srv.URL,
		gitlab:            srv.URL,
		bitbucket:         srv.URL,
		codeberg:          srv.URL,
	}
	return p, srv
}

func TestRegistryMetadataProvider_NPM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy-addr", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name": "proxy-addr",
			"description": "Determine address of proxied request",
			"homepage": "https://github.com/jshttp/proxy-addr#readme",
			"dist-tags": {"latest": "2.0.7"},
			"time": {"2.0.7": "2021-05-31T12:34:00.000Z", "created": "2014-10-10T00:00:00.000Z"},
			"maintainers": [{"name": "dougwilson", "email": "doug@somethingdoug.com"}],
			"versions": {
				"2.0.7": {
					"license": "MIT",
					"description": "Determine address of proxied request",
					"homepage": "https://github.com/jshttp/proxy-addr#readme",
					"repository": {"type":"git","url":"git+https://github.com/jshttp/proxy-addr.git"},
					"bugs": {"url":"https://github.com/jshttp/proxy-addr/issues"},
					"dist": {
						"tarball": "https://registry.npmjs.org/proxy-addr/-/proxy-addr-2.0.7.tgz",
						"shasum": "f19fe69ceab311eeb94b42e70e8c2070f9ba1025",
						"integrity": "sha512-abc"
					},
					"maintainers": [{"name": "dougwilson", "email": "doug@somethingdoug.com"}],
					"_npmUser": {"name": "dougwilson"}
				}
			}
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "npm", Package: "proxy-addr", Version: "2.0.7"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pr.Warnings) > 0 {
		t.Fatalf("unexpected warnings: %+v", pr.Warnings)
	}
	if pr.Metadata == nil || pr.Metadata.LicenseExpression != "MIT" {
		t.Fatalf("license: got %+v", pr.Metadata)
	}
	if pr.Release == nil || pr.Release.PublishedAt == nil {
		t.Fatalf("publishedAt not set: %+v", pr.Release)
	}
	if pr.Release.LatestVersion != "2.0.7" {
		t.Fatalf("latestVersion: %q", pr.Release.LatestVersion)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/jshttp/proxy-addr" {
		t.Fatalf("sourceRepoURL: got %+v", pr.URLs)
	}
	if pr.Artifact == nil || pr.Artifact.Digests.SHA1 == "" {
		t.Fatalf("artifact digest missing: %+v", pr.Artifact)
	}
	if pr.People == nil || len(pr.People.Maintainers) == 0 {
		t.Fatalf("maintainers missing: %+v", pr.People)
	}
	if pr.Provenance == nil || pr.Provenance.SourceRepo == "" {
		t.Fatalf("provenance.sourceRepo missing: %+v", pr.Provenance)
	}
}

// TestRegistryMetadataProvider_NPMVersionTimeline locks in the
// sparse-data-cascade fix: the registry-metadata provider must extract
// the FULL set of (version, publishedAt) tuples from the npm packument
// — not just the requested version — and surface them on
// MaintenanceSection.VersionTimeline. This is the substrate that
// downstream VersionCount and metadiff.semver_regression rely on, so a
// regression here re-introduces the false-flag-on-jose@5.10.0 bug.
func TestRegistryMetadataProvider_NPMVersionTimeline(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/jose", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name": "jose",
			"dist-tags": {"latest": "6.2.3"},
			"time": {
				"5.0.0": "2023-12-01T00:00:00.000Z",
				"5.10.0": "2024-11-01T00:00:00.000Z",
				"6.0.0": "2025-03-01T00:00:00.000Z",
				"6.2.3": "2025-09-01T00:00:00.000Z"
			},
			"versions": {
				"5.0.0": {"license": "MIT", "dist": {"tarball": "x", "shasum": "a"}},
				"5.10.0": {"license": "MIT", "dist": {"tarball": "x", "shasum": "b"}},
				"6.0.0": {"license": "MIT", "dist": {"tarball": "x", "shasum": "c"}},
				"6.2.3": {"license": "MIT", "dist": {"tarball": "x", "shasum": "d"}}
			}
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "npm", Package: "jose", Version: "5.10.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil {
		t.Fatalf("Maintenance: got nil, want populated VersionTimeline")
	}
	if got, want := len(pr.Maintenance.VersionTimeline), 4; got != want {
		t.Fatalf("VersionTimeline len: got %d, want %d (%+v)", got, want, pr.Maintenance.VersionTimeline)
	}
	// Build a quick lookup so we can assert each version got the right
	// publishedAt without depending on map-iteration order.
	got := map[string]string{}
	for _, v := range pr.Maintenance.VersionTimeline {
		got[v.Version] = v.PublishedAt.UTC().Format("2006-01-02")
	}
	want := map[string]string{
		"5.0.0":  "2023-12-01",
		"5.10.0": "2024-11-01",
		"6.0.0":  "2025-03-01",
		"6.2.3":  "2025-09-01",
	}
	for ver, wantDate := range want {
		if got[ver] != wantDate {
			t.Errorf("VersionTimeline[%q].PublishedAt: got %q, want %q", ver, got[ver], wantDate)
		}
	}
}

// TestRegistryMetadataProvider_NPMVersionTimelineMissingTime — the
// `time` map can be missing for some entries on real packuments
// (registries occasionally drop ancient timestamps). The provider must
// still surface the versions with a zero PublishedAt rather than
// dropping them, so VersionCount stays accurate.
func TestRegistryMetadataProvider_NPMVersionTimelineMissingTime(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/has-no-time", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name": "has-no-time",
			"dist-tags": {"latest": "1.0.0"},
			"versions": {
				"0.9.0": {"license": "MIT", "dist": {"tarball": "x", "shasum": "a"}},
				"1.0.0": {"license": "MIT", "dist": {"tarball": "x", "shasum": "b"}}
			}
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "npm", Package: "has-no-time", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil || len(pr.Maintenance.VersionTimeline) != 2 {
		t.Fatalf("VersionTimeline: got %+v, want 2 entries even without `time` map", pr.Maintenance)
	}
}

func TestRegistryMetadataProvider_NPMScopedPackage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/@babel/core", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"@babel/core","dist-tags":{"latest":"7.0.0"},"versions":{"7.0.0":{"license":"MIT","dist":{"tarball":"x","shasum":"abc"}}},"time":{"7.0.0":"2018-01-01T00:00:00Z"}}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "npm", Package: "@babel/core", Version: "7.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pr.Warnings) > 0 {
		t.Fatalf("warnings: %+v", pr.Warnings)
	}
	if pr.Metadata.LicenseExpression != "MIT" {
		t.Fatalf("license: %q", pr.Metadata.LicenseExpression)
	}
}

func TestRegistryMetadataProvider_PyPI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/requests/2.31.0/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"info": {
				"author": "Kenneth Reitz",
				"author_email": "me@kennethreitz.org",
				"license": "Apache 2.0",
				"summary": "Python HTTP for Humans.",
				"description": "Full description here.",
				"home_page": "https://requests.readthedocs.io",
				"project_urls": {"Source": "https://github.com/psf/requests", "Issues": "https://github.com/psf/requests/issues"},
				"requires_python": ">=3.7"
			},
			"urls": [
				{"filename": "requests-2.31.0-py3-none-any.whl", "packagetype": "bdist_wheel", "size": 62574, "url": "https://files.pythonhosted.org/x.whl", "upload_time_iso_8601": "2023-05-22T15:12:00.000Z", "digests": {"sha256": "deadbeef"}},
				{"filename": "requests-2.31.0.tar.gz", "packagetype": "sdist", "size": 110000, "url": "https://files.pythonhosted.org/x.tar.gz", "upload_time_iso_8601": "2023-05-22T15:12:00.000Z", "digests": {"sha256": "bead"}}
			]
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "pypi", Package: "requests", Version: "2.31.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Metadata == nil || !strings.Contains(pr.Metadata.LicenseExpression, "Apache") {
		t.Fatalf("license: %+v", pr.Metadata)
	}
	if pr.Artifact == nil || pr.Artifact.Filename == "" || pr.Artifact.Packaging != "bdist_wheel" {
		t.Fatalf("artifact preference: %+v", pr.Artifact)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/psf/requests" {
		t.Fatalf("sourceRepoURL: %+v", pr.URLs)
	}
	if pr.People == nil || len(pr.People.Authors) == 0 {
		t.Fatalf("authors: %+v", pr.People)
	}
}

func TestRegistryMetadataProvider_Cargo(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/crates/serde/1.0.200", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"crate": {"homepage": "https://serde.rs", "repository": "https://github.com/serde-rs/serde", "description": "serialization", "keywords": ["serialization"], "license": "MIT OR Apache-2.0"},
			"version": {"license": "MIT OR Apache-2.0", "created_at": "2024-04-18T00:00:00Z", "dl_path": "/api/v1/crates/serde/1.0.200/download", "crate_size": 123456, "checksum": "abcd", "yanked": false, "published_by": {"login": "dtolnay", "name": "David Tolnay"}}
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "cargo", Package: "serde", Version: "1.0.200"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Metadata.LicenseExpression != "MIT OR Apache-2.0" {
		t.Fatalf("license: %q", pr.Metadata.LicenseExpression)
	}
	if pr.Artifact.Digests.SHA256 != "abcd" {
		t.Fatalf("sha256: %q", pr.Artifact.Digests.SHA256)
	}
	if pr.People == nil || len(pr.People.PublisherIDs) == 0 {
		t.Fatalf("publisherIds: %+v", pr.People)
	}
}

func TestRegistryMetadataProvider_MavenPOM(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/com/google/guava/guava/32.0.0-jre/guava-32.0.0-jre.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?>
<project>
	<groupId>com.google.guava</groupId>
	<artifactId>guava</artifactId>
	<version>32.0.0-jre</version>
	<name>Guava</name>
	<description>Guava is a suite of core and expanded libraries.</description>
	<url>https://github.com/google/guava</url>
	<licenses><license><name>Apache License, Version 2.0</name></license></licenses>
	<scm><url>https://github.com/google/guava</url></scm>
</project>`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "maven", Package: "com.google.guava:guava", Version: "32.0.0-jre"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Metadata == nil || !strings.Contains(pr.Metadata.LicenseExpression, "Apache") {
		t.Fatalf("license: %+v", pr.Metadata)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/google/guava" {
		t.Fatalf("sourceRepoURL: %+v", pr.URLs)
	}
}

func TestRegistryMetadataProvider_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/missing-pkg", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "npm", Package: "missing-pkg", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run should not error on 404: %v", err)
	}
	if len(pr.Warnings) == 0 || pr.Warnings[0].Code != "not_found" {
		t.Fatalf("expected not_found warning, got: %+v", pr.Warnings)
	}
}

func TestRegistryMetadataProvider_UnsupportedEcosystem(t *testing.T) {
	p := newRegistryMetadataProvider()
	if p.Supports("apt") || p.Supports("dnf") {
		t.Fatal("Supports should return false for non-packument ecosystems")
	}
	if !p.Supports("huggingface") || !p.Supports("go") || !p.Supports("docker") || !p.Supports("cocoapods") || !p.Supports("pub") {
		t.Fatal("Supports should return true for the new fetcher ecosystems")
	}
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "apt", Package: "bash", Version: "5.1"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Release != nil || pr.Metadata != nil || len(pr.Warnings) != 0 {
		t.Fatalf("expected empty partial for unsupported ecosystem, got: %+v", pr)
	}
}

func TestRegistryMetadataProvider_NPMIntegrity(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/has-integrity", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name":"has-integrity",
			"dist-tags":{"latest":"1.0.0"},
			"versions":{
				"1.0.0":{
					"license":"MIT",
					"dist":{
						"tarball":"https://example.com/x.tgz",
						"shasum":"deadbeef",
						"integrity":"sha512-AbC123=="
					}
				}
			}
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "npm", Package: "has-integrity", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Artifact == nil || pr.Artifact.Digests.SHA1 != "deadbeef" {
		t.Fatalf("sha1: %+v", pr.Artifact)
	}
	if pr.Artifact.Digests.Integrity != "sha512-AbC123==" {
		t.Fatalf("integrity not surfaced: %+v", pr.Artifact)
	}
}

func TestRegistryMetadataProvider_PyPIYankedReason(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/badpkg/1.0.0/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"info": {"yanked": true, "yanked_reason": "security issue"},
			"urls": []
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "pypi", Package: "badpkg", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Release == nil || pr.Release.Yanked == nil || !*pr.Release.Yanked {
		t.Fatalf("yanked not set: %+v", pr.Release)
	}
	if !strings.Contains(pr.Release.Deprecated, "security issue") {
		t.Fatalf("yanked reason not surfaced: %q", pr.Release.Deprecated)
	}
}

func TestRegistryMetadataProvider_PyPIRequiresDistExtras(t *testing.T) {
	d := parsePyPIRequiresDist([]string{
		"requests[security] >=2.27",
		"pytest >=7 ; extra == 'test'",
		"numpy",
	})
	if len(d.direct) != 2 || len(d.optional) != 1 {
		t.Fatalf("buckets: direct=%d optional=%d", len(d.direct), len(d.optional))
	}
	if d.direct[0].Name != "requests" {
		t.Fatalf("first direct name: %q", d.direct[0].Name)
	}
	if d.direct[0].Constraint != ">=2.27" {
		t.Fatalf("constraint should drop extras: %q", d.direct[0].Constraint)
	}
	if d.optional[0].Name != "pytest" {
		t.Fatalf("optional name: %q", d.optional[0].Name)
	}
}

func TestRegistryMetadataProvider_MavenClassifier(t *testing.T) {
	g, a, c := splitMavenCoordinate("com.foo:bar:sources")
	if g != "com.foo" || a != "bar" || c != "sources" {
		t.Fatalf("3-segment: g=%q a=%q c=%q", g, a, c)
	}
	g, a, c = splitMavenCoordinate("com.foo:bar:1.0:javadoc")
	if g != "com.foo" || a != "bar" || c != "javadoc" {
		t.Fatalf("4-segment: g=%q a=%q c=%q", g, a, c)
	}
	g, a, c = splitMavenCoordinate("com.foo:bar")
	if g != "com.foo" || a != "bar" || c != "" {
		t.Fatalf("2-segment: g=%q a=%q c=%q", g, a, c)
	}
}

func TestRunGo(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/github.com/foo/!bar/@v/v1.2.3.info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Version":"v1.2.3","Time":"2024-01-15T12:00:00Z","Origin":{"URL":"https://github.com/foo/Bar","Ref":"refs/tags/v1.2.3","Hash":"abc"}}`))
	})
	mux.HandleFunc("/github.com/foo/!bar/@latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Version":"v1.2.4","Time":"2024-02-01T00:00:00Z"}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "go", Package: "github.com/foo/Bar", Version: "v1.2.3"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pr.Warnings) > 0 {
		t.Fatalf("warnings: %+v", pr.Warnings)
	}
	if pr.Release == nil || pr.Release.PublishedAt == nil {
		t.Fatalf("publishedAt missing: %+v", pr.Release)
	}
	if pr.Release.LatestVersion != "v1.2.4" {
		t.Fatalf("latestVersion: %q", pr.Release.LatestVersion)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/foo/Bar" {
		t.Fatalf("sourceRepoURL: %+v", pr.URLs)
	}
	if pr.Provenance == nil || pr.Provenance.SourceRepo == "" {
		t.Fatalf("provenance: %+v", pr.Provenance)
	}
}

func TestRunGoNotFound(t *testing.T) {
	mux := http.NewServeMux()
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "go", Package: "example.com/missing", Version: "v0.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pr.Warnings) == 0 {
		t.Fatalf("expected a not_found warning")
	}
}

// registerGoBaseRoutes registers the .info + @latest endpoints reused by
// the dependency-extraction tests below so they only need to wire the
// per-test .mod handler.
func registerGoBaseRoutes(mux *http.ServeMux, encodedModule string) {
	mux.HandleFunc("/"+encodedModule+"/@v/v1.2.3.info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Version":"v1.2.3","Time":"2024-01-15T12:00:00Z","Origin":{"URL":"https://github.com/foo/Bar","Ref":"refs/tags/v1.2.3","Hash":"abc"}}`))
	})
	mux.HandleFunc("/"+encodedModule+"/@latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Version":"v1.2.4"}`))
	})
}

func TestRegistryMetadataProvider_GoDependencies(t *testing.T) {
	mux := http.NewServeMux()
	const encModule = "github.com/foo/!bar"
	registerGoBaseRoutes(mux, encModule)
	mux.HandleFunc("/"+encModule+"/@v/v1.2.3.mod", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(`module github.com/foo/Bar

go 1.21

require (
	github.com/stretchr/testify v1.9.0
	golang.org/x/text v0.14.0 // indirect
)
`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "go", Package: "github.com/foo/Bar", Version: "v1.2.3"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pr.Warnings) > 0 {
		t.Fatalf("unexpected warnings: %+v", pr.Warnings)
	}
	if pr.Dependencies == nil {
		t.Fatalf("expected Dependencies to be populated")
	}
	if got := len(pr.Dependencies.Direct); got != 1 {
		t.Fatalf("Direct length: want 1 (indirect skipped), got %d (%+v)", got, pr.Dependencies.Direct)
	}
	d := pr.Dependencies.Direct[0]
	if d.Name != "github.com/stretchr/testify" {
		t.Fatalf("direct name: %q", d.Name)
	}
	if d.Constraint != "v1.9.0" {
		t.Fatalf("direct constraint: %q", d.Constraint)
	}
	// Sanity: existing fields untouched.
	if pr.Release == nil || pr.Release.LatestVersion != "v1.2.4" {
		t.Fatalf("latestVersion lost: %+v", pr.Release)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/foo/Bar" {
		t.Fatalf("sourceRepoURL lost: %+v", pr.URLs)
	}
}

func TestRegistryMetadataProvider_GoDependencies_PseudoVersion(t *testing.T) {
	mux := http.NewServeMux()
	const encModule = "github.com/foo/!bar"
	registerGoBaseRoutes(mux, encModule)
	mux.HandleFunc("/"+encModule+"/@v/v1.2.3.mod", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(`module github.com/foo/Bar

go 1.21

require golang.org/x/sync v0.0.0-20240101000000-abc123def456
`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "go", Package: "github.com/foo/Bar", Version: "v1.2.3"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pr.Warnings) > 0 {
		t.Fatalf("unexpected warnings: %+v", pr.Warnings)
	}
	if pr.Dependencies == nil || len(pr.Dependencies.Direct) != 1 {
		t.Fatalf("expected one direct dep: %+v", pr.Dependencies)
	}
	d := pr.Dependencies.Direct[0]
	if d.Name != "golang.org/x/sync" {
		t.Fatalf("pseudo dep name: %q", d.Name)
	}
	if d.Constraint != "v0.0.0-20240101000000-abc123def456" {
		t.Fatalf("pseudo-version constraint should propagate verbatim, got %q", d.Constraint)
	}
}

func TestRegistryMetadataProvider_GoDependencies_FetchFailSoft(t *testing.T) {
	mux := http.NewServeMux()
	const encModule = "github.com/foo/!bar"
	registerGoBaseRoutes(mux, encModule)
	mux.HandleFunc("/"+encModule+"/@v/v1.2.3.mod", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "go", Package: "github.com/foo/Bar", Version: "v1.2.3"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Dependencies != nil {
		t.Fatalf("Dependencies should be nil on mod fetch failure: %+v", pr.Dependencies)
	}
	// Primary .info path still produced a Release section.
	if pr.Release == nil || pr.Release.LatestVersion != "v1.2.4" {
		t.Fatalf("primary fetch broken: %+v", pr.Release)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/foo/Bar" {
		t.Fatalf("primary URLs lost: %+v", pr.URLs)
	}
	found := false
	for _, w := range pr.Warnings {
		if w.Code == "mod_fetch_failed" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected mod_fetch_failed warning, got: %+v", pr.Warnings)
	}
}

func TestRegistryMetadataProvider_GoDependencies_ParseFailSoft(t *testing.T) {
	mux := http.NewServeMux()
	const encModule = "github.com/foo/!bar"
	registerGoBaseRoutes(mux, encModule)
	mux.HandleFunc("/"+encModule+"/@v/v1.2.3.mod", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// Garbage that modfile.Parse cannot interpret.
		_, _ = w.Write([]byte("this is !! not a go.mod file @@@\nrequire ((( bogus\n"))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "go", Package: "github.com/foo/Bar", Version: "v1.2.3"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Dependencies != nil {
		t.Fatalf("Dependencies should be nil on parse failure: %+v", pr.Dependencies)
	}
	if pr.Release == nil || pr.Release.LatestVersion != "v1.2.4" {
		t.Fatalf("primary fetch broken: %+v", pr.Release)
	}
	found := false
	for _, w := range pr.Warnings {
		if w.Code == "mod_fetch_failed" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected mod_fetch_failed warning on parse failure, got: %+v", pr.Warnings)
	}
}

func TestRunCocoapods(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/pods/AFNetworking", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name":"AFNetworking",
			"versions":[{"name":"4.0.0","created_at":"2020-05-01T00:00:00Z"},{"name":"4.0.1","created_at":"2020-06-01T00:00:00Z"}],
			"owners":[{"name":"Mattt","email":"mattt@example.com"}]
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "cocoapods", Package: "AFNetworking", Version: "4.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pr.Warnings) > 0 {
		t.Fatalf("warnings: %+v", pr.Warnings)
	}
	if pr.Release == nil || pr.Release.PublishedAt == nil {
		t.Fatalf("publishedAt missing: %+v", pr.Release)
	}
	if pr.Release.LatestVersion != "4.0.1" {
		t.Fatalf("latestVersion: %q", pr.Release.LatestVersion)
	}
	if pr.People == nil || len(pr.People.Maintainers) == 0 {
		t.Fatalf("maintainers missing: %+v", pr.People)
	}
}

func TestRunHuggingFace(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models/bert-base-uncased/revision/main", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"modelId":"bert-base-uncased",
			"id":"bert-base-uncased",
			"sha":"deadbeefcafe",
			"lastModified":"2024-08-01T00:00:00Z",
			"tags":["pytorch","bert"],
			"pipeline_tag":"fill-mask",
			"library_name":"transformers",
			"author":"google",
			"cardData":{"license":"apache-2.0"}
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "huggingface", Package: "bert-base-uncased", Version: "main"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pr.Warnings) > 0 {
		t.Fatalf("warnings: %+v", pr.Warnings)
	}
	if pr.Metadata == nil || pr.Metadata.LicenseExpression != "apache-2.0" {
		t.Fatalf("license: %+v", pr.Metadata)
	}
	if pr.Artifact == nil || pr.Artifact.Digests.SHA256 != "deadbeefcafe" {
		t.Fatalf("sha256: %+v", pr.Artifact)
	}
	if pr.Release == nil || pr.Release.ModifiedAt == nil {
		t.Fatalf("modifiedAt: %+v", pr.Release)
	}
}

func TestRunHuggingFaceNotFound(t *testing.T) {
	mux := http.NewServeMux()
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "huggingface", Package: "fake/model", Version: "main"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pr.Warnings) == 0 {
		t.Fatalf("expected warning on missing repo")
	}
}

func TestRunDocker(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/repositories/library/nginx/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"user":"library","name":"nginx","namespace":"library",
			"description":"Official build of Nginx",
			"full_description":"## Long description","pull_count":1234567,
			"last_updated":"2024-09-01T00:00:00Z",
			"date_registered":"2014-06-05T00:00:00Z"
		}`))
	})
	mux.HandleFunc("/v2/repositories/library/nginx/tags/1.27/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name":"1.27","full_size":54321,"last_updated":"2024-09-15T00:00:00Z",
			"digest":"sha256:abc123"
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "docker", Package: "nginx", Version: "1.27"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pr.Warnings) > 0 {
		t.Fatalf("warnings: %+v", pr.Warnings)
	}
	if pr.Artifact == nil || pr.Artifact.Digests.SHA256 != "abc123" {
		t.Fatalf("digest: %+v", pr.Artifact)
	}
	if pr.Artifact.Size != 54321 {
		t.Fatalf("size: %d", pr.Artifact.Size)
	}
	if pr.Release == nil || pr.Release.PublishedAt == nil {
		t.Fatalf("publishedAt: %+v", pr.Release)
	}
	if pr.Metadata == nil || !strings.Contains(pr.Metadata.Summary, "Nginx") {
		t.Fatalf("summary: %+v", pr.Metadata)
	}
}

func TestRunDockerNamespacedImage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/repositories/bitnami/redis/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user":"bitnami","name":"redis","namespace":"bitnami","description":"Redis"}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "docker", Package: "bitnami/redis", Version: "7.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pr.Warnings) > 0 {
		t.Fatalf("warnings: %+v", pr.Warnings)
	}
	if pr.People == nil || len(pr.People.PublisherIDs) == 0 || pr.People.PublisherIDs[0] != "bitnami" {
		t.Fatalf("publisherIds: %+v", pr.People)
	}
}

// -- Cross-ecosystem version-timeline coverage -----------------------
//
// The five tests below lock in the new fan-out of the version-timeline
// extraction across ecosystems that lacked it before. Each builds a
// large-ish fixture (50–200 versions) so a future "off-by-one when
// pagination kicks in" regression shows up immediately.

// pypiTimelineFixture returns a json packument with n synthetic
// versions starting at start and incrementing by one day per release.
// Each release entry holds a single upload record matching real PyPI
// shape.
func pypiTimelineFixture(start time.Time, n int) string {
	var b strings.Builder
	b.WriteString(`{"info":{"version":"1.` + fmt.Sprint(n-1) + `.0"},"releases":{`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		ver := fmt.Sprintf("1.%d.0", i)
		ts := start.Add(time.Duration(i) * 24 * time.Hour).UTC().Format(time.RFC3339)
		fmt.Fprintf(&b, `"%s":[{"upload_time_iso_8601":"%s","filename":"x.tar.gz"}]`, ver, ts)
	}
	b.WriteString(`}}`)
	return b.String()
}

func TestRegistryMetadataProvider_PyPITimeline(t *testing.T) {
	start := time.Date(2014, 1, 1, 0, 0, 0, 0, time.UTC)
	mux := http.NewServeMux()
	// Per-version endpoint — minimal but valid.
	mux.HandleFunc("/pypi/idna/3.6/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"info":{"summary":"idna"},"urls":[]}`))
	})
	// Project-level endpoint — full timeline.
	mux.HandleFunc("/pypi/idna/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(pypiTimelineFixture(start, 24)))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "pypi", Package: "idna", Version: "3.6"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil {
		t.Fatalf("Maintenance: got nil, want VersionTimeline populated")
	}
	if got := len(pr.Maintenance.VersionTimeline); got <= 10 {
		t.Fatalf("VersionTimeline len: got %d, want >10", got)
	}
	if pr.Maintenance.FirstPublishedAt == nil {
		t.Fatalf("FirstPublishedAt: got nil")
	}
	if pr.Maintenance.FirstPublishedAt.Year() >= 2020 {
		t.Fatalf("FirstPublishedAt: got %v, want well before 2020", pr.Maintenance.FirstPublishedAt)
	}
	if pr.Release == nil || pr.Release.LatestVersion == "" {
		t.Fatalf("LatestVersion: not set (%+v)", pr.Release)
	}
}

// cargoTimelineFixture returns a /api/v1/crates/{crate} response with
// `n` version records, one day apart.
func cargoTimelineFixture(start time.Time, n int, maxVersion string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"crate":{"max_version":"%s","max_stable_version":"%s","newest_version":"%s"},"versions":[`, maxVersion, maxVersion, maxVersion)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		ver := fmt.Sprintf("1.0.%d", i)
		ts := start.Add(time.Duration(i) * 24 * time.Hour).UTC().Format(time.RFC3339)
		fmt.Fprintf(&b, `{"num":"%s","created_at":"%s"}`, ver, ts)
	}
	b.WriteString(`]}`)
	return b.String()
}

func TestRegistryMetadataProvider_CargoTimeline(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/crates/serde/1.0.99", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"description":"ser"},"version":{"license":"MIT","created_at":"2024-01-01T00:00:00Z"}}`))
	})
	mux.HandleFunc("/api/v1/crates/serde", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		start := time.Date(2014, 8, 1, 0, 0, 0, 0, time.UTC)
		_, _ = w.Write([]byte(cargoTimelineFixture(start, 150, "1.0.149")))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "cargo", Package: "serde", Version: "1.0.99"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil {
		t.Fatalf("Maintenance: nil")
	}
	if got := len(pr.Maintenance.VersionTimeline); got <= 100 {
		t.Fatalf("VersionTimeline len: got %d, want >100", got)
	}
	if pr.Maintenance.FirstPublishedAt == nil || pr.Maintenance.FirstPublishedAt.Year() != 2014 {
		t.Fatalf("FirstPublishedAt: got %v, want 2014", pr.Maintenance.FirstPublishedAt)
	}
	if pr.Release == nil || pr.Release.LatestVersion != "1.0.149" {
		t.Fatalf("LatestVersion: %+v", pr.Release)
	}
}

// rubygemsTimelineFixture returns the `[{number, created_at}]` shape
// the /api/v1/versions/{gem}.json endpoint emits.
func rubygemsTimelineFixture(start time.Time, n int) string {
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		ver := fmt.Sprintf("7.0.%d", i)
		ts := start.Add(time.Duration(i) * 24 * time.Hour).UTC().Format(time.RFC3339)
		fmt.Fprintf(&b, `{"number":"%s","created_at":"%s","prerelease":false}`, ver, ts)
	}
	b.WriteByte(']')
	return b.String()
}

func TestRegistryMetadataProvider_RubyGemsTimeline(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/rubygems/rails/versions/7.0.0.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"rails","version":"7.0.0","authors":"DHH","created_at":"2021-12-15T00:00:00Z","licenses":["MIT"],"info":"web framework"}`))
	})
	mux.HandleFunc("/api/v1/versions/rails.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		start := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
		_, _ = w.Write([]byte(rubygemsTimelineFixture(start, 130)))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "rubygems", Package: "rails", Version: "7.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil {
		t.Fatalf("Maintenance: nil")
	}
	if got := len(pr.Maintenance.VersionTimeline); got <= 100 {
		t.Fatalf("VersionTimeline len: got %d, want >100", got)
	}
	if pr.Maintenance.FirstPublishedAt == nil || pr.Maintenance.FirstPublishedAt.Year() != 2010 {
		t.Fatalf("FirstPublishedAt: got %v, want 2010", pr.Maintenance.FirstPublishedAt)
	}
}

func TestRegistryMetadataProvider_NuGetTimeline(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/newtonsoft.json/13.0.3/newtonsoft.json.nuspec", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><package><metadata><id>Newtonsoft.Json</id><version>13.0.3</version><authors>James Newton-King</authors></metadata></package>`))
	})
	// Registration catalog endpoint.
	mux.HandleFunc("/newtonsoft.json/index.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"items":[
				{"items":[
					{"catalogEntry":{"version":"12.0.0","published":"2018-12-01T00:00:00Z"}},
					{"catalogEntry":{"version":"12.0.1","published":"2019-03-01T00:00:00Z"}},
					{"catalogEntry":{"version":"13.0.0","published":"2021-03-01T00:00:00Z"}},
					{"catalogEntry":{"version":"13.0.3","published":"2023-03-01T00:00:00Z"}}
				]}
			]
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "nuget", Package: "Newtonsoft.Json", Version: "13.0.3"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil || len(pr.Maintenance.VersionTimeline) != 4 {
		t.Fatalf("VersionTimeline: %+v", pr.Maintenance)
	}
	if pr.Maintenance.FirstPublishedAt == nil || pr.Maintenance.FirstPublishedAt.Year() != 2018 {
		t.Fatalf("FirstPublishedAt: got %v, want 2018", pr.Maintenance.FirstPublishedAt)
	}
	if pr.Release == nil || pr.Release.LatestVersion != "13.0.3" {
		t.Fatalf("LatestVersion: %+v", pr.Release)
	}
}

func TestRegistryMetadataProvider_ComposerTimeline(t *testing.T) {
	mux := http.NewServeMux()
	// p2 returns ALL versions inline, including the one we requested.
	mux.HandleFunc("/p2/monolog/monolog.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"packages":{
				"monolog/monolog":[
					{"version":"3.5.0","time":"2024-01-05T12:00:00+00:00","source":{"url":"https://github.com/Seldaek/monolog","type":"git"},"dist":{"url":"u","type":"zip"}},
					{"version":"3.4.0","time":"2023-09-01T00:00:00+00:00","source":{"url":"https://github.com/Seldaek/monolog","type":"git"},"dist":{"url":"u","type":"zip"}},
					{"version":"3.0.0","time":"2022-12-01T00:00:00+00:00","source":{"url":"https://github.com/Seldaek/monolog","type":"git"},"dist":{"url":"u","type":"zip"}},
					{"version":"2.0.0","time":"2019-12-01T00:00:00+00:00","source":{"url":"https://github.com/Seldaek/monolog","type":"git"},"dist":{"url":"u","type":"zip"}},
					{"version":"1.0.0","time":"2014-01-01T00:00:00+00:00","source":{"url":"https://github.com/Seldaek/monolog","type":"git"},"dist":{"url":"u","type":"zip"}},
					{"version":"3.5.0-RC1","time":"2023-12-15T00:00:00+00:00","source":{"url":"https://github.com/Seldaek/monolog","type":"git"},"dist":{"url":"u","type":"zip"}}
				]
			}
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "composer", Package: "monolog/monolog", Version: "3.5.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil || len(pr.Maintenance.VersionTimeline) != 6 {
		t.Fatalf("VersionTimeline: %+v", pr.Maintenance)
	}
	if pr.Maintenance.FirstPublishedAt == nil || pr.Maintenance.FirstPublishedAt.Year() != 2014 {
		t.Fatalf("FirstPublishedAt: got %v, want 2014", pr.Maintenance.FirstPublishedAt)
	}
	// The pre-release "3.5.0-RC1" must not win the latest-version label.
	if pr.Release == nil || pr.Release.LatestVersion != "3.5.0" {
		t.Fatalf("LatestVersion: got %q, want %q", pr.Release.LatestVersion, "3.5.0")
	}
}

// -- GitHub stars enrichment -----------------------------------------

func TestRegistryMetadataProvider_GitHubStars(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/owner/repo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stargazers_count":1234,"forks_count":56,"open_issues_count":7,"subscribers_count":89}`))
	})
	// Drive the enrichment through the cargo run since that path
	// populates URLs.SourceRepoURL via crate.repository.
	mux.HandleFunc("/api/v1/crates/owner-repo/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"repository":"https://github.com/owner/repo","description":"x"},"version":{"created_at":"2024-01-01T00:00:00Z"}}`))
	})
	mux.HandleFunc("/api/v1/crates/owner-repo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"max_version":"1.0.0"},"versions":[{"num":"1.0.0","created_at":"2024-01-01T00:00:00Z"}]}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "cargo", Package: "owner-repo", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil {
		t.Fatalf("Maintenance: nil")
	}
	if pr.Maintenance.Stars != 1234 {
		t.Errorf("Stars: got %d, want 1234", pr.Maintenance.Stars)
	}
	if pr.Maintenance.Forks != 56 {
		t.Errorf("Forks: got %d, want 56", pr.Maintenance.Forks)
	}
	if pr.Maintenance.OpenIssues != 7 {
		t.Errorf("OpenIssues: got %d, want 7", pr.Maintenance.OpenIssues)
	}
	if pr.Maintenance.Subscribers != 89 {
		t.Errorf("Subscribers: got %d, want 89", pr.Maintenance.Subscribers)
	}
}

func TestRegistryMetadataProvider_GitHubStarsTokenSent(t *testing.T) {
	var seenAuth string
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r", func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stargazers_count":1}`))
	})
	mux.HandleFunc("/api/v1/crates/p/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"repository":"https://github.com/o/r"},"version":{"created_at":"2024-01-01T00:00:00Z"}}`))
	})
	mux.HandleFunc("/api/v1/crates/p", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"max_version":"1.0.0"},"versions":[{"num":"1.0.0","created_at":"2024-01-01T00:00:00Z"}]}`))
	})
	t.Setenv("CHAINSAW_GITHUB_TOKEN", "ghp_testtoken")
	p, _ := newStubProvider(t, mux)
	_, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "cargo", Package: "p", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.HasPrefix(seenAuth, "Bearer ghp_") {
		t.Fatalf("Authorization header: got %q, want Bearer ghp_…", seenAuth)
	}
}

// TestRegistryMetadataProvider_TimelineFailSoft confirms that a 500 on
// the secondary timeline endpoint surfaces a `timeline_fetch_failed`
// Warning but does NOT abort the primary fetch — the rest of the
// PartialReport must still come back populated.
func TestRegistryMetadataProvider_TimelineFailSoft(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/crates/p/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"description":"x","repository":"https://example.com/p"},"version":{"license":"MIT","created_at":"2024-01-01T00:00:00Z"}}`))
	})
	mux.HandleFunc("/api/v1/crates/p", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "cargo", Package: "p", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Primary fetch succeeded → license is set.
	if pr.Metadata == nil || pr.Metadata.LicenseExpression != "MIT" {
		t.Fatalf("Metadata: got %+v, want license=MIT", pr.Metadata)
	}
	// Timeline empty (or Maintenance entirely nil).
	if pr.Maintenance != nil && len(pr.Maintenance.VersionTimeline) > 0 {
		t.Fatalf("VersionTimeline should be empty on 500: %+v", pr.Maintenance)
	}
	// Warning emitted.
	gotWarn := false
	for _, w := range pr.Warnings {
		if w.Code == "timeline_fetch_failed" {
			gotWarn = true
			break
		}
	}
	if !gotWarn {
		t.Fatalf("expected timeline_fetch_failed warning, got: %+v", pr.Warnings)
	}
}

// TestRegistryMetadataProvider_TimelineMalformedJSON — a server that
// returns a 200 with garbage JSON must NOT bubble up as an error from
// Run() but should emit a warning and leave the timeline empty.
func TestRegistryMetadataProvider_TimelineMalformedJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/versions/rails/versions/7.0.0.json", func(w http.ResponseWriter, r *http.Request) {
		// Not actually invoked; the rubygems run uses /api/v2/...
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/api/v2/rubygems/rails/versions/7.0.0.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"rails","version":"7.0.0","authors":"DHH","created_at":"2021-12-15T00:00:00Z","licenses":["MIT"],"info":"x"}`))
	})
	mux.HandleFunc("/api/v1/versions/rails.json", func(w http.ResponseWriter, r *http.Request) {
		// Return non-JSON garbage.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`<not json>`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "rubygems", Package: "rails", Version: "7.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance != nil && len(pr.Maintenance.VersionTimeline) > 0 {
		t.Fatalf("VersionTimeline should be empty on decode error: %+v", pr.Maintenance)
	}
	hasWarn := false
	for _, w := range pr.Warnings {
		if w.Code == "timeline_fetch_failed" {
			hasWarn = true
			break
		}
	}
	if !hasWarn {
		t.Fatalf("expected timeline_fetch_failed warning, got: %+v", pr.Warnings)
	}
}

// mavenMetadataXMLFixture renders a maven-metadata.xml body for
// org.apache.commons:commons-lang3 with `n` synthetic versions and a
// realistic `<lastUpdated>` stamp. Mirrors the cargo/rubygems timeline
// fixtures so a regression in the maven path surfaces the same way.
func mavenMetadataXMLFixture(n int, lastUpdated string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<metadata><groupId>org.apache.commons</groupId>`)
	b.WriteString(`<artifactId>commons-lang3</artifactId><versioning>`)
	b.WriteString(`<latest>3.` + fmt.Sprint(n-1) + `.0</latest>`)
	b.WriteString(`<release>3.` + fmt.Sprint(n-1) + `.0</release>`)
	b.WriteString(`<versions>`)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, `<version>3.%d.0</version>`, i)
	}
	b.WriteString(`</versions>`)
	b.WriteString(`<lastUpdated>` + lastUpdated + `</lastUpdated>`)
	b.WriteString(`</versioning></metadata>`)
	return b.String()
}

// TestRegistryMetadataProvider_MavenTimeline locks in the Maven branch
// of the sparse-data-cascade fix: the artifact-level
// maven-metadata.xml document yields the full version list, and the
// `<lastUpdated>` stamp is mapped to Maintenance.FirstPublishedAt when
// parseable (the only repo-side timestamp Maven Central exposes
// without N HEAD requests).
func TestRegistryMetadataProvider_MavenTimeline(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><project><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.14.0</version><licenses><license><name>Apache License, Version 2.0</name></license></licenses><scm><url>https://github.com/apache/commons-lang</url></scm></project>`))
	})
	mux.HandleFunc("/org/apache/commons/commons-lang3/maven-metadata.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(mavenMetadataXMLFixture(15, "20240501123456")))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "maven", Package: "org.apache.commons:commons-lang3", Version: "3.14.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil {
		t.Fatalf("Maintenance: nil")
	}
	if got := len(pr.Maintenance.VersionTimeline); got < 10 {
		t.Fatalf("VersionTimeline len: got %d, want >= 10", got)
	}
	if pr.Maintenance.FirstPublishedAt == nil || pr.Maintenance.FirstPublishedAt.Year() != 2024 {
		t.Fatalf("FirstPublishedAt: got %v, want 2024-* parsed from <lastUpdated>", pr.Maintenance.FirstPublishedAt)
	}
	if pr.Release == nil || pr.Release.LatestVersion != "3.14.0" {
		t.Fatalf("LatestVersion: got %+v, want 3.14.0 from <latest>", pr.Release)
	}
	// The primary POM fetch must still have populated license + repo —
	// the timeline fetcher runs on top of, not instead of, the POM path.
	if pr.Metadata == nil || !strings.Contains(pr.Metadata.LicenseExpression, "Apache") {
		t.Fatalf("license dropped by timeline path: %+v", pr.Metadata)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/apache/commons-lang" {
		t.Fatalf("sourceRepoURL dropped by timeline path: %+v", pr.URLs)
	}
}

// TestRegistryMetadataProvider_MavenTimelineFailSoft mirrors the
// cross-ecosystem fail-soft contract: a 500 on the maven-metadata.xml
// endpoint must NOT abort the primary POM fetch — Metadata + URLs must
// still be populated and a timeline_fetch_failed warning surfaces so
// operators can tell the difference between "no data" and "fetch
// errored".
func TestRegistryMetadataProvider_MavenTimelineFailSoft(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><project><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.14.0</version><licenses><license><name>Apache License, Version 2.0</name></license></licenses><scm><url>https://github.com/apache/commons-lang</url></scm></project>`))
	})
	mux.HandleFunc("/org/apache/commons/commons-lang3/maven-metadata.xml", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "maven", Package: "org.apache.commons:commons-lang3", Version: "3.14.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Primary fetch succeeded.
	if pr.Metadata == nil || !strings.Contains(pr.Metadata.LicenseExpression, "Apache") {
		t.Fatalf("Metadata dropped on timeline failure: %+v", pr.Metadata)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL == "" {
		t.Fatalf("URLs dropped on timeline failure: %+v", pr.URLs)
	}
	// Timeline empty (or Maintenance nil).
	if pr.Maintenance != nil && len(pr.Maintenance.VersionTimeline) > 0 {
		t.Fatalf("VersionTimeline should be empty on maven-metadata.xml 500: %+v", pr.Maintenance)
	}
	hasWarn := false
	for _, w := range pr.Warnings {
		if w.Code == "timeline_fetch_failed" {
			hasWarn = true
			break
		}
	}
	if !hasWarn {
		t.Fatalf("expected timeline_fetch_failed warning, got: %+v", pr.Warnings)
	}
}

// TestRegistryMetadataProvider_PyPIGitHubStars proves the PyPI runner
// drives the GitHub stars enrichment when project_urls.Source points
// at a github.com repo — direct regression guard for the idna 3.15
// production miss (stars/forks/openIssues stored as NULL despite the
// source URL being known).
func TestRegistryMetadataProvider_PyPIGitHubStars(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/pypi/idna/3.15/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"info":{
				"author":"Kim Davies","license":"BSD","summary":"idna",
				"project_urls":{"Source":"https://github.com/kjd/idna","Issue tracker":"https://github.com/kjd/idna/issues"}
			},
			"urls":[]
		}`))
	})
	mux.HandleFunc("/pypi/idna/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"info":{"version":"3.15"},"releases":{}}`))
	})
	mux.HandleFunc("/repos/kjd/idna", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stargazers_count":234,"forks_count":12,"open_issues_count":5,"subscribers_count":8}`))
	})
	_ = os.Unsetenv("CHAINSAW_GITHUB_TOKEN")
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "pypi", Package: "idna", Version: "3.15"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/kjd/idna" {
		t.Fatalf("SourceRepoURL not populated from project_urls.Source: %+v", pr.URLs)
	}
	if pr.Maintenance == nil {
		t.Fatalf("Maintenance: nil — stars enrichment didn't fire from runPyPI")
	}
	if pr.Maintenance.Stars == 0 {
		t.Errorf("Stars: got 0, want 234 (runPyPI did not call enrichGitHubStars)")
	}
	if pr.Maintenance.Forks == 0 {
		t.Errorf("Forks: got 0, want 12")
	}
	if pr.Maintenance.OpenIssues == 0 {
		t.Errorf("OpenIssues: got 0, want 5")
	}
}

// TestRegistryMetadataProvider_GitHubRateLimitRetry locks in the
// retry-once-on-403 path: an anonymous GitHub fetch that returns 403
// (rate limit) on the first attempt and 200 on the second must end up
// with Stars populated and no warning surfaced.
func TestRegistryMetadataProvider_GitHubRateLimitRetry(t *testing.T) {
	var calls int
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r", func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stargazers_count":42}`))
	})
	mux.HandleFunc("/api/v1/crates/p/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"repository":"https://github.com/o/r"},"version":{"created_at":"2024-01-01T00:00:00Z"}}`))
	})
	mux.HandleFunc("/api/v1/crates/p", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"max_version":"1.0.0"},"versions":[{"num":"1.0.0","created_at":"2024-01-01T00:00:00Z"}]}`))
	})
	_ = os.Unsetenv("CHAINSAW_GITHUB_TOKEN")
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "cargo", Package: "p", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls < 2 {
		t.Fatalf("expected retry on 403, got %d call(s)", calls)
	}
	if pr.Maintenance == nil || pr.Maintenance.Stars != 42 {
		t.Fatalf("Stars: got %+v, want 42 after retry", pr.Maintenance)
	}
	for _, w := range pr.Warnings {
		if w.Code == "github_meta_fetch_failed" {
			t.Errorf("unexpected github_meta_fetch_failed warning after successful retry: %+v", w)
		}
	}
}

// TestParseMavenLastUpdated covers the two canonical maven-metadata.xml
// shapes (compact YYYYMMDDhhmmss and YYYYMMDD), plus rejection of
// junk input — the only reason we don't fold this into parseTime() is
// that those layouts are Maven-specific and would conflict with the
// year-only fall-through some other ecosystems emit.
func TestParseMavenLastUpdated(t *testing.T) {
	cases := []struct {
		in   string
		year int
		ok   bool
	}{
		{"20240501123456", 2024, true},
		{"20180101", 2018, true},
		{"", 0, false},
		{"not-a-date", 0, false},
		{"2024-05-01", 0, false},
	}
	for _, c := range cases {
		got, ok := parseMavenLastUpdated(c.in)
		if ok != c.ok {
			t.Errorf("parseMavenLastUpdated(%q) ok: got %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && got.Year() != c.year {
			t.Errorf("parseMavenLastUpdated(%q) year: got %d, want %d", c.in, got.Year(), c.year)
		}
	}
}

// TestParseGitHubRepo covers the input shapes we accept (https,
// trailing slashes, .git suffix, ssh-style, sub-paths) and the
// rejection of non-GitHub hosts.
func TestParseGitHubRepo(t *testing.T) {
	cases := []struct {
		in    string
		owner string
		repo  string
		ok    bool
	}{
		{"https://github.com/foo/bar", "foo", "bar", true},
		{"https://github.com/foo/bar.git", "foo", "bar", true},
		{"https://github.com/foo/bar/tree/main/sub", "foo", "bar", true},
		{"git+https://github.com/foo/bar.git", "foo", "bar", true},
		{"git@github.com:foo/bar.git", "foo", "bar", true},
		{"https://www.github.com/foo/bar", "foo", "bar", true},
		{"https://gitlab.com/foo/bar", "", "", false},
		{"https://github.com/foo", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		o, r, ok := parseGitHubRepo(c.in)
		if o != c.owner || r != c.repo || ok != c.ok {
			t.Errorf("parseGitHubRepo(%q): got (%q,%q,%v), want (%q,%q,%v)", c.in, o, r, ok, c.owner, c.repo, c.ok)
		}
	}
}

// TestRegistryMetadataProvider_GitHubFetchFailSoft confirms a 500 from
// GitHub leaves fields at zero and surfaces a `github_meta_fetch_failed`
// warning rather than erroring out the Run.
func TestRegistryMetadataProvider_GitHubFetchFailSoft(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/v1/crates/p/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"repository":"https://github.com/o/r"},"version":{"created_at":"2024-01-01T00:00:00Z"}}`))
	})
	mux.HandleFunc("/api/v1/crates/p", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"max_version":"1.0.0"},"versions":[{"num":"1.0.0","created_at":"2024-01-01T00:00:00Z"}]}`))
	})
	// Make sure no token is sent so we exercise the unauthenticated path.
	_ = os.Unsetenv("CHAINSAW_GITHUB_TOKEN")
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "cargo", Package: "p", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance != nil && pr.Maintenance.Stars != 0 {
		t.Errorf("Stars should stay zero on GitHub 500: got %d", pr.Maintenance.Stars)
	}
	hasWarn := false
	for _, w := range pr.Warnings {
		if w.Code == "github_meta_fetch_failed" {
			hasWarn = true
		}
	}
	if !hasWarn {
		t.Fatalf("expected github_meta_fetch_failed warning, got: %+v", pr.Warnings)
	}
}

// -- G4: NuGet unlisted → Release.Yanked ------------------------------

// TestRegistryMetadataProvider_NuGetUnlistedYanked locks in the
// promotion of catalogEntry.listed=false into Release.Yanked. NuGet has
// no per-version "yanked" boolean — the registry instead flips listed
// to false when an owner unlists a version; that's the closest analogue
// to a yank on this registry, and downstream consumers (metadiff
// filtering, risk projection) expect Release.Yanked to reflect it.
func TestRegistryMetadataProvider_NuGetUnlistedYanked(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/badpkg/1.2.3/badpkg.nuspec", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><package><metadata><id>BadPkg</id><version>1.2.3</version><authors>A</authors></metadata></package>`))
	})
	mux.HandleFunc("/badpkg/index.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"items":[
				{"items":[
					{"catalogEntry":{"version":"1.0.0","published":"2024-01-01T00:00:00Z","listed":true}},
					{"catalogEntry":{"version":"1.2.3","published":"2024-06-01T00:00:00Z","listed":false}}
				]}
			]
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "nuget", Package: "BadPkg", Version: "1.2.3"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Release == nil || pr.Release.Yanked == nil || !*pr.Release.Yanked {
		t.Fatalf("Release.Yanked: got %+v, want *true", pr.Release)
	}
}

// TestRegistryMetadataProvider_NuGetListedNotYanked confirms the
// fallthrough: catalogEntry.listed=true (or missing) must leave
// Release.Yanked nil so well-behaved packages don't get falsely flagged.
func TestRegistryMetadataProvider_NuGetListedNotYanked(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/goodpkg/1.0.0/goodpkg.nuspec", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><package><metadata><id>GoodPkg</id><version>1.0.0</version><authors>A</authors></metadata></package>`))
	})
	mux.HandleFunc("/goodpkg/index.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"items":[
				{"items":[
					{"catalogEntry":{"version":"1.0.0","published":"2024-01-01T00:00:00Z","listed":true}}
				]}
			]
		}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "nuget", Package: "GoodPkg", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Release != nil && pr.Release.Yanked != nil && *pr.Release.Yanked {
		t.Fatalf("Release.Yanked: got *true, want unset for listed=true")
	}
}

// -- G5: Apache gitbox → GitHub mirror lookup -------------------------

// TestApacheGitboxToGitHub covers the canonical URL shapes the helper
// must recognise plus the rejection of non-gitbox URLs.
func TestApacheGitboxToGitHub(t *testing.T) {
	cases := []struct {
		in    string
		owner string
		repo  string
		ok    bool
	}{
		{"https://gitbox.apache.org/repos/asf?p=commons-lang.git", "apache", "commons-lang", true},
		{"https://gitbox.apache.org/repos/asf?p=commons-lang3.git", "apache", "commons-lang3", true},
		{"https://gitbox.apache.org/repos/asf/commons-lang.git", "apache", "commons-lang", true},
		{"https://gitbox.apache.org/repos/asf/commons-lang3.git", "apache", "commons-lang3", true},
		{"https://github.com/apache/commons-lang", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		m, ok := apacheGitboxToGitHub("https://api.github.com", c.in)
		if ok != c.ok || m.owner != c.owner || m.repo != c.repo {
			t.Errorf("apacheGitboxToGitHub(%q): got (%q,%q,%v), want (%q,%q,%v)",
				c.in, m.owner, m.repo, ok, c.owner, c.repo, c.ok)
		}
	}
}

// TestApacheGitboxTrimTrailingDigit covers the artifact-vs-project
// fallback used when the canonical mirror 404s.
func TestApacheGitboxTrimTrailingDigit(t *testing.T) {
	cases := []struct {
		in   string
		out  string
		trim bool
	}{
		{"commons-lang3", "commons-lang", true},
		{"commons-lang", "commons-lang", false}, // no trailing digit
		{"abc-3", "abc-3", false},               // would leave trailing hyphen
		{"", "", false},
	}
	for _, c := range cases {
		got, trimmed := apacheGitboxTrimTrailingDigit(c.in)
		if got != c.out || trimmed != c.trim {
			t.Errorf("apacheGitboxTrimTrailingDigit(%q): got (%q,%v), want (%q,%v)",
				c.in, got, trimmed, c.out, c.trim)
		}
	}
}

// TestRegistryMetadataProvider_MavenApacheGitboxRewrite verifies the
// end-to-end path: a POM whose <scm><url> points at gitbox.apache.org
// must be rewritten to the GitHub mirror, the mirror's stars must flow
// into Maintenance, and SourceRepoURL must be updated so downstream
// signals see the real repo.
func TestRegistryMetadataProvider_MavenApacheGitboxRewrite(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/org/apache/commons/commons-lang/3.12.0/commons-lang-3.12.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><project>
			<groupId>org.apache.commons</groupId>
			<artifactId>commons-lang</artifactId>
			<version>3.12.0</version>
			<scm><url>https://gitbox.apache.org/repos/asf?p=commons-lang.git</url></scm>
		</project>`))
	})
	mux.HandleFunc("/org/apache/commons/commons-lang/maven-metadata.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><metadata><versioning><latest>3.12.0</latest><versions><version>3.12.0</version></versions></versioning></metadata>`))
	})
	mux.HandleFunc("/repos/apache/commons-lang", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stargazers_count":4321,"forks_count":111,"open_issues_count":22,"subscribers_count":33}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "maven", Package: "org.apache.commons:commons-lang", Version: "3.12.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/apache/commons-lang" {
		t.Fatalf("SourceRepoURL: got %+v, want github.com/apache/commons-lang", pr.URLs)
	}
	if pr.Maintenance == nil || pr.Maintenance.Stars != 4321 {
		t.Fatalf("Stars: got %+v, want 4321", pr.Maintenance)
	}
}

// TestRegistryMetadataProvider_MavenApacheGitboxTrailingDigitFallback
// exercises the commons-lang3 → commons-lang fallback: the canonical
// candidate (commons-lang3) 404s; the helper retries the
// trailing-digit-trimmed name and finds it.
func TestRegistryMetadataProvider_MavenApacheGitboxTrailingDigitFallback(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><project>
			<groupId>org.apache.commons</groupId>
			<artifactId>commons-lang3</artifactId>
			<version>3.12.0</version>
			<scm><url>https://gitbox.apache.org/repos/asf?p=commons-lang3.git</url></scm>
		</project>`))
	})
	mux.HandleFunc("/org/apache/commons/commons-lang3/maven-metadata.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><metadata><versioning><latest>3.12.0</latest><versions><version>3.12.0</version></versions></versioning></metadata>`))
	})
	mux.HandleFunc("/repos/apache/commons-lang3", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/repos/apache/commons-lang", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stargazers_count":4321}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "maven", Package: "org.apache.commons:commons-lang3", Version: "3.12.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/apache/commons-lang" {
		t.Fatalf("SourceRepoURL: got %+v, want github.com/apache/commons-lang (after trim fallback)", pr.URLs)
	}
	if pr.Maintenance == nil || pr.Maintenance.Stars != 4321 {
		t.Fatalf("Stars: got %+v, want 4321", pr.Maintenance)
	}
}

// -- G6: multi-forge stars/forks -------------------------------------

func TestRegistryMetadataProvider_GitLabRepoMeta(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/group%2Fproject", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"star_count":42,"forks_count":7,"open_issues_count":3}`))
	})
	// Drive the enrichment through cargo with a gitlab repo URL.
	mux.HandleFunc("/api/v1/crates/p/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"repository":"https://gitlab.com/group/project"},"version":{"created_at":"2024-01-01T00:00:00Z"}}`))
	})
	mux.HandleFunc("/api/v1/crates/p", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"max_version":"1.0.0"},"versions":[{"num":"1.0.0","created_at":"2024-01-01T00:00:00Z"}]}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "cargo", Package: "p", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil || pr.Maintenance.Stars != 42 || pr.Maintenance.Forks != 7 || pr.Maintenance.OpenIssues != 3 {
		t.Fatalf("Maintenance: got %+v, want stars=42 forks=7 issues=3", pr.Maintenance)
	}
	if pr.Maintenance.Subscribers != 0 {
		t.Errorf("Subscribers: got %d, want 0 (GitLab has no public count)", pr.Maintenance.Subscribers)
	}
}

func TestRegistryMetadataProvider_BitbucketRepoMeta(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/2.0/repositories/ws/repo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"forks_count":9,"watchers_count":15}`))
	})
	mux.HandleFunc("/api/v1/crates/p/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"repository":"https://bitbucket.org/ws/repo"},"version":{"created_at":"2024-01-01T00:00:00Z"}}`))
	})
	mux.HandleFunc("/api/v1/crates/p", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"max_version":"1.0.0"},"versions":[{"num":"1.0.0","created_at":"2024-01-01T00:00:00Z"}]}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "cargo", Package: "p", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil {
		t.Fatalf("Maintenance: nil")
	}
	if pr.Maintenance.Stars != 0 {
		t.Errorf("Stars: got %d, want 0 (Bitbucket has no public count)", pr.Maintenance.Stars)
	}
	if pr.Maintenance.Forks != 9 {
		t.Errorf("Forks: got %d, want 9", pr.Maintenance.Forks)
	}
	if pr.Maintenance.Subscribers != 15 {
		t.Errorf("Subscribers: got %d, want 15", pr.Maintenance.Subscribers)
	}
}

func TestRegistryMetadataProvider_CodebergRepoMeta(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/repos/owner/repo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stars_count":11,"forks_count":2,"open_issues_count":4,"watchers_count":6}`))
	})
	mux.HandleFunc("/api/v1/crates/p/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"repository":"https://codeberg.org/owner/repo"},"version":{"created_at":"2024-01-01T00:00:00Z"}}`))
	})
	mux.HandleFunc("/api/v1/crates/p", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"crate":{"max_version":"1.0.0"},"versions":[{"num":"1.0.0","created_at":"2024-01-01T00:00:00Z"}]}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "cargo", Package: "p", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil ||
		pr.Maintenance.Stars != 11 ||
		pr.Maintenance.Forks != 2 ||
		pr.Maintenance.OpenIssues != 4 ||
		pr.Maintenance.Subscribers != 6 {
		t.Fatalf("Maintenance: got %+v, want stars=11 forks=2 issues=4 subscribers=6", pr.Maintenance)
	}
}

// TestParseForgeRepo covers the URL shapes the dispatcher recognises
// for the three non-GitHub forges.
func TestParseForgeRepo(t *testing.T) {
	cases := []struct {
		in    string
		forge string
		owner string
		repo  string
		ok    bool
	}{
		{"https://gitlab.com/group/project", "gitlab", "group", "project", true},
		{"https://gitlab.com/group/sub/project", "gitlab", "group/sub", "project", true},
		{"https://gitlab.com/group/project/-/tree/main", "gitlab", "group", "project", true},
		{"https://gitlab.com/group/project.git", "gitlab", "group", "project", true},
		{"https://bitbucket.org/ws/repo", "bitbucket", "ws", "repo", true},
		{"https://bitbucket.org/ws/repo.git", "bitbucket", "ws", "repo", true},
		{"https://codeberg.org/owner/repo", "codeberg", "owner", "repo", true},
		{"https://github.com/owner/repo", "", "", "", false}, // not in this dispatcher
		{"https://example.com/owner/repo", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, c := range cases {
		f, o, r, ok := parseForgeRepo(c.in)
		if f != c.forge || o != c.owner || r != c.repo || ok != c.ok {
			t.Errorf("parseForgeRepo(%q): got (%q,%q,%q,%v), want (%q,%q,%q,%v)",
				c.in, f, o, r, ok, c.forge, c.owner, c.repo, c.ok)
		}
	}
}

// -- Maven SCM fallback (url → connection → developerConnection) -----

func TestExtractMavenSourceRepo_URLOnly(t *testing.T) {
	got := extractMavenSourceRepo(mavenPOMSCM{URL: "https://github.com/x/y"})
	if got != "https://github.com/x/y" {
		t.Fatalf("URL precedence: got %q, want https://github.com/x/y", got)
	}
}

func TestExtractMavenSourceRepo_ConnectionFallback(t *testing.T) {
	got := extractMavenSourceRepo(mavenPOMSCM{Connection: "scm:git:https://github.com/x/y.git"})
	if got != "https://github.com/x/y" {
		t.Fatalf("connection fallback: got %q, want https://github.com/x/y (.git stripped)", got)
	}
}

func TestExtractMavenSourceRepo_SSHConnection(t *testing.T) {
	got := extractMavenSourceRepo(mavenPOMSCM{Connection: "scm:git:git@github.com:x/y.git"})
	if got != "https://github.com/x/y" {
		t.Fatalf("scp-style ssh: got %q, want https://github.com/x/y", got)
	}
}

func TestExtractMavenSourceRepo_SSHWithScheme(t *testing.T) {
	got := extractMavenSourceRepo(mavenPOMSCM{Connection: "scm:git:ssh://git@github.com/x/y.git"})
	if got != "https://github.com/x/y" {
		t.Fatalf("ssh:// shape: got %q, want https://github.com/x/y", got)
	}
}

func TestExtractMavenSourceRepo_DeveloperConnectionLast(t *testing.T) {
	got := extractMavenSourceRepo(mavenPOMSCM{
		DeveloperConnection: "scm:git:https://github.com/foo/bar.git",
	})
	if got != "https://github.com/foo/bar" {
		t.Fatalf("developerConnection fallback: got %q, want https://github.com/foo/bar", got)
	}
}

func TestExtractMavenSourceRepo_NonGitProtocol(t *testing.T) {
	cases := []string{
		"scm:svn:https://svn.example.org/repo/trunk",
		"scm:hg:https://hg.example.org/repo",
		"scm:bzr:https://bzr.example.org/repo",
		"scm:cvs:pserver:anon@cvs.example.org:/cvs",
	}
	for _, in := range cases {
		if got := extractMavenSourceRepo(mavenPOMSCM{Connection: in}); got != "" {
			t.Errorf("non-git provider %q: got %q, want empty", in, got)
		}
	}
}

func TestExtractMavenSourceRepo_Empty(t *testing.T) {
	if got := extractMavenSourceRepo(mavenPOMSCM{}); got != "" {
		t.Fatalf("all-empty SCM: got %q, want empty string", got)
	}
	// Leading/trailing whitespace must not leak through as a "non-empty"
	// URL — TrimSpace at the top of the helper handles this. Connection
	// with only whitespace likewise returns "".
	if got := extractMavenSourceRepo(mavenPOMSCM{URL: "   "}); got != "" {
		t.Fatalf("whitespace-only URL: got %q, want empty (fell through to empty connections)", got)
	}
	if got := extractMavenSourceRepo(mavenPOMSCM{Connection: "   "}); got != "" {
		t.Fatalf("whitespace-only connection: got %q, want empty", got)
	}
}

// TestRegistryMetadataProvider_MavenSCMDeveloperConnection drives the
// fallback through runMaven end-to-end: a POM with ONLY
// <developerConnection> populated must (a) resolve SourceRepoURL to the
// normalised https form and (b) trigger enrichRepoStars against the
// stubbed GitHub endpoint, populating Maintenance.Stars.
func TestRegistryMetadataProvider_MavenSCMDeveloperConnection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/com/foo/bar/1.0.0/bar-1.0.0.pom", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><project>
			<groupId>com.foo</groupId>
			<artifactId>bar</artifactId>
			<version>1.0.0</version>
			<scm>
				<developerConnection>scm:git:git@github.com:foo/bar.git</developerConnection>
			</scm>
		</project>`))
	})
	mux.HandleFunc("/com/foo/bar/maven-metadata.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?><metadata><versioning><latest>1.0.0</latest><versions><version>1.0.0</version></versions></versioning></metadata>`))
	})
	githubHit := 0
	mux.HandleFunc("/repos/foo/bar", func(w http.ResponseWriter, r *http.Request) {
		githubHit++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"stargazers_count":1234,"forks_count":56,"open_issues_count":7,"subscribers_count":8}`))
	})
	p, _ := newStubProvider(t, mux)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "maven", Package: "com.foo:bar", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/foo/bar" {
		t.Fatalf("SourceRepoURL: got %+v, want https://github.com/foo/bar", pr.URLs)
	}
	if githubHit == 0 {
		t.Fatalf("enrichRepoStars did not fire: GitHub stub was never hit")
	}
	if pr.Maintenance == nil || pr.Maintenance.Stars != 1234 {
		t.Fatalf("Maintenance.Stars: got %+v, want 1234", pr.Maintenance)
	}
}

func TestRegistryMetadataProvider_Pub(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/packages/http", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name": "http",
			"latest": {"version": "1.2.0", "published": "2024-03-10T12:00:00.000Z"},
			"versions": [
				{"version": "1.1.0", "published": "2023-01-01T00:00:00.000Z",
				 "pubspec": {"description": "older", "repository": "https://github.com/dart-lang/http"}},
				{"version": "1.2.0", "published": "2024-03-10T12:00:00.000Z",
				 "pubspec": {"description": "A composable, Future-based library for making HTTP requests.",
				             "homepage": "https://github.com/dart-lang/http/tree/master/pkgs/http",
				             "repository": "https://github.com/dart-lang/http"}}
			]
		}`))
	})
	mux.HandleFunc("/api/packages/http/score", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"grantedPoints":150,"maxPoints":160,
			"tags":["sdk:dart","license:bsd-3-clause","license:fsf-libre","license:osi-approved"]}`))
	})
	mux.HandleFunc("/api/packages/http/publisher", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"publisherId":"dart.dev"}`))
	})
	p, _ := newStubProvider(t, mux)

	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "pub", Package: "http", Version: "1.2.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Release == nil || pr.Release.PublishedAt == nil {
		t.Fatalf("expected release date, got %+v", pr.Release)
	}
	if got := pr.Release.PublishedAt.UTC().Format(time.RFC3339); got != "2024-03-10T12:00:00Z" {
		t.Fatalf("PublishedAt: got %q, want 2024-03-10T12:00:00Z", got)
	}
	if pr.Release.LatestVersion != "1.2.0" {
		t.Fatalf("LatestVersion: got %q, want 1.2.0", pr.Release.LatestVersion)
	}
	if pr.Metadata == nil || pr.Metadata.LicenseExpression != "BSD-3-Clause" {
		t.Fatalf("license: got %+v, want BSD-3-Clause", pr.Metadata)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/dart-lang/http" {
		t.Fatalf("SourceRepoURL: got %+v", pr.URLs)
	}
	if pr.People == nil || len(pr.People.PublisherIDs) != 1 || pr.People.PublisherIDs[0] != "dart.dev" {
		t.Fatalf("PublisherIDs: got %+v, want [dart.dev]", pr.People)
	}
	// The full versions[] timeline must thread through to Maintenance so the
	// version-anomaly path (provider_metadiff) and VersionCount see real
	// per-version release-date history — not just the matched version.
	if pr.Maintenance == nil || len(pr.Maintenance.VersionTimeline) != 2 {
		t.Fatalf("VersionTimeline: got %+v, want 2 entries", pr.Maintenance)
	}
	// applyTimeline sorts ascending by published date.
	if got := pr.Maintenance.VersionTimeline[0].Version; got != "1.1.0" {
		t.Fatalf("timeline[0].Version: got %q, want 1.1.0 (earliest)", got)
	}
	if got := pr.Maintenance.VersionTimeline[1].Version; got != "1.2.0" {
		t.Fatalf("timeline[1].Version: got %q, want 1.2.0 (latest)", got)
	}
	if got := pr.Maintenance.VersionTimeline[0].PublishedAt.UTC().Format(time.RFC3339); got != "2023-01-01T00:00:00Z" {
		t.Fatalf("timeline[0].PublishedAt: got %q, want 2023-01-01T00:00:00Z", got)
	}
	if pr.Maintenance.FirstPublishedAt == nil ||
		pr.Maintenance.FirstPublishedAt.UTC().Format(time.RFC3339) != "2023-01-01T00:00:00Z" {
		t.Fatalf("FirstPublishedAt: got %+v, want 2023-01-01T00:00:00Z", pr.Maintenance.FirstPublishedAt)
	}
}

// TestRegistryMetadataProvider_PubVersionTimeline pins the version-anomaly
// wiring (plan_coverage_uplift Item 2-T1b): runPub must thread the FULL
// versions[] published timeline into Maintenance.VersionTimeline (the slice
// provider_metadiff consumes for version-anomaly history), even when the
// requested version is not the latest. Before this wiring runPub only set the
// single matched version's Release.PublishedAt, leaving the anomaly provider
// blind to prior cadence.
func TestRegistryMetadataProvider_PubVersionTimeline(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/packages/cadence", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Out-of-order versions[] with a long-dormant gap then a sudden 1.0.0
		// — the kind of cadence the anomaly path keys on. Requested version is
		// an OLDER one (0.2.0), proving the timeline is independent of which
		// version is matched.
		_, _ = w.Write([]byte(`{
			"name": "cadence",
			"latest": {"version": "1.0.0", "published": "2024-06-01T00:00:00.000Z"},
			"versions": [
				{"version": "1.0.0", "published": "2024-06-01T00:00:00.000Z", "pubspec": {}},
				{"version": "0.1.0", "published": "2019-01-01T00:00:00.000Z", "pubspec": {}},
				{"version": "0.2.0", "published": "2019-02-01T00:00:00.000Z", "pubspec": {}}
			]
		}`))
	})
	p, _ := newStubProvider(t, mux)

	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "pub", Package: "cadence", Version: "0.2.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Maintenance == nil || len(pr.Maintenance.VersionTimeline) != 3 {
		t.Fatalf("VersionTimeline: got %+v, want 3 entries", pr.Maintenance)
	}
	// Ascending sort: 0.1.0 (2019-01) → 0.2.0 (2019-02) → 1.0.0 (2024-06).
	wantOrder := []string{"0.1.0", "0.2.0", "1.0.0"}
	for i, want := range wantOrder {
		if got := pr.Maintenance.VersionTimeline[i].Version; got != want {
			t.Fatalf("timeline[%d].Version: got %q, want %q", i, got, want)
		}
	}
	// VersionCount derives from the timeline length downstream — confirm the
	// matched version's release date is still set independently.
	if pr.Release == nil || pr.Release.PublishedAt == nil ||
		pr.Release.PublishedAt.UTC().Format(time.RFC3339) != "2019-02-01T00:00:00Z" {
		t.Fatalf("matched Release.PublishedAt: got %+v, want 2019-02-01T00:00:00Z", pr.Release)
	}
	if pr.Maintenance.FirstPublishedAt == nil ||
		pr.Maintenance.FirstPublishedAt.UTC().Format(time.RFC3339) != "2019-01-01T00:00:00Z" {
		t.Fatalf("FirstPublishedAt: got %+v, want 2019-01-01T00:00:00Z", pr.Maintenance.FirstPublishedAt)
	}
}

// TestRegistryMetadataProvider_PubUnverifiedPublisher confirms a package with
// no verified publisher (publisherId:null) leaves People nil rather than
// emitting a phantom empty publisher set — the publisherChanged diff must see
// "unknown", not an empty baseline.
func TestRegistryMetadataProvider_PubUnverifiedPublisher(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/packages/solo/publisher", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"publisherId":null}`))
	})
	mux.HandleFunc("/api/packages/solo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"solo","latest":{"version":"1.0.0","published":"2024-01-01T00:00:00Z"},
			"versions":[{"version":"1.0.0","published":"2024-01-01T00:00:00Z","pubspec":{"description":"x"}}]}`))
	})
	p, _ := newStubProvider(t, mux)

	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "pub", Package: "solo", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.People != nil {
		t.Fatalf("expected nil People for unverified package, got %+v", pr.People)
	}
}

// TestRegistryMetadataProvider_PubRetracted pins coverage-uplift Item 2-T2's
// decode half: a pub version flagged `retracted:true` must set the plumbed
// Release.Yanked=true on the matched version. The withdrawal *signal* (routing
// into versionAnomaly) is owned by provider_pubwithdrawal; this asserts the
// upstream field plumbing only.
func TestRegistryMetadataProvider_PubRetracted(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/packages/badpkg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name": "badpkg",
			"latest": {"version": "2.0.0", "published": "2024-05-01T00:00:00Z"},
			"versions": [
				{"version": "1.0.0", "published": "2023-01-01T00:00:00Z", "retracted": true, "pubspec": {"description": "old"}},
				{"version": "2.0.0", "published": "2024-05-01T00:00:00Z", "pubspec": {"description": "new"}}
			]
		}`))
	})
	p, _ := newStubProvider(t, mux)

	// The retracted 1.0.0 must surface Release.Yanked=true.
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "pub", Package: "badpkg", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Release == nil || pr.Release.Yanked == nil || !*pr.Release.Yanked {
		t.Fatalf("retracted version must set Release.Yanked=true, got %+v", pr.Release)
	}

	// A non-retracted sibling version must leave Yanked nil (three-state:
	// "not retracted" stays distinct from "unknown").
	pr2, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "pub", Package: "badpkg", Version: "2.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr2.Release == nil {
		t.Fatalf("expected release section")
	}
	if pr2.Release.Yanked != nil {
		t.Fatalf("non-retracted version must leave Yanked nil, got %v", *pr2.Release.Yanked)
	}
}

// TestRegistryMetadataProvider_PubDiscontinued pins the package-level
// discontinuation decode: isDiscontinued=true must populate Release.Deprecated
// (which feeds DeprecatedByMaintainer downstream), and a replacedBy hint must
// be threaded into the reason string. Never mints a malware verdict.
//
// CONTRACT: pub.dev exposes discontinuation ONLY on /api/packages/{name}/options
// — NOT on /api/packages/{name}. This test deliberately stubs the main endpoint
// WITHOUT any isDiscontinued field (matching the real API) and serves the flag
// from /options, so a regression that reads the wrong endpoint fails here.
func TestRegistryMetadataProvider_PubDiscontinued(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/packages/oldpkg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// No isDiscontinued/replacedBy here — the real pub.dev endpoint omits them.
		_, _ = w.Write([]byte(`{
			"name": "oldpkg",
			"latest": {"version": "1.0.0", "published": "2024-01-01T00:00:00Z"},
			"versions": [
				{"version": "1.0.0", "published": "2024-01-01T00:00:00Z", "pubspec": {"description": "x"}}
			]
		}`))
	})
	mux.HandleFunc("/api/packages/oldpkg/options", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"isDiscontinued": true, "replacedBy": "newpkg", "isUnlisted": false}`))
	})
	p, _ := newStubProvider(t, mux)

	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "pub", Package: "oldpkg", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Release == nil || pr.Release.Deprecated == "" {
		t.Fatalf("discontinued package must set Release.Deprecated, got %+v", pr.Release)
	}
	if !strings.Contains(pr.Release.Deprecated, "discontinued") || !strings.Contains(pr.Release.Deprecated, "newpkg") {
		t.Fatalf("Deprecated reason should mention discontinued + replacedBy, got %q", pr.Release.Deprecated)
	}
	// Invariant: discontinuation is malicious-adjacent, never malware. No
	// provider on this path may stamp MalwareStatus.
	if pr.SupplyChain != nil && pr.SupplyChain.MalwareStatus != "" {
		t.Fatalf("discontinued must NOT stamp MalwareStatus, got %q", pr.SupplyChain.MalwareStatus)
	}
}

// TestRegistryMetadataProvider_PubCleanNoWithdrawal confirms a healthy pub
// package (neither retracted nor discontinued) leaves Yanked nil and Deprecated
// empty — "not withdrawn", not silently stamped.
func TestRegistryMetadataProvider_PubCleanNoWithdrawal(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/packages/goodpkg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"name": "goodpkg",
			"isDiscontinued": false,
			"latest": {"version": "1.0.0", "published": "2024-01-01T00:00:00Z"},
			"versions": [
				{"version": "1.0.0", "published": "2024-01-01T00:00:00Z", "retracted": false, "pubspec": {"description": "healthy"}}
			]
		}`))
	})
	p, _ := newStubProvider(t, mux)

	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "pub", Package: "goodpkg", Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if pr.Release == nil {
		t.Fatalf("expected release section")
	}
	if pr.Release.Yanked != nil {
		t.Fatalf("clean version must leave Yanked nil, got %v", *pr.Release.Yanked)
	}
	if pr.Release.Deprecated != "" {
		t.Fatalf("clean package must leave Deprecated empty, got %q", pr.Release.Deprecated)
	}
}

func TestPubLicenseFromTags(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		want string
	}{
		{"bsd3 with markers", []string{"license:bsd-3-clause", "license:fsf-libre", "license:osi-approved"}, "BSD-3-Clause"},
		{"mit", []string{"sdk:dart", "license:mit"}, "MIT"},
		{"apache", []string{"license:apache-2.0"}, "Apache-2.0"},
		{"only markers", []string{"license:fsf-libre", "license:osi-approved"}, ""},
		{"unknown id falls back", []string{"license:zlib"}, "Zlib"},
		{"no license tag", []string{"sdk:flutter"}, ""},
		{"explicit unknown", []string{"license:unknown"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pubLicenseFromTags(tc.tags); got != tc.want {
				t.Fatalf("pubLicenseFromTags(%v) = %q, want %q", tc.tags, got, tc.want)
			}
		})
	}
}
