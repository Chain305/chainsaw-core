package intelligence

import (
	"context"
	"net/http"
	"testing"
)

// The fixture is a trimmed copy of formulae.brew.sh/api/formula/jq.json and
// its ghcr.io manifest index (2026-11-04), with a revision and a deprecation
// added so every mapped field is exercised.
const homebrewJQFixture = `{
  "name": "jq", "tap": "homebrew/core", "desc": "Lightweight and flexible command-line JSON processor",
  "license": "MIT", "homepage": "https://jqlang.github.io/jq/",
  "versions": {"stable": "1.8.2", "bottle": true},
  "revision": 1,
  "urls": {"stable": {"url": "https://github.com/jqlang/jq/releases/download/jq-1.8.2/jq-1.8.2.tar.gz"}},
  "bottle": {"stable": {"rebuild": 1, "files": {"arm64_sequoia": {"url": "https://ghcr.io/v2/homebrew/core/jq/blobs/sha256:ef70", "sha256": "ef70"}}}},
  "deprecated": true, "deprecation_reason": "unmaintained", "deprecation_replacement_formula": "gojq",
  "analytics": {"install": {"90d": {"jq": 181192, "jq --HEAD": 514, "jqp": 9}}}
}`

func newHomebrewStub(t *testing.T) (*registryMetadataProvider, *int) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/formula/jq.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(homebrewJQFixture))
	})
	manifestHits := 0
	mux.HandleFunc("/v2/homebrew/core/jq/manifests/1.8.2_1-1", func(w http.ResponseWriter, r *http.Request) {
		manifestHits++
		if r.Header.Get("Authorization") != "Bearer QQ==" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"annotations":{"org.opencontainers.image.created":"2026-08-17T13:32:32Z"}}`))
	})
	p, srv := newStubProvider(t, mux)
	p.endpoints.homebrew = srv.URL
	p.endpoints.homebrewBottles = srv.URL
	return p, &manifestHits
}

func TestRegistryMetadataHomebrewCurrentVersion(t *testing.T) {
	p, _ := newHomebrewStub(t)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "homebrew", Package: "jq", Version: "1.8.2_1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pr.Warnings) != 0 {
		t.Fatalf("warnings: %+v", pr.Warnings)
	}
	if pr.Metadata == nil || pr.Metadata.LicenseExpression != "MIT" || pr.Metadata.Description == "" {
		t.Errorf("metadata = %+v", pr.Metadata)
	}
	if pr.Release.LatestVersion != "1.8.2_1" {
		t.Errorf("latest = %q, want pkg_version 1.8.2_1", pr.Release.LatestVersion)
	}
	if want := "deprecated: unmaintained; replaced by gojq"; pr.Release.Deprecated != want {
		t.Errorf("deprecated = %q, want %q", pr.Release.Deprecated, want)
	}
	if pr.Release.PublishedAt == nil || pr.Release.PublishedAt.Format("2006-01-02") != "2026-08-17" {
		t.Errorf("publishedAt = %v, want the bottle manifest's created time", pr.Release.PublishedAt)
	}
	if pr.URLs.SourceRepoURL != "https://github.com/jqlang/jq" {
		t.Errorf("source repo = %q", pr.URLs.SourceRepoURL)
	}
	d := pr.Maintenance.Downloads
	if d == nil || d.Count != 181192+514 || d.Window != DownloadWindow90Days {
		t.Errorf("downloads = %+v, want jq + its option rows, not jqp", d)
	}
}

// Homebrew publishes only the current version, so an older pkg_version gets
// the formula-level facts but no publish date and — the point — no
// version_not_found.
func TestRegistryMetadataHomebrewOlderVersionIsNotNotFound(t *testing.T) {
	p, manifestHits := newHomebrewStub(t)
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "homebrew", Package: "jq", Version: "1.7.1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range pr.Warnings {
		t.Errorf("unexpected warning %s: %s", w.Code, w.Message)
	}
	if pr.Release.PublishedAt != nil || *manifestHits != 0 {
		t.Errorf("publishedAt = %v (manifest hits %d); an older version has no knowable date", pr.Release.PublishedAt, *manifestHits)
	}
	if pr.Metadata == nil || pr.Metadata.LicenseExpression != "MIT" {
		t.Errorf("formula-level licence missing: %+v", pr.Metadata)
	}
}

func TestRegistryMetadataHomebrewThirdPartyTapIsNotApplicable(t *testing.T) {
	p, _ := newHomebrewStub(t)
	pr, _ := p.Run(context.Background(), Request{Key: Key{Ecosystem: "homebrew", Package: "someone/tap/jq", Version: "1.0"}}, nil)
	if pr.Metadata != nil || len(pr.Warnings) != 1 || pr.Warnings[0].Code != WarnUnsupported {
		t.Fatalf("a tap formula must not borrow core jq's facts: %+v", pr)
	}
}

func TestRegistryMetadataHomebrew404IsNotPackageNotFound(t *testing.T) {
	p, _ := newHomebrewStub(t)
	pr, _ := p.Run(context.Background(), Request{Key: Key{Ecosystem: "homebrew", Package: "nosuch", Version: "1.0"}}, nil)
	for _, w := range pr.Warnings {
		if w.Code == WarnPackageNotFound {
			t.Fatalf("a name missing from homebrew/core may be a tap formula; got %s", w.Code)
		}
	}
	if len(pr.Warnings) == 0 {
		t.Fatal("a 404 must still leave a warning")
	}
}
