package intelligence

// Y2 regression guard, provider half.
//
// The Go depparsers (core/depparser/parser/golang/{mod,sum}) both emit
// versions WITHOUT the leading "v" so their coordinates dedup against each
// other and match how vuln DBs index semver. The Go module proxy protocol
// requires the "v" — "@v/1.2.3.info" is rejected as an invalid version — and
// deps.dev indexes the canonical spelling too. So every version reaching this
// provider must have the prefix put back before it goes on the wire.
//
// Without this, stripping in mod.go would have silently deleted the only Go
// row that returned real release/license/source-repo data.

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestRunGoRestoresVPrefixOnStrippedVersion(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.RequestURI)
		mu.Unlock()

		switch {
		case strings.HasSuffix(r.RequestURI, "/@v/v1.2.3.info"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Version":"v1.2.3","Time":"2024-01-15T12:00:00Z","Origin":{"URL":"https://github.com/foo/bar"}}`))
		case strings.HasSuffix(r.RequestURI, "/@latest"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Version":"v1.2.4"}`))
		case strings.HasSuffix(r.RequestURI, "/@v/v1.2.3.mod"):
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("module github.com/foo/bar\n\ngo 1.21\n\nrequire github.com/stretchr/testify v1.9.0\n"))
		case strings.Contains(r.RequestURI, "/v3/systems/go/packages/"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"licenses":["MIT"]}`))
		default:
			// Anything else — notably an un-prefixed "@v/1.2.3.info" — is
			// what proxy.golang.org answers with for an invalid version.
			http.NotFound(w, r)
		}
	})

	p, _ := newStubProvider(t, mux)

	// The stripped spelling the depparsers now emit for every Go module.
	pr, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "go", Package: "github.com/foo/bar", Version: "1.2.3"},
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(pr.Warnings) > 0 {
		t.Fatalf("stripped version produced warnings — the prefix was not restored: %+v", pr.Warnings)
	}

	mu.Lock()
	requested := append([]string(nil), seen...)
	mu.Unlock()

	for _, want := range []string{
		"/github.com/foo/bar/@v/v1.2.3.info",
		"/github.com/foo/bar/@v/v1.2.3.mod",
	} {
		if !containsExact(requested, want) {
			t.Errorf("never requested %s\nrequests: %v", want, requested)
		}
	}
	for _, got := range requested {
		if strings.Contains(got, "/@v/1.2.3") {
			t.Errorf("requested a version without the \"v\" prefix — the module proxy rejects it: %s", got)
		}
	}
	// deps.dev must also see the canonical spelling.
	var sawDepsDev bool
	for _, got := range requested {
		if strings.Contains(got, "/v3/systems/go/packages/") {
			sawDepsDev = true
			if !strings.HasSuffix(got, "/versions/v1.2.3") {
				t.Errorf("deps.dev version segment not canonical: %s", got)
			}
		}
	}
	if !sawDepsDev {
		t.Errorf("deps.dev license lookup never fired\nrequests: %v", requested)
	}

	// The whole point: real data came back for a stripped input version.
	if pr.URLs == nil || !strings.HasSuffix(pr.URLs.MetadataURL, "/@v/v1.2.3.info") {
		t.Errorf("MetadataURL not v-prefixed: %+v", pr.URLs)
	}
	if pr.URLs == nil || pr.URLs.SourceRepoURL != "https://github.com/foo/bar" {
		t.Errorf("SourceRepoURL empty — the report would have been blank: %+v", pr.URLs)
	}
	if pr.Release == nil || pr.Release.PublishedAt == nil {
		t.Errorf("Release.PublishedAt empty: %+v", pr.Release)
	}
	if pr.Metadata == nil || pr.Metadata.LicenseExpression != "MIT" {
		t.Errorf("LicenseExpression not resolved: %+v", pr.Metadata)
	}
	if pr.Dependencies == nil || len(pr.Dependencies.Direct) != 1 {
		t.Errorf("go.mod dependencies not resolved: %+v", pr.Dependencies)
	}
}

// TestGoProxyVersionIdempotent — a version that already carries the prefix
// (bare `chainsaw scan pkg@v1.2.3` specs, cached rows) must pass through
// untouched, never becoming "vv1.2.3".
func TestGoProxyVersionIdempotent(t *testing.T) {
	cases := map[string]string{
		"1.2.3":                            "v1.2.3",
		"v1.2.3":                           "v1.2.3",
		"  v1.2.3  ":                       "v1.2.3",
		"0.0.0-20240103183307-be819d1f06f": "v0.0.0-20240103183307-be819d1f06f",
		"2.0.0+incompatible":               "v2.0.0+incompatible",
		"":                                 "",
	}
	for in, want := range cases {
		if got := goProxyVersion(in); got != want {
			t.Errorf("goProxyVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func containsExact(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
