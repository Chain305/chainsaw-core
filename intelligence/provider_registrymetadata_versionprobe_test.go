package intelligence

// Tests for the Group A version_not_found probe: the ecosystems that ask
// a PER-VERSION endpoint and therefore get one 404 for two different
// facts ("no such package" and "no such version of this package").
//
// Two tests in here are load-bearing and should be read before the rest:
//
//   - TestGroupAProbeSuppressedWithoutPositiveEvidence — a package-level
//     probe that 404s or 500s must leave the generic not_found alone.
//     Emitting the marker is easy; refusing to emit it when the registry
//     said nothing is the reason this is safe to ship, because the marker
//     projects to SignalsUnavailable and flips `intel scan` to exit 2.
//
//   - TestGroupAProbeDoesNotFireOnSuccessPath — the cost guarantee. A
//     healthy scan must issue exactly the requests it issued before the
//     probe existed, so the assertion is on the literal request count and
//     the literal paths, not on a "roughly the same" heuristic.

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// countingHandler records every path served so a test can assert on the
// exact request sequence a run produced.
type countingHandler struct {
	inner http.Handler
	mu    sync.Mutex
	paths []string
}

func (c *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.paths = append(c.paths, r.URL.Path)
	c.mu.Unlock()
	c.inner.ServeHTTP(w, r)
}

func (c *countingHandler) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.paths...)
}

// newCountingStubProvider wires a counting wrapper in front of routes and
// returns a provider pointed at it. Mounting the wrapper at "/" makes it
// the catch-all, so unregistered paths still reach it (and still 404),
// which is what lets a test count the 404s too.
func newCountingStubProvider(t *testing.T, routes *http.ServeMux) (*registryMetadataProvider, *countingHandler) {
	t.Helper()
	c := &countingHandler{inner: routes}
	outer := http.NewServeMux()
	outer.Handle("/", c)
	p, _ := newStubProvider(t, outer)
	return p, c
}

// versionNotFoundMessage returns the marker's message, or "" when the
// partial report carries no marker.
func versionNotFoundMessage(pr PartialReport) string {
	for _, w := range pr.Warnings {
		if w.Code == WarnVersionNotFound {
			return w.Message
		}
	}
	return ""
}

func hasWarningCode(pr PartialReport, code string) bool {
	for _, w := range pr.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// TestGroupAVersionNotFoundProbe covers one row per ecosystem actually
// wired to the probe. huggingface is absent on purpose — a HF "version"
// is a git revision and can be an arbitrary commit SHA, so no endpoint
// enumerates the valid pins and no honest discriminator exists. See the
// decision table above promoteVersionNotFound.
func TestGroupAVersionNotFoundProbe(t *testing.T) {
	type route struct {
		path   string
		status int
		body   string
	}
	tests := []struct {
		name      string
		ecosystem string
		pkg       string
		version   string
		routes    []route
		want      bool
		why       string
	}{
		{
			name:      "pypi/package exists, version does not",
			ecosystem: "pypi",
			pkg:       "leftpad",
			version:   "9.9.9",
			routes: []route{{
				path: "/pypi/leftpad/json",
				body: `{"info":{"version":"1.0.0"},"releases":{"1.0.0":[{"upload_time_iso_8601":"2024-01-01T00:00:00Z"}]}}`,
			}},
			want: true,
			why:  "the project JSON listed 1.0.0 and nothing else",
		},
		{
			name:      "pypi/version really is published",
			ecosystem: "pypi",
			pkg:       "leftpad",
			version:   "1.0.0",
			routes: []route{{
				path: "/pypi/leftpad/json",
				body: `{"info":{"version":"1.0.0"},"releases":{"1.0.0":[]}}`,
			}},
			want: false,
			why:  "a per-version 404 against a listed version is a fetch artifact, not a hallucination",
		},
		{
			name:      "maven/package exists, version does not",
			ecosystem: "maven",
			pkg:       "com.example:widget",
			version:   "9.9.9",
			routes: []route{{
				path: "/com/example/widget/maven-metadata.xml",
				body: `<metadata><groupId>com.example</groupId><artifactId>widget</artifactId>` +
					`<versioning><latest>1.0.0</latest><versions><version>1.0.0</version></versions></versioning></metadata>`,
			}},
			want: true,
			why:  "maven-metadata.xml is the only package-level object Maven has, and it listed 1.0.0",
		},
		{
			name:      "cargo/package exists, version does not",
			ecosystem: "cargo",
			pkg:       "serde",
			version:   "9.9.9",
			routes: []route{{
				path: "/api/v1/crates/serde",
				body: `{"crate":{"max_stable_version":"1.0.0"},"versions":[{"num":"1.0.0","created_at":"2024-01-01T00:00:00Z"}]}`,
			}},
			want: true,
			why:  "the crate summary enumerates every published version",
		},
		{
			name:      "rubygems/package exists, version does not",
			ecosystem: "rubygems",
			pkg:       "rails",
			version:   "9.9.9",
			routes: []route{{
				path: "/api/v1/versions/rails.json",
				body: `[{"number":"7.1.0","created_at":"2024-01-01T00:00:00Z","prerelease":false}]`,
			}},
			want: true,
			why:  "the gem's version index listed 7.1.0",
		},
		{
			name:      "nuget/package exists, version does not",
			ecosystem: "nuget",
			pkg:       "Newtonsoft.Json",
			version:   "9.9.9",
			routes: []route{{
				path: "/newtonsoft.json/index.json",
				body: `{"versions":["13.0.3"]}`,
			}},
			want: true,
			why:  "the flat-container index is the complete, unpaginated version list",
		},
		{
			name:      "nuget/pin 1.0 against normalised 1.0.0",
			ecosystem: "nuget",
			pkg:       "Newtonsoft.Json",
			version:   "1.0",
			routes: []route{{
				path: "/newtonsoft.json/index.json",
				body: `{"versions":["1.0.0"]}`,
			}},
			want: false,
			why:  "NuGet normalises 1.0 to 1.0.0; a packages.config pin of 1.0 is a real, installed package",
		},
		{
			name:      "nuget/empty index is a partial document",
			ecosystem: "nuget",
			pkg:       "Newtonsoft.Json",
			version:   "9.9.9",
			routes: []route{{
				path: "/newtonsoft.json/index.json",
				body: `{"versions":[]}`,
			}},
			want: false,
			why:  "200 with nothing enumerated says nothing about versions",
		},
		{
			name:      "go/module exists, version does not",
			ecosystem: "go",
			pkg:       "github.com/pkg/errors",
			version:   "v9.9.9",
			routes: []route{{
				path: "/github.com/pkg/errors/@v/list",
				body: "v0.9.1\nv0.8.1\n",
			}},
			want: true,
			why:  "@v/list answers 404 only for a module the proxy has never heard of",
		},
		{
			name:      "go/empty @v/list is pseudo-versions only",
			ecosystem: "go",
			pkg:       "github.com/pkg/errors",
			version:   "v9.9.9",
			routes: []route{{
				path: "/github.com/pkg/errors/@v/list",
				body: "",
			}},
			want: false,
			why:  "a module with no tagged versions answers 200 with an empty body; that is not a version list",
		},
		{
			name:      "docker/image exists, tag does not",
			ecosystem: "docker",
			pkg:       "library/nginx",
			version:   "9.9.9",
			routes: []route{
				{
					path: "/v2/repositories/library/nginx/",
					body: `{"name":"nginx","namespace":"library","user":"library","last_updated":"2024-01-01T00:00:00Z"}`,
				},
				// Registered explicitly because the repository route above
				// is a ServeMux SUBTREE pattern and would otherwise serve
				// the repo body for every tag, masking the 404 under test.
				{path: "/v2/repositories/library/nginx/tags/", status: http.StatusNotFound},
			},
			want: true,
			why:  "the repository object answered 200 while the tag object 404ed",
		},
		{
			name:      "docker/digest pin is not a tag",
			ecosystem: "docker",
			pkg:       "library/nginx",
			version:   "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			routes: []route{
				{
					path: "/v2/repositories/library/nginx/",
					body: `{"name":"nginx","namespace":"library","user":"library"}`,
				},
				{path: "/v2/repositories/library/nginx/tags/", status: http.StatusNotFound},
			},
			want: false,
			why:  "Hub's /tags/{ref}/ 404s for every digest; promoting that would unevaluate all digest pins",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			routes := http.NewServeMux()
			for _, r := range tc.routes {
				r := r
				routes.HandleFunc(r.path, func(w http.ResponseWriter, _ *http.Request) {
					if r.status != 0 {
						w.WriteHeader(r.status)
						return
					}
					_, _ = w.Write([]byte(r.body))
				})
			}
			p, _ := newStubProvider(t, routes)

			pr, err := p.Run(context.Background(), Request{Key: Key{
				Ecosystem: tc.ecosystem, Package: tc.pkg, Version: tc.version,
			}}, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if got := hasVersionNotFound(pr); got != tc.want {
				t.Fatalf("version_not_found = %v, want %v (%s)\nwarnings: %+v",
					got, tc.want, tc.why, pr.Warnings)
			}
			if tc.want {
				// The finding on this path IS the endpoint pair, so the
				// message has to carry both halves for an operator to be
				// able to re-run the check by hand.
				msg := versionNotFoundMessage(pr)
				if !strings.Contains(msg, "endpoint=") || !strings.Contains(msg, "packageEndpoint=") {
					t.Fatalf("marker message must name both endpoints, got %q", msg)
				}
			}
		})
	}
}

// TestGroupAProbeSuppressedWithoutPositiveEvidence is the false-positive
// guard the whole feature rests on. A package-level probe that 404s means
// the package itself is absent (not_found is already the right, narrower
// answer); a probe that 5xxs means the registry told us nothing at all.
// Neither may be promoted into a claim that the version does not exist.
func TestGroupAProbeSuppressedWithoutPositiveEvidence(t *testing.T) {
	tests := []struct {
		name        string
		probeStatus int // 0 = do not register the route at all (404)
		why         string
	}{
		{
			name:        "package-level 404",
			probeStatus: 0,
			why:         "the package itself is absent; not_found already says so",
		},
		{
			name:        "package-level 500",
			probeStatus: http.StatusInternalServerError,
			why:         "absence of evidence is not evidence of absence — a registry outage must not break a build",
		},
		{
			name:        "package-level 403",
			probeStatus: http.StatusForbidden,
			why:         "an auth wall tells us nothing about the version list",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			routes := http.NewServeMux()
			if tc.probeStatus != 0 {
				status := tc.probeStatus
				routes.HandleFunc("/pypi/leftpad/json", func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(status)
				})
			}
			p, _ := newStubProvider(t, routes)

			pr, err := p.Run(context.Background(), Request{Key: Key{
				Ecosystem: "pypi", Package: "leftpad", Version: "9.9.9",
			}}, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if hasVersionNotFound(pr) {
				t.Fatalf("marker emitted without positive evidence (%s): %+v", tc.why, pr.Warnings)
			}
			if !hasWarningCode(pr, "not_found") {
				t.Fatalf("the original not_found must survive untouched, got %+v", pr.Warnings)
			}
		})
	}
}

// TestGroupAProbeDoesNotFireOnSuccessPath pins the cost contract: the
// probe is behind the 404 branch, so a healthy scan issues exactly the
// requests it issued before the probe existed.
//
// For PyPI that is two, both of which predate this change: the
// per-version document, and the project-level document runPyPI has always
// fetched to build the version timeline. If a future edit hoists the
// probe out of the 404 branch this count goes to three and the test says
// so.
func TestGroupAProbeDoesNotFireOnSuccessPath(t *testing.T) {
	routes := http.NewServeMux()
	routes.HandleFunc("/pypi/leftpad/1.0.0/json", func(w http.ResponseWriter, _ *http.Request) {
		// No home_page / project_urls, so no SourceRepoURL and therefore
		// no enrichRepoStars call to muddy the count.
		_, _ = w.Write([]byte(`{"info":{"version":"1.0.0","summary":"pad"},"urls":[]}`))
	})
	routes.HandleFunc("/pypi/leftpad/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"version":"1.0.0"},"releases":{"1.0.0":[{"upload_time_iso_8601":"2024-01-01T00:00:00Z"}]}}`))
	})
	p, counter := newCountingStubProvider(t, routes)

	pr, err := p.Run(context.Background(), Request{Key: Key{
		Ecosystem: "pypi", Package: "leftpad", Version: "1.0.0",
	}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if hasVersionNotFound(pr) {
		t.Fatalf("success path emitted the marker: %+v", pr.Warnings)
	}

	got := counter.seen()
	want := []string{"/pypi/leftpad/1.0.0/json", "/pypi/leftpad/json"}
	if len(got) != len(want) {
		t.Fatalf("success path issued %d requests %v, want %d %v — the probe must not fire when the version resolves",
			len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("request %d = %q, want %q (full sequence %v)", i, got[i], want[i], got)
		}
	}
}

// TestGroupAProbeIssuesExactlyOneExtraRequest pins the other half of the
// cost contract. The retry loop treats 4xx as terminal, so the 404 must
// not become three requests, and the probe must not become a second
// retry storm on top of it.
func TestGroupAProbeIssuesExactlyOneExtraRequest(t *testing.T) {
	routes := http.NewServeMux()
	routes.HandleFunc("/pypi/leftpad/json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"info":{"version":"1.0.0"},"releases":{"1.0.0":[]}}`))
	})
	p, counter := newCountingStubProvider(t, routes)

	pr, err := p.Run(context.Background(), Request{Key: Key{
		Ecosystem: "pypi", Package: "leftpad", Version: "9.9.9",
	}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !hasVersionNotFound(pr) {
		t.Fatalf("expected the marker, got %+v", pr.Warnings)
	}

	got := counter.seen()
	want := []string{"/pypi/leftpad/9.9.9/json", "/pypi/leftpad/json"}
	if len(got) != len(want) {
		t.Fatalf("404 path issued %d requests %v, want exactly %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("request %d = %q, want %q (full sequence %v)", i, got[i], want[i], got)
		}
	}
}

// TestCanonicalVersionKey documents the suppress-only comparison. It can
// only ever hide a marker, never manufacture one, which is why the
// trailing-zero collapse is an acceptable trade on Maven (where 1.0 and
// 1.0.0 really are different artifacts) in exchange for not calling every
// NuGet `1.0` pin a hallucination.
func TestCanonicalVersionKey(t *testing.T) {
	same := [][2]string{
		{"1.0", "1.0.0"},
		{"1.0.0", "1.0.0.0"},
		{"v1.2.3", "1.2.3"},
		{"1.2.3+build5", "1.2.3"},
		{"1.0.0-RC1", "1.0.0-rc1"},
	}
	for _, pair := range same {
		if canonicalVersionKey(pair[0]) != canonicalVersionKey(pair[1]) {
			t.Errorf("%q and %q should share a key, got %q vs %q",
				pair[0], pair[1], canonicalVersionKey(pair[0]), canonicalVersionKey(pair[1]))
		}
	}
	differ := [][2]string{
		{"1.0.0", "1.0.1"},
		{"1.0.0-rc1", "1.0.0"},
		{"2.0", "1.0"},
	}
	for _, pair := range differ {
		if canonicalVersionKey(pair[0]) == canonicalVersionKey(pair[1]) {
			t.Errorf("%q and %q must not share a key (%q)",
				pair[0], pair[1], canonicalVersionKey(pair[0]))
		}
	}
}
