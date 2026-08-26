package intelligence

// P8-45 — `chainsaw intel package npm lodash latest` must return a scored
// verdict for the version the tag points at, not NOT EVALUATED.
//
// The two negative controls are as important as the positive case and are
// the reason the rule is an allowlist rather than a "resolve `latest`
// everywhere":
//
//	maven  … latest  must keep taking the version_not_evaluable branch
//	                 (LATEST is a Maven RESOLVER DIRECTIVE, not a version)
//	docker … latest  must keep scoring (it is an ordinary tag that
//	                 Docker Hub serves a manifest for)

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withStubLatestRegistries points every latest-resolver at h for the
// duration of the test and restores the production roots afterwards.
func withStubLatestRegistries(t *testing.T, h http.Handler) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	saved := latestRegistryBases
	t.Cleanup(func() { latestRegistryBases = saved })
	latestRegistryBases.npm = srv.URL
	latestRegistryBases.pypi = srv.URL
	latestRegistryBases.cargo = srv.URL
	latestRegistryBases.rubygems = srv.URL
}

func TestResolvableLatestSentinel(t *testing.T) {
	cases := []struct {
		eco, ver string
		want     bool
		why      string
	}{
		{"npm", "latest", true, "the case the defect is about"},
		{"pypi", "latest", true, ""},
		{"pip", "latest", true, "alias of pypi"},
		{"cargo", "latest", true, ""},
		{"rubygems", "latest", true, ""},
		{"yarn", "latest", true, "shares npm's registry"},
		{"NPM", "latest", true, "ecosystem case must not matter (P8-33)"},
		{"npm", " latest ", true, "the wire may pad the segment"},

		// -- negative controls --
		{"docker", "latest", false, "an ordinary tag Docker Hub serves; already scores"},
		{"oci", "latest", false, "docker's other spelling"},
		{"maven", "latest", false, "LATEST is a Maven resolver directive"},
		{"gradle", "latest", false, "Maven family"},
		{"maven", "LATEST", false, "Maven family, upper-cased"},
		{"nuget", "latest", false, "no resolver exists, so nothing to dereference"},
		{"composer", "latest", false, "no resolver exists"},

		{"npm", "4.17.21", false, "an ordinary version"},
		{"npm", "LATEST", false, "dist-tags are case-sensitive; LATEST is not one"},
		{"npm", "latest-1", false, "a real dist-tag name that merely starts with it"},
		{"npm", "", false, ""},
	}
	for _, tc := range cases {
		got := ResolvableLatestSentinel(tc.eco, tc.ver)
		if got != tc.want {
			t.Errorf("ResolvableLatestSentinel(%q, %q) = %v, want %v — %s",
				tc.eco, tc.ver, got, tc.want, tc.why)
		}
	}
}

// The Maven negative control, stated as the property that actually matters:
// the coordinate must still reach the version_not_evaluable branch, which
// is what routes it to Unknown with the right explanation.
func TestMavenLatestStaysNotEvaluable(t *testing.T) {
	for _, eco := range []string{"maven", "gradle"} {
		for _, ver := range []string{"latest", "LATEST"} {
			if ResolvableLatestSentinel(eco, ver) {
				t.Fatalf("%s %s must not be dereferenced", eco, ver)
			}
			if reason := UnevaluableVersionReason(eco, ver); reason != UnevaluableVersionMavenNonVersion {
				t.Errorf("UnevaluableVersionReason(%q,%q) = %q, want %q — "+
					"the resolver must not have taken this branch away",
					eco, ver, reason, UnevaluableVersionMavenNonVersion)
			}
		}
	}
}

// The docker negative control: `latest` is a real tag, so the coordinate
// must stay evaluable AND must not be rewritten.
func TestDockerLatestStillScores(t *testing.T) {
	if !EvaluableVersion("docker", "latest") {
		t.Fatal("docker latest must stay an evaluable coordinate")
	}
	key := Key{Ecosystem: "docker", Package: "library/nginx", Version: "latest"}
	got, was := ResolveLatestKey(context.Background(), key)
	if was != "" || got.Version != "latest" {
		t.Fatalf("ResolveLatestKey rewrote a docker tag: %+v (was %q)", got, was)
	}
}

func TestResolveLatestKeyDereferencesDistTag(t *testing.T) {
	withStubLatestRegistries(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/lodash"):
			_, _ = w.Write([]byte(`{"dist-tags":{"latest":"4.17.21","next":"5.0.0-rc1"}}`))
		case strings.HasPrefix(r.URL.Path, "/pypi/requests/"):
			_, _ = w.Write([]byte(`{"info":{"version":"2.32.3"}}`))
		default:
			http.NotFound(w, r)
		}
	}))

	t.Run("npm", func(t *testing.T) {
		got, was := ResolveLatestKey(context.Background(),
			Key{Ecosystem: "npm", Package: "lodash", Version: "latest"})
		if was != "latest" {
			t.Fatalf("substituted version = %q, want %q", was, "latest")
		}
		if got.Version != "4.17.21" {
			t.Fatalf("Version = %q, want 4.17.21 (dist-tags.latest)", got.Version)
		}
	})

	t.Run("pypi", func(t *testing.T) {
		got, _ := ResolveLatestKey(context.Background(),
			Key{Ecosystem: "pypi", Package: "requests", Version: "latest"})
		if got.Version != "2.32.3" {
			t.Fatalf("Version = %q, want 2.32.3", got.Version)
		}
	})

	// A registry that does not answer must leave the coordinate alone —
	// inventing a version would be strictly worse than the NOT EVALUATED
	// this fix removes.
	t.Run("unresolvable package leaves the key alone", func(t *testing.T) {
		key := Key{Ecosystem: "npm", Package: "does-not-exist", Version: "latest"}
		got, was := ResolveLatestKey(context.Background(), key)
		if was != "" || got.Version != "latest" {
			t.Fatalf("got %+v (was %q), want the key unchanged", got, was)
		}
	})
}

// The resolvable allowlist and the resolver switch must not drift: an
// ecosystem in the list with no resolver arm silently returns "" forever,
// and — worse — makes the one-shot cleanup delete rows that will come
// straight back with the same unresolved answer.
func TestLatestResolvableSetHasAResolver(t *testing.T) {
	withStubLatestRegistries(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every shape the four resolvers can read, so a resolver that
		// exists answers and one that does not returns "".
		_, _ = w.Write([]byte(`{"dist-tags":{"latest":"9.9.9"},` +
			`"info":{"version":"9.9.9"},` +
			`"crate":{"max_stable_version":"9.9.9"},` +
			`"version":"9.9.9"}`))
	}))
	for _, eco := range latestResolvableEcosystems {
		if got := ResolveLatestVersion(context.Background(), eco, "anything"); got != "9.9.9" {
			t.Errorf("ResolveLatestVersion(%q) = %q, want 9.9.9 — "+
				"the ecosystem is in latestResolvableEcosystems with no resolver arm", eco, got)
		}
	}
}

// LatestSentinelRule is what the DELETE runs against. It must carry exactly
// the resolvable set, and must never carry docker or a Maven-family name.
func TestLatestSentinelRuleExcludesDockerAndMaven(t *testing.T) {
	rule := LatestSentinelRule()
	if rule.Sentinel != LatestSentinel {
		t.Fatalf("Sentinel = %q, want %q", rule.Sentinel, LatestSentinel)
	}
	if len(rule.Ecosystems) != len(latestResolvableEcosystems) {
		t.Fatalf("Ecosystems = %v, want the resolvable set %v",
			rule.Ecosystems, latestResolvableEcosystems)
	}
	banned := append([]string{"docker", "oci"}, mavenFamilyEcosystems...)
	for _, e := range rule.Ecosystems {
		for _, b := range banned {
			if strings.EqualFold(e, b) {
				t.Fatalf("purge allowlist contains %q — that DELETE would "+
					"destroy real evaluations", e)
			}
		}
	}
	// Mutating the returned slice must not reach the package definition.
	rule.Ecosystems[0] = "mutated"
	if latestResolvableEcosystems[0] == "mutated" {
		t.Fatal("LatestSentinelRule handed out the package-level slice")
	}
}
