package swift

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// mustIdentifierMap builds a map that the caller expects to be valid.
func mustIdentifierMap(t *testing.T, cfg IdentifierMapConfig) *IdentifierMap {
	t.Helper()
	m, err := NewIdentifierMap(cfg)
	if err != nil {
		t.Fatalf("NewIdentifierMap: %v", err)
	}
	return m
}

func TestIdentifierMapStaticResolve(t *testing.T) {
	m := mustIdentifierMap(t, IdentifierMapConfig{
		Static: map[string]string{
			"apple.swift-nio": "https://github.com/apple/swift-nio.git",
		},
	})
	if got, ok := m.Resolve("apple.swift-nio"); !ok || got != "https://github.com/apple/swift-nio.git" {
		t.Errorf("Resolve static = (%q, %v), want apple's git URL", got, ok)
	}
	// case insensitive
	if got, ok := m.Resolve("APPLE.SWIFT-NIO"); !ok || got != "https://github.com/apple/swift-nio.git" {
		t.Errorf("Resolve case-insensitive = (%q, %v)", got, ok)
	}
	// unknown without convention → false
	if _, ok := m.Resolve("unknown.package"); ok {
		t.Errorf("Resolve unknown should fail when convention is disabled")
	}
}

// TestIdentifierMapConventionRequiresAllowList pins the fail-closed
// invariant: the convention cannot be enabled without something to
// constrain which GitHub orgs it will guess. An unconstrained convention
// is a scope-squatting vector — whoever registers `evil` on GitHub gets
// their code served for every `evil.<anything>` identifier — so asking
// for it with no allowlist is a configuration ERROR, not a silent grant.
func TestIdentifierMapConventionRequiresAllowList(t *testing.T) {
	for _, tc := range []struct {
		name      string
		allowList []string
	}{
		{"nil allowlist", nil},
		{"empty allowlist", []string{}},
		{"blank entries only", []string{"", "   "}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewIdentifierMap(IdentifierMapConfig{
				EnableGitHubConvention: true,
				GitHubOrgAllowList:     tc.allowList,
			})
			if !errors.Is(err, ErrConventionWithoutAllowList) {
				t.Fatalf("want ErrConventionWithoutAllowList, got err=%v map=%v", err, m)
			}
			if m != nil {
				t.Fatalf("failed construction must not return a usable map")
			}
		})
	}
}

func TestIdentifierMapGitHubConvention(t *testing.T) {
	m := mustIdentifierMap(t, IdentifierMapConfig{
		EnableGitHubConvention: true,
		GitHubOrgAllowList:     []string{"vapor"},
	})
	got, ok := m.Resolve("vapor.vapor")
	if !ok || got != "https://github.com/vapor/vapor.git" {
		t.Errorf("convention Resolve = (%q, %v)", got, ok)
	}
	// The allowlist is the whole mitigation: a scope outside it must not
	// resolve even though the convention is on.
	if got, ok := m.Resolve("attacker.vapor"); ok {
		t.Errorf("squatted scope resolved to %q; allowlist did not hold", got)
	}
}

func TestIdentifierMapGitHubConventionAllowList(t *testing.T) {
	m := mustIdentifierMap(t, IdentifierMapConfig{
		EnableGitHubConvention: true,
		GitHubOrgAllowList:     []string{"apple", "vapor"},
	})
	if _, ok := m.Resolve("vapor.vapor"); !ok {
		t.Errorf("allowed scope should resolve")
	}
	if _, ok := m.Resolve("evil.package"); ok {
		t.Errorf("scope outside allowlist should NOT resolve")
	}
}

func TestIdentifierMapReverseLookup(t *testing.T) {
	m := mustIdentifierMap(t, IdentifierMapConfig{
		Static: map[string]string{
			"apple.swift-nio": "https://github.com/apple/swift-nio.git",
		},
	})
	tests := []string{
		"https://github.com/apple/swift-nio.git",
		"https://github.com/apple/swift-nio",
		"https://GitHub.com/Apple/Swift-NIO.git",
		"https://github.com/apple/swift-nio/",
	}
	for _, in := range tests {
		got, ok := m.ReverseLookup(in)
		if !ok || got != "apple.swift-nio" {
			t.Errorf("ReverseLookup(%q) = (%q, %v)", in, got, ok)
		}
	}
	if _, ok := m.ReverseLookup("https://github.com/unknown/repo.git"); ok {
		t.Errorf("ReverseLookup unknown should fail")
	}
}

func TestIdentifierMapReverseLookupHonorsGitHubConvention(t *testing.T) {
	// Positive: convention on + scope in allowlist → reverse synthesises id.
	// This mirrors the forward Resolve path so SwiftPM's /identifiers?url=…
	// probe round-trips for convention-only packages.
	m := mustIdentifierMap(t, IdentifierMapConfig{
		EnableGitHubConvention: true,
		GitHubOrgAllowList:     []string{"apple", "vapor"},
	})

	// Forward synthesis is the comparator for the round-trip.
	fwd, ok := m.Resolve("apple.swift-log")
	if !ok || fwd != "https://github.com/apple/swift-log.git" {
		t.Fatalf("forward Resolve baseline = (%q, %v)", fwd, ok)
	}

	// Reverse synthesis: every URL variant the forward path could emit
	// (or that SwiftPM is likely to send) must round-trip.
	reverseInputs := []string{
		"https://github.com/apple/swift-log",
		"https://github.com/apple/swift-log.git",
		"https://github.com/apple/swift-log/",
		"https://GitHub.com/Apple/Swift-Log.git",
	}
	for _, in := range reverseInputs {
		got, ok := m.ReverseLookup(in)
		if !ok || got != "apple.swift-log" {
			t.Errorf("ReverseLookup(%q) = (%q, %v), want (apple.swift-log, true)", in, got, ok)
		}
	}

	// Explicit reverse entries still win over convention (no static here, but
	// we exercise the same path for a second allowed scope).
	if got, ok := m.ReverseLookup("https://github.com/vapor/vapor.git"); !ok || got != "vapor.vapor" {
		t.Errorf("ReverseLookup(vapor) = (%q, %v)", got, ok)
	}
}

func TestIdentifierMapReverseLookupConventionScopeNotAllowlisted(t *testing.T) {
	// Negative: convention on but scope not in allowlist → reverse fails.
	// Symmetric with the forward path which also refuses.
	m := mustIdentifierMap(t, IdentifierMapConfig{
		EnableGitHubConvention: true,
		GitHubOrgAllowList:     []string{"apple"},
	})
	if _, ok := m.Resolve("evil.pkg"); ok {
		t.Fatalf("forward Resolve baseline must refuse evil scope")
	}
	if id, ok := m.ReverseLookup("https://github.com/evil/pkg.git"); ok {
		t.Errorf("ReverseLookup with non-allowlisted scope must fail, got %q", id)
	}
	// Deep paths under an allowed scope are also not convention-eligible.
	if id, ok := m.ReverseLookup("https://github.com/apple/swift-log/subpath"); ok {
		t.Errorf("ReverseLookup with deep path must fail, got %q", id)
	}
	// Non-github hosts are never convention-eligible.
	if id, ok := m.ReverseLookup("https://gitlab.com/apple/swift-log.git"); ok {
		t.Errorf("ReverseLookup with non-github host must fail, got %q", id)
	}
}

func TestIdentifierMapReverseLookupConventionDisabled(t *testing.T) {
	// Negative: convention OFF → reverse falls back to explicit reverse map
	// only, so a github URL with no static entry returns false.
	m := mustIdentifierMap(t, IdentifierMapConfig{
		EnableGitHubConvention: false,
		GitHubOrgAllowList:     []string{"apple"},
	})
	if _, ok := m.ReverseLookup("https://github.com/apple/swift-log.git"); ok {
		t.Errorf("convention-off ReverseLookup must fail without explicit entry")
	}
}

func TestLoadIdentifierMapFromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "map.yaml")
	body := []byte(`
identifiers:
  apple.swift-nio: "https://github.com/apple/swift-nio.git"
  vapor.vapor: "https://github.com/vapor/vapor.git"
github_convention: true
github_org_allowlist:
  - apple
  - vapor
`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadIdentifierMapFromYAML(path)
	if err != nil {
		t.Fatalf("LoadIdentifierMapFromYAML: %v", err)
	}
	if got, ok := m.Resolve("apple.swift-nio"); !ok || got != "https://github.com/apple/swift-nio.git" {
		t.Errorf("static entry missing: %q %v", got, ok)
	}
	// convention on + in allowlist → resolves even without static entry
	if got, ok := m.Resolve("apple.other-thing"); !ok || got != "https://github.com/apple/other-thing.git" {
		t.Errorf("convention resolve failed: %q %v", got, ok)
	}
	// not in allowlist → fails
	if _, ok := m.Resolve("attacker.pkg"); ok {
		t.Errorf("attacker scope must not resolve")
	}
}

// TestLoadIdentifierMapFromYAMLConventionWithoutAllowList proves the
// invariant is enforced on the FILE path too, not just the DB-settings
// path. A map file is operator-supplied config like any other and must
// not be able to reopen the squatting hole.
func TestLoadIdentifierMapFromYAMLConventionWithoutAllowList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "map.yaml")
	body := []byte("identifiers:\n  apple.swift-nio: \"https://github.com/apple/swift-nio.git\"\ngithub_convention: true\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentifierMapFromYAML(path); !errors.Is(err, ErrConventionWithoutAllowList) {
		t.Fatalf("want ErrConventionWithoutAllowList, got %v", err)
	}
}

// TestParseIdentifierMapYAMLDistinguishesAbsentConvention pins the
// tri-state the builder relies on to merge file settings over
// deployment settings without silently discarding either.
func TestParseIdentifierMapYAMLDistinguishesAbsentConvention(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	absent, err := ParseIdentifierMapYAML(write("absent.yaml", "identifiers: {}\n"))
	if err != nil {
		t.Fatalf("parse absent: %v", err)
	}
	if absent.GitHubConvention != nil {
		t.Errorf("omitted github_convention must parse as nil, got %v", *absent.GitHubConvention)
	}

	explicitOff, err := ParseIdentifierMapYAML(write("off.yaml", "github_convention: false\n"))
	if err != nil {
		t.Fatalf("parse explicit false: %v", err)
	}
	if explicitOff.GitHubConvention == nil || *explicitOff.GitHubConvention {
		t.Errorf("explicit false must parse as non-nil false, got %v", explicitOff.GitHubConvention)
	}
}

func TestLoadIdentifierMapFromYAMLMissingFile(t *testing.T) {
	m, err := LoadIdentifierMapFromYAML(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("missing file should be tolerated: %v", err)
	}
	if _, ok := m.Resolve("apple.swift-nio"); ok {
		t.Errorf("empty map should not resolve any id")
	}
}
