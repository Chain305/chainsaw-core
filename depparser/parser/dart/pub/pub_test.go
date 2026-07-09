package pub

import (
	"sort"
	"strings"
	"testing"
)

// mixedLock exercises every source type pub emits: hosted (pub.dev), hosted on
// a custom private registry, git, path, and sdk. Only the pub.dev-hosted
// entries must survive the source filter (Task 0.7 regression net).
const mixedLock = `packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
  collection:
    dependency: "transitive"
    description:
      name: collection
      url: "https://pub.dev"
    source: hosted
    version: "1.18.0"
  no_url_hosted:
    dependency: "direct main"
    description:
      name: no_url_hosted
    source: hosted
    version: "0.5.0"
  private_pkg:
    dependency: "direct main"
    description:
      name: private_pkg
      url: "https://pub.mycorp.internal"
    source: hosted
    version: "9.9.9"
  my_git_dep:
    dependency: "direct main"
    description:
      path: "."
      ref: HEAD
      resolved-ref: "abc123"
      url: "https://github.com/example/my_git_dep.git"
    source: git
    version: "0.0.1"
  my_path_dep:
    dependency: "direct main"
    description:
      path: "../local_pkg"
      relative: true
    source: path
    version: "1.0.0"
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
  flutter_test:
    dependency: "direct dev"
    description: flutter
    source: sdk
    version: "0.0.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
`

func parseNames(t *testing.T, lock string) map[string]bool {
	t.Helper()
	pkgs, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	names := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		names[p.Name] = true
	}
	return names
}

func TestParseSourceFilter(t *testing.T) {
	pkgs, err := Parse(strings.NewReader(mixedLock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	got := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		got = append(got, p.Name)
	}
	sort.Strings(got)

	want := []string{"collection", "http", "no_url_hosted"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("emitted packages = %v, want %v", got, want)
	}

	// Explicit exclusion assertions for the false-positive-CVE classes.
	for _, excluded := range []string{
		"private_pkg",  // hosted but non-pub.dev registry
		"my_git_dep",   // git source
		"my_path_dep",  // path source
		"flutter",      // sdk source
		"flutter_test", // sdk source (dev)
	} {
		for _, p := range pkgs {
			if p.Name == excluded {
				t.Errorf("excluded package %q was emitted (source/url filter failed)", excluded)
			}
		}
	}
}

func TestParseDevFlagging(t *testing.T) {
	const lock = `packages:
  http:
    dependency: "direct main"
    description: { name: http, url: "https://pub.dev" }
    source: hosted
    version: "1.2.0"
  test:
    dependency: "direct dev"
    description: { name: test, url: "https://pub.dev" }
    source: hosted
    version: "1.25.0"
  lints:
    dependency: "transitive"
    description: { name: lints, url: "https://pub.dev" }
    source: hosted
    version: "3.0.0"
`
	pkgs, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	devByName := map[string]bool{}
	for _, p := range pkgs {
		devByName[p.Name] = p.Dev
	}
	if devByName["test"] != true {
		t.Errorf("expected test to be Dev=true")
	}
	if devByName["http"] != false || devByName["lints"] != false {
		t.Errorf("expected http/lints Dev=false, got http=%v lints=%v", devByName["http"], devByName["lints"])
	}
}

func TestParseHostedOnlyHappyPath(t *testing.T) {
	const lock = `packages:
  http:
    dependency: "direct main"
    description: { name: http, url: "https://pub.dev" }
    source: hosted
    version: "1.2.0"
  path:
    dependency: "transitive"
    description: { name: path, url: "https://pub.dev" }
    source: hosted
    version: "1.9.0"
`
	names := parseNames(t, lock)
	if !names["http"] || !names["path"] {
		t.Fatalf("expected both hosted packages, got %v", names)
	}
}

// TestParseLegacyDartlangHost is the regression net for the legacy-host false
// negative: hosted deps published before 2021 carry url:
// "https://pub.dartlang.org" (and trailing-slash variants), which serve the
// SAME packages as pub.dev. Before the fix the parser only accepted
// "https://pub.dev", so these legacy-host deps were silently dropped and never
// matched against pub.dev advisories. FAILS before the fix, PASSES after.
func TestParseLegacyDartlangHost(t *testing.T) {
	const lock = `packages:
  http:
    dependency: "direct main"
    description: { name: http, url: "https://pub.dartlang.org" }
    source: hosted
    version: "0.13.0"
  collection:
    dependency: "transitive"
    description: { name: collection, url: "https://pub.dartlang.org/" }
    source: hosted
    version: "1.15.0"
  meta:
    dependency: "transitive"
    description: { name: meta, url: "https://pub.dev/" }
    source: hosted
    version: "1.7.0"
  private_pkg:
    dependency: "direct main"
    description: { name: private_pkg, url: "https://pub.mycorp.internal" }
    source: hosted
    version: "9.9.9"
`
	names := parseNames(t, lock)
	for _, want := range []string{"http", "collection", "meta"} {
		if !names[want] {
			t.Errorf("expected legacy/canonical pub.dev host package %q to be emitted, got %v", want, names)
		}
	}
	if names["private_pkg"] {
		t.Errorf("private-registry package must NOT be emitted, got %v", names)
	}
}

func TestParseEmptyAndSdkOnlyNoPanic(t *testing.T) {
	const lock = `packages:
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
`
	pkgs, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("expected no packages from sdk-only lock, got %v", pkgs)
	}
}
