package depgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func cmp(name, version string) Key {
	return Key{Ecosystem: "composer", Name: name, Version: version}
}

func TestParseComposerLockfile_Simple(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "composer_simple.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseComposerLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	root := cmp("monolog/monolog", "2.9.1")
	if len(g.Roots) != 1 || g.Roots[0] != root {
		t.Fatalf("roots: got %v, want [%v]", g.Roots, root)
	}
	dep := cmp("psr/log", "1.1.4")
	n, ok := g.Nodes[dep]
	if !ok {
		t.Fatalf("psr/log not in graph: %v", g.Nodes)
	}
	if n.Direct {
		t.Errorf("psr/log should NOT be Direct (transitive)")
	}
	if d := g.Depth(dep); d != 1 {
		t.Errorf("psr/log depth: got %d, want 1", d)
	}
}

func TestParseComposerLockfile_TransitiveChain(t *testing.T) {
	data := []byte(`{
  "packages": [
    {"name":"acme/app","version":"1.0.0","require":{"acme/lib-a":"^2.0"}},
    {"name":"acme/lib-a","version":"2.0.0","require":{"acme/lib-b":"^3.0"}},
    {"name":"acme/lib-b","version":"3.0.0","require":{}}
  ]
}`)
	g, err := ParseComposerLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	a := cmp("acme/lib-a", "2.0.0")
	b := cmp("acme/lib-b", "3.0.0")
	if g.Nodes[a].Direct {
		t.Errorf("lib-a should NOT be Direct (it is required by app)")
	}
	if d := g.Depth(b); d != 2 {
		t.Errorf("lib-b depth: got %d, want 2", d)
	}
	root := cmp("acme/app", "1.0.0")
	if len(g.Roots) != 1 || g.Roots[0] != root {
		t.Fatalf("roots: got %v, want [%v]", g.Roots, root)
	}
}

func TestParseComposerLockfile_Diamond(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "composer_diamond.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseComposerLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	psr := cmp("psr/log", "1.1.4")
	n, ok := g.Nodes[psr]
	if !ok {
		t.Fatalf("psr/log missing")
	}
	if len(n.Parents) != 2 {
		t.Errorf("psr/log parents: got %d, want 2 (diamond)", len(n.Parents))
	}
	if d := g.Depth(psr); d != 2 {
		t.Errorf("psr/log depth: got %d, want 2", d)
	}
}

func TestParseComposerLockfile_DevProdSeparation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "composer_with_dev.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseComposerLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	prod := cmp("psr/log", "1.1.4")
	if !g.Nodes[prod].Prod {
		t.Errorf("psr/log should be Prod=true")
	}
	dev := cmp("phpunit/phpunit", "9.5.0")
	devNode, ok := g.Nodes[dev]
	if !ok {
		t.Fatalf("phpunit not in graph")
	}
	if devNode.Prod {
		t.Errorf("phpunit/phpunit should be Prod=false (packages-dev)")
	}
	devTrans := cmp("phpunit/php-code-coverage", "9.2.0")
	if g.Nodes[devTrans].Prod {
		t.Errorf("phpunit/php-code-coverage should be Prod=false")
	}

	// Both top-level prod and top-level dev nodes should be roots
	// (neither is required by another package).
	wantRoots := map[Key]bool{
		cmp("acme/app", "1.0.0"):        false,
		cmp("phpunit/phpunit", "9.5.0"): false,
	}
	for _, r := range g.Roots {
		if _, ok := wantRoots[r]; ok {
			wantRoots[r] = true
		}
	}
	for k, seen := range wantRoots {
		if !seen {
			t.Errorf("expected root %v in g.Roots=%v", k, g.Roots)
		}
	}
}

func TestParseComposerLockfile_PlatformExclusion(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "composer_with_platform.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseComposerLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	// php / ext-* / lib-* must NOT appear as nodes.
	for k := range g.Nodes {
		switch {
		case k.Name == "php",
			k.Name == "ext-json",
			k.Name == "ext-mbstring",
			k.Name == "lib-openssl":
			t.Errorf("platform pseudo-package %v leaked into graph", k)
		}
	}
	// Real edge survives.
	app := cmp("acme/app", "1.0.0")
	psr := cmp("psr/log", "1.1.4")
	found := false
	for _, c := range g.Nodes[app].Children {
		if c == psr {
			found = true
		}
	}
	if !found {
		t.Errorf("expected acme/app→psr/log edge; children=%v", g.Nodes[app].Children)
	}
}

func TestParseComposerLockfileWithJSON_ManifestRoots(t *testing.T) {
	lock, err := os.ReadFile(filepath.Join("testdata", "composer_with_root_json.lock"))
	if err != nil {
		t.Fatalf("read lock: %v", err)
	}
	manifest, err := os.ReadFile(filepath.Join("testdata", "composer_with_root_json.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	// Without manifest: heuristic picks acme/app + phpunit/phpunit only;
	// acme/util is inferred as transitive (required by acme/app).
	gNoMan, err := ParseComposerLockfile(lock)
	if err != nil {
		t.Fatalf("parse no-manifest: %v", err)
	}
	hasUtilRoot := false
	for _, r := range gNoMan.Roots {
		if r.Name == "acme/util" {
			hasUtilRoot = true
		}
	}
	if hasUtilRoot {
		t.Errorf("inference should NOT promote acme/util to root; roots=%v", gNoMan.Roots)
	}

	// With manifest: acme/util IS a declared require, so it surfaces
	// as a root even though acme/app also requires it transitively.
	g, err := ParseComposerLockfileWithJSON(lock, manifest)
	if err != nil {
		t.Fatalf("parse with manifest: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	wantRoots := map[Key]bool{
		cmp("acme/app", "1.0.0"):        false,
		cmp("acme/util", "2.1.0"):       false,
		cmp("phpunit/phpunit", "9.5.0"): false,
	}
	for _, r := range g.Roots {
		if _, ok := wantRoots[r]; ok {
			wantRoots[r] = true
		}
	}
	for k, seen := range wantRoots {
		if !seen {
			t.Errorf("manifest-root %v missing from g.Roots=%v", k, g.Roots)
		}
	}
	// require-dev membership keeps Prod=false.
	phpunit := cmp("phpunit/phpunit", "9.5.0")
	if g.Nodes[phpunit].Prod {
		t.Errorf("phpunit should be Prod=false (require-dev only)")
	}
	util := cmp("acme/util", "2.1.0")
	if !g.Nodes[util].Prod {
		t.Errorf("acme/util should be Prod=true (require)")
	}
}

func TestParseComposerLockfileWithJSON_NilFallsBack(t *testing.T) {
	// Passing nil composerJSON is identical to ParseComposerLockfile.
	data, err := os.ReadFile(filepath.Join("testdata", "composer_simple.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g1, err := ParseComposerLockfile(data)
	if err != nil {
		t.Fatalf("baseline: %v", err)
	}
	g2, err := ParseComposerLockfileWithJSON(data, nil)
	if err != nil {
		t.Fatalf("nil-json: %v", err)
	}
	if len(g1.Roots) != len(g2.Roots) {
		t.Fatalf("root counts differ: %d vs %d", len(g1.Roots), len(g2.Roots))
	}
}

func TestParseComposerLockfileWithJSON_EmptyManifestFallsBack(t *testing.T) {
	// An empty/manifest-without-require composer.json must NOT strand
	// the graph — we fall back to inference.
	lock := []byte(`{
  "packages": [
    {"name":"acme/app","version":"1.0.0","require":{"psr/log":"^1.0"}},
    {"name":"psr/log","version":"1.1.4","require":{}}
  ]
}`)
	manifest := []byte(`{}`)
	g, err := ParseComposerLockfileWithJSON(lock, manifest)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	root := cmp("acme/app", "1.0.0")
	if len(g.Roots) != 1 || g.Roots[0] != root {
		t.Errorf("empty-manifest fallback roots: got %v, want [%v]", g.Roots, root)
	}
}

func TestParseComposerLockfile_Malformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":           []byte(``),
		"not-json":        []byte(`<<not json>>`),
		"empty-object":    []byte(`{}`),
		"missing-version": []byte(`{"packages":[{"name":"a/b"}]}`),
		"missing-name":    []byte(`{"packages":[{"version":"1.0.0"}]}`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseComposerLockfile(data); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestIsComposerPlatform(t *testing.T) {
	cases := map[string]bool{
		"php":          true,
		"php-64bit":    true,
		"ext-json":     true,
		"ext-mbstring": true,
		"lib-openssl":  true,
		"vendor/pkg":   false,
		"phpunit":      false, // bare name; not vendor/pkg, but also not a platform prefix
	}
	for in, want := range cases {
		if got := isComposerPlatform(in); got != want {
			t.Errorf("isComposerPlatform(%q) = %v, want %v", in, got, want)
		}
	}
}
