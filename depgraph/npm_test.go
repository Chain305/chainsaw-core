package depgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseNPMLockfile_Simple(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "npm-simple.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseNPMLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Expect 3 roots: lodash, left-pad, mocha.
	if len(g.Roots) != 3 {
		t.Errorf("roots: got %d, want 3: %v", len(g.Roots), g.Roots)
	}

	// lodash@4.17.21 should be a node with parents left-pad and mocha.
	lodash := mk("lodash", "4.17.21")
	n, ok := g.Nodes[lodash]
	if !ok {
		t.Fatalf("lodash not in graph")
	}
	if len(n.Parents) < 2 {
		t.Errorf("expected lodash to have >=2 parents, got %v", n.Parents)
	}

	// mocha is a dev-only dep — should have Prod=false.
	mocha := mk("mocha", "10.2.0")
	if g.Nodes[mocha].Prod {
		t.Error("mocha expected Prod=false")
	}

	// left-pad is prod and is a root.
	leftpad := mk("left-pad", "1.3.0")
	if !g.Nodes[leftpad].Prod {
		t.Error("left-pad expected Prod=true")
	}
	if !g.Nodes[leftpad].Direct {
		t.Error("left-pad expected Direct=true")
	}

	// Depth: lodash (reachable via left-pad AND directly as a root)
	// should be depth 0 because it IS a root here.
	if d := g.Depth(lodash); d != 0 {
		t.Errorf("lodash depth: got %d, want 0", d)
	}
}

func TestParseNPMLockfile_RejectsV1(t *testing.T) {
	// v1 has no "packages" map — only legacy "dependencies" tree.
	data := []byte(`{"name":"demo","version":"1.0.0","lockfileVersion":1}`)
	if _, err := ParseNPMLockfile(data); err == nil {
		t.Error("expected error for v1 lockfile without packages map")
	}
}

func TestNameFromNodeModulesPath(t *testing.T) {
	cases := map[string]string{
		"node_modules/lodash":                    "lodash",
		"node_modules/@scope/pkg":                "@scope/pkg",
		"foo/node_modules/bar":                   "bar",
		"foo/node_modules/@scope/pkg":            "@scope/pkg",
		"foo/node_modules/bar/node_modules/@s/p": "@s/p",
	}
	for in, want := range cases {
		if got := nameFromNodeModulesPath(in); got != want {
			t.Errorf("nameFromNodeModulesPath(%q) = %q, want %q", in, got, want)
		}
	}
}
