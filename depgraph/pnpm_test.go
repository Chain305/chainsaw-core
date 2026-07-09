package depgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsePnpmLockfile_Simple(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "pnpm-simple.yaml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParsePnpmLockfile(data)
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

	// lodash should exist with parents left-pad and mocha.
	lodash := mk("lodash", "4.17.21")
	n, ok := g.Nodes[lodash]
	if !ok {
		t.Fatalf("lodash not in graph")
	}
	if len(n.Parents) < 2 {
		t.Errorf("lodash parents: %v", n.Parents)
	}

	// mocha is dev.
	mocha := mk("mocha", "10.2.0")
	if g.Nodes[mocha].Prod {
		t.Error("mocha expected Prod=false")
	}
}

func TestSplitPnpmPackageKey(t *testing.T) {
	cases := []struct {
		in    string
		wantN string
		wantV string
	}{
		{"/lodash@4.17.21", "lodash", "4.17.21"},
		{"/@scope/pkg@1.0.0", "@scope/pkg", "1.0.0"},
		{"/lodash/4.17.21", "lodash", "4.17.21"},
		{"/@scope/pkg/1.0.0", "@scope/pkg", "1.0.0"},
		{"/foo@1.0.0(react@18.0.0)", "foo", "1.0.0"},
	}
	for _, c := range cases {
		gn, gv := splitPnpmPackageKey(c.in)
		if gn != c.wantN || gv != c.wantV {
			t.Errorf("split(%q) = (%q,%q), want (%q,%q)", c.in, gn, gv, c.wantN, c.wantV)
		}
	}
}

func TestStripPeerSuffix(t *testing.T) {
	if got := stripPeerSuffix("1.2.3"); got != "1.2.3" {
		t.Errorf("no-op: %q", got)
	}
	if got := stripPeerSuffix("1.2.3(react@18)"); got != "1.2.3" {
		t.Errorf("strip: %q", got)
	}
}
