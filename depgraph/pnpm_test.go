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
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"@scope/pkg@1.0.0(react@18.0.0)", "@scope/pkg", "1.0.0"},
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

// pnpm lockfile v9: keys have no leading "/" and the edges live in
// `snapshots`. Every key used to be dropped, so the graph had no registry
// nodes and nothing was direct.
func TestParsePnpmLockfile_V9(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "pnpm-v9.yaml"))
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
	if len(g.Nodes) != 28 {
		t.Errorf("nodes: got %d, want 28", len(g.Nodes))
	}
	direct := map[string]bool{}
	for _, n := range g.Nodes {
		if n.Direct {
			direct[n.Key.Name] = true
		}
	}
	// string-width is reached through the alias string-width-cjs; the
	// workspace link to @acme/shared is not a registry package.
	want := []string{"@tanstack/react-query", "axios", "debug", "react", "react-dom", "string-width", "@types/react", "prettier", "typescript"}
	if len(direct) != len(want) {
		t.Errorf("direct: got %v, want %v", direct, want)
	}
	for _, name := range want {
		if !direct[name] {
			t.Errorf("%s: want Direct", name)
		}
	}
	// Edges come from snapshots, including through a peer-suffixed key.
	rq := g.Nodes[mk("@tanstack/react-query", "5.28.4")]
	if rq == nil || !containsKey(rq.Children, mk("@tanstack/query-core", "5.28.4")) {
		t.Errorf("react-query children: %+v", rq)
	}
	if d := g.Depth(mk("delayed-stream", "1.0.0")); d != 3 {
		t.Errorf("delayed-stream depth = %d, want 3 (axios > form-data > combined-stream > delayed-stream)", d)
	}
	// Prod by reachability: csstype is reached only from the dev @types/react.
	if n := g.Nodes[mk("csstype", "3.1.3")]; n == nil || n.Prod {
		t.Errorf("csstype: want Prod=false (dev-only), got %+v", n)
	}
	if n := g.Nodes[mk("mime-db", "1.52.0")]; n == nil || !n.Prod {
		t.Errorf("mime-db: want Prod=true (under axios), got %+v", n)
	}
}
