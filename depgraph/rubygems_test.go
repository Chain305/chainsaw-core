package depgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func gem(name, version string) Key {
	return Key{Ecosystem: "rubygems", Name: name, Version: version}
}

func TestParseGemfileLockfile_Simple(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "gemfile_simple.lock"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseGemfileLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	rake := gem("rake", "13.0.6")
	if len(g.Roots) != 1 || g.Roots[0] != rake {
		t.Fatalf("roots: got %v, want [%v]", g.Roots, rake)
	}
	if !g.Nodes[rake].Direct {
		t.Errorf("rake should be Direct (root)")
	}
	if d := g.Depth(rake); d != 0 {
		t.Errorf("rake depth: got %d, want 0", d)
	}
}

func TestParseGemfileLockfile_TransitiveChain(t *testing.T) {
	lock := []byte(`GEM
  remote: https://rubygems.org/
  specs:
    app (1.0.0)
      lib-a (= 2.0.0)
    lib-a (2.0.0)
      lib-b (= 3.0.0)
    lib-b (3.0.0)

PLATFORMS
  ruby

DEPENDENCIES
  app
`)
	g, err := ParseGemfileLockfile(lock)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	a := gem("lib-a", "2.0.0")
	b := gem("lib-b", "3.0.0")
	if g.Nodes[a].Direct {
		t.Errorf("lib-a should NOT be Direct (only app is root)")
	}
	if g.Nodes[b].Direct {
		t.Errorf("lib-b should NOT be Direct")
	}
	if d := g.Depth(b); d != 2 {
		t.Errorf("lib-b depth: got %d, want 2", d)
	}
}

func TestParseGemfileLockfile_Diamond(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "gemfile_diamond.lock"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseGemfileLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	shared := gem("shared", "2.0.0")
	n, ok := g.Nodes[shared]
	if !ok {
		t.Fatalf("shared missing")
	}
	if len(n.Parents) != 2 {
		t.Errorf("shared parents: got %d, want 2 (diamond)", len(n.Parents))
	}
	if d := g.Depth(shared); d != 2 {
		t.Errorf("shared depth: got %d, want 2", d)
	}
}

func TestParseGemfileLockfile_RailsSubset(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "gemfile_rails_subset.lock"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseGemfileLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// DEPENDENCIES roots: actionpack and rake. The "(~> 7.0.4)"
	// requirement on actionpack must be discarded so the name resolves.
	wantRoots := map[Key]bool{
		gem("actionpack", "7.0.4"): true,
		gem("rake", ""):            false, // rake is in DEPENDENCIES but NOT in GEM specs — should be filtered.
	}
	_ = wantRoots
	ap := gem("actionpack", "7.0.4")
	if len(g.Roots) != 1 || g.Roots[0] != ap {
		t.Fatalf("roots: got %v, want [%v] (rake should drop — no GEM specs entry)", g.Roots, ap)
	}
	// Transitive: rack via actionpack → "(~> 2.0, >= 2.2.0)" requirement
	// must be ignored; resolution is by name.
	rack := gem("rack", "2.2.4")
	if _, ok := g.Nodes[rack]; !ok {
		t.Fatalf("rack missing")
	}
	if d := g.Depth(rack); d != 1 {
		t.Errorf("rack depth: got %d, want 1", d)
	}
	// Diamond-ish: concurrent-ruby reachable via activesupport AND i18n.
	cr := gem("concurrent-ruby", "1.1.10")
	n, ok := g.Nodes[cr]
	if !ok {
		t.Fatalf("concurrent-ruby missing")
	}
	if len(n.Parents) < 2 {
		t.Errorf("concurrent-ruby parents: got %d, want >=2", len(n.Parents))
	}
}

func TestParseGemfileLockfile_DependenciesWithRequirement(t *testing.T) {
	// A DEPENDENCIES entry with a version constraint must resolve to
	// the GEM specs version, not the constraint string.
	lock := []byte(`GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.0.4)
`)
	g, err := ParseGemfileLockfile(lock)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	rails := gem("rails", "7.0.4")
	if len(g.Roots) != 1 || g.Roots[0] != rails {
		t.Fatalf("roots: got %v, want [%v]", g.Roots, rails)
	}
}

func TestParseGemfileLockfile_GitAndPath(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "gemfile_with_git_path.lock"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseGemfileLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	rails := gem("rails", "7.1.0")
	local := gem("my-local-gem", "0.1.0")
	rake := gem("rake", "13.0.6")
	activesupport := gem("activesupport", "7.1.0")
	concurrent := gem("concurrent-ruby", "1.2.0")

	for _, k := range []Key{rails, local, rake, activesupport, concurrent} {
		if _, ok := g.Nodes[k]; !ok {
			t.Errorf("expected node %v in graph", k)
		}
	}

	wantRoots := map[Key]bool{rails: false, local: false, rake: false}
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

	// Edges from GIT/PATH gems into rubygems-sourced gems carry NO
	// source attribute (the rubygems target itself is the GEM-block
	// child).
	if got := g.EdgeAttr(rails, activesupport, "source"); got != nil {
		t.Errorf("rails→activesupport source: got %v, want nil (target is GEM-sourced)", got)
	}
	if got := g.EdgeAttr(local, activesupport, "source"); got != nil {
		t.Errorf("local→activesupport source: got %v, want nil", got)
	}

	// Sanity: confirm the rails GIT spec is in the graph and reachable.
	if d := g.Depth(activesupport); d < 1 {
		t.Errorf("activesupport depth: got %d, want >=1", d)
	}
}

func TestParseGemfileLockfile_GitPathSourceOnIncomingEdges(t *testing.T) {
	// A GEM-sourced gem that depends on a GIT-sourced gem produces a
	// "git" source attribute on the GEM→GIT edge.
	lock := []byte(`GIT
  remote: https://github.com/example/git-gem.git
  revision: deadbeef
  specs:
    git-gem (1.0.0)

PATH
  remote: ../local
  specs:
    local-gem (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    consumer (1.0.0)
      git-gem (= 1.0.0)
      local-gem (= 0.1.0)

DEPENDENCIES
  consumer
`)
	g, err := ParseGemfileLockfile(lock)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	consumer := gem("consumer", "1.0.0")
	gitGem := gem("git-gem", "1.0.0")
	localGem := gem("local-gem", "0.1.0")

	if got := g.EdgeAttr(consumer, gitGem, "source"); len(got) != 1 || got[0] != "git" {
		t.Errorf("consumer→git-gem source: got %v, want [git]", got)
	}
	if got := g.EdgeAttr(consumer, localGem, "source"); len(got) != 1 || got[0] != "path" {
		t.Errorf("consumer→local-gem source: got %v, want [path]", got)
	}
}

func TestParseGemfileLockfile_Malformed(t *testing.T) {
	cases := map[string][]byte{
		"empty": []byte(``),
		"missing-deps-section": []byte(`GEM
  remote: https://rubygems.org/
  specs:
    rake (13.0.6)
`),
		"missing-gem-section": []byte(`DEPENDENCIES
  rake
`),
		"malformed-spec-line": []byte(`GEM
  remote: https://rubygems.org/
  specs:
    rake-no-version-here

DEPENDENCIES
  rake-no-version-here
`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseGemfileLockfile(data); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestSplitGemSpec(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantVer  string
		ok       bool
	}{
		{"rake (13.0.6)", "rake", "13.0.6", true},
		{"actionpack (7.0.4)", "actionpack", "7.0.4", true},
		{"weird-name (1.0.0.pre1)", "weird-name", "1.0.0.pre1", true},
		{"no-parens", "", "", false},
		{"name ()", "", "", false},
	}
	for _, c := range cases {
		name, ver, ok := splitGemSpec(c.in)
		if ok != c.ok || name != c.wantName || ver != c.wantVer {
			t.Errorf("splitGemSpec(%q) = (%q,%q,%v); want (%q,%q,%v)", c.in, name, ver, ok, c.wantName, c.wantVer, c.ok)
		}
	}
}

func TestSplitGemDep(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantReq  string
		ok       bool
	}{
		{"rake", "rake", "", true},
		{"rack (~> 2.0, >= 2.2.0)", "rack", "~> 2.0, >= 2.2.0", true},
		{"i18n (>= 1.6, < 2)", "i18n", ">= 1.6, < 2", true},
		{"", "", "", false},
	}
	for _, c := range cases {
		name, req, ok := splitGemDep(c.in)
		if ok != c.ok || name != c.wantName || req != c.wantReq {
			t.Errorf("splitGemDep(%q) = (%q,%q,%v); want (%q,%q,%v)", c.in, name, req, ok, c.wantName, c.wantReq, c.ok)
		}
	}
}
