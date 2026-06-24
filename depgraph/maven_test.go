package depgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func mvn(name, version string) Key {
	return Key{Ecosystem: "maven", Name: name, Version: version}
}

func TestParseMavenDepTree_Simple(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "maven_simple.tgf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseMavenDepTree(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	root := mvn("com.example:my-app", "1.0.0")
	if len(g.Roots) != 1 || g.Roots[0] != root {
		t.Fatalf("roots: got %v, want [%v]", g.Roots, root)
	}
	dep := mvn("org.springframework:spring-core", "5.3.20")
	if _, ok := g.Nodes[dep]; !ok {
		t.Fatalf("spring-core not in graph: %v", g.Nodes)
	}
	if !g.Nodes[dep].Direct {
		t.Errorf("spring-core should be Direct (root edge)")
	}
	if d := g.Depth(dep); d != 1 {
		t.Errorf("spring-core depth: got %d, want 1", d)
	}
}

func TestParseMavenDepTree_TransitiveChain(t *testing.T) {
	tgf := []byte(`1 com.example:app:1.0.0
2 com.example:lib-a:2.0.0
3 com.example:lib-b:3.0.0
#
1 2
2 3
`)
	g, err := ParseMavenDepTree(tgf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	a := mvn("com.example:lib-a", "2.0.0")
	b := mvn("com.example:lib-b", "3.0.0")
	if !g.Nodes[a].Direct {
		t.Errorf("lib-a should be Direct")
	}
	if g.Nodes[b].Direct {
		t.Errorf("lib-b should NOT be Direct (transitive only)")
	}
	if d := g.Depth(b); d != 2 {
		t.Errorf("lib-b depth: got %d, want 2", d)
	}
}

func TestParseMavenDepTree_Diamond(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "maven_diamond.tgf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseMavenDepTree(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	slf4j := mvn("org.slf4j:slf4j-api", "1.7.36")
	n, ok := g.Nodes[slf4j]
	if !ok {
		t.Fatalf("slf4j-api missing")
	}
	if len(n.Parents) != 2 {
		t.Errorf("slf4j-api parents: got %d, want 2 (diamond)", len(n.Parents))
	}
	if d := g.Depth(slf4j); d != 2 {
		t.Errorf("slf4j-api depth: got %d, want 2", d)
	}
}

func TestParseMavenDepTree_Classifier(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "maven_with_classifier.tgf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseMavenDepTree(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	netty := mvn("io.netty:netty-transport-native-epoll", "4.1.86.Final")
	if _, ok := g.Nodes[netty]; !ok {
		t.Fatalf("netty-transport-native-epoll@4.1.86.Final missing — classifier parse broken; nodes=%v", g.Nodes)
	}
	common := mvn("io.netty:netty-common", "4.1.86.Final")
	if _, ok := g.Nodes[common]; !ok {
		t.Fatalf("netty-common missing")
	}
}

func TestParseMavenDepTree_PackagingType(t *testing.T) {
	tgf := []byte(`1 com.example:app:jar:1.0.0
2 org.example:lib:war:2.0.0
#
1 2
`)
	g, err := ParseMavenDepTree(tgf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	root := mvn("com.example:app", "1.0.0")
	if g.Roots[0] != root {
		t.Errorf("root: got %v, want %v", g.Roots[0], root)
	}
	lib := mvn("org.example:lib", "2.0.0")
	if _, ok := g.Nodes[lib]; !ok {
		t.Errorf("lib missing; nodes=%v", g.Nodes)
	}
}

func TestParseMavenDepTree_Malformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":               []byte(``),
		"only-separator":      []byte(`#`),
		"missing-version":     []byte("1 com.example:lib\n#\n"),
		"non-numeric-node-id": []byte("alpha com.example:lib:1.0.0\n#\n"),
		"unknown-edge-id":     []byte("1 com.example:app:1.0.0\n#\n1 99\n"),
		"empty-segment":       []byte("1 com.example::1.0.0\n#\n"),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMavenDepTree(data); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestParseMavenDepTree_ScopeOnEdges(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "maven_with_scope.tgf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseMavenDepTree(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	root := mvn("com.example:my-app", "1.0.0")
	spring := mvn("org.springframework:spring-core", "5.3.20")
	junit := mvn("org.junit.jupiter:junit-jupiter-api", "5.9.0")

	if got := g.EdgeAttr(root, spring, "scope"); len(got) != 1 || got[0] != "compile" {
		t.Errorf("spring-core edge scope: got %v, want [compile]", got)
	}
	if got := g.EdgeAttr(root, junit, "scope"); len(got) != 1 || got[0] != "test" {
		t.Errorf("junit edge scope: got %v, want [test]", got)
	}
}

func TestParseMavenDepTree_ScopeDefaultsToCompile(t *testing.T) {
	tgf := []byte(`1 com.example:app:jar:1.0.0
2 com.example:lib:jar:2.0.0
#
1 2
`)
	g, err := ParseMavenDepTree(tgf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	root := mvn("com.example:app", "1.0.0")
	lib := mvn("com.example:lib", "2.0.0")
	got := g.EdgeAttr(root, lib, "scope")
	if len(got) != 1 || got[0] != "compile" {
		t.Errorf("default scope: got %v, want [compile]", got)
	}
}

func TestParseMavenDepTree_ClassifierAndScope(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "maven_with_classifier_and_scope.tgf"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseMavenDepTree(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	root := mvn("com.example:my-app", "1.0.0")
	netty := mvn("io.netty:netty-transport-native-epoll", "4.1.86.Final")
	jackson := mvn("com.fasterxml.jackson.core:jackson-core", "2.13.0")

	if g.Nodes[netty].Classifier != "linux-x86_64" {
		t.Errorf("netty classifier: got %q, want linux-x86_64", g.Nodes[netty].Classifier)
	}
	if g.Nodes[jackson].Classifier != "tests" {
		t.Errorf("jackson classifier: got %q, want tests", g.Nodes[jackson].Classifier)
	}
	if got := g.EdgeAttr(root, netty, "scope"); len(got) != 1 || got[0] != "runtime" {
		t.Errorf("netty edge scope: got %v, want [runtime]", got)
	}
	if got := g.EdgeAttr(root, jackson, "scope"); len(got) != 1 || got[0] != "test" {
		t.Errorf("jackson edge scope: got %v, want [test]", got)
	}
}

func TestParseMavenCoord_Shapes(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantVer  string
	}{
		{"g:a:1.0", "g:a", "1.0"},
		{"g:a:jar:1.0", "g:a", "1.0"},
		{"g:a:jar:1.0:compile", "g:a", "1.0"},
		{"g:a:jar:linux-x86_64:1.0", "g:a", "1.0"},
		{"g:a:jar:linux-x86_64:1.0:runtime", "g:a", "1.0"},
	}
	for _, c := range cases {
		k, err := parseMavenCoord(c.in)
		if err != nil {
			t.Errorf("parseMavenCoord(%q) error: %v", c.in, err)
			continue
		}
		if k.Name != c.wantName || k.Version != c.wantVer {
			t.Errorf("parseMavenCoord(%q) = %s@%s, want %s@%s", c.in, k.Name, k.Version, c.wantName, c.wantVer)
		}
	}
}
