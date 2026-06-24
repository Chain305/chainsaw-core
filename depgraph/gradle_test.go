package depgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func gr(name, version string) Key {
	return Key{Ecosystem: "gradle", Name: name, Version: version}
}

func TestParseGradleDependencyTree_Simple(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "gradle_simple.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseGradleDependencyTree(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	dep := gr("org.springframework:spring-core", "5.3.20")
	n, ok := g.Nodes[dep]
	if !ok {
		t.Fatalf("spring-core missing; nodes=%v", g.Nodes)
	}
	if !n.Direct {
		t.Errorf("spring-core should be Direct (top-level)")
	}
	if d := g.Depth(dep); d != 1 {
		t.Errorf("spring-core depth: got %d, want 1", d)
	}
}

func TestParseGradleDependencyTree_TransitiveChain(t *testing.T) {
	in := []byte(`compileClasspath - Compile classpath for source set 'main'.
\--- com.example:lib-a:2.0.0
     \--- com.example:lib-b:3.0.0
`)
	g, err := ParseGradleDependencyTree(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	a := gr("com.example:lib-a", "2.0.0")
	b := gr("com.example:lib-b", "3.0.0")
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

func TestParseGradleDependencyTree_Multilevel(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "gradle_multilevel.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseGradleDependencyTree(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	guava := gr("com.google.guava:guava", "31.1-jre")
	if !g.Nodes[guava].Direct {
		t.Errorf("guava should be Direct")
	}
	checker := gr("org.checkerframework:checker-qual", "3.12.0")
	if d := g.Depth(checker); d != 2 {
		t.Errorf("checker-qual depth: got %d, want 2", d)
	}
	jcl := gr("org.springframework:spring-jcl", "5.3.20")
	if d := g.Depth(jcl); d != 2 {
		t.Errorf("spring-jcl depth: got %d, want 2", d)
	}
}

func TestParseGradleDependencyTree_DiamondDuplicateMarker(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "gradle_diamond.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseGradleDependencyTree(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	slf4j := gr("org.slf4j:slf4j-api", "1.7.36")
	n, ok := g.Nodes[slf4j]
	if !ok {
		t.Fatalf("slf4j-api missing")
	}
	if len(n.Parents) != 2 {
		t.Errorf("slf4j-api parents: got %d, want 2 (diamond via (*))", len(n.Parents))
	}
}

func TestParseGradleDependencyTree_Resolved(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "gradle_resolved.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseGradleDependencyTree(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	guava := gr("com.google.guava:guava", "31.1-jre")
	if _, ok := g.Nodes[guava]; !ok {
		t.Errorf("guava resolved version not used; nodes=%v", g.Nodes)
	}
	spring := gr("org.springframework:spring-core", "5.3.20")
	if _, ok := g.Nodes[spring]; !ok {
		t.Errorf("spring-core resolved version not used; nodes=%v", g.Nodes)
	}
}

func TestParseGradleDependencyTree_LastChildMarker(t *testing.T) {
	// "+---" vs "\---" must produce identical parent/child wiring;
	// only the rendering differs.
	in := []byte(`compileClasspath - Compile classpath for source set 'main'.
+--- com.example:a:1.0.0
\--- com.example:b:2.0.0
`)
	g, err := ParseGradleDependencyTree(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !g.Nodes[gr("com.example:a", "1.0.0")].Direct {
		t.Errorf("a should be Direct")
	}
	if !g.Nodes[gr("com.example:b", "2.0.0")].Direct {
		t.Errorf("b should be Direct")
	}
}

func TestParseGradleDependencyTree_Malformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":           []byte(``),
		"no-deps-header":  []byte("compileClasspath - Compile classpath for source set 'main'.\n"),
		"missing-version": []byte("compileClasspath - Compile classpath for source set 'main'.\n+--- com.example:lib\n"),
		"empty-segment":   []byte("compileClasspath - Compile classpath for source set 'main'.\n+--- com.example::1.0.0\n"),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseGradleDependencyTree(data); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}

func TestParseGradleDependencyTree_AllConfigsParsed(t *testing.T) {
	// Wave 6: every configuration block contributes. The output is the
	// union of compileClasspath + runtimeClasspath nodes.
	in := []byte(`compileClasspath - Compile classpath for source set 'main'.
\--- com.example:compile-only:1.0.0

runtimeClasspath - Runtime classpath for source set 'main'.
\--- com.example:runtime-only:2.0.0
`)
	g, err := ParseGradleDependencyTree(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := g.Nodes[gr("com.example:compile-only", "1.0.0")]; !ok {
		t.Errorf("compile-only should be present")
	}
	if _, ok := g.Nodes[gr("com.example:runtime-only", "2.0.0")]; !ok {
		t.Errorf("runtime-only should be present (multi-config aggregation)")
	}
}

func TestParseGradleDependencyTree_MultiConfigFixture(t *testing.T) {
	// Full fixture exercise: compileClasspath + runtimeClasspath +
	// testCompileClasspath share guava, runtimeClasspath additionally
	// pulls spring-jcl, only testCompileClasspath introduces junit and
	// hamcrest. apiElements has "No dependencies" and must not break
	// parsing of its siblings.
	data, err := os.ReadFile(filepath.Join("testdata", "gradle_multiconfig.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseGradleDependencyTree(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Union of nodes across the three non-empty configs (plus the
	// :root sentinel) — guava+checker-qual+spring-core+spring-jcl
	// +junit+hamcrest-core = 6 deps + 1 root = 7 nodes.
	wantNodes := []Key{
		gr("com.google.guava:guava", "31.1-jre"),
		gr("org.checkerframework:checker-qual", "3.12.0"),
		gr("org.springframework:spring-core", "5.3.20"),
		gr("org.springframework:spring-jcl", "5.3.20"),
		gr("junit:junit", "4.13.2"),
		gr("org.hamcrest:hamcrest-core", "1.3"),
	}
	for _, k := range wantNodes {
		if _, ok := g.Nodes[k]; !ok {
			t.Errorf("expected node %s in graph", k)
		}
	}

	// Edge config attribution. spring-jcl is reached only via
	// runtimeClasspath; junit only via testCompileClasspath; guava is
	// in all three.
	rootKey := Key{Ecosystem: "gradle", Name: ":root", Version: "0.0.0"}
	guava := gr("com.google.guava:guava", "31.1-jre")
	guavaConfigs := g.EdgeConfigs(rootKey, guava)
	wantGuava := map[string]bool{"compileClasspath": true, "runtimeClasspath": true, "testCompileClasspath": true}
	if len(guavaConfigs) != len(wantGuava) {
		t.Errorf("guava edge configs: got %v, want keys of %v", guavaConfigs, wantGuava)
	}
	for _, c := range guavaConfigs {
		if !wantGuava[c] {
			t.Errorf("guava unexpectedly tagged with config %q", c)
		}
	}

	spring := gr("org.springframework:spring-core", "5.3.20")
	jcl := gr("org.springframework:spring-jcl", "5.3.20")
	jclConfigs := g.EdgeConfigs(spring, jcl)
	if len(jclConfigs) != 1 || jclConfigs[0] != "runtimeClasspath" {
		t.Errorf("spring-jcl edge configs: got %v, want [runtimeClasspath]", jclConfigs)
	}

	junit := gr("junit:junit", "4.13.2")
	junitConfigs := g.EdgeConfigs(rootKey, junit)
	if len(junitConfigs) != 1 || junitConfigs[0] != "testCompileClasspath" {
		t.Errorf("junit edge configs: got %v, want [testCompileClasspath]", junitConfigs)
	}
}

func TestParseGradleDependencyTreeForConfig_Filter(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "gradle_multiconfig.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseGradleDependencyTreeForConfig(data, "testCompileClasspath")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := g.Nodes[gr("junit:junit", "4.13.2")]; !ok {
		t.Errorf("junit should be present when filtering to testCompileClasspath")
	}
	// spring-jcl is exclusive to runtimeClasspath; filtering should
	// drop it.
	if _, ok := g.Nodes[gr("org.springframework:spring-jcl", "5.3.20")]; ok {
		t.Errorf("spring-jcl should NOT be present when filtering to testCompileClasspath")
	}
	if _, err := ParseGradleDependencyTreeForConfig(data, "noSuchConfig"); err == nil {
		t.Errorf("expected error when requested config is absent")
	}
}

func TestParseGradleDependencyTree_NoDependenciesBlockTolerated(t *testing.T) {
	// A "No dependencies" config sandwiched between real configs must
	// not abort parsing of the surrounding blocks.
	in := []byte(`compileClasspath - Compile classpath for source set 'main'.
\--- com.example:a:1.0.0

apiElements - API elements for main.
No dependencies

runtimeClasspath - Runtime classpath for source set 'main'.
\--- com.example:b:2.0.0
`)
	g, err := ParseGradleDependencyTree(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := g.Nodes[gr("com.example:a", "1.0.0")]; !ok {
		t.Errorf("compile-only dep missing")
	}
	if _, ok := g.Nodes[gr("com.example:b", "2.0.0")]; !ok {
		t.Errorf("runtime-only dep missing")
	}
}

func TestParseGradleCoord_Shapes(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantVer  string
	}{
		{"g:a:1.0", "g:a", "1.0"},
		{"g:a:1.0 -> 2.0", "g:a", "2.0"},
		{"g:a:1.0 -> g:a:2.0", "g:a", "2.0"},
	}
	for _, c := range cases {
		k, err := parseGradleCoord(c.in)
		if err != nil {
			t.Errorf("parseGradleCoord(%q) error: %v", c.in, err)
			continue
		}
		if k.Name != c.wantName || k.Version != c.wantVer {
			t.Errorf("parseGradleCoord(%q) = %s@%s, want %s@%s", c.in, k.Name, k.Version, c.wantName, c.wantVer)
		}
	}
}
