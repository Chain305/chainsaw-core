package depgraph

import (
	"os"
	"path/filepath"
	"testing"
)

func nuget(name, version string) Key {
	return Key{Ecosystem: "nuget", Name: name, Version: version}
}

func TestParseNuGetLockfile_Simple(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "nuget_simple.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseNuGetLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	newtonsoft := nuget("Newtonsoft.Json", "13.0.1")
	logging := nuget("Microsoft.Extensions.Logging.Abstractions", "6.0.0")
	buffers := nuget("System.Buffers", "4.5.1")

	if _, ok := g.Nodes[newtonsoft]; !ok {
		t.Fatalf("Newtonsoft.Json missing")
	}
	if _, ok := g.Nodes[buffers]; !ok {
		t.Fatalf("System.Buffers missing")
	}
	if !g.Nodes[newtonsoft].Direct {
		t.Errorf("Newtonsoft.Json should be Direct")
	}
	if g.Nodes[buffers].Direct {
		t.Errorf("System.Buffers should NOT be Direct (transitive only)")
	}
	if d := g.Depth(buffers); d != 1 {
		t.Errorf("System.Buffers depth: got %d, want 1 (child of logging)", d)
	}
	// Verify the edge from logging → buffers exists.
	loggingNode := g.Nodes[logging]
	if !containsKey(loggingNode.Children, buffers) {
		t.Errorf("logging → buffers edge missing; children=%v", loggingNode.Children)
	}
}

func TestParseNuGetLockfile_TransitiveChain(t *testing.T) {
	data := []byte(`{
		"version": 1,
		"dependencies": {
			"net6.0": {
				"A": {"type": "Direct", "resolved": "1.0.0", "dependencies": {"B": "1.0.0"}},
				"B": {"type": "Transitive", "resolved": "1.0.0", "dependencies": {"C": "1.0.0"}},
				"C": {"type": "Transitive", "resolved": "1.0.0"}
			}
		}
	}`)
	g, err := ParseNuGetLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	a := nuget("A", "1.0.0")
	c := nuget("C", "1.0.0")
	if !g.Nodes[a].Direct {
		t.Errorf("A should be Direct")
	}
	if g.Nodes[c].Direct {
		t.Errorf("C should NOT be Direct")
	}
	if d := g.Depth(c); d != 2 {
		t.Errorf("C depth: got %d, want 2", d)
	}
}

func TestParseNuGetLockfile_Diamond(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "nuget_diamond.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseNuGetLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	shared := nuget("App.Shared", "2.0.0")
	n, ok := g.Nodes[shared]
	if !ok {
		t.Fatalf("App.Shared missing")
	}
	if len(n.Parents) != 2 {
		t.Errorf("App.Shared parents: got %d, want 2 (diamond)", len(n.Parents))
	}
	if d := g.Depth(shared); d != 1 {
		t.Errorf("App.Shared depth: got %d, want 1", d)
	}
}

func TestParseNuGetLockfile_MultiTargetMerged(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "nuget_multitarget.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseNuGetLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	// Both framework-exclusive nodes must be present.
	base := nuget("OnlyInBaseTarget", "1.0.0")
	runtime := nuget("OnlyInRuntimeTarget", "9.9.9")
	if _, ok := g.Nodes[base]; !ok {
		t.Errorf("OnlyInBaseTarget missing")
	}
	if _, ok := g.Nodes[runtime]; !ok {
		t.Errorf("OnlyInRuntimeTarget missing — runtime-suffix framework not parsed")
	}

	// A shared edge present in both frameworks accumulates both
	// framework labels under the "frameworks" attribute.
	shared := nuget("Shared.Lib", "2.0.0")
	transitive := nuget("Shared.Transitive", "1.0.0")
	got := g.EdgeAttr(shared, transitive, "frameworks")
	wantSet := map[string]bool{"net6.0": false, "net6.0/win-x64": false}
	for _, fw := range got {
		if _, ok := wantSet[fw]; ok {
			wantSet[fw] = true
		}
	}
	for fw, seen := range wantSet {
		if !seen {
			t.Errorf("Shared.Lib→Shared.Transitive missing framework %q (got %v)", fw, got)
		}
	}
}

func TestParseNuGetLockfile_SingleFrameworkUnchanged(t *testing.T) {
	// Single-framework input must produce the same nodes and edges as
	// before, with one entry in the frameworks attribute per edge.
	data, err := os.ReadFile(filepath.Join("testdata", "nuget_simple.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseNuGetLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	logging := nuget("Microsoft.Extensions.Logging.Abstractions", "6.0.0")
	buffers := nuget("System.Buffers", "4.5.1")
	got := g.EdgeAttr(logging, buffers, "frameworks")
	if len(got) != 1 {
		t.Errorf("single-framework edge: got %v, want one framework", got)
	}
}

func TestParseNuGetLockfile_ProjectTypeExcluded(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "nuget_with_project.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	g, err := ParseNuGetLockfile(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for k := range g.Nodes {
		if k.Name == "MySolution.SiblingProject" {
			t.Errorf("Project-type entry should not appear in graph: %v", k)
		}
	}
	if _, ok := g.Nodes[nuget("Newtonsoft.Json", "13.0.1")]; !ok {
		t.Errorf("Newtonsoft.Json missing alongside skipped Project entry")
	}
}

func TestParseNuGetLockfile_Malformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":            []byte(``),
		"not-json":         []byte(`<<<not json>>>`),
		"no-frameworks":    []byte(`{"version":1,"dependencies":{}}`),
		"missing-resolved": []byte(`{"version":1,"dependencies":{"net6.0":{"X":{"type":"Direct"}}}}`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNuGetLockfile(data); err == nil {
				t.Errorf("expected error for %s, got nil", name)
			}
		})
	}
}
