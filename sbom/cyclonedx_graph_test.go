package sbom

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/depgraph"
)

// TestGenerate_FlatBackCompat asserts the contract from the deliverable:
// when graph is nil, the BOM stays in flat-component shape — no
// dependencies[] array — so existing SBOM consumers continue to receive
// byte-equal output.
func TestGenerate_FlatBackCompat(t *testing.T) {
	bom := Generate([]PackageEntry{
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0"},
		{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"},
	}, "urn:test:flat")
	if len(bom.Dependencies) != 0 {
		t.Errorf("Generate (no graph) must not populate dependencies[]; got %d entries", len(bom.Dependencies))
	}
	if len(bom.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(bom.Components))
	}
}

// TestGenerateWithGraph_DirectEdgesOnly asserts the CycloneDX 1.6 §7.6
// contract: dependsOn[] enumerates ONLY direct children, not transitive
// descendants. For a chain A → B → C, the SBOM's dependencies row for A
// must list [B] (not [B, C]); the row for B must list [C].
//
// This is the load-bearing invariant for downstream consumers
// (Dependency-Track, Snyk, Grype, in-toto verifiers) which reconstruct
// the transitive closure by walking the graph themselves. Doubling up
// edges here would skew their per-edge metrics and confuse path
// visualizations.
func TestGenerateWithGraph_DirectEdgesOnly(t *testing.T) {
	g := depgraph.NewGraph()
	a := depgraph.Key{Ecosystem: "npm", Name: "a", Version: "1.0.0"}
	b := depgraph.Key{Ecosystem: "npm", Name: "b", Version: "2.0.0"}
	c := depgraph.Key{Ecosystem: "npm", Name: "c", Version: "3.0.0"}
	g.AddNode(a, true, true)
	g.AddNode(b, false, true)
	g.AddNode(c, false, true)
	g.AddEdge(a, b)
	g.AddEdge(b, c)
	g.AddRoot(a)

	entries := []PackageEntry{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "b", Version: "2.0.0"},
		{Ecosystem: "npm", Name: "c", Version: "3.0.0"},
	}
	bom := GenerateWithGraph(entries, "urn:test:graph", g)
	if len(bom.Dependencies) == 0 {
		t.Fatalf("expected dependencies[] to be populated, got 0 entries")
	}

	rowFor := func(name string) *CycloneDXDependency {
		for i := range bom.Dependencies {
			if strings.Contains(bom.Dependencies[i].Ref, "/"+name+"@") {
				return &bom.Dependencies[i]
			}
		}
		return nil
	}

	rowA := rowFor("a")
	if rowA == nil {
		t.Fatalf("expected a dependencies row for 'a'; got %+v", bom.Dependencies)
	}
	if len(rowA.DependsOn) != 1 {
		t.Fatalf("a's DependsOn must contain exactly 1 direct child (b); got %v", rowA.DependsOn)
	}
	if !strings.Contains(rowA.DependsOn[0], "/b@") {
		t.Errorf("a's direct child should be b; got %v", rowA.DependsOn)
	}
	// CRUCIAL: the spec violation we're fixing — a must NOT list c.
	for _, child := range rowA.DependsOn {
		if strings.Contains(child, "/c@") {
			t.Errorf("a's DependsOn must NOT contain transitive descendant c; got %v",
				rowA.DependsOn)
		}
	}

	rowB := rowFor("b")
	if rowB == nil {
		t.Fatalf("expected a dependencies row for 'b'; got %+v", bom.Dependencies)
	}
	if len(rowB.DependsOn) != 1 || !strings.Contains(rowB.DependsOn[0], "/c@") {
		t.Errorf("b's DependsOn should be [c]; got %v", rowB.DependsOn)
	}

	// Leaf node c has no children — there should be no row for it
	// (the implementation skips leaves).
	if rowC := rowFor("c"); rowC != nil {
		t.Errorf("leaf node c should not have a dependencies row; got %+v", rowC)
	}
}

// TestGenerateWithGraph_DiamondNoDoubleEdge: A → B → D and A → C → D.
// The dependsOn for A must list {B, C} exactly (no D, since D is
// reached only transitively). The dependsOn for B and C must each
// list [D]. D appearing twice under A would be the bug.
func TestGenerateWithGraph_DiamondNoDoubleEdge(t *testing.T) {
	g := depgraph.NewGraph()
	a := depgraph.Key{Ecosystem: "npm", Name: "a", Version: "1.0.0"}
	b := depgraph.Key{Ecosystem: "npm", Name: "b", Version: "2.0.0"}
	c := depgraph.Key{Ecosystem: "npm", Name: "c", Version: "2.0.0"}
	d := depgraph.Key{Ecosystem: "npm", Name: "d", Version: "3.0.0"}
	g.AddNode(a, true, true)
	g.AddNode(b, false, true)
	g.AddNode(c, false, true)
	g.AddNode(d, false, true)
	g.AddEdge(a, b)
	g.AddEdge(a, c)
	g.AddEdge(b, d)
	g.AddEdge(c, d)
	g.AddRoot(a)

	entries := []PackageEntry{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "b", Version: "2.0.0"},
		{Ecosystem: "npm", Name: "c", Version: "2.0.0"},
		{Ecosystem: "npm", Name: "d", Version: "3.0.0"},
	}
	bom := GenerateWithGraph(entries, "urn:test:diamond", g)

	rowFor := func(name string) *CycloneDXDependency {
		for i := range bom.Dependencies {
			if strings.Contains(bom.Dependencies[i].Ref, "/"+name+"@") {
				return &bom.Dependencies[i]
			}
		}
		return nil
	}

	rowA := rowFor("a")
	if rowA == nil {
		t.Fatalf("expected a row for 'a'")
	}
	if len(rowA.DependsOn) != 2 {
		t.Fatalf("a's DependsOn must list exactly {b, c}; got %v", rowA.DependsOn)
	}
	for _, child := range rowA.DependsOn {
		if strings.Contains(child, "/d@") {
			t.Errorf("a's DependsOn must NOT contain d (transitive); got %v",
				rowA.DependsOn)
		}
	}

	// Count occurrences of d across the whole dependencies array.
	// d should appear under b's row AND c's row, exactly once each
	// — never twice in one row, never under a.
	totalD := 0
	for _, dep := range bom.Dependencies {
		for _, child := range dep.DependsOn {
			if strings.Contains(child, "/d@") {
				totalD++
				if strings.Contains(dep.Ref, "/a@") {
					t.Errorf("d must not appear under a's DependsOn; got %v", dep)
				}
			}
		}
	}
	if totalD != 2 {
		t.Errorf("d should appear under b and c (2 occurrences total); got %d",
			totalD)
	}
}

// TestGenerateWithGraph_PopulatesDependencies retains the original
// "graph yields dependencies[]" sanity check, updated to assert direct-
// only behaviour. Keeps the test name stable for grep/changelog
// reference.
func TestGenerateWithGraph_PopulatesDependencies(t *testing.T) {
	g := depgraph.NewGraph()
	root := depgraph.Key{Ecosystem: "npm", Name: "root", Version: "1.0.0"}
	mid := depgraph.Key{Ecosystem: "npm", Name: "middle", Version: "2.0.0"}
	leaf := depgraph.Key{Ecosystem: "npm", Name: "leaf", Version: "3.0.0"}
	g.AddNode(root, true, true)
	g.AddNode(mid, false, true)
	g.AddNode(leaf, false, true)
	g.AddEdge(root, mid)
	g.AddEdge(mid, leaf)
	g.AddRoot(root)

	entries := []PackageEntry{
		{Ecosystem: "npm", Name: "root", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "middle", Version: "2.0.0"},
		{Ecosystem: "npm", Name: "leaf", Version: "3.0.0"},
	}
	bom := GenerateWithGraph(entries, "urn:test:graph", g)
	if len(bom.Dependencies) == 0 {
		t.Fatalf("expected dependencies[] to be populated, got 0 entries")
	}
	var rootRow *CycloneDXDependency
	for i := range bom.Dependencies {
		if strings.Contains(bom.Dependencies[i].Ref, "/root@") {
			rootRow = &bom.Dependencies[i]
			break
		}
	}
	if rootRow == nil {
		t.Fatalf("expected a dependencies row for root; got %+v", bom.Dependencies)
	}
	// DIRECT child of root = {middle}; leaf is transitive and must NOT
	// appear under root.
	if len(rootRow.DependsOn) != 1 {
		t.Fatalf("root's DependsOn must list exactly the direct child (middle); got %v",
			rootRow.DependsOn)
	}
	if !strings.Contains(rootRow.DependsOn[0], "/middle@") {
		t.Errorf("root's direct child should be middle; got %v", rootRow.DependsOn)
	}
}

// TestGenerate_LinkBackProperties asserts the three new
// chainsaw:supply-chain:* properties land on each component when the
// PackageEntry sets them.
func TestGenerate_LinkBackProperties(t *testing.T) {
	bom := Generate([]PackageEntry{{
		Ecosystem:  "npm",
		Name:       "x",
		Version:    "1.0.0",
		EventID:    "evt-42",
		ClientID:   "ci-runner-1",
		SnapshotID: "snap-100",
	}}, "")
	if len(bom.Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(bom.Components))
	}
	props := bom.Components[0].Properties
	want := map[string]string{
		"chainsaw:supply-chain:event-id":    "evt-42",
		"chainsaw:supply-chain:client-id":   "ci-runner-1",
		"chainsaw:supply-chain:snapshot-id": "snap-100",
	}
	for name, val := range want {
		found := false
		for _, p := range props {
			if p.Name == name {
				if p.Value != val {
					t.Errorf("%s: got %q want %q", name, p.Value, val)
				}
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing property %s", name)
		}
	}
}

// TestGenerate_LinkBackPropertiesOmittedWhenEmpty asserts the back-
// compat invariant: PackageEntry without the link-back fields produces
// a property list with NONE of the chainsaw:supply-chain:* names. This
// is what keeps existing SBOM consumers byte-equal.
func TestGenerate_LinkBackPropertiesOmittedWhenEmpty(t *testing.T) {
	bom := Generate([]PackageEntry{{Ecosystem: "npm", Name: "x", Version: "1"}}, "")
	for _, p := range bom.Components[0].Properties {
		if strings.HasPrefix(p.Name, "chainsaw:supply-chain:") {
			t.Errorf("unexpected supply-chain property when entry is empty: %s", p.Name)
		}
	}
}
