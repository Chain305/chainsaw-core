package depgraph

import (
	"reflect"
	"sort"
	"testing"
)

func mk(name, v string) Key {
	return Key{Ecosystem: "npm", Name: name, Version: v}
}

func buildLinearGraph() *Graph {
	g := NewGraph()
	a, b, c := mk("a", "1"), mk("b", "1"), mk("c", "1")
	g.AddNode(a, true, true)
	g.AddNode(b, false, true)
	g.AddNode(c, false, true)
	g.AddEdge(a, b)
	g.AddEdge(b, c)
	g.AddRoot(a)
	return g
}

func TestGraph_Depth(t *testing.T) {
	g := buildLinearGraph()
	if got := g.Depth(mk("a", "1")); got != 0 {
		t.Errorf("root depth: got %d, want 0", got)
	}
	if got := g.Depth(mk("b", "1")); got != 1 {
		t.Errorf("b depth: got %d, want 1", got)
	}
	if got := g.Depth(mk("c", "1")); got != 2 {
		t.Errorf("c depth: got %d, want 2", got)
	}
	if got := g.Depth(mk("ghost", "9")); got != -1 {
		t.Errorf("unknown depth: got %d, want -1", got)
	}
}

func TestGraph_DescendantsAndCycles(t *testing.T) {
	g := NewGraph()
	a, b := mk("a", "1"), mk("b", "1")
	g.AddNode(a, true, true)
	g.AddNode(b, false, true)
	g.AddEdge(a, b)
	g.AddEdge(b, a) // cycle
	g.AddRoot(a)

	// Must terminate — if Descendants loops forever the test hangs.
	desc := g.Descendants(a)
	sort.Slice(desc, func(i, j int) bool { return KeyLess(desc[i], desc[j]) })
	want := []Key{mk("a", "1"), mk("b", "1")}
	if !reflect.DeepEqual(desc, want) {
		t.Errorf("cyclic Descendants: got %v, want %v", desc, want)
	}
}

func TestGraph_WalkRootsFirstStable(t *testing.T) {
	g := buildLinearGraph()
	var order []Key
	g.Walk(func(n *Node) { order = append(order, n.Key) })
	want := []Key{mk("a", "1"), mk("b", "1"), mk("c", "1")}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("Walk order: got %v, want %v", order, want)
	}
}

func TestGraph_Validate_DetectsUnknownRoot(t *testing.T) {
	g := NewGraph()
	g.Roots = append(g.Roots, mk("ghost", "1"))
	if err := g.Validate(); err == nil {
		t.Error("expected validation error for unknown root")
	}
}

func TestGraph_Validate_HappyPath(t *testing.T) {
	g := buildLinearGraph()
	if err := g.Validate(); err != nil {
		t.Errorf("valid graph should validate: %v", err)
	}
}

func TestGraph_MultiParent(t *testing.T) {
	// pnpm case: two roots both depend on the same transitive.
	g := NewGraph()
	r1, r2, shared := mk("r1", "1"), mk("r2", "1"), mk("shared", "1")
	g.AddNode(r1, true, true)
	g.AddNode(r2, true, true)
	g.AddNode(shared, false, true)
	g.AddEdge(r1, shared)
	g.AddEdge(r2, shared)
	g.AddRoot(r1)
	g.AddRoot(r2)

	n := g.Nodes[shared]
	if len(n.Parents) != 2 {
		t.Errorf("expected 2 parents, got %d", len(n.Parents))
	}
	// Shared should appear only once in a walk.
	seen := make(map[Key]int)
	g.Walk(func(node *Node) { seen[node.Key]++ })
	if seen[shared] != 1 {
		t.Errorf("shared visited %d times, want 1", seen[shared])
	}
}

func TestGraph_AddRoot_PromotesDirect(t *testing.T) {
	g := NewGraph()
	k := mk("x", "1")
	g.AddNode(k, false, true)
	g.AddRoot(k)
	if !g.Nodes[k].Direct {
		t.Error("AddRoot should have flipped Direct")
	}
}

func TestGraph_AddEdge_Dedupe(t *testing.T) {
	g := NewGraph()
	a, b := mk("a", "1"), mk("b", "1")
	g.AddNode(a, true, true)
	g.AddNode(b, false, true)
	g.AddEdge(a, b)
	g.AddEdge(a, b)
	if len(g.Nodes[a].Children) != 1 {
		t.Errorf("duplicate edge not deduped: %v", g.Nodes[a].Children)
	}
}
