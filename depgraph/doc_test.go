package depgraph

import (
	"reflect"
	"sort"
	"testing"
)

// keyPath is a test helper rendering a Key slice to its canonical strings
// so assertions read as the audit surface does.
func keyPath(path []Key) []string {
	out := make([]string, len(path))
	for i, k := range path {
		out[i] = k.String()
	}
	return out
}

func TestPathFromRoot_Linear(t *testing.T) {
	// root a -> b -> c
	g := NewGraph()
	a, b, c := mk("a", "1"), mk("b", "1"), mk("c", "1")
	g.AddNode(a, true, true)
	g.AddNode(b, false, true)
	g.AddNode(c, false, true)
	g.AddEdge(a, b)
	g.AddEdge(b, c)
	g.AddRoot(a)

	got := keyPath(g.PathFromRoot(c))
	want := []string{"npm:a@1", "npm:b@1", "npm:c@1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("linear path = %v, want %v", got, want)
	}

	// Root itself -> single element.
	if got := keyPath(g.PathFromRoot(a)); !reflect.DeepEqual(got, []string{"npm:a@1"}) {
		t.Fatalf("root path = %v, want [npm:a@1]", got)
	}
}

func TestPathFromRoot_Diamond(t *testing.T) {
	// a -> b -> d, a -> c -> d. Shortest path is length 3 either way; BFS
	// is deterministic on insertion order so b (added first) wins.
	g := NewGraph()
	a, b, c, d := mk("a", "1"), mk("b", "1"), mk("c", "1"), mk("d", "1")
	for _, k := range []Key{a, b, c, d} {
		g.AddNode(k, false, true)
	}
	g.AddEdge(a, b)
	g.AddEdge(a, c)
	g.AddEdge(b, d)
	g.AddEdge(c, d)
	g.AddRoot(a)

	got := g.PathFromRoot(d)
	if len(got) != 3 {
		t.Fatalf("diamond path length = %d (%v), want 3", len(got), keyPath(got))
	}
	if got[0] != a || got[len(got)-1] != d {
		t.Fatalf("diamond path endpoints = %v, want root a … leaf d", keyPath(got))
	}
	// Middle hop must be a real parent of d.
	mid := got[1]
	if mid != b && mid != c {
		t.Fatalf("diamond middle hop = %s, want b or c", mid)
	}
}

func TestPathFromRoot_Cycle(t *testing.T) {
	// a -> b -> c -> b (cycle b<->c) ; target c is still reachable and the
	// walk must terminate.
	g := NewGraph()
	a, b, c := mk("a", "1"), mk("b", "1"), mk("c", "1")
	for _, k := range []Key{a, b, c} {
		g.AddNode(k, false, true)
	}
	g.AddEdge(a, b)
	g.AddEdge(b, c)
	g.AddEdge(c, b) // back-edge forms a cycle
	g.AddRoot(a)

	got := keyPath(g.PathFromRoot(c))
	want := []string{"npm:a@1", "npm:b@1", "npm:c@1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cycle path = %v, want %v", got, want)
	}
}

func TestPathFromRoot_Unreachable(t *testing.T) {
	g := NewGraph()
	a, b, orphan := mk("a", "1"), mk("b", "1"), mk("orphan", "1")
	for _, k := range []Key{a, b, orphan} {
		g.AddNode(k, false, true)
	}
	g.AddEdge(a, b)
	g.AddRoot(a)

	if got := g.PathFromRoot(orphan); got != nil {
		t.Fatalf("orphan path = %v, want nil", keyPath(got))
	}
	// Not in graph at all.
	if got := g.PathFromRoot(mk("ghost", "9")); got != nil {
		t.Fatalf("ghost path = %v, want nil", keyPath(got))
	}
	// No roots -> nil even for a present node.
	g2 := NewGraph()
	g2.AddNode(a, false, true)
	if got := g2.PathFromRoot(a); got != nil {
		t.Fatalf("no-roots path = %v, want nil", keyPath(got))
	}
}

func TestSerializeDeserialize_RoundTrip(t *testing.T) {
	// a (root, direct, prod) -> b (prod) -> c (dev) ; a -> c too.
	g := NewGraph()
	a, b, c := mk("a", "1"), mk("b", "2"), mk("c", "3")
	g.AddNode(a, true, true)
	g.AddNode(b, false, true)
	g.AddNode(c, false, false)
	g.AddEdge(a, b)
	g.AddEdge(b, c)
	g.AddEdge(a, c)
	g.AddRoot(a)

	fired := map[Key][]string{
		c: {"sig-malware-1", "sig-cve-2"},
		b: {"sig-vuln-3"},
	}

	data, err := g.Serialize(fired)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	g2, fired2, err := Deserialize(data)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if err := g2.Validate(); err != nil {
		t.Fatalf("round-tripped graph invalid: %v", err)
	}

	// Roots preserved.
	if !reflect.DeepEqual(g2.Roots, []Key{a}) {
		t.Fatalf("roots = %v, want [a]", g2.Roots)
	}
	// Node flags preserved.
	if n := g2.Nodes[a]; n == nil || !n.Direct || !n.Prod {
		t.Fatalf("node a flags lost: %+v", n)
	}
	if n := g2.Nodes[c]; n == nil || n.Prod {
		t.Fatalf("node c prod flag should be false: %+v", n)
	}
	// Edges preserved: path a->...->c reconstructs.
	if p := g2.PathFromRoot(c); len(p) == 0 || p[0] != a || p[len(p)-1] != c {
		t.Fatalf("post-roundtrip path to c = %v", keyPath(p))
	}
	// Fired signals preserved.
	gotB := append([]string(nil), fired2[b]...)
	gotC := append([]string(nil), fired2[c]...)
	sort.Strings(gotC)
	if !reflect.DeepEqual(gotB, []string{"sig-vuln-3"}) {
		t.Fatalf("fired[b] = %v", gotB)
	}
	if !reflect.DeepEqual(gotC, []string{"sig-cve-2", "sig-malware-1"}) {
		t.Fatalf("fired[c] = %v", gotC)
	}
}

func TestSerialize_NilAndEmpty(t *testing.T) {
	// Nil graph -> valid, parseable, empty doc.
	data, err := (*Graph)(nil).Serialize(nil)
	if err != nil {
		t.Fatalf("nil serialize: %v", err)
	}
	g, fired, err := Deserialize(data)
	if err != nil {
		t.Fatalf("deserialize nil-graph doc: %v", err)
	}
	if len(g.Nodes) != 0 || len(g.Roots) != 0 || fired != nil {
		t.Fatalf("nil-graph doc not empty: nodes=%d roots=%d fired=%v", len(g.Nodes), len(g.Roots), fired)
	}
}

func TestDeserialize_EmptyInputIsEmptyGraph(t *testing.T) {
	// The legacy-NULL-column case: empty bytes read as an empty graph,
	// never an error.
	for _, in := range [][]byte{nil, {}} {
		g, fired, err := Deserialize(in)
		if err != nil {
			t.Fatalf("deserialize(%v): unexpected err %v", in, err)
		}
		if g == nil || len(g.Nodes) != 0 || fired != nil {
			t.Fatalf("deserialize(%v) not empty graph", in)
		}
		if p := g.PathFromRoot(mk("x", "1")); p != nil {
			t.Fatalf("empty graph PathFromRoot != nil: %v", p)
		}
	}
}

func TestSerialize_DepthCapBounds(t *testing.T) {
	// A chain deeper than the cap: nodes beyond maxSerializeDepth are
	// dropped, keeping the doc bounded, and the retained prefix still
	// round-trips.
	g := NewGraph()
	root := mk("n0", "1")
	g.AddNode(root, true, true)
	g.AddRoot(root)
	prev := root
	total := maxSerializeDepth + 50
	for i := 1; i <= total; i++ {
		k := mk("n"+itoa(i), "1")
		g.AddNode(k, false, true)
		g.AddEdge(prev, k)
		prev = k
	}

	data, err := g.Serialize(nil)
	if err != nil {
		t.Fatalf("serialize deep chain: %v", err)
	}
	g2, _, err := Deserialize(data)
	if err != nil {
		t.Fatalf("deserialize deep chain: %v", err)
	}
	// Retained node count is bounded: root (depth 0) plus nodes up to and
	// including depth maxSerializeDepth = maxSerializeDepth+1 nodes.
	if len(g2.Nodes) > maxSerializeDepth+1 {
		t.Fatalf("depth cap not enforced: %d nodes retained", len(g2.Nodes))
	}
	// The node exactly at the cap survives; the one past it does not.
	if _, ok := g2.Nodes[mk("n"+itoa(maxSerializeDepth), "1")]; !ok {
		t.Fatalf("node at cap depth missing")
	}
	if _, ok := g2.Nodes[mk("n"+itoa(maxSerializeDepth+10), "1")]; ok {
		t.Fatalf("node past cap depth should be dropped")
	}
}

// itoa is a tiny local int->string to avoid importing strconv in a test
// helper that only needs base-10 positives.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
