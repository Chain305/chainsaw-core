// Package depgraph models a lockfile-derived dependency graph — the
// structural layer above the flat Package lists produced by
// internal/depparser/analyzer. A Graph carries per-node parent/child
// edges so the risk engine can roll up transitive risk, report blame
// chains, and apply depth-based decay.
//
// Only npm and pnpm have graph parsers today (package-lock.json v2/v3
// and pnpm-lock.yaml encode parent→child edges). Every other ecosystem
// degrades gracefully: WalkDirGraph simply returns no graph and callers
// fall back to flat evaluation.
//
// The type surface here is intentionally small and does NOT depend on
// internal/risk — that dependency runs the other way so the risk engine
// can consume graphs without pulling lockfile parser code in reverse.
package depgraph

import (
	"fmt"
	"sort"
	"strings"
)

// Key uniquely identifies a package version inside a Graph. The three
// fields together form the hash key; duplicates across ecosystems are
// resolved naturally because Ecosystem differs.
type Key struct {
	Ecosystem string
	Name      string
	Version   string
}

// String returns a canonical "ecosystem:name@version" form used in error
// messages and test fixture expectations.
func (k Key) String() string {
	return fmt.Sprintf("%s:%s@%s", k.Ecosystem, k.Name, k.Version)
}

// Node is one package version inside a Graph, with edges in both
// directions so traversals from roots OR from leaves are O(1) per edge.
// Parents is non-empty for transitive nodes; a root has an empty Parents
// list (manifest-declared, no in-edge from another dep).
type Node struct {
	Key        Key
	Direct     bool   // true when the manifest lists this package explicitly
	Prod       bool   // false when reachable only via devDependencies
	Classifier string // ecosystem-scoped qualifier (Maven classifier today; empty otherwise)
	Parents    []Key  // multi-parent permitted (pnpm shares transitives)
	Children   []Key
}

// Graph is the flat index of every parsed package plus the set of roots
// (manifest-declared direct deps). Roots is ordered so the tree
// evaluator produces stable output; Nodes uses Key as map key for O(1)
// lookup during traversal.
//
// edgeAttrs is a lazily-allocated, per-edge string-map store. It is
// optional metadata — most ecosystems leave it nil. Today only the
// Gradle parser populates it (with the "configs" attribute listing
// which Gradle configurations contain a given parent→child edge), but
// the surface is generic so other ecosystems can attach edge-scoped
// labels (e.g. optional/peer flags) without further graph changes.
type Graph struct {
	Roots     []Key
	Nodes     map[Key]*Node
	edgeAttrs map[edgeID]map[string]string
}

// edgeID is the composite map key for per-edge metadata. Keeping it
// unexported so the storage shape can evolve without breaking callers.
type edgeID struct {
	parent Key
	child  Key
}

// NewGraph returns an empty Graph ready for population by an ecosystem
// parser. Parsers should call AddNode before AddEdge so edge endpoints
// are always resolvable.
func NewGraph() *Graph {
	return &Graph{
		Nodes: make(map[Key]*Node),
	}
}

// AddNode inserts a node if it is not already present and returns the
// canonical pointer. Idempotent so pnpm's shared-transitive case
// (multiple parents discovering the same child) cannot double-insert.
func (g *Graph) AddNode(k Key, direct, prod bool) *Node {
	if n, ok := g.Nodes[k]; ok {
		// Promote flags monotonically: once a package is known to be
		// Direct or Prod it cannot revert.
		if direct {
			n.Direct = true
		}
		if prod {
			n.Prod = true
		}
		return n
	}
	n := &Node{Key: k, Direct: direct, Prod: prod}
	g.Nodes[k] = n
	return n
}

// AddEdge records a parent→child relationship. Both endpoints must
// already exist (call AddNode first). Duplicate edges are de-duplicated
// silently so a parser that walks a lockfile twice does not corrupt the
// adjacency lists.
func (g *Graph) AddEdge(parent, child Key) {
	p, ok := g.Nodes[parent]
	if !ok {
		return
	}
	c, ok := g.Nodes[child]
	if !ok {
		return
	}
	if !containsKey(p.Children, child) {
		p.Children = append(p.Children, child)
	}
	if !containsKey(c.Parents, parent) {
		c.Parents = append(c.Parents, parent)
	}
}

// AddRoot marks a key as a manifest-declared direct dependency. Roots
// are the entry points for Depth / Walk traversals. Duplicate roots are
// dropped. The node must already exist.
func (g *Graph) AddRoot(k Key) {
	if _, ok := g.Nodes[k]; !ok {
		return
	}
	for _, existing := range g.Roots {
		if existing == k {
			return
		}
	}
	g.Roots = append(g.Roots, k)
	g.Nodes[k].Direct = true
}

// Validate returns non-nil when the graph has structural inconsistencies:
// a root that is not in Nodes, or an edge whose endpoint is unknown.
// Called by tests — parsers do not have to call it, but doing so cheaply
// catches programming errors during authoring.
func (g *Graph) Validate() error {
	for _, r := range g.Roots {
		if _, ok := g.Nodes[r]; !ok {
			return fmt.Errorf("depgraph: root %s not in Nodes", r)
		}
	}
	for k, n := range g.Nodes {
		for _, c := range n.Children {
			if _, ok := g.Nodes[c]; !ok {
				return fmt.Errorf("depgraph: node %s has unknown child %s", k, c)
			}
		}
		for _, p := range n.Parents {
			if _, ok := g.Nodes[p]; !ok {
				return fmt.Errorf("depgraph: node %s has unknown parent %s", k, p)
			}
		}
	}
	return nil
}

// Depth returns the minimum number of edges from any Root to k using
// BFS. Roots themselves are depth 0. Returns -1 when k is not reachable
// from any root (orphans, or a key that is not in the graph). Stable
// under cycles thanks to a visited set.
func (g *Graph) Depth(k Key) int {
	if _, ok := g.Nodes[k]; !ok {
		return -1
	}
	if len(g.Roots) == 0 {
		return -1
	}
	type frame struct {
		key   Key
		depth int
	}
	visited := make(map[Key]struct{}, len(g.Nodes))
	queue := make([]frame, 0, len(g.Roots))
	for _, r := range g.Roots {
		if r == k {
			return 0
		}
		queue = append(queue, frame{r, 0})
		visited[r] = struct{}{}
	}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		node := g.Nodes[f.key]
		for _, child := range node.Children {
			if _, seen := visited[child]; seen {
				continue
			}
			visited[child] = struct{}{}
			if child == k {
				return f.depth + 1
			}
			queue = append(queue, frame{child, f.depth + 1})
		}
	}
	return -1
}

// PathFromRoot returns the shortest edge path from any Root down to
// target, as a slice of Keys ordered root→…→target (inclusive on both
// ends). It is the "show me the chain that brought this package in"
// reconstruction backing the affected-packages transitive_path surface.
//
// Implementation: BFS from all Roots simultaneously, recording a
// predecessor for each first-visited node, then walking the predecessor
// chain back from target and reversing. BFS guarantees the path is a
// shortest one; the predecessor map is single-valued so the walk-back
// terminates in at most len(Nodes) steps even across cycles.
//
// Returns nil when target is not in the graph, when there are no roots,
// or when target is unreachable from every root (orphan). A target that
// is itself a root yields a single-element path []Key{target}.
func (g *Graph) PathFromRoot(target Key) []Key {
	if _, ok := g.Nodes[target]; !ok {
		return nil
	}
	if len(g.Roots) == 0 {
		return nil
	}
	// pred maps child -> parent for the BFS tree. A root maps to itself
	// as a sentinel so the back-walk can detect "reached a root" without
	// a second set lookup.
	pred := make(map[Key]Key, len(g.Nodes))
	queue := make([]Key, 0, len(g.Roots))
	for _, r := range g.Roots {
		if _, seen := pred[r]; seen {
			continue
		}
		pred[r] = r // self-sentinel marks a root
		if r == target {
			return []Key{target}
		}
		queue = append(queue, r)
	}
	found := false
	for len(queue) > 0 && !found {
		cur := queue[0]
		queue = queue[1:]
		node, ok := g.Nodes[cur]
		if !ok {
			continue
		}
		for _, child := range node.Children {
			if _, seen := pred[child]; seen {
				continue
			}
			pred[child] = cur
			if child == target {
				found = true
				break
			}
			queue = append(queue, child)
		}
	}
	if !found {
		return nil
	}
	// Reconstruct target -> root by following predecessors, then reverse.
	rev := make([]Key, 0, 8)
	cur := target
	for {
		rev = append(rev, cur)
		p, ok := pred[cur]
		if !ok {
			// Should not happen given found==true, but guard against a
			// corrupt predecessor chain rather than spinning.
			return nil
		}
		if p == cur {
			break // reached a root sentinel
		}
		cur = p
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// Descendants returns every transitive child of k (not including k
// itself), deduped and stable-ordered. Cycle-safe: a visited set blocks
// revisits so A→B→A terminates.
func (g *Graph) Descendants(k Key) []Key {
	if _, ok := g.Nodes[k]; !ok {
		return nil
	}
	visited := make(map[Key]struct{})
	out := make([]Key, 0, 8)
	var walk func(Key)
	walk = func(cur Key) {
		node, ok := g.Nodes[cur]
		if !ok {
			return
		}
		for _, child := range node.Children {
			if _, seen := visited[child]; seen {
				continue
			}
			visited[child] = struct{}{}
			out = append(out, child)
			walk(child)
		}
	}
	walk(k)
	sort.Slice(out, func(i, j int) bool { return keyLess(out[i], out[j]) })
	return out
}

// Walk invokes f for each node in a stable order: roots first (in the
// order they were added), then remaining nodes in BFS order from those
// roots, then any orphans sorted by Key. Cycle-safe.
func (g *Graph) Walk(f func(*Node)) {
	visited := make(map[Key]struct{}, len(g.Nodes))
	queue := make([]Key, 0, len(g.Roots))
	for _, r := range g.Roots {
		if _, seen := visited[r]; seen {
			continue
		}
		visited[r] = struct{}{}
		queue = append(queue, r)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		node, ok := g.Nodes[cur]
		if !ok {
			continue
		}
		f(node)
		// Stable child iteration.
		children := append([]Key(nil), node.Children...)
		sort.Slice(children, func(i, j int) bool { return keyLess(children[i], children[j]) })
		for _, c := range children {
			if _, seen := visited[c]; seen {
				continue
			}
			visited[c] = struct{}{}
			queue = append(queue, c)
		}
	}
	// Orphans (unreachable from any root) — still useful to surface for
	// debugging and to keep Walk total.
	orphans := make([]Key, 0)
	for k := range g.Nodes {
		if _, seen := visited[k]; seen {
			continue
		}
		orphans = append(orphans, k)
	}
	sort.Slice(orphans, func(i, j int) bool { return keyLess(orphans[i], orphans[j]) })
	for _, k := range orphans {
		visited[k] = struct{}{}
		f(g.Nodes[k])
	}
}

// keyLess orders Keys lexicographically by (Ecosystem, Name, Version).
// Exported for use by tree evaluator sort helpers.
func keyLess(a, b Key) bool {
	if a.Ecosystem != b.Ecosystem {
		return a.Ecosystem < b.Ecosystem
	}
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	return a.Version < b.Version
}

// KeyLess is the exported ordering function for callers building their
// own sorts. Kept as a thin re-export so internal impl can change.
func KeyLess(a, b Key) bool { return keyLess(a, b) }

// AddEdgeConfig appends a Gradle-style configuration label (e.g.
// "compileClasspath", "testRuntimeClasspath") to the parent→child
// edge's "configs" attribute. Idempotent on (parent, child, config).
// Both endpoints must already exist as nodes; otherwise the call is a
// no-op so callers can't accidentally smuggle phantom edges in via
// metadata. The edge itself does NOT need to have been recorded with
// AddEdge — this method only stores attribution; AddEdge is still the
// canonical way to wire the adjacency lists.
func (g *Graph) AddEdgeConfig(parent, child Key, config string) {
	g.appendEdgeAttr(parent, child, "configs", config)
}

// EdgeConfigs returns the list of configuration labels attached to the
// parent→child edge by AddEdgeConfig, in the order they were first
// added. Returns nil when the edge has no recorded configs (either it
// was never labeled or the edge does not exist).
func (g *Graph) EdgeConfigs(parent, child Key) []string {
	return g.edgeAttrList(parent, child, "configs")
}

// AddEdgeAttr appends a value to a named, list-valued edge attribute.
// It is the generic backing primitive for AddEdgeConfig and the
// per-ecosystem attribute helpers that followed (Maven scope, RubyGems
// source, NuGet frameworks). Stored as a comma-separated list keyed by
// (parent, child, attr); idempotent on (parent, child, attr, value).
// Both endpoints must already exist; empty value is a no-op.
func (g *Graph) AddEdgeAttr(parent, child Key, attr, value string) {
	g.appendEdgeAttr(parent, child, attr, value)
}

// EdgeAttr returns the list of values stored under attr for the
// parent→child edge in the order they were first added. Returns nil
// when the attribute is unset or the edge is unknown.
func (g *Graph) EdgeAttr(parent, child Key, attr string) []string {
	return g.edgeAttrList(parent, child, attr)
}

func (g *Graph) appendEdgeAttr(parent, child Key, attr, value string) {
	if attr == "" || value == "" {
		return
	}
	if _, ok := g.Nodes[parent]; !ok {
		return
	}
	if _, ok := g.Nodes[child]; !ok {
		return
	}
	if g.edgeAttrs == nil {
		g.edgeAttrs = make(map[edgeID]map[string]string)
	}
	id := edgeID{parent: parent, child: child}
	attrs, ok := g.edgeAttrs[id]
	if !ok {
		attrs = make(map[string]string)
		g.edgeAttrs[id] = attrs
	}
	cur := attrs[attr]
	if cur == "" {
		attrs[attr] = value
		return
	}
	for _, existing := range strings.Split(cur, ",") {
		if existing == value {
			return
		}
	}
	attrs[attr] = cur + "," + value
}

func (g *Graph) edgeAttrList(parent, child Key, attr string) []string {
	if g.edgeAttrs == nil {
		return nil
	}
	attrs, ok := g.edgeAttrs[edgeID{parent: parent, child: child}]
	if !ok {
		return nil
	}
	raw := attrs[attr]
	if raw == "" {
		return nil
	}
	return strings.Split(raw, ",")
}

func containsKey(set []Key, k Key) bool {
	for _, x := range set {
		if x == k {
			return true
		}
	}
	return false
}
