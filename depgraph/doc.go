package depgraph

// doc.go owns the compact, index-based serialization of a Graph plus the
// per-node fired-signals attribution that ADR-012 (Item 4) persists into
// each SBOM snapshot for point-in-time audit.
//
// Why a separate, index-based shape (not just json-marshalling Graph):
//   - Nodes carry redundant Parents/Children slices of full Keys; a flat
//     edge list keyed by integer index is dramatically smaller for a
//     real lockfile (hundreds of nodes, each Key ~60 bytes repeated on
//     both sides of every edge).
//   - The snapshot column is additive and read-rarely; we optimise the
//     stored bytes, not deserialize speed.
//
// Boundedness (mandatory — the doc lands in a per-snapshot DB column):
//   - Edges are deduped (a parser that walks a lockfile twice can't
//     double-list an edge; AddEdge already dedupes, but Serialize
//     re-dedupes defensively).
//   - A depth cap drops any node whose minimum root-distance exceeds
//     maxSerializeDepth, and every edge incident to a dropped node, so a
//     pathological deep/wide graph can't blow the column size. Roots are
//     always depth 0 and always retained.

import (
	"encoding/json"
	"sort"
)

// maxSerializeDepth bounds how deep the persisted graph reaches from the
// roots. Real npm/pnpm trees are rarely deeper than this; capping keeps
// the stored doc size bounded for pathological inputs. Nodes beyond the
// cap (and their incident edges) are omitted from the doc — the path
// reconstruction on read still works for everything at or above the cap.
const maxSerializeDepth = 64

// graphDocNode is one node in the serialized doc. Field names are short
// because they repeat once per package.
type graphDocNode struct {
	Eco     string `json:"eco"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Direct  bool   `json:"direct"`
	Prod    bool   `json:"prod"`
}

// graphDoc is the on-disk shape: an index-addressed node table, an edge
// list of [parentIdx, childIdx] pairs, the root indices, and a
// per-node-index list of fired signal IDs. Indices reference positions
// in Nodes.
type graphDoc struct {
	Nodes        []graphDocNode   `json:"nodes"`
	Edges        [][2]int         `json:"edges"`
	Roots        []int            `json:"roots"`
	FiredSignals map[int][]string `json:"fired_signals,omitempty"`
}

// Serialize encodes g into the compact index-based JSON doc. firedSignals
// maps a node Key to the signal IDs that fired against that package at
// snapshot time (npm/pnpm today; nil/empty for ecosystems without a
// graph or without fired signals). Keys in firedSignals that are not in
// the graph are ignored.
//
// The returned bytes are bounded by the depth cap and edge dedupe. A nil
// or empty graph serializes to a small but valid doc (empty node table)
// so the snapshot column always holds parseable JSON.
func (g *Graph) Serialize(firedSignals map[Key][]string) ([]byte, error) {
	if g == nil {
		return json.Marshal(graphDoc{Nodes: []graphDocNode{}, Edges: [][2]int{}, Roots: []int{}})
	}

	// Depth-bounded reachable set via BFS from roots. depth[k] is the
	// minimum root-distance; nodes never reached (orphans) or beyond the
	// cap are excluded.
	depth := make(map[Key]int, len(g.Nodes))
	queue := make([]Key, 0, len(g.Roots))
	for _, r := range g.Roots {
		if _, ok := g.Nodes[r]; !ok {
			continue
		}
		if _, seen := depth[r]; seen {
			continue
		}
		depth[r] = 0
		queue = append(queue, r)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		d := depth[cur]
		if d >= maxSerializeDepth {
			continue // do not expand past the cap
		}
		node := g.Nodes[cur]
		for _, child := range node.Children {
			if _, ok := g.Nodes[child]; !ok {
				continue
			}
			if _, seen := depth[child]; seen {
				continue
			}
			depth[child] = d + 1
			queue = append(queue, child)
		}
	}

	// Stable index assignment: roots first in their declared order, then
	// the remaining retained nodes sorted by Key for determinism.
	idx := make(map[Key]int, len(depth))
	ordered := make([]Key, 0, len(depth))
	for _, r := range g.Roots {
		if _, ok := depth[r]; !ok {
			continue
		}
		if _, assigned := idx[r]; assigned {
			continue
		}
		idx[r] = len(ordered)
		ordered = append(ordered, r)
	}
	rest := make([]Key, 0, len(depth))
	for k := range depth {
		if _, assigned := idx[k]; assigned {
			continue
		}
		rest = append(rest, k)
	}
	sort.Slice(rest, func(i, j int) bool { return keyLess(rest[i], rest[j]) })
	for _, k := range rest {
		idx[k] = len(ordered)
		ordered = append(ordered, k)
	}

	doc := graphDoc{
		Nodes: make([]graphDocNode, 0, len(ordered)),
		Edges: make([][2]int, 0, len(ordered)),
		Roots: make([]int, 0, len(g.Roots)),
	}
	for _, k := range ordered {
		n := g.Nodes[k]
		doc.Nodes = append(doc.Nodes, graphDocNode{
			Eco:     k.Ecosystem,
			Name:    k.Name,
			Version: k.Version,
			Direct:  n.Direct,
			Prod:    n.Prod,
		})
	}
	for _, r := range g.Roots {
		if i, ok := idx[r]; ok {
			doc.Roots = append(doc.Roots, i)
		}
	}

	// Edges: only those whose BOTH endpoints survived the depth cap.
	// Dedupe defensively on (parentIdx, childIdx).
	seenEdge := make(map[[2]int]struct{})
	// Walk in stable node order, stable child order, for deterministic output.
	for _, k := range ordered {
		pi := idx[k]
		children := append([]Key(nil), g.Nodes[k].Children...)
		sort.Slice(children, func(i, j int) bool { return keyLess(children[i], children[j]) })
		for _, c := range children {
			ci, ok := idx[c]
			if !ok {
				continue // child dropped by depth cap
			}
			e := [2]int{pi, ci}
			if _, dup := seenEdge[e]; dup {
				continue
			}
			seenEdge[e] = struct{}{}
			doc.Edges = append(doc.Edges, e)
		}
	}

	if len(firedSignals) > 0 {
		fired := make(map[int][]string)
		for k, sigs := range firedSignals {
			i, ok := idx[k]
			if !ok || len(sigs) == 0 {
				continue
			}
			cp := append([]string(nil), sigs...)
			fired[i] = cp
		}
		if len(fired) > 0 {
			doc.FiredSignals = fired
		}
	}

	return json.Marshal(doc)
}

// Deserialize decodes a doc produced by Serialize back into a Graph plus
// the per-Key fired-signals map. An empty or nil input yields a fresh
// empty Graph and a nil signals map (the legacy-NULL-column case: a
// snapshot written before this column existed reads as an empty graph,
// never an error).
//
// Edges referencing out-of-range indices are skipped rather than
// erroring — a forward-compatible read should not fail because a future
// writer trimmed differently.
func Deserialize(data []byte) (*Graph, map[Key][]string, error) {
	g := NewGraph()
	if len(data) == 0 {
		return g, nil, nil
	}
	var doc graphDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, err
	}

	keys := make([]Key, len(doc.Nodes))
	for i, n := range doc.Nodes {
		k := Key{Ecosystem: n.Eco, Name: n.Name, Version: n.Version}
		keys[i] = k
		g.AddNode(k, n.Direct, n.Prod)
	}
	for _, e := range doc.Edges {
		p, c := e[0], e[1]
		if p < 0 || p >= len(keys) || c < 0 || c >= len(keys) {
			continue
		}
		g.AddEdge(keys[p], keys[c])
	}
	for _, ri := range doc.Roots {
		if ri < 0 || ri >= len(keys) {
			continue
		}
		g.AddRoot(keys[ri])
	}

	var fired map[Key][]string
	if len(doc.FiredSignals) > 0 {
		fired = make(map[Key][]string, len(doc.FiredSignals))
		for i, sigs := range doc.FiredSignals {
			if i < 0 || i >= len(keys) || len(sigs) == 0 {
				continue
			}
			fired[keys[i]] = append([]string(nil), sigs...)
		}
	}
	return g, fired, nil
}
