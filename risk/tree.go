package risk

import (
	"fmt"
	"math"
	"sort"

	"github.com/chain305/chainsaw-core/depgraph"
)

// Tunables for transitive rollup. Exposed as consts so tests and docs
// share the same values. Any change here counts as an engine-version
// bump (see EngineVersion in evaluation.go).
const (
	// TransitiveDecayBase is the geometric decay applied to a
	// descendant's direct deficit per depth hop. depth=1 (immediate
	// child of self) gets one unit of decay; roots evaluate themselves
	// at depth 0 (no decay).
	TransitiveDecayBase = 0.6

	// TransitiveProdWeight scales a descendant's deficit down when the
	// descendant is dev-only. A risky devDep shouldn't drag a prod
	// package into quarantine at full strength.
	TransitiveProdWeight = 1.0
	TransitiveDevWeight  = 0.4

	// TransitiveBlameThreshold is the minimum points that RolledUp has
	// to drop below DirectScore for the tree evaluator to populate
	// TransitiveBlame. Smaller drops are noise.
	TransitiveBlameThreshold = 5
)

// TreeEvaluation is the aggregate result of scoring every node in a
// dep graph. ByKey gives O(1) lookup for a specific package; Roots
// mirrors graph.Roots order so UI consumers can render per-root
// hierarchies without a second sort.
type TreeEvaluation struct {
	Roots   []*EvaluatedNode
	ByKey   map[depgraph.Key]*Evaluation
	Summary TreeSummary
}

// EvaluatedNode is a tree-shaped view over a Graph node plus its
// scored Evaluation. Children are the direct-child wrappers so a
// caller can walk the tree without re-consulting the Graph.
type EvaluatedNode struct {
	Key      depgraph.Key
	Direct   bool
	Depth    int
	Prod     bool
	Eval     *Evaluation
	Children []*EvaluatedNode
}

// TreeSummary is the one-page rollup of a TreeEvaluation — the shape
// the UI's "scan summary" card consumes. ByVerdict is a histogram of
// verdicts across every scored node.
type TreeSummary struct {
	TotalNodes              int
	DirectCount             int
	TransitiveCount         int
	ByVerdict               map[Verdict]int
	MinOverall              int
	MaxTransitiveBlameChain int
}

// EvaluateTree scores an entire dependency graph. For each node it
// calls EvaluatePackage with the caller-provided Input, then folds
// descendants' direct-score deficits into the node's RolledUp score
// using max-with-depth-decay aggregation. The verdict is re-resolved
// against the rolled-up score, and TransitiveBlame is populated when a
// descendant drags the verdict below the direct score.
//
// EvaluateTree is safe for an empty graph — it returns a TreeEvaluation
// with zero nodes and an empty ByVerdict map.
func EvaluateTree(graph *depgraph.Graph, inputs map[depgraph.Key]Input, opts Options) *TreeEvaluation {
	te := &TreeEvaluation{
		ByKey:   make(map[depgraph.Key]*Evaluation),
		Summary: TreeSummary{ByVerdict: make(map[Verdict]int)},
	}
	if graph == nil || len(graph.Nodes) == 0 {
		te.Summary.MinOverall = 100
		return te
	}

	// Pass 1: score every node individually. DirectScore is authoritative
	// after this pass; RolledUp is provisional (equals DirectScore) and
	// will be rewritten in pass 2.
	for k := range graph.Nodes {
		in := inputs[k]
		// If caller didn't supply an Input for this key, synthesize one
		// from the Key so EvaluatePackage still has identity fields. The
		// resulting Evaluation will have a clean 100 overall.
		if in.Ecosystem == "" && in.Package == "" && in.Version == "" {
			in = Input{Ecosystem: k.Ecosystem, Package: k.Name, Version: k.Version}
		}
		ev := EvaluatePackage(in, opts)
		te.ByKey[k] = ev
	}

	// Pass 2: for each node, compute per-category deficit contributions
	// from every descendant with depth-decay + prod-weight, take the
	// category-wise max over (self_deficit, scaled_descendant_deficits),
	// rewrite RolledUp, and if the rolled-up score drops meaningfully,
	// re-resolve the verdict and populate TransitiveBlame.
	for k, ev := range te.ByKey {
		rolled, blame := rollupForNode(graph, k, ev, te.ByKey)
		ev.RolledUp = rolled

		// Only re-resolve verdict when RolledUp dropped below DirectScore
		// by more than the blame threshold. A tiny decay-driven drop
		// shouldn't flip an Allow into Warn — only a material transitive
		// signal should.
		drop := ev.DirectScore.Overall - rolled.Overall
		if drop > TransitiveBlameThreshold && len(blame) > 0 {
			// Re-resolve on the rolled-up score. We pass empty maps for
			// primitives/compound since we don't have the original fired
			// signals for the rolled-up picture — the rationale stays
			// tied to the direct evaluation, while the verdict reflects
			// the rolled-up score.
			newVerdict, newResolution := ResolveVerdictFromScore(
				rolled.Overall,
				map[string]FiredSignal{},
				map[string]FiredSignal{},
				opts,
			)
			// Preserve the original resolution's rationale — it still
			// explains the direct-score picture, which is useful context.
			newResolution.Rationale = ev.Resolution.Rationale
			newResolution.TransitiveBlame = blame
			newResolution.Summary = fmt.Sprintf(
				"Transitive dependency %s@%s drags this package into %s territory.",
				blame[0].Package, blame[0].Version, newVerdict,
			)
			ev.Verdict = newVerdict
			ev.Resolution = newResolution
		} else if len(blame) > 0 {
			// Verdict unchanged but we still want the blame attached so
			// UI consumers can explain the rolled-up delta.
			ev.Resolution.TransitiveBlame = blame
		}
	}

	// Pass 3: build the tree view keyed on Graph's Roots order.
	built := make(map[depgraph.Key]*EvaluatedNode, len(te.ByKey))
	var build func(k depgraph.Key, depth int, visited map[depgraph.Key]struct{}) *EvaluatedNode
	build = func(k depgraph.Key, depth int, visited map[depgraph.Key]struct{}) *EvaluatedNode {
		if existing, ok := built[k]; ok {
			return existing
		}
		if _, cycle := visited[k]; cycle {
			return nil
		}
		node := graph.Nodes[k]
		if node == nil {
			return nil
		}
		en := &EvaluatedNode{
			Key:    k,
			Direct: node.Direct,
			Depth:  depth,
			Prod:   node.Prod,
			Eval:   te.ByKey[k],
		}
		built[k] = en
		visited[k] = struct{}{}
		children := append([]depgraph.Key(nil), node.Children...)
		sort.Slice(children, func(i, j int) bool { return depgraph.KeyLess(children[i], children[j]) })
		for _, c := range children {
			if child := build(c, depth+1, visited); child != nil {
				en.Children = append(en.Children, child)
			}
		}
		delete(visited, k)
		return en
	}
	for _, rk := range graph.Roots {
		visited := make(map[depgraph.Key]struct{})
		if root := build(rk, 0, visited); root != nil {
			te.Roots = append(te.Roots, root)
		}
	}

	// Summary.
	te.Summary.TotalNodes = len(te.ByKey)
	te.Summary.MinOverall = 100
	for k, ev := range te.ByKey {
		node := graph.Nodes[k]
		if node != nil && node.Direct {
			te.Summary.DirectCount++
		} else {
			te.Summary.TransitiveCount++
		}
		te.Summary.ByVerdict[ev.Verdict]++
		if ev.RolledUp.Overall < te.Summary.MinOverall {
			te.Summary.MinOverall = ev.RolledUp.Overall
		}
		if n := len(ev.Resolution.TransitiveBlame); n > 0 {
			// "chain depth" is the greatest graph-depth of any blamed
			// key relative to THIS node. Compute depth of each blamed
			// descendant via a BFS from k.
			for _, bk := range ev.Resolution.TransitiveBlame {
				if d := descendantDepth(graph, k, bk); d > te.Summary.MaxTransitiveBlameChain {
					te.Summary.MaxTransitiveBlameChain = d
				}
			}
		}
	}
	return te
}

// rollupForNode applies max-with-depth-decay aggregation for one node.
// Returns the rolled-up Score and the top-3 blame Keys (risk.Key
// because that's what Resolution.TransitiveBlame wants) ranked by how
// much they pulled the rolled-up overall below the direct overall.
func rollupForNode(graph *depgraph.Graph, self depgraph.Key, selfEval *Evaluation, byKey map[depgraph.Key]*Evaluation) (Score, []Key) {
	// Start from a copy of DirectScore categories.
	rolled := make(map[Category]CategoryScore, len(selfEval.DirectScore.Categories))
	for cat, cs := range selfEval.DirectScore.Categories {
		rolled[cat] = cs
	}

	// BFS from self to compute depth of every descendant. A descendant
	// can appear at multiple depths if the graph diamonds; we use the
	// minimum depth (strongest decay) so a direct-and-transitive path
	// uses the direct weighting.
	depths := bfsDepths(graph, self)

	// Per-category contribution tracker — how much deficit each
	// descendant contributes to the worst category. Used to rank blame.
	type contrib struct {
		key    depgraph.Key
		amount float64
	}
	contribs := make([]contrib, 0, 8)

	for dk, depth := range depths {
		if dk == self || depth <= 0 {
			continue
		}
		dEval, ok := byKey[dk]
		if !ok {
			continue
		}
		node := graph.Nodes[dk]
		prodW := TransitiveProdWeight
		if node != nil && !node.Prod {
			prodW = TransitiveDevWeight
		}
		decay := math.Pow(TransitiveDecayBase, float64(depth))

		// Track the single worst category deficit this descendant
		// contributes — used for blame ranking.
		maxCatContrib := 0.0

		for cat, descCS := range dEval.DirectScore.Categories {
			directDeficit := float64(100 - descCS.Score)
			effective := directDeficit * decay * prodW
			selfCS, ok := rolled[cat]
			if !ok {
				continue
			}
			selfDeficit := float64(100 - selfCS.Score)
			if effective > selfDeficit {
				newScore := 100 - int(effective+0.5)
				if newScore < 0 {
					newScore = 0
				}
				if newScore > 100 {
					newScore = 100
				}
				rolled[cat] = CategoryScore{
					Score:         newScore,
					Grade:         gradeForScore(newScore),
					DataAvailable: selfCS.DataAvailable,
					FiredSignals:  selfCS.FiredSignals,
				}
				if effective-selfDeficit > maxCatContrib {
					maxCatContrib = effective - selfDeficit
				}
			}
		}
		if maxCatContrib > 0 {
			contribs = append(contribs, contrib{dk, maxCatContrib})
		}
	}

	// Rank blame by amount desc, then by Key for stability.
	sort.Slice(contribs, func(i, j int) bool {
		if contribs[i].amount != contribs[j].amount {
			return contribs[i].amount > contribs[j].amount
		}
		return depgraph.KeyLess(contribs[i].key, contribs[j].key)
	})
	blame := make([]Key, 0, 3)
	for i := 0; i < len(contribs) && len(blame) < 3; i++ {
		k := contribs[i].key
		blame = append(blame, Key{Ecosystem: k.Ecosystem, Package: k.Name, Version: k.Version})
	}

	overall := ComputeOverallFromCategories(rolled)
	// MaxImpact ceiling: the tree rollup must never raise overall above
	// the per-signal cap that the direct evaluation already enforced.
	// Transitive rollup can only LOWER the score (descendant deficit), so
	// clamping at DirectScore.Overall is the correct bound for orphans
	// and the upper bound for nodes with descendants.
	if overall > selfEval.DirectScore.Overall {
		overall = selfEval.DirectScore.Overall
	}
	return Score{Overall: overall, Categories: rolled}, blame
}

// bfsDepths runs BFS from self and returns the minimum depth to each
// reachable key. Cycle-safe via a visited set.
func bfsDepths(graph *depgraph.Graph, self depgraph.Key) map[depgraph.Key]int {
	out := map[depgraph.Key]int{self: 0}
	if _, ok := graph.Nodes[self]; !ok {
		return out
	}
	type frame struct {
		key   depgraph.Key
		depth int
	}
	queue := []frame{{self, 0}}
	for len(queue) > 0 {
		f := queue[0]
		queue = queue[1:]
		node := graph.Nodes[f.key]
		if node == nil {
			continue
		}
		for _, c := range node.Children {
			if _, seen := out[c]; seen {
				continue
			}
			out[c] = f.depth + 1
			queue = append(queue, frame{c, f.depth + 1})
		}
	}
	return out
}

// descendantDepth returns the minimum-depth distance from `self` to
// `target`, or 0 if target is unreachable. Cycle-safe. The conversion
// between risk.Key (Ecosystem/Package/Version) and depgraph.Key
// (Ecosystem/Name/Version) is handled here so callers at the summary
// level can pass risk.Key directly.
func descendantDepth(graph *depgraph.Graph, self depgraph.Key, target Key) int {
	want := depgraph.Key{Ecosystem: target.Ecosystem, Name: target.Package, Version: target.Version}
	depths := bfsDepths(graph, self)
	return depths[want]
}
