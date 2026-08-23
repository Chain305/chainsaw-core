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

	// UnknownCount is the number of nodes the engine COULD NOT evaluate
	// (Input.SignalsUnavailable → VerdictUnknown). Broken out of
	// ByVerdict as a first-class field because it is the one number a
	// consumer must not miss: a summary with UnknownCount > 0 does not
	// describe the whole tree, whatever the other counters say. It
	// duplicates ByVerdict[VerdictUnknown] on purpose — a consumer that
	// only knows the pre-Unknown verdict vocabulary still sees it.
	UnknownCount int
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
//
// Nodes whose Input carries SignalsUnavailable are NOT scored: they
// resolve to VerdictUnknown, are excluded from the transitive rollup in
// both directions (they neither absorb descendants' deficits nor
// contribute one to their ancestors), are excluded from MinOverall, and
// are counted in Summary.UnknownCount. A tree containing them is a
// PARTIAL result and callers must say so.
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
	//
	// effective records the Input each node was ACTUALLY scored with
	// (which is not always inputs[k] — see the synthesis branch below).
	// Pass 2 needs it to re-evaluate a promotion candidate against the
	// very same facts, so a promotion can never be built on a different
	// input than the verdict it is replacing.
	effective := make(map[depgraph.Key]Input, len(graph.Nodes))
	for k := range graph.Nodes {
		in := inputs[k]
		// If caller didn't supply an Input for this key, synthesize one
		// from the Key so EvaluatePackage still has identity fields. The
		// resulting Evaluation will have a clean 100 overall.
		//
		// TRAP: that fallback is only correct when a missing entry means
		// "nothing to report". If it means "we could not fetch the
		// facts", the caller MUST supply an Input with
		// SignalsUnavailable set — otherwise an outage is scored as a
		// clean package. The fallback cannot tell the two apart, which
		// is why the decision belongs to the caller.
		if in.Ecosystem == "" && in.Package == "" && in.Version == "" {
			in = Input{Ecosystem: k.Ecosystem, Package: k.Name, Version: k.Version}
		}
		ev := EvaluatePackage(in, opts)
		effective[k] = in
		te.ByKey[k] = ev
	}

	// Pass 2: for each node, compute per-category deficit contributions
	// from every descendant with depth-decay + prod-weight, take the
	// category-wise max over (self_deficit, scaled_descendant_deficits),
	// rewrite RolledUp, and if the rolled-up score drops meaningfully,
	// re-resolve the verdict and populate TransitiveBlame.
	for k, ev := range te.ByKey {
		// A node we could not evaluate has no direct score to roll
		// descendants into, and folding descendants in would invent
		// one. Leave it Unknown — the honest answer stays honest.
		if ev.Verdict == VerdictUnknown {
			continue
		}
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

		// Per-node upgrade promotion, judged LAST so every gate sees the
		// node's FINAL state: its own fired signals, its own direct
		// score, and the rolled-up score its own descendants produced. A
		// node dragged into the bottom band by its dependencies fails
		// gate (c) here and stays blocked, exactly as
		// intelligence.ReapplyKnownFixAfterTransitive keeps the root
		// honest after the same rollup.
		promoteNodeInTree(k, ev, effective[k], opts)
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
		if ev.Verdict == VerdictUnknown {
			// Unevaluated nodes are counted, never scored. Their
			// Overall=0 means "no score" and would otherwise read as
			// "the worst package in the tree" in MinOverall.
			te.Summary.UnknownCount++
			continue
		}
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

// promoteNodeInTree gives ONE node in a tree its own upgrade-available
// decision, on its own evidence, and mutates ev in place when it earns
// one. It is the tree-pass twin of
// intelligence.promoteToUpgradeAvailable and enforces the same gates in
// the same order:
//
//	(a) EVIDENCE — a per-node candidate supplied by the caller in
//	    Options.PerNodeSafeUpgrade. The caller derives it from THAT
//	    node's own advisory fix data (intelligence.MinimumSafeVersion on
//	    the node's own cached Report) and corroborates it against THAT
//	    node's registry-advertised latest. No entry, no promotion.
//	(b)+(c) UpgradePromotionEligible on THIS node's evaluation — the
//	    supply_chain / quality veto, the vulnerability-dominance test,
//	    and the bottom-band check. Because it runs after pass 2 the band
//	    check reads the node's post-rollup RolledUp, so a node whose own
//	    dependencies dragged it under ThresholdQuarantine is refused.
//	    A malware-flagged descendant fires sc.known_malicious and is
//	    vetoed outright; a KEV descendant carries MaxImpact 20 and is
//	    pinned into band 1, so neither can ever be promoted — whatever
//	    the parent's verdict is.
//
// The re-evaluation is a second pure EvaluatePackage call on the SAME
// Input with the SAME weights, so the scores must come back identical;
// the guards below refuse the promotion if the engine ever disagrees.
// Promotion moves the VERDICT and nothing else — the rolled-up score and
// the transitive blame the tree pass computed are carried across
// verbatim, because a re-evaluation of a single node cannot reproduce
// them.
func promoteNodeInTree(k depgraph.Key, ev *Evaluation, in Input, opts Options) {
	if ev == nil || len(opts.PerNodeSafeUpgrade) == 0 {
		return
	}
	safeVersion := opts.PerNodeSafeUpgrade[k]
	if safeVersion == "" {
		return
	}
	if !UpgradePromotionEligible(ev) {
		return
	}
	nodeOpts := opts
	nodeOpts.PerNodeSafeUpgrade = nil
	nodeOpts.SafeUpgradeVersion = safeVersion
	promoted := EvaluatePackage(in, nodeOpts)
	if promoted == nil || promoted.Verdict != VerdictUpgradeAvailable {
		return
	}
	if promoted.Resolution.SafeVersion != safeVersion {
		return
	}
	// The option we flipped must not move a score. If it did, something
	// other than the verdict branch is in play and the safe answer is
	// the un-promoted one.
	if promoted.DirectScore.Overall != ev.DirectScore.Overall {
		return
	}
	// Keep the ORIGINAL score objects, not the re-evaluation's copies.
	// They are equal by construction (same Input, same weights, and the
	// guard above proves it for Overall), but pass 2 is still walking
	// te.ByKey and other nodes' rollups read this node's DirectScore —
	// reusing the object makes the pass provably order-independent
	// instead of order-independent-by-argument.
	promoted.DirectScore = ev.DirectScore
	promoted.RolledUp = ev.RolledUp
	promoted.Resolution.TransitiveBlame = ev.Resolution.TransitiveBlame
	promoted.Resolution.TransitiveSeverity = ev.Resolution.TransitiveSeverity
	*ev = *promoted
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
		// An unevaluated descendant carries Overall=0 with every
		// category DataAvailable=false. Folding that in would read as
		// a 100-point deficit and drag every ancestor into quarantine
		// — turning a backend outage into a tree-wide block. Skip it:
		// the ancestor is still scored honestly on its OWN signals,
		// and the unevaluated descendant is reported in its own right
		// (TreeSummary.UnknownCount) rather than laundered into a
		// score. "Could not evaluate" is not evidence of risk.
		if dEval.Verdict == VerdictUnknown {
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
