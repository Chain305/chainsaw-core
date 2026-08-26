package risk

import (
	"fmt"
	"testing"

	"github.com/chain305/chainsaw-core/depgraph"
)

// blameOf renders a node's TransitiveBlame as a comparable string.
func blameOf(te *TreeEvaluation, k depgraph.Key) string {
	ev := te.ByKey[k]
	if ev == nil {
		return "<nil>"
	}
	out := ""
	for _, b := range ev.Resolution.TransitiveBlame {
		out += fmt.Sprintf("%s/%s@%s ", b.Ecosystem, b.Package, b.Version)
	}
	return out
}

// badInput forces a real category deficit via the known-malicious
// instant block — the same lever the other tree tests use, because
// MaxCVSS alone does not fire a signal.
func badInput(k depgraph.Key) Input {
	return Input{
		Ecosystem:        k.Ecosystem,
		Package:          k.Name,
		Version:          k.Version,
		IsKnownMalicious: true,
		MalwareID:        "OSV-MAL-" + k.Name,
	}
}

func okInput(k depgraph.Key) Input {
	return Input{Ecosystem: k.Ecosystem, Package: k.Name, Version: k.Version}
}

// TransitiveBlame must not depend on Go's map iteration order.
//
// rollupForNode walks bfsDepths, which is a map. It used to read the
// self-deficit out of the progressively-mutated `rolled` values, so a
// descendant visited early raised the bar for every descendant after
// it: the same dependency was blamed when visited first and contributed
// nothing when visited second. The rolled SCORE hid this, because it is
// a max and max is commutative.
//
// The fixture mixes prod and dev descendants at two depths so several
// carry DISTINCT contributions and the top-3 cut is contested.
func blameFixture() (*depgraph.Graph, map[depgraph.Key]Input, depgraph.Key) {
	root := dk("root", "1")
	g := depgraph.NewGraph()
	g.AddNode(root, true, true)
	g.AddRoot(root)
	inputs := map[depgraph.Key]Input{root: okInput(root)}

	// Six direct children, alternating prod/dev (weight 1.0 vs 0.4).
	for i := 0; i < 6; i++ {
		d := dk(fmt.Sprintf("dep%02d", i), "1")
		g.AddNode(d, false, i%2 == 0)
		g.AddEdge(root, d)
		inputs[d] = badInput(d)

		// Give half of them a grandchild, adding a depth-2 tier.
		if i%3 == 0 {
			gc := dk(fmt.Sprintf("gc%02d", i), "1")
			g.AddNode(gc, false, true)
			g.AddEdge(d, gc)
			inputs[gc] = badInput(gc)
		}
	}
	return g, inputs, root
}

func TestTransitiveBlameIsOrderIndependent(t *testing.T) {
	g, inputs, root := blameFixture()

	want := blameOf(EvaluateTree(g, inputs, Options{}), root)
	if want == "" {
		t.Fatal("fixture produced no blame — it cannot detect blame instability")
	}
	for i := 0; i < 300; i++ {
		if got := blameOf(EvaluateTree(g, inputs, Options{}), root); got != want {
			t.Fatalf("TransitiveBlame nondeterministic on identical input:\n  first: %s\n  run %d: %s", want, i, got)
		}
	}
}

// The rolled-up score was always order-independent (it is a max). Pin
// that, so a future change to the blame logic cannot quietly make the
// score order-dependent instead.
func TestRolledUpScoreIsOrderIndependent(t *testing.T) {
	g, inputs, root := blameFixture()
	first := EvaluateTree(g, inputs, Options{}).ByKey[root].RolledUp.Overall
	for i := 0; i < 300; i++ {
		if got := EvaluateTree(g, inputs, Options{}).ByKey[root].RolledUp.Overall; got != first {
			t.Fatalf("RolledUp.Overall nondeterministic: %d then %d", first, got)
		}
	}
}

// Every descendant that is worse than the node must be a blame
// CANDIDATE, regardless of what else is in the tree. Under the old
// running-deficit rule a descendant visited after a harsher sibling
// contributed 0 and dropped out of the ranking entirely — which is how
// the blamed set changed run to run. The top-3 cut still applies; this
// asserts the candidate set, via the contribution ranking being stable
// across many runs with a contested cut.
func TestBlameCutIsStableAcrossRuns(t *testing.T) {
	g, inputs, root := blameFixture()
	seen := map[string]int{}
	for i := 0; i < 400; i++ {
		seen[blameOf(EvaluateTree(g, inputs, Options{}), root)]++
	}
	if len(seen) != 1 {
		t.Fatalf("blame cut produced %d distinct results across 400 runs: %v", len(seen), seen)
	}
}
