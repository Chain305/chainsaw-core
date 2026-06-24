package risk

import (
	"testing"

	"github.com/chain305/chainsaw-core/depgraph"
)

func dk(name, v string) depgraph.Key {
	return depgraph.Key{Ecosystem: "npm", Name: name, Version: v}
}

// cleanInput returns an Input that fires no negative signals — its
// DirectScore.Overall is 100.
func cleanInput(k depgraph.Key) Input {
	return Input{Ecosystem: k.Ecosystem, Package: k.Name, Version: k.Version}
}

// maliciousInput forces a short-circuit instant-block via the
// known-malicious signal.
func maliciousInput(k depgraph.Key) Input {
	in := cleanInput(k)
	in.IsKnownMalicious = true
	in.MalwareID = "OSV-MAL-TEST"
	return in
}

func TestEvaluateTree_EmptyGraph(t *testing.T) {
	te := EvaluateTree(depgraph.NewGraph(), nil, Options{})
	if te.Summary.TotalNodes != 0 {
		t.Errorf("expected 0 nodes, got %d", te.Summary.TotalNodes)
	}
	if te.Summary.MinOverall != 100 {
		t.Errorf("expected MinOverall 100 for empty graph, got %d", te.Summary.MinOverall)
	}
}

func TestEvaluateTree_Chain_MaliciousLeafBlamesRoot(t *testing.T) {
	// A → B → C where C is malicious. A's rolled-up score should drop
	// and TransitiveBlame should include C.
	g := depgraph.NewGraph()
	a, b, c := dk("a", "1"), dk("b", "1"), dk("c", "1")
	g.AddNode(a, true, true)
	g.AddNode(b, false, true)
	g.AddNode(c, false, true)
	g.AddEdge(a, b)
	g.AddEdge(b, c)
	g.AddRoot(a)

	inputs := map[depgraph.Key]Input{
		a: cleanInput(a),
		b: cleanInput(b),
		c: maliciousInput(c),
	}
	te := EvaluateTree(g, inputs, Options{})

	aEval := te.ByKey[a]
	if aEval == nil {
		t.Fatalf("no eval for A")
	}
	// The "clean" input may still accrue small maintenance/quality
	// deficits (no repo link, etc) — we only care that RolledUp is
	// meaningfully below DirectScore thanks to the malicious leaf.
	if aEval.DirectScore.Overall-aEval.RolledUp.Overall < 5 {
		t.Errorf("rolled-up should be dragged down by >5 points: direct=%d rolled=%d",
			aEval.DirectScore.Overall, aEval.RolledUp.Overall)
	}
	foundC := false
	for _, k := range aEval.Resolution.TransitiveBlame {
		if k.Package == "c" {
			foundC = true
		}
	}
	if !foundC {
		t.Errorf("A.TransitiveBlame missing C: %+v", aEval.Resolution.TransitiveBlame)
	}
}

func TestEvaluateTree_DevOnlyDescendantReducedImpact(t *testing.T) {
	// A → B where B is malicious. Compare prod-B vs dev-B.
	build := func(prod bool) *depgraph.Graph {
		g := depgraph.NewGraph()
		a, b := dk("a", "1"), dk("b", "1")
		g.AddNode(a, true, true)
		g.AddNode(b, false, prod)
		g.AddEdge(a, b)
		g.AddRoot(a)
		return g
	}
	runFor := func(prod bool) int {
		g := build(prod)
		b := dk("b", "1")
		inputs := map[depgraph.Key]Input{
			dk("a", "1"): cleanInput(dk("a", "1")),
			b:            maliciousInput(b),
		}
		te := EvaluateTree(g, inputs, Options{})
		return te.ByKey[dk("a", "1")].RolledUp.Overall
	}
	prodOverall := runFor(true)
	devOverall := runFor(false)
	if devOverall <= prodOverall {
		t.Errorf("dev descendant should hurt less (higher overall): prod=%d dev=%d", prodOverall, devOverall)
	}
}

func TestEvaluateTree_CycleTerminates(t *testing.T) {
	g := depgraph.NewGraph()
	a, b := dk("a", "1"), dk("b", "1")
	g.AddNode(a, true, true)
	g.AddNode(b, false, true)
	g.AddEdge(a, b)
	g.AddEdge(b, a) // cycle
	g.AddRoot(a)

	inputs := map[depgraph.Key]Input{
		a: cleanInput(a),
		b: maliciousInput(b),
	}
	// If this hangs, the cycle guard is broken.
	te := EvaluateTree(g, inputs, Options{})
	if te.ByKey[a] == nil || te.ByKey[b] == nil {
		t.Fatalf("missing evals")
	}
}

func TestEvaluateTree_OrphanEqualsDirect(t *testing.T) {
	g := depgraph.NewGraph()
	a := dk("a", "1")
	g.AddNode(a, true, true)
	g.AddRoot(a)

	in := cleanInput(a)
	in.IsVulnerable = true
	in.MaxCVSS = 8.0
	te := EvaluateTree(g, map[depgraph.Key]Input{a: in}, Options{})

	aEval := te.ByKey[a]
	if aEval.RolledUp.Overall != aEval.DirectScore.Overall {
		t.Errorf("orphan RolledUp (%d) should equal DirectScore (%d)",
			aEval.RolledUp.Overall, aEval.DirectScore.Overall)
	}
}

func TestEvaluateTree_MultiRoot_Independent(t *testing.T) {
	g := depgraph.NewGraph()
	r1, r2, bad := dk("r1", "1"), dk("r2", "1"), dk("bad", "1")
	g.AddNode(r1, true, true)
	g.AddNode(r2, true, true)
	g.AddNode(bad, false, true)
	g.AddEdge(r1, bad) // only r1 depends on bad
	g.AddRoot(r1)
	g.AddRoot(r2)

	inputs := map[depgraph.Key]Input{
		r1:  cleanInput(r1),
		r2:  cleanInput(r2),
		bad: maliciousInput(bad),
	}
	te := EvaluateTree(g, inputs, Options{})

	if te.ByKey[r1].RolledUp.Overall >= 100 {
		t.Errorf("r1 should be dragged down; got %d", te.ByKey[r1].RolledUp.Overall)
	}
	// r2 has no bad descendants; its RolledUp should equal DirectScore
	// regardless of the baseline clean score.
	if te.ByKey[r2].RolledUp.Overall != te.ByKey[r2].DirectScore.Overall {
		t.Errorf("r2 should have RolledUp==Direct; got rolled=%d direct=%d",
			te.ByKey[r2].RolledUp.Overall, te.ByKey[r2].DirectScore.Overall)
	}
	if len(te.Roots) != 2 {
		t.Errorf("expected 2 roots, got %d", len(te.Roots))
	}
}

func TestEvaluateTree_Summary(t *testing.T) {
	g := depgraph.NewGraph()
	a, b := dk("a", "1"), dk("b", "1")
	g.AddNode(a, true, true)
	g.AddNode(b, false, true)
	g.AddEdge(a, b)
	g.AddRoot(a)

	inputs := map[depgraph.Key]Input{a: cleanInput(a), b: cleanInput(b)}
	te := EvaluateTree(g, inputs, Options{})
	if te.Summary.TotalNodes != 2 {
		t.Errorf("TotalNodes=%d, want 2", te.Summary.TotalNodes)
	}
	if te.Summary.DirectCount != 1 {
		t.Errorf("DirectCount=%d, want 1", te.Summary.DirectCount)
	}
	if te.Summary.TransitiveCount != 1 {
		t.Errorf("TransitiveCount=%d, want 1", te.Summary.TransitiveCount)
	}
	if total := te.Summary.ByVerdict[VerdictAllow] + te.Summary.ByVerdict[VerdictWarn]; total != 2 {
		t.Errorf("expected 2 verdicts counted across allow/warn, got %d (%v)",
			total, te.Summary.ByVerdict)
	}
}
