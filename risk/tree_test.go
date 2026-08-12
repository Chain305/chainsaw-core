package risk

import (
	"strings"
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

// unavailableInput is the "we could not fetch the facts" Input — the
// distinction this suite exists to protect.
func unavailableInput(k depgraph.Key) Input {
	in := cleanInput(k)
	in.SignalsUnavailable = true
	in.UnavailableReason = "provider unavailable"
	return in
}

// TestEvaluatePackage_Unavailable_IsNotAllow is the unit-level statement of
// the fix: an Input whose facts were never obtained must not be scored like
// a package that was checked and found clean.
func TestEvaluatePackage_Unavailable_IsNotAllow(t *testing.T) {
	clean := EvaluatePackage(cleanInput(dk("a", "1")), Options{})
	if clean.Verdict != VerdictAllow {
		t.Fatalf("baseline broken: clean input → verdict %q, want allow", clean.Verdict)
	}

	ev := EvaluatePackage(unavailableInput(dk("a", "1")), Options{})
	if ev.Verdict == VerdictAllow {
		t.Error("unavailable input scored VerdictAllow — an outage must not read as clean")
	}
	if ev.Verdict != VerdictUnknown {
		t.Errorf("verdict = %q, want %q", ev.Verdict, VerdictUnknown)
	}
	for _, cat := range AllCategories() {
		if cs, ok := ev.DirectScore.Categories[cat]; !ok || cs.DataAvailable {
			t.Errorf("category %q reports DataAvailable=%v, want false", cat, cs.DataAvailable)
		}
	}
	if !strings.Contains(ev.Resolution.Summary, "provider unavailable") {
		t.Errorf("resolution summary drops the reason: %q", ev.Resolution.Summary)
	}
	if ev.Key.Package != "a" {
		t.Errorf("identity lost: key = %+v", ev.Key)
	}
}

// TestEvaluateTree_UnavailableNode_CountedNotScored asserts the tree
// treats an unevaluated node as a counted non-answer: it does not join the
// allow bucket and it does not drag MinOverall to zero.
func TestEvaluateTree_UnavailableNode_CountedNotScored(t *testing.T) {
	g := depgraph.NewGraph()
	a, b := dk("a", "1"), dk("b", "1")
	g.AddNode(a, true, true)
	g.AddNode(b, false, true)
	g.AddEdge(a, b)
	g.AddRoot(a)

	te := EvaluateTree(g, map[depgraph.Key]Input{
		a: cleanInput(a),
		b: unavailableInput(b),
	}, Options{})

	if te.Summary.UnknownCount != 1 {
		t.Errorf("UnknownCount = %d, want 1", te.Summary.UnknownCount)
	}
	if te.Summary.ByVerdict[VerdictUnknown] != 1 {
		t.Errorf("ByVerdict[unknown] = %d, want 1", te.Summary.ByVerdict[VerdictUnknown])
	}
	if te.Summary.ByVerdict[VerdictAllow] != 1 {
		t.Errorf("ByVerdict[allow] = %d, want 1 (only A was evaluated)", te.Summary.ByVerdict[VerdictAllow])
	}
	// MinOverall must reflect A alone — the unevaluated node's Overall=0
	// means "no score" and must not be mistaken for the tree's worst.
	wantMin := te.ByKey[a].RolledUp.Overall
	if te.Summary.MinOverall != wantMin {
		t.Errorf("MinOverall = %d, want %d; an unevaluated node's 0 must not be read as a score",
			te.Summary.MinOverall, wantMin)
	}
}

// TestEvaluateTree_UnavailableDescendant_DoesNotQuarantineAncestors is the
// other half of the doctrine: on a QUERY surface, "could not evaluate" is
// reported, not enforced. An unevaluated child must not crater its parent
// into a block — that would turn a backend outage into a tree-wide refusal.
func TestEvaluateTree_UnavailableDescendant_DoesNotQuarantineAncestors(t *testing.T) {
	g := depgraph.NewGraph()
	a, b := dk("a", "1"), dk("b", "1")
	g.AddNode(a, true, true)
	g.AddNode(b, false, true)
	g.AddEdge(a, b)
	g.AddRoot(a)

	te := EvaluateTree(g, map[depgraph.Key]Input{
		a: cleanInput(a),
		b: unavailableInput(b),
	}, Options{})

	aEval := te.ByKey[a]
	if aEval == nil {
		t.Fatal("no eval for A")
	}
	if aEval.Verdict != VerdictAllow {
		t.Errorf("A verdict = %q, want allow — A's own signals were evaluated and are clean", aEval.Verdict)
	}
	if aEval.RolledUp.Overall != aEval.DirectScore.Overall {
		t.Errorf("A RolledUp.Overall = %d but DirectScore.Overall = %d — an unevaluated child is not evidence of risk",
			aEval.RolledUp.Overall, aEval.DirectScore.Overall)
	}
	if len(aEval.Resolution.TransitiveBlame) != 0 {
		t.Errorf("A blames %v for a child that was never evaluated", aEval.Resolution.TransitiveBlame)
	}

	// And a genuinely malicious child still blames the parent — the skip
	// above must not have disabled rollup generally.
	g2 := depgraph.NewGraph()
	g2.AddNode(a, true, true)
	g2.AddNode(b, false, true)
	g2.AddEdge(a, b)
	g2.AddRoot(a)
	te2 := EvaluateTree(g2, map[depgraph.Key]Input{a: cleanInput(a), b: maliciousInput(b)}, Options{})
	if te2.ByKey[a].RolledUp.Overall >= te2.ByKey[a].DirectScore.Overall {
		t.Errorf("malicious child no longer drags the parent: RolledUp = %d, DirectScore = %d",
			te2.ByKey[a].RolledUp.Overall, te2.ByKey[a].DirectScore.Overall)
	}
}
