package risk

import (
	"testing"

	"github.com/chain305/chainsaw-core/depgraph"
)

// EvaluateTree re-derives EVERY node from its risk.Input. Before
// Options.PerNodeSafeUpgrade existed it did so with whatever single
// SafeUpgradeVersion the caller passed — in production, none — so a
// DESCENDANT that had legitimately earned upgrade_available in its own
// scan was re-evaluated as bare quarantine inside a parent's tree. It
// then stayed in computeTransitiveSeverity's blockedNodes set and the
// parent reported it as an unfixable blocked dependency.
//
// These tests pin the per-node decision: each node is judged on its OWN
// evidence and its OWN signals, and a candidate is never a decision.

// fixableCriticalInput fires vuln.cvss_critical (SevCritical, MaxImpact
// 30) plus the positive vuln.fix_available. The ceiling pins overall at
// exactly 30 — band 2 with a critical signal, which resolveVerdict
// answers with quarantine, and which UpgradePromotionEligible accepts
// because the deficit is entirely vulnerability-category.
func fixableCriticalInput(k depgraph.Key) Input {
	in := cleanInput(k)
	in.IsVulnerable = true
	in.MaxCVSS = 9.8
	in.FixAvailable = true
	in.CVEs = []string{"CVE-2024-9999"}
	return in
}

// fixableHighInput fires vuln.cvss_high (MaxImpact 40) plus
// vuln.fix_available — overall 40, verdict warn, promotable. Used where a
// test needs headroom above the band-1 cutoff so a descendant can push it
// through.
func fixableHighInput(k depgraph.Key) Input {
	in := cleanInput(k)
	in.IsVulnerable = true
	in.MaxCVSS = 7.5
	in.FixAvailable = true
	in.CVEs = []string{"CVE-2024-8888"}
	return in
}

// kevInput fires vuln.kev, whose MaxImpact of 20 pins the node into
// band 1 by construction. Gate (c) refuses band 1, so a KEV node can
// never be promoted no matter how much fix evidence exists.
func kevInput(k depgraph.Key) Input {
	in := fixableCriticalInput(k)
	in.KnownExploited = true
	return in
}

// chainGraph builds root → child, both prod.
func chainGraph(root, child depgraph.Key) *depgraph.Graph {
	g := depgraph.NewGraph()
	g.AddNode(root, true, true)
	g.AddNode(child, false, true)
	g.AddEdge(root, child)
	g.AddRoot(root)
	return g
}

// blockedDescendants mirrors what
// intelligence.computeTransitiveSeverity counts: descendants whose
// FINAL tree verdict is quarantine or replace.
func blockedDescendants(te *TreeEvaluation, root depgraph.Key) []depgraph.Key {
	var out []depgraph.Key
	for k, ev := range te.ByKey {
		if k == root || ev == nil {
			continue
		}
		if ev.Verdict == VerdictQuarantine || ev.Verdict == VerdictReplace {
			out = append(out, k)
		}
	}
	return out
}

// (1) A descendant with a proven safe upgrade promotes on its own
// evidence, and leaves the blocked set.
func TestEvaluateTree_DescendantWithKnownFixPromotes(t *testing.T) {
	root, child := dk("app", "1.0.0"), dk("lib", "1.0.0")
	g := chainGraph(root, child)
	inputs := map[depgraph.Key]Input{
		root:  cleanInput(root),
		child: fixableCriticalInput(child),
	}

	// Baseline: today's behaviour, no per-node evidence.
	base := EvaluateTree(g, inputs, Options{})
	if got := base.ByKey[child].Verdict; got != VerdictQuarantine {
		t.Fatalf("precondition: child verdict = %q, want quarantine without evidence", got)
	}
	if n := len(blockedDescendants(base, root)); n != 1 {
		t.Fatalf("precondition: blocked descendants = %d, want 1", n)
	}

	te := EvaluateTree(g, inputs, Options{
		PerNodeSafeUpgrade: map[depgraph.Key]string{child: "2.0.0"},
	})
	ce := te.ByKey[child]
	if ce == nil {
		t.Fatal("no evaluation for the child")
	}
	if ce.Verdict != VerdictUpgradeAvailable {
		t.Fatalf("child verdict = %q, want upgrade_available — a descendant's own "+
			"advisory fix data must survive the tree pass", ce.Verdict)
	}
	if ce.Resolution.SafeVersion != "2.0.0" {
		t.Errorf("child SafeVersion = %q, want 2.0.0", ce.Resolution.SafeVersion)
	}
	if blocked := blockedDescendants(te, root); len(blocked) != 0 {
		t.Errorf("child still counted as a blocked dependency: %v — the parent's "+
			"\"N blocked dependencies\" number is the user-visible consequence", blocked)
	}
	// Promotion moves the verdict and nothing else.
	if ce.DirectScore.Overall != base.ByKey[child].DirectScore.Overall {
		t.Errorf("child DirectScore moved: %d -> %d",
			base.ByKey[child].DirectScore.Overall, ce.DirectScore.Overall)
	}
	if ce.RolledUp.Overall != base.ByKey[child].RolledUp.Overall {
		t.Errorf("child RolledUp moved: %d -> %d",
			base.ByKey[child].RolledUp.Overall, ce.RolledUp.Overall)
	}
	// The root's own numbers are untouched — promotion is a verdict
	// change, not a score change, at every level.
	if te.ByKey[root].RolledUp.Overall != base.ByKey[root].RolledUp.Overall {
		t.Errorf("root RolledUp moved: %d -> %d",
			base.ByKey[root].RolledUp.Overall, te.ByKey[root].RolledUp.Overall)
	}
}

// (2) A malware-flagged descendant must NOT promote, whatever evidence
// the caller supplies and however clean its parent is. sc.known_malicious
// is a vetoed category in UpgradePromotionEligible.
func TestEvaluateTree_MaliciousDescendantNeverPromotes(t *testing.T) {
	root, child := dk("app", "1.0.0"), dk("evil", "1.0.0")
	g := chainGraph(root, child)

	te := EvaluateTree(g, map[depgraph.Key]Input{
		root:  cleanInput(root),
		child: maliciousInput(child),
	}, Options{
		PerNodeSafeUpgrade: map[depgraph.Key]string{child: "2.0.0"},
	})

	ce := te.ByKey[child]
	if ce.Verdict == VerdictUpgradeAvailable {
		t.Fatalf("malicious descendant promoted to %q — a newer release of a "+
			"malicious package is still malicious", ce.Verdict)
	}
	if ce.Resolution.SafeVersion != "" {
		t.Errorf("malicious descendant advertises SafeVersion %q", ce.Resolution.SafeVersion)
	}
	if blocked := blockedDescendants(te, root); len(blocked) != 1 {
		t.Errorf("blocked descendants = %v, want the malicious child still blocking", blocked)
	}
	// And it still drags the parent.
	if te.ByKey[root].RolledUp.Overall >= te.ByKey[root].DirectScore.Overall {
		t.Errorf("malicious child stopped dragging the parent: RolledUp %d, Direct %d",
			te.ByKey[root].RolledUp.Overall, te.ByKey[root].DirectScore.Overall)
	}
}

// (3) A KEV descendant never promotes. vuln.kev carries MaxImpact 20, so
// the node is structurally pinned to band 1 and gate (c) refuses it. Note
// that EvaluatePackage WOULD answer upgrade_available if the safe version
// were handed to it directly — the gate, not the evaluator, is what makes
// this hold.
func TestEvaluateTree_KEVDescendantNeverPromotes(t *testing.T) {
	root, child := dk("app", "1.0.0"), dk("exploited", "1.0.0")
	g := chainGraph(root, child)
	in := kevInput(child)

	// Prove the evaluator alone is not the safeguard.
	if unguarded := EvaluatePackage(in, Options{SafeUpgradeVersion: "2.0.0"}); unguarded.Verdict != VerdictUpgradeAvailable {
		t.Fatalf("precondition changed: bare EvaluatePackage no longer promotes KEV (got %q); "+
			"re-derive what this test is proving", unguarded.Verdict)
	}

	te := EvaluateTree(g, map[depgraph.Key]Input{
		root:  cleanInput(root),
		child: in,
	}, Options{
		PerNodeSafeUpgrade: map[depgraph.Key]string{child: "2.0.0"},
	})

	ce := te.ByKey[child]
	if ce.Verdict != VerdictQuarantine {
		t.Fatalf("KEV descendant verdict = %q, want quarantine — MaxImpact 20 pins "+
			"known-exploited packages to band 1 and band 1 never becomes \"just upgrade\"",
			ce.Verdict)
	}
	if blocked := blockedDescendants(te, root); len(blocked) != 1 {
		t.Errorf("blocked descendants = %v, want the KEV child still blocking", blocked)
	}
}

// (4) The root is not special-cased INSIDE the tree pass, but the map is
// per-node: an entry for one node must never leak onto another. Two
// siblings with identical inputs, evidence supplied for only one.
func TestEvaluateTree_PerNodeEvidenceDoesNotLeak(t *testing.T) {
	root := dk("app", "1.0.0")
	fixed, unfixed := dk("fixed", "1.0.0"), dk("unfixed", "1.0.0")
	g := depgraph.NewGraph()
	g.AddNode(root, true, true)
	g.AddNode(fixed, false, true)
	g.AddNode(unfixed, false, true)
	g.AddEdge(root, fixed)
	g.AddEdge(root, unfixed)
	g.AddRoot(root)

	te := EvaluateTree(g, map[depgraph.Key]Input{
		root:    cleanInput(root),
		fixed:   fixableCriticalInput(fixed),
		unfixed: fixableCriticalInput(unfixed),
	}, Options{
		PerNodeSafeUpgrade: map[depgraph.Key]string{fixed: "2.0.0"},
	})

	if got := te.ByKey[fixed].Verdict; got != VerdictUpgradeAvailable {
		t.Errorf("node with evidence: verdict = %q, want upgrade_available", got)
	}
	if got := te.ByKey[unfixed].Verdict; got != VerdictQuarantine {
		t.Errorf("node WITHOUT evidence: verdict = %q, want quarantine — one "+
			"package's safe version is not another package's", got)
	}
	if got := te.ByKey[unfixed].Resolution.SafeVersion; got != "" {
		t.Errorf("node without evidence advertises SafeVersion %q", got)
	}
	if blocked := blockedDescendants(te, root); len(blocked) != 1 {
		t.Errorf("blocked descendants = %v, want exactly the unfixed sibling", blocked)
	}
}

// (5) The promotion runs AFTER the rollup pass, so it is judged on the
// node's final state and it must carry the tree-owned fields across. A
// re-evaluation of a single node cannot reproduce RolledUp or
// TransitiveBlame — those are the tree pass's answers, and losing them
// would trade one wrong number for another.
//
// (The RolledUp arm of gate (c) is currently unreachable in practice:
// TransitiveDecayBase 0.6 floors a one-hop rollup at 40, so no descendant
// can push an eligible node below ThresholdQuarantine. The arm stays in
// UpgradePromotionEligible because the decay constant is a tunable, and
// this ordering is what makes it bite the day it changes.)
func TestEvaluateTree_PromotedNodeKeepsTreeOwnedFields(t *testing.T) {
	root, mid, leaf := dk("app", "1.0.0"), dk("mid", "1.0.0"), dk("evil", "1.0.0")
	g := depgraph.NewGraph()
	g.AddNode(root, true, true)
	g.AddNode(mid, false, true)
	g.AddNode(leaf, false, true)
	g.AddEdge(root, mid)
	g.AddEdge(mid, leaf)
	g.AddRoot(root)

	inputs := map[depgraph.Key]Input{
		root: cleanInput(root),
		mid:  fixableHighInput(mid),
		leaf: maliciousInput(leaf),
	}
	base := EvaluateTree(g, inputs, Options{})
	if len(base.ByKey[mid].Resolution.TransitiveBlame) == 0 {
		t.Fatal("precondition: mid should blame its malicious leaf")
	}

	te := EvaluateTree(g, inputs, Options{
		PerNodeSafeUpgrade: map[depgraph.Key]string{mid: "2.0.0"},
	})
	me := te.ByKey[mid]
	if me.Verdict != VerdictUpgradeAvailable {
		t.Fatalf("mid verdict = %q, want upgrade_available", me.Verdict)
	}
	if me.RolledUp.Overall != base.ByKey[mid].RolledUp.Overall {
		t.Errorf("promoted mid lost the tree's RolledUp: %d, want %d",
			me.RolledUp.Overall, base.ByKey[mid].RolledUp.Overall)
	}
	if len(me.Resolution.TransitiveBlame) != len(base.ByKey[mid].Resolution.TransitiveBlame) {
		t.Errorf("promoted mid lost TransitiveBlame: %#v", me.Resolution.TransitiveBlame)
	}
	// The malicious leaf is still blocked and still blames upward.
	if te.ByKey[leaf].Verdict != VerdictQuarantine {
		t.Errorf("leaf verdict = %q, want quarantine", te.ByKey[leaf].Verdict)
	}
}

// (6) A nil / empty PerNodeSafeUpgrade must reproduce pre-existing
// behaviour byte-for-byte. Every existing caller passes nothing.
func TestEvaluateTree_NoPerNodeEvidenceIsUnchanged(t *testing.T) {
	root, child := dk("app", "1.0.0"), dk("lib", "1.0.0")
	g := chainGraph(root, child)
	inputs := map[depgraph.Key]Input{
		root:  cleanInput(root),
		child: fixableCriticalInput(child),
	}

	bare := EvaluateTree(g, inputs, Options{})
	empty := EvaluateTree(g, inputs, Options{PerNodeSafeUpgrade: map[depgraph.Key]string{}})

	for _, k := range []depgraph.Key{root, child} {
		if bare.ByKey[k].Verdict != empty.ByKey[k].Verdict {
			t.Errorf("%v verdict diverged with an empty map: %q vs %q",
				k, bare.ByKey[k].Verdict, empty.ByKey[k].Verdict)
		}
		if bare.ByKey[k].RolledUp.Overall != empty.ByKey[k].RolledUp.Overall {
			t.Errorf("%v RolledUp diverged with an empty map: %d vs %d",
				k, bare.ByKey[k].RolledUp.Overall, empty.ByKey[k].RolledUp.Overall)
		}
	}
}
