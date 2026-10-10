package risk

import (
	"testing"
	"time"
)

// TestProvenanceDowngrade: fires on two attested predecessors, not on one;
// alone it warns and never blocks; on an established package it suspends the
// damper, so an archived repo keeps its full weight beside it.
func TestProvenanceDowngrade(t *testing.T) {
	opts := Options{Now: func() time.Time { return dampNow }}
	in := archivedInput(2_000_000)
	in.RepoLinkStatus = ""

	in.ProvenanceDowngradeFrom, in.ProvenanceDowngradePriorCount = "21.4.1", 1
	if _, ok := findFired(EvaluatePackage(in, opts), SignalSCProvenanceDowngrade); ok {
		t.Fatal("fired on one attested predecessor; needs ProvenanceDowngradeMinPrior")
	}

	in.ProvenanceDowngradePriorCount = 2
	ev := EvaluatePackage(in, opts)
	if _, ok := findFired(ev, SignalSCProvenanceDowngrade); !ok {
		t.Fatal("did not fire on two attested predecessors")
	}
	if ev.Verdict != VerdictWarn {
		t.Fatalf("alone: verdict %q (overall %d), want warn", ev.Verdict, ev.DirectScore.Overall)
	}

	in.RepoLinkStatus = "archived"
	f, ok := findFired(EvaluatePackage(in, opts), SignalSCRepoArchived)
	if !ok || f.Evidence["damped"] == true || f.Weight != Registry[SignalSCRepoArchived].Weight {
		t.Fatalf("established package with a provenance downgrade: archived-repo finding damped (%+v)", f)
	}
}
