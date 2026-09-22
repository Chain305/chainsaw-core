package risk

import "testing"

// TestInstantBlockIDsAllHaveSummaries is the paired-map guard.
//
// instantBlockFrom looks the summary up by id and passes whatever it
// finds straight into instantBlock. A missing entry is not a compile
// error and not a panic — it is a quarantine whose Resolution.Summary is
// the empty string, i.e. a block with no stated reason. That is the same
// class of defect as the one sc.transitive_malware was added here to
// fix, so it gets a guard rather than a comment.
func TestInstantBlockIDsAllHaveSummaries(t *testing.T) {
	for _, id := range instantBlockIDs {
		summary, ok := instantBlockSummaries[id]
		if !ok {
			t.Errorf("instantBlockIDs contains %q with no instantBlockSummaries entry — it would block with an empty reason", id)
			continue
		}
		if summary == "" {
			t.Errorf("instantBlockSummaries[%q] is empty", id)
		}
	}
	if len(instantBlockSummaries) != len(instantBlockIDs) {
		t.Errorf("instantBlockSummaries has %d entries for %d ids — an unused summary means an id was removed and its reason left behind",
			len(instantBlockSummaries), len(instantBlockIDs))
	}
}

// TestInstantBlockIDsCoverEverySentinel pins the membership rule.
//
// The registry expresses "no other evidence can change this" as
// Weight: -1000 + NotTunable. sc.transitive_malware carried that and was
// not listed, so a malicious descendant went through the additive path
// and its signal never reached the report. Anything that gains the
// sentinel from here on must be listed too, or this fails.
func TestInstantBlockIDsCoverEverySentinel(t *testing.T) {
	listed := make(map[string]bool, len(instantBlockIDs))
	for _, id := range instantBlockIDs {
		listed[id] = true
	}
	for _, sig := range AllSignals() {
		if sig.Weight != -1000 {
			continue
		}
		if !listed[sig.ID] {
			t.Errorf("signal %q carries the -1000 sentinel weight but is not in instantBlockIDs; it will be scored additively instead of ending the evaluation", sig.ID)
		}
	}
	for id := range listed {
		if !sentinelWeighted(t, id) {
			t.Errorf("instantBlockIDs lists %q, which does not carry the -1000 sentinel weight", id)
		}
	}
}

func sentinelWeighted(t *testing.T, id string) bool {
	t.Helper()
	for _, sig := range AllSignals() {
		if sig.ID == id {
			return sig.Weight == -1000
		}
	}
	t.Errorf("instantBlockIDs lists %q, which is not a registered signal", id)
	return false
}

// TestTransitiveMalwareEndsTheEvaluationWithItsReason is the behavioural
// half: the four prod reports that prompted this carried malwareCount=1
// and quarantine and did NOT contain the signal.
func TestTransitiveMalwareEndsTheEvaluationWithItsReason(t *testing.T) {
	in := Input{
		Ecosystem:              "npm",
		Package:                "example",
		Version:                "1.0.0",
		TransitiveMalwareCount: 1,
	}
	ev := EvaluatePackage(in, Options{})
	if ev.Verdict != VerdictQuarantine {
		t.Fatalf("verdict = %v, want quarantine", ev.Verdict)
	}
	if ev.Resolution.Summary == "" {
		t.Fatalf("quarantine with an empty summary — the block has no stated reason")
	}

	var found bool
	for _, cat := range ev.RolledUp.Categories {
		for _, f := range cat.FiredSignals {
			if f.ID == SignalSCTransitiveMalware {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("%s did not reach the evaluation's fired set; the verdict is right and the reason is absent", SignalSCTransitiveMalware)
	}
}

// TestTransitiveMalwareIsNotFabricatedWhenCountIsZero — the sentinel must
// stay inert on the unavailable path, where risk_projection deliberately
// carries only two facts and every transitive count is zero.
func TestTransitiveMalwareIsNotFabricatedWhenCountIsZero(t *testing.T) {
	in := Input{
		Ecosystem:          "npm",
		Package:            "example",
		Version:            "1.0.0",
		SignalsUnavailable: true,
	}
	ev := EvaluatePackage(in, Options{})
	if ev.Verdict == VerdictQuarantine {
		t.Fatalf("an Input with no transitive facts must not instant-block; got quarantine (%q)", ev.Resolution.Summary)
	}
}
