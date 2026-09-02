package intelligence

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"testing"
	"time"
)

// P8-71: a sticky fact must bind the VERDICT, not just the display.
//
// Before this wave the sticky carry-forward lived only inside
// mergeReportPayload, which runs in Store.Upsert — after
// ComputeTrustScoreForOrg has already run the real risk evaluation on the
// in-flight report. So the persisted `report` column and the persisted
// `risk_evaluation` column were snapshots of two different sets of facts.
// Measured on prod at epoch 12: 298 rows carried a supply-chain fact the
// evaluation next to it had never seen, and ZERO the other way round.
//
// Every test below drives the REAL evaluator through
// ComputeTrustScoreForOrg — none of them calls a signal's Fires closure
// directly, because the defect was never in a Fires closure. It was in
// which facts reached it.

// firedSignalIDs returns every signal ID in an evaluation's rolled-up
// categories, so a test can assert on what the evaluator actually saw.
func firedSignalIDs(t *testing.T, r *Report) map[string]bool {
	t.Helper()
	if r.Risk == nil {
		t.Fatal("report has no Risk evaluation; ComputeTrustScoreForOrg did not run")
	}
	out := map[string]bool{}
	for _, cat := range r.Risk.RolledUp.Categories {
		for _, s := range cat.FiredSignals {
			out[s.ID] = true
		}
	}
	return out
}

// scanOrder reproduces the production sequence for one coordinate:
// the fan-out builds `next`, the sticky facts are revived from the prior
// row, the evaluation runs, and only then is the row merged and persisted.
// It returns the report as EVALUATED and the report as PERSISTED — the two
// things P8-71 found disagreeing.
func scanOrder(t *testing.T, prior, next *Report) (evaluated *Report, persisted Report) {
	t.Helper()
	priorBytes, err := json.Marshal(prior)
	if err != nil {
		t.Fatal(err)
	}
	applyStickySupplyChain(next, prior)
	ComputeTrustScoreForOrg(next, "")
	merged, err := mergeReportPayload(priorBytes, next)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(merged, &persisted); err != nil {
		t.Fatal(err)
	}
	return next, persisted
}

func npmReport(v string) *Report {
	return &Report{Identity: IdentitySection{Ecosystem: "npm", Package: "p", Version: v}}
}

// TestStickyPublisherChangedBindsTheVerdict is the publisherChanged half of
// P8-71: 28 prod rows said publisherChanged=true with no publisher signal
// anywhere in the evaluation stored beside them.
func TestStickyPublisherChangedBindsTheVerdict(t *testing.T) {
	prior := npmReport("1")
	prior.SupplyChain.PublisherChanged = boolp(true)

	// The defect, reproduced: evaluate the in-flight report as it arrives
	// from a Tier-1-only refresh, with the revival happening afterwards.
	unfixed := npmReport("1")
	ComputeTrustScoreForOrg(unfixed, "")
	if firedSignalIDs(t, unfixed)["sc.publisher_changed"] {
		t.Fatal("vacuous: the signal fired without the sticky fact being carried")
	}

	evaluated, persisted := scanOrder(t, prior, npmReport("1"))

	if !firedSignalIDs(t, evaluated)["sc.publisher_changed"] {
		t.Error("sc.publisher_changed did not fire after the sticky carry-forward.\n" +
			"That is P8-71: the fact is revived for the report and discarded for the verdict.")
	}
	if persisted.SupplyChain.PublisherChanged == nil || !*persisted.SupplyChain.PublisherChanged {
		t.Fatal("persisted report lost publisherChanged")
	}
	// The invariant, stated directly: what the row SAYS and what the row's
	// verdict SAW are the same fact.
	if deref(persisted.SupplyChain.PublisherChanged) != firedSignalIDs(t, evaluated)["sc.publisher_changed"] {
		t.Error("stored report and stored evaluation disagree about publisherChanged")
	}
}

// TestStickyVersionAnomalyBindsTheVerdict is the larger half: 180 prod rows.
//
// It also pins the pair-carry. qual.version_anomaly fires on
// VersionAnomalyFlags, never on the bool, so carrying the bool alone leaves
// the fact unable to bind anything — which is exactly the state 161 of
// those 180 rows are in.
func TestStickyVersionAnomalyBindsTheVerdict(t *testing.T) {
	prior := npmReport("1")
	prior.SupplyChain.VersionAnomaly = boolp(true)
	prior.SupplyChain.VersionAnomalyFlags = []string{"semver_regression"}

	unfixed := npmReport("1")
	ComputeTrustScoreForOrg(unfixed, "")
	if firedSignalIDs(t, unfixed)["qual.version_anomaly"] {
		t.Fatal("vacuous: the signal fired without the sticky fact being carried")
	}

	evaluated, persisted := scanOrder(t, prior, npmReport("1"))

	if !firedSignalIDs(t, evaluated)["qual.version_anomaly"] {
		t.Error("qual.version_anomaly did not fire after the sticky carry-forward.\n" +
			"If only the bool was carried, the flags — which are what the signal " +
			"actually reads — were left behind and the fact still binds nothing.")
	}
	if len(persisted.SupplyChain.VersionAnomalyFlags) == 0 {
		t.Error("persisted report kept versionAnomaly=true with no flags: " +
			"the fact was revived without its evidence")
	}
}

// TestStickyRepoLinkStatusBindsTheVerdict covers the third and least
// obvious slice of the class — 83 prod rows, mostly repoLinkStatus=archived
// with no sc.repo_archived in the evaluation. It is here because P8-71 was
// filed about two *bool fields and the generalised fix has to cover the
// string fields in the same block.
func TestStickyRepoLinkStatusBindsTheVerdict(t *testing.T) {
	prior := npmReport("1")
	prior.SupplyChain.RepoLinkStatus = "archived"

	evaluated, persisted := scanOrder(t, prior, npmReport("1"))

	if !firedSignalIDs(t, evaluated)["sc.repo_archived"] {
		t.Error("sc.repo_archived did not fire after the sticky carry-forward")
	}
	if persisted.SupplyChain.RepoLinkStatus != "archived" {
		t.Fatalf("persisted report lost repoLinkStatus: %q", persisted.SupplyChain.RepoLinkStatus)
	}
}

// TestStickyExplicitFalseStillClearsTheVerdict is the P8-35 guard at the
// VERDICT level. Sticky is ON SILENCE ONLY. An explicit incoming false is a
// real observation: it must clear the flag AND leave the signal dormant,
// and it must not drag stale evidence in behind it.
func TestStickyExplicitFalseStillClearsTheVerdict(t *testing.T) {
	prior := npmReport("1")
	prior.SupplyChain.PublisherChanged = boolp(true)
	prior.SupplyChain.VersionAnomaly = boolp(true)
	prior.SupplyChain.VersionAnomalyFlags = []string{"semver_regression"}

	next := npmReport("1")
	next.SupplyChain.PublisherChanged = boolp(false)
	next.SupplyChain.VersionAnomaly = boolp(false)

	evaluated, persisted := scanOrder(t, prior, next)

	fired := firedSignalIDs(t, evaluated)
	if fired["sc.publisher_changed"] {
		t.Error("an explicit incoming false left sc.publisher_changed firing.\n" +
			"Sticky is on SILENCE, never 'once true always true' — a package that " +
			"had one legitimate maintainer handover must have a path back to clean.")
	}
	if fired["qual.version_anomaly"] {
		t.Error("an explicit incoming versionAnomaly=false revived the prior FLAGS, " +
			"so the signal fired on a package the latest scan just cleared")
	}
	if persisted.SupplyChain.PublisherChanged == nil || *persisted.SupplyChain.PublisherChanged {
		t.Error("explicit false did not clear publisherChanged in the persisted row")
	}
	if len(persisted.SupplyChain.VersionAnomalyFlags) != 0 {
		t.Errorf("explicit false left stale flags on the persisted row: %v",
			persisted.SupplyChain.VersionAnomalyFlags)
	}
}

// TestApplyStickySupplyChainIsIdempotent is the proof that keeping BOTH
// call sites is safe.
//
// The pre-evaluation call (runFanout) and the persistence call
// (mergeReportPayload) both run against the same prior row. Every rule is
// guarded on the DESTINATION being empty, so the second application is a
// no-op — but "obviously" is not a proof, and the double-apply is the thing
// a reviewer will ask about first.
func TestApplyStickySupplyChainIsIdempotent(t *testing.T) {
	commit := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	prior := npmReport("1")
	prior.SupplyChain = SupplyChainSection{
		MalwareStatus:       "clean",
		TyposquatStatus:     "suspected",
		RepoLinkStatus:      "archived",
		RepoLastCommitAt:    &commit,
		PublisherChanged:    boolp(true),
		VersionAnomaly:      boolp(true),
		VersionAnomalyFlags: []string{"semver_regression", "timestamp_regression"},
	}

	once := npmReport("1")
	applyStickySupplyChain(once, prior)

	twice := npmReport("1")
	applyStickySupplyChain(twice, prior)
	applyStickySupplyChain(twice, prior)

	if !reflect.DeepEqual(once.SupplyChain, twice.SupplyChain) {
		t.Fatalf("not idempotent:\n once:  %+v\n twice: %+v", once.SupplyChain, twice.SupplyChain)
	}

	// And the production composition: pre-evaluation apply, then the store
	// applies it again on the way to the row. The persisted row must be
	// identical to the one the merge alone would have produced.
	priorBytes, err := json.Marshal(prior)
	if err != nil {
		t.Fatal(err)
	}
	mergeOf := func(next *Report) SupplyChainSection {
		out, err := mergeReportPayload(priorBytes, next)
		if err != nil {
			t.Fatal(err)
		}
		var got Report
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatal(err)
		}
		return got.SupplyChain
	}
	preStickied := npmReport("1")
	applyStickySupplyChain(preStickied, prior)
	if !reflect.DeepEqual(mergeOf(preStickied), mergeOf(npmReport("1"))) {
		t.Error("merging an already-stickied report differs from merging a raw one; " +
			"the two call sites are not composing cleanly")
	}

	// The prior must never be mutated, and the copies must not alias it —
	// otherwise a later write through the report would reach back into the
	// object the store handed us.
	if prior.SupplyChain.PublisherChanged == once.SupplyChain.PublisherChanged {
		t.Error("PublisherChanged aliases the prior's pointer")
	}
	if len(prior.SupplyChain.VersionAnomalyFlags) > 0 && len(once.SupplyChain.VersionAnomalyFlags) > 0 &&
		&prior.SupplyChain.VersionAnomalyFlags[0] == &once.SupplyChain.VersionAnomalyFlags[0] {
		t.Error("VersionAnomalyFlags aliases the prior's backing array")
	}
}

// TestStickySupplyChainIsTheOnlyCarryForward is the generality guard.
//
// The reason fix (b) was chosen over "re-evaluate after the merge" is that
// it makes the class impossible rather than patching two instances. That
// only holds while there is exactly ONE list of sticky SupplyChain fields.
// A new field added straight into mergeReportPayload would be revived for
// the row and invisible to the evaluator — P8-71, again, with a different
// field name.
func TestStickySupplyChainIsTheOnlyCarryForward(t *testing.T) {
	raw, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatalf("read store.go: %v", err)
	}
	src := string(raw)

	// Vacuity: if the call were renamed or removed, the scan below would
	// find nothing and pass having checked nothing.
	if !regexp.MustCompile(`applyStickySupplyChain\(&merged, &prior\)`).MatchString(src) {
		t.Fatal("mergeReportPayload no longer calls applyStickySupplyChain — " +
			"if this was renamed, update the guard; do not delete it")
	}

	// Any `merged.SupplyChain.X = prior.SupplyChain.X` is a carry-forward
	// that bypasses the shared function.
	stray := regexp.MustCompile(`merged\.SupplyChain\.\w+\s*=\s*prior\.SupplyChain\.`)
	if m := stray.FindAllString(src, -1); len(m) > 0 {
		t.Errorf("store.go carries SupplyChain fields forward on its own: %v\n"+
			"Add sticky fields to applyStickySupplyChain in sticky.go instead — a rule "+
			"that lives only in the store runs AFTER the risk evaluation and so binds "+
			"the display without binding the verdict (P8-71).", m)
	}
}

// TestStickyIsAppliedBeforeTheEvaluation pins the ORDER at the scan call
// site. The fix is not "the store also does it"; it is "the evaluator sees
// it first". A refactor that moves the call below ComputeTrustScoreForOrg
// restores the defect while leaving every other test in this file green.
func TestStickyIsAppliedBeforeTheEvaluation(t *testing.T) {
	raw, err := os.ReadFile("scanner.go")
	if err != nil {
		t.Fatalf("read scanner.go: %v", err)
	}
	src := string(raw)
	apply := regexp.MustCompile(`applyStickySupplyChain\(report, prior\)`).FindStringIndex(src)
	if apply == nil {
		t.Fatal("runFanout no longer applies the sticky facts before evaluating — " +
			"if this was renamed, update the guard; do not delete it")
	}
	eval := regexp.MustCompile(`ComputeTrustScoreForOrg\(report, req\.OrgID\)`).FindStringIndex(src)
	if eval == nil {
		t.Fatal("ComputeTrustScoreForOrg call site not found in scanner.go")
	}
	if apply[0] > eval[0] {
		t.Error("the sticky carry-forward runs AFTER the risk evaluation. " +
			"That is the P8-71 defect: the fact reaches the row and not the verdict.")
	}
}
