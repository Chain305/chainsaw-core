package risk

import "testing"

// P8-70. These tests drive the real EvaluatePackage — not the Fires
// closure — so they break if the evaluation path is refactored around the
// signal, not only if a predicate changes.
//
// P8-70 landed in two parts.
//
// Epoch 11 (2026-09-02) fixed an EXTRACTOR mismatch: the baseline and the
// incoming publisher set were built by two different pieces of code that
// disagreed about which POM element is the publisher identity, so the diff
// reported a total publisher replacement on every maven/gradle coordinate
// with any scan history. 30 prod coordinates carried publisherChanged=true;
// 19 cleared.
//
// Epoch 12 (this file's current shape) fixed the CLAIM. The 11 rows that
// survived the extractor fix are genuine `<developers>` edits — a committer
// added, a committer removed, `lightbend` renamed to `akka` — and not one is
// an account takeover, because the POM `<developers>` block is not an access
// control list. So on POM ecosystems the SevHigh "signature of account
// takeover" reading was replaced by the SevLow, uncapped
// SignalSCPOMDeveloperListChanged, which reports only the fact.
//
// The numbers that justified both epoch bumps are pinned here.

func firedIDs(eval *Evaluation) map[string]FiredSignal {
	out := map[string]FiredSignal{}
	if eval == nil {
		return out
	}
	for _, cat := range eval.DirectScore.Categories {
		for _, fs := range cat.FiredSignals {
			out[fs.ID] = fs
		}
	}
	return out
}

func publisherChangedFired(eval *Evaluation) bool {
	_, ok := firedIDs(eval)[SignalSCPublisherChanged]
	return ok
}

// The epoch-11 headline: clearing a FALSE publisherChanged is
// verdict-affecting.
//
// The ecosystem here was "maven" when this test was written, because the
// epoch-11 flip population was entirely maven. Epoch 12 demoted the signal
// for exactly that ecosystem, so the assertion moved to npm — where the
// publisher set IS a registry-enforced identity and the SevHigh reading
// still holds. What is being pinned is unchanged: sc.publisher_changed can
// move a verdict on its own, so a false positive in it is never "score
// only", and neither epoch bump was cosmetic.
func TestPublisherChanged_IsVerdictAffecting(t *testing.T) {
	mk := func(changed bool) *Evaluation {
		return EvaluatePackage(Input{
			Ecosystem:            "npm",
			PublisherChanged:     changed,
			VersionDataAvailable: true,
			VersionCount:         24,
		}, Options{})
	}
	withSignal, without := mk(true), mk(false)
	if !publisherChangedFired(withSignal) {
		t.Fatalf("control failed: %q did not fire on PublisherChanged=true", SignalSCPublisherChanged)
	}
	if publisherChangedFired(without) {
		t.Fatalf("%q fired on PublisherChanged=false", SignalSCPublisherChanged)
	}
	if withSignal.Verdict == without.Verdict {
		t.Fatalf("expected a verdict flip and got none (changed=%v/%d clean=%v/%d). "+
			"A publisher-set false positive would then be score-only and the "+
			"epoch history in core/intelligence/report.go would be unjustified",
			withSignal.Verdict, withSignal.DirectScore.Overall,
			without.Verdict, without.DirectScore.Overall)
	}
	if without.DirectScore.Overall <= withSignal.DirectScore.Overall {
		t.Errorf("clearing the signal must RAISE the score: changed=%d clean=%d",
			withSignal.DirectScore.Overall, without.DirectScore.Overall)
	}
}

// Why a -25 weight behaves like a block: MaxImpact.
//
// The signal declares MaxImpact 40, so on its own it CAPS overall at 40
// regardless of how clean the rest of the package is. That is why every one
// of the 30 false-positive prod rows sat at exactly overall=40, and why "it
// is only -25 out of 100" was the wrong way to size this finding. Pinned on
// npm since epoch 12 — see TestPublisherChangedDemotion_POMEcosystemIsNotCapped
// for the deliberate absence of the same ceiling on maven.
func TestPublisherChanged_CapsScoreAtMaxImpact(t *testing.T) {
	eval := EvaluatePackage(Input{
		Ecosystem:            "npm",
		PublisherChanged:     true,
		VersionDataAvailable: true,
		VersionCount:         24,
	}, Options{})
	if eval.DirectScore.Overall > 40 {
		t.Fatalf("overall=%d: publisherChanged declares MaxImpact 40 and must cap an "+
			"otherwise-clean package at or below it", eval.DirectScore.Overall)
	}
	if eval.Verdict == VerdictAllow {
		t.Fatalf("a lone publisherChanged must not resolve to allow (overall=%d)",
			eval.DirectScore.Overall)
	}
}

// Negative control, and the boundary of the fix. Neither epoch disabled
// publisher-change detection anywhere.
//
// Epoch 11's version of this test asserted sc.publisher_changed fires on all
// seven ecosystems including maven and gradle, and said in its comment that a
// future attempt at the blunt instrument — dropping maven from
// supportedMetadiffEcosystems — should be argued here rather than silently
// landed. Epoch 12 is that future change and this is the argument: maven and
// gradle still produce a signal on a real `<developers>` change, it is just
// the honest one. The blunt instrument was still NOT taken: nothing was
// removed from supportedMetadiffEcosystems, the diff still runs, the fact is
// still reported, and a policy author can still gate on it. Only the severity
// claim moved, and only where the data cannot support it.
func TestPublisherChanged_StillFiresPerEcosystem(t *testing.T) {
	for _, eco := range []string{"npm", "pypi", "cargo", "rubygems", "nuget"} {
		fired := firedIDs(EvaluatePackage(Input{Ecosystem: eco, PublisherChanged: true}, Options{}))
		if _, ok := fired[SignalSCPublisherChanged]; !ok {
			t.Errorf("%s: %q must still fire on a real publisher-set change — "+
				"the publisher set is registry-enforced here and the takeover reading holds",
				eco, SignalSCPublisherChanged)
		}
	}
	// POM ecosystems: a signal still fires, it is just the demoted one.
	// Firing NOTHING would be the blunt instrument this test exists to
	// block, so both halves are asserted.
	for _, eco := range []string{"maven", "gradle", "Maven", "maven-central"} {
		fired := firedIDs(EvaluatePackage(Input{Ecosystem: eco, PublisherChanged: true}, Options{}))
		if _, ok := fired[SignalSCPublisherChanged]; ok {
			t.Errorf("%s: %q must NOT fire — the POM <developers> block is not an "+
				"access-control list, so the takeover claim is unsupported (P8-70)",
				eco, SignalSCPublisherChanged)
		}
		if _, ok := fired[SignalSCPOMDeveloperListChanged]; !ok {
			t.Errorf("%s: %q must fire instead — P8-70 demoted the claim, it did not "+
				"delete the fact; a POM roster change is still reported",
				eco, SignalSCPOMDeveloperListChanged)
		}
	}
}

// The epoch-12 headline. On a POM ecosystem the signal must no longer be
// able to hold an otherwise-clean package below the allow band.
//
// Epoch 11's TestPublisherChanged_CapsScoreAtMaxImpact asserted the exact
// opposite for ecosystem "maven": overall <= 40 and verdict != allow. That
// was the defect — 30 of 30 prod rows sat at overall=40 on a documentation
// edit, and the Wave S incident (2026-05-23) turned the same mechanism into
// a 403 on every `mvn` invocation in the smoke org. If this test ever fails,
// a MaxImpact ceiling or a severity has been put back and the demotion is
// undone.
func TestPublisherChangedDemotion_POMEcosystemIsNotCapped(t *testing.T) {
	for _, eco := range []string{"maven", "gradle"} {
		eval := EvaluatePackage(Input{
			Ecosystem:            eco,
			PublisherChanged:     true,
			VersionDataAvailable: true,
			VersionCount:         24,
		}, Options{})
		if eval.DirectScore.Overall <= 40 {
			t.Errorf("%s: overall=%d — a lone POM <developers> edit is still being "+
				"held at the MaxImpact-40 ceiling; the demotion did not take",
				eco, eval.DirectScore.Overall)
		}
		if eval.Verdict != VerdictAllow {
			t.Errorf("%s: verdict=%v — an otherwise-clean package whose only finding "+
				"is a declared-developer-list change must resolve to allow",
				eco, eval.Verdict)
		}
		fs, ok := firedIDs(eval)[SignalSCPOMDeveloperListChanged]
		if !ok {
			t.Fatalf("%s: control failed, %q did not fire", eco, SignalSCPOMDeveloperListChanged)
		}
		if fs.Severity != SevLow {
			t.Errorf("%s: %q severity is %q, want %q — anything above low re-asserts "+
				"the takeover reading P8-70 refuted", eco, fs.ID, fs.Severity, SevLow)
		}
	}
}

// The back door. CompoundSCTakeoverSignature carries -55, the heaviest
// non-instant-block weight in the product, and it keys off PublisherChanged.
// Demoting the primitive is worthless if the compound still escalates off
// the same POM prose, so the compound is guarded for POM ecosystems too and
// that guard is pinned independently of the primitive.
//
// The npm arm is the control: the identical Input on a registry-enforced
// ecosystem MUST still escalate. A version of this test with only the maven
// arm would pass just as well against a compound rule that had been deleted.
func TestTakeoverCompound_DoesNotEscalateOnPOMEcosystems(t *testing.T) {
	mk := func(eco string) *Evaluation {
		return EvaluatePackage(Input{
			Ecosystem:                  eco,
			Package:                    "p",
			Version:                    "1.0.0",
			PublisherChanged:           true,
			HasInstallScript:           true,
			InstallScriptFetchesRemote: true,
			VersionDataAvailable:       true,
			VersionCount:               24,
		}, Options{})
	}
	control := firedIDs(mk("npm"))
	if _, ok := control[CompoundSCTakeoverSignature]; !ok {
		t.Fatalf("control failed: %q did not fire on npm with publisher-change + "+
			"install script — the compound rule itself is broken, so the maven "+
			"assertions below prove nothing", CompoundSCTakeoverSignature)
	}
	for _, eco := range []string{"maven", "gradle"} {
		if _, ok := firedIDs(mk(eco))[CompoundSCTakeoverSignature]; ok {
			t.Errorf("%s: %q fired — the -55 takeover weight is back on POM "+
				"<developers> prose through the compound rule, which reinstates "+
				"the block P8-70 removed", eco, CompoundSCTakeoverSignature)
		}
	}
}

// sc.first_time_collaborator (-15) is computed by
// firstTimeCollaboratorProvider from the same two fields as the publisher
// diff — prior publisher_set vs Report.People.PublisherIDs — so on
// maven/gradle it reads the same POM <developers> roster. "Publisher has
// never previously CONTRIBUTED to this package" is false by construction
// there: a new name in <developers> is a documentation edit, not a push.
//
// It contributes no prod flips today because the provider is env-gated off
// for maven (CHAINSAW_WAVE4_FIRST_TIME_COLLABORATOR unset), which is exactly
// why it needs a test — the guard's whole job is to stop that flag from
// silently reintroducing the class.
func TestFirstTimeCollaborator_SuppressedOnPOMEcosystems(t *testing.T) {
	yes := true
	mk := func(eco string) map[string]FiredSignal {
		return firedIDs(EvaluatePackage(Input{
			Ecosystem:             eco,
			Package:               "p",
			Version:               "1.0.0",
			FirstTimeCollaborator: &yes,
			VersionDataAvailable:  true,
			VersionCount:          24,
		}, Options{}))
	}
	if _, ok := mk("npm")[SignalSCFirstTimeCollaborator]; !ok {
		t.Fatalf("control failed: %q did not fire on npm", SignalSCFirstTimeCollaborator)
	}
	for _, eco := range []string{"maven", "gradle"} {
		if _, ok := mk(eco)[SignalSCFirstTimeCollaborator]; ok {
			t.Errorf("%s: %q fired off a POM <developers> roster — the same P8-70 "+
				"root cause as sc.publisher_changed, treated inconsistently",
				eco, SignalSCFirstTimeCollaborator)
		}
	}
}
