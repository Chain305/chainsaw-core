package risk

import "testing"

// P8-70 / epoch 11. These tests drive the real EvaluatePackage — not the
// Fires closure — so they break if the evaluation path is refactored
// around the signal, not only if the predicate changes.
//
// The fix for P8-70 lives upstream of this package: two POM extractors
// disagreed about which `<developer>` element is the publisher identity,
// so sc.publisher_changed fired on maven packages whose roster had not
// moved. The reason that bug mattered THIS much, and the reason it
// forced a matcher-epoch bump, is entirely in the numbers here — so the
// numbers are pinned here.

func publisherChangedFired(eval *Evaluation) bool {
	if eval == nil {
		return false
	}
	for _, cat := range eval.DirectScore.Categories {
		for _, fs := range cat.FiredSignals {
			if fs.ID == SignalSCPublisherChanged {
				return true
			}
		}
	}
	return false
}

// The headline: clearing a FALSE publisherChanged is verdict-affecting.
//
// This is the epoch-11 justification. Six of the nineteen prod rows the
// fix clears change verdict, every one warn -> allow. The input below is
// the shape of the smallest of them — a maven coordinate with no other
// deduction at all, e.g. org.slf4j:slf4j-bom 2.1.0-alpha1.
//
// If this stops flipping, the epoch-11 history note in
// core/intelligence/report.go is wrong and should be corrected rather
// than left as folklore.
func TestPublisherChanged_IsVerdictAffecting(t *testing.T) {
	mk := func(changed bool) *Evaluation {
		return EvaluatePackage(Input{
			Ecosystem:            "maven",
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
			"A publisher-set false positive on maven would then be score-only and the "+
			"epoch-11 bump in core/intelligence/report.go would be unjustified",
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
// regardless of how clean the rest of the package is. That is why every
// one of the 30 false-positive prod rows sat at exactly overall=40, and
// why "it is only -25 out of 100" was the wrong way to size this finding.
// A future weight change that quietly drops the cap would make the P8-70
// severity narrative wrong, so pin the cap itself.
func TestPublisherChanged_CapsScoreAtMaxImpact(t *testing.T) {
	eval := EvaluatePackage(Input{
		Ecosystem:            "maven",
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

// Negative control, and the boundary of the fix. P8-70 did NOT disable
// the signal for maven — a genuine `<developer><id>` set change still
// fires, exactly as it does for npm. Eleven prod rows still fire after
// the fix for precisely this reason. If a later change reaches for the
// blunt instrument (dropping maven from supportedMetadiffEcosystems),
// this test is where it should be argued, not silently landed.
func TestPublisherChanged_StillFiresPerEcosystem(t *testing.T) {
	for _, eco := range []string{"maven", "gradle", "npm", "pypi", "cargo", "rubygems", "nuget"} {
		eval := EvaluatePackage(Input{Ecosystem: eco, PublisherChanged: true}, Options{})
		if !publisherChangedFired(eval) {
			t.Errorf("%s: %q must still fire on a real publisher-set change — "+
				"P8-70 fixed the extractor, it did not suppress the signal",
				eco, SignalSCPublisherChanged)
		}
	}
}
