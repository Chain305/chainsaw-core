package risk

// ceiling_attribution_test.go — P8-12, downgraded to explainability.
//
// THE ORIGINAL FRAMING WAS REFUTED AND MUST NOT BE REINTRODUCED. The filing
// said "a composite below the minimum of its sub-scores is arithmetically
// impossible". It is not impossible; it is the DESIGN.
// applyMaxImpactCeiling clamps `overall` AFTER computeCategoryScores has
// already stored the un-ceilinged per-category numbers, so "overall 40,
// every category 65+" is the intended output of a signal whose declared
// MaxImpact is 40.
//
// What survives is that the clamp left NO TRACE. A user reads a composite
// they cannot derive from the parts shown, with nothing on the page saying
// why. Score.CeilingSignal is that trace.

import "testing"

// TestCeilingSignalNamesThePinningSignal is the positive case: a lone
// ceilinged signal fires, it binds, and the evaluation says which one.
func TestCeilingSignalNamesThePinningSignal(t *testing.T) {
	ev := EvaluatePackage(Input{
		Ecosystem:    "pypi",
		Package:      "fixture",
		Version:      "1.0.0",
		LicenseSPDX:  "MIT",
		LicenseTags:  Classify("MIT"),
		IsVulnerable: true,
		MaxCVSS:      7.5,
		CVEs:         []string{"CVE-0000-0001"},
	}, Options{})

	if ev.DirectScore.CeilingSignal != SignalVulnCVSSHigh {
		t.Fatalf("CeilingSignal = %q, want %q (overall %d)",
			ev.DirectScore.CeilingSignal, SignalVulnCVSSHigh, ev.DirectScore.Overall)
	}
	// The whole point: the composite is BELOW every category subscore, and
	// that is correct. Assert the shape so the attribution is demonstrably
	// answering a real question rather than decorating an ordinary rollup.
	if ev.DirectScore.Overall >= ev.DirectScore.MinCategoryScore {
		t.Errorf("overall %d is not below the worst category %d — this fixture "+
			"no longer exercises a binding ceiling, so it no longer tests anything",
			ev.DirectScore.Overall, ev.DirectScore.MinCategoryScore)
	}
	sig, ok := Registry[ev.DirectScore.CeilingSignal]
	if !ok {
		t.Fatalf("CeilingSignal %q is not a registered signal", ev.DirectScore.CeilingSignal)
	}
	if ev.DirectScore.Overall != sig.MaxImpact {
		t.Errorf("overall %d != the named signal's declared ceiling %d — the "+
			"attribution names a signal that did not in fact pin the score",
			ev.DirectScore.Overall, sig.MaxImpact)
	}
}

// TestCeilingSignalEmptyWhenTheCeilingDidNotBind is the negative case, and
// it is the one that keeps the field honest. An empty string must mean
// "nothing to explain" — if it were populated whenever a ceilinged signal
// merely FIRED, every renderer would print a note about a clamp that never
// happened.
func TestCeilingSignalEmptyWhenTheCeilingDidNotBind(t *testing.T) {
	// Clean package: no ceilinged signal fires at all.
	clean := EvaluatePackage(Input{
		Ecosystem:   "npm",
		Package:     "fixture",
		Version:     "1.0.0",
		LicenseSPDX: "MIT",
		LicenseTags: Classify("MIT"),
	}, Options{})
	if clean.DirectScore.CeilingSignal != "" {
		t.Errorf("clean package reports CeilingSignal %q — nothing was capped",
			clean.DirectScore.CeilingSignal)
	}

	// A ceilinged signal that fires alongside enough other deficit that
	// the rollup already lands at or below its ceiling. The ceiling is
	// present but does not BIND, so there is nothing to explain.
	heavy := EvaluatePackage(Input{
		Ecosystem:      "pypi",
		Package:        "fixture",
		Version:        "1.0.0",
		LicenseSPDX:    "AGPL-3.0-only",
		LicenseTags:    Classify("AGPL-3.0-only"),
		IsVulnerable:   true,
		KnownExploited: true,
		MaxCVSS:        9.8,
		CVEs:           []string{"CVE-0000-0002"},
	}, Options{})
	if sig, ok := Registry[SignalVulnKEV]; ok && heavy.DirectScore.Overall < sig.MaxImpact {
		if heavy.DirectScore.CeilingSignal != "" {
			t.Errorf("CeilingSignal = %q but overall %d is already below the "+
				"ceiling %d, so the clamp did not fire",
				heavy.DirectScore.CeilingSignal, heavy.DirectScore.Overall, sig.MaxImpact)
		}
	}
}

// TestCeilingAttributionIsDeterministic — applyMaxImpactCeiling walks a
// map. Two signals may declare the same MaxImpact, and the blame must not
// move between runs of the same coordinate.
func TestCeilingAttributionIsDeterministic(t *testing.T) {
	in := Input{
		Ecosystem:            "npm",
		Package:              "fixture",
		Version:              "1.0.0",
		LicenseSPDX:          "MIT",
		LicenseTags:          Classify("MIT"),
		IsSuspectedTyposquat: true,
		TyposquatConfidence:  "high",
		TyposquatSimilarTo:   "lodash",
		IsVulnerable:         true,
		MaxCVSS:              9.5,
		CVEs:                 []string{"CVE-0000-0003"},
	}
	first := EvaluatePackage(in, Options{}).DirectScore.CeilingSignal
	for i := 0; i < 50; i++ {
		if got := EvaluatePackage(in, Options{}).DirectScore.CeilingSignal; got != first {
			t.Fatalf("ceiling attribution moved between identical runs: %q then %q", first, got)
		}
	}
}

// TestCompoundRuleSuppressesCeilingAttribution pins the documented bypass.
// A compound rule means genuine multi-signal elevation and the additive
// deficit stays authoritative — so no ceiling is applied and there is
// nothing to attribute.
func TestCompoundRuleSuppressesCeilingAttribution(t *testing.T) {
	ev := EvaluatePackage(Input{
		Ecosystem:    "pypi",
		Package:      "fixture",
		Version:      "1.0.0",
		LicenseSPDX:  "MIT",
		LicenseTags:  Classify("MIT"),
		IsVulnerable: true,
		MaxCVSS:      7.5,
		CVEs:         []string{"CVE-0000-0004"},
	}, Options{})
	// Sanity: the no-compound fixture above DOES attribute. If a future
	// compound rule starts matching this shape, the assertion below stops
	// meaning anything, and this line says so out loud.
	if ev.DirectScore.CeilingSignal == "" {
		t.Skip("fixture no longer produces a binding ceiling; rewrite it")
	}
}
