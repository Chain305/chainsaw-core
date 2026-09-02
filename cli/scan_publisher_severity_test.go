package cli

import "testing"

// P8-70, CLI half. The server stopped treating `publisherChanged` as a
// high-severity takeover signal on Maven/Gradle in v0.21.16 — its input is the
// POM <developers> block, and of the 30 production coordinates that ever fired
// it, ZERO were takeovers. But `supplyChainConditionSeverity` is a SEPARATE
// surface and did not follow, so `chainsaw scan --fail-on high` kept breaking
// Maven builds on what is usually a documentation edit.
//
// Two surfaces answering one question differently is the whole defect, so these
// tests always assert BOTH halves: demoted where the server demoted it, and
// unchanged everywhere else. A test that only checked Maven would pass just as
// happily if someone disabled the signal globally.

func TestPublisherChangedIsLowOnPOMEcosystems(t *testing.T) {
	for _, eco := range []string{"maven", "gradle", "Maven", "GRADLE", " maven"} {
		if got := supplyChainConditionSeverityFor("publisherChanged", eco); got != "low" {
			t.Errorf("publisherChanged on %q = %q, want \"low\": the POM <developers> "+
				"block is hand-written and is not a publisher ACL, so --fail-on high "+
				"must not break the build on it", eco, got)
		}
		if demotedConditionNote("publisherChanged", eco) == "" {
			t.Errorf("%q: demotion is silent — an operator who pinned --fail-on high "+
				"and saw no break is owed the reason", eco)
		}
	}
}

// CONTROL. The demotion must be scoped to the POM ecosystems. If this fails
// while the test above passes, the signal was disabled globally rather than
// corrected, which is a far worse outcome than the bug being fixed.
func TestPublisherChangedStaysHighElsewhere(t *testing.T) {
	for _, eco := range []string{"npm", "pypi", "cargo", "rubygems", "nuget", "go", ""} {
		if got := supplyChainConditionSeverityFor("publisherChanged", eco); got != "high" {
			t.Errorf("publisherChanged on %q = %q, want \"high\": the demotion is "+
				"specific to POM-derived publisher data and must not leak", eco, got)
		}
		if note := demotedConditionNote("publisherChanged", eco); note != "" {
			t.Errorf("%q: unexpected demotion note %q", eco, note)
		}
	}
}

// Every other condition is untouched on every ecosystem, including the POM ones.
func TestOtherConditionsUnaffectedByTheDemotion(t *testing.T) {
	for cond, want := range supplyChainConditionSeverity {
		if cond == "publisherChanged" {
			continue
		}
		for _, eco := range []string{"maven", "gradle", "npm", ""} {
			if got := supplyChainConditionSeverityFor(cond, eco); got != want {
				t.Errorf("%s on %q = %q, want %q (unchanged)", cond, eco, got, want)
			}
		}
	}
}

// An unknown condition still contributes nothing, on any ecosystem.
func TestUnknownConditionContributesNothing(t *testing.T) {
	for _, eco := range []string{"maven", "npm"} {
		if got := supplyChainConditionSeverityFor("notARealCondition", eco); got != "" {
			t.Errorf("unknown condition on %q = %q, want empty", eco, got)
		}
	}
}
