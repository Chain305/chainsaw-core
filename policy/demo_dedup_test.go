package policy

// A brand-new org used to open its policy list to ELEVEN rules: seven from
// configs/seed.yaml plus four demo rules, including two near-duplicate cooldown
// rules differing only in their window (7 vs 10 days) and two publisher-change
// rules. That list is friction for exactly the hobbyist the demo seed exists to
// serve.
//
// The fix drops a demo rule when an already-seeded policy covers every
// condition it uses. These tests pin both directions, because the dangerous
// failure is dropping too much: a self-hosted install with no config policies
// must still receive the full demo set, or nothing teaches the controls at all.

import (
	"testing"
)

func condTypeSet(cts ...ConditionType) map[ConditionType]struct{} {
	m := make(map[ConditionType]struct{}, len(cts))
	for _, ct := range cts {
		m[ct] = struct{}{}
	}
	return m
}

func demoNames(ps []Policy) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

func demoNamesContain(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// The self-hosted case: nothing seeded, so nothing is dropped.
func TestDropCoveredDemoPolicies_NoCoverageKeepsEverything(t *testing.T) {
	t.Parallel()
	got := dropCoveredDemoPolicies(DemoPolicies(), condTypeSet())
	if len(got) != len(DemoPolicies()) {
		t.Fatalf("kept %d of %d demo policies with no coverage — a config-less "+
			"install must receive the full set", len(got), len(DemoPolicies()))
	}
}

// The chain305.com case: the config seed already carries cooldown and
// publisher-change, so those two demo copies are redundant — but malware and
// typosquat are NOT in the config seed and must survive.
func TestDropCoveredDemoPolicies_DropsOnlyTheCoveredOnes(t *testing.T) {
	t.Parallel()
	covered := condTypeSet(ConditionCooldown, ConditionPublisherChanged, ConditionCVE)
	names := demoNames(dropCoveredDemoPolicies(DemoPolicies(), covered))

	for _, gone := range []string{
		"Demo: Cooldown: flag brand-new versions",
		"Demo: Flag publisher change (account-takeover)",
	} {
		if demoNamesContain(names, gone) {
			t.Errorf("%q survived despite its signal already being seeded", gone)
		}
	}
	for _, kept := range []string{
		"Demo: Block known malware",
		"Demo: Block suspected typosquats",
	} {
		if !demoNamesContain(names, kept) {
			t.Errorf("%q was dropped, but no config rule covers its signal. "+
				"These two are the activation moment — losing them means a new org "+
				"has nothing that demonstrates a block.", kept)
		}
	}
}

// Partial overlap is not duplication: a rule that ANDs a covered condition with
// an uncovered one is a different rule and must be kept.
func TestDropCoveredDemoPolicies_PartialOverlapIsKept(t *testing.T) {
	t.Parallel()
	yes := true
	seven := 7
	compound := []Policy{{
		Name:       "compound",
		Conditions: Conditions{CooldownDays: &seven, IsKnownMalicious: &yes},
	}}
	got := dropCoveredDemoPolicies(compound, condTypeSet(ConditionCooldown))
	if len(got) != 1 {
		t.Error("dropped a rule that only partially overlaps the covered set; " +
			"AND-composed conditions make it a different rule")
	}
}
