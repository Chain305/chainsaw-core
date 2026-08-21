package policy

import (
	"strings"
	"testing"
)

// A demo policy that ships with an EMPTY Conditions is not inert — it is the
// most dangerous rule in the system. matchesConditions returns true for a
// zero-value Conditions (every branch is guarded on the field being set, and
// the function ends in `return true`), and the seeded identifier is */*/*, so
// a zero-condition BLOCK policy matches EVERY package rather than none.
//
// validatePolicy is the write-path gate that keeps such a row out of the
// database ("policy must include at least one condition or scoped target"),
// and seedPolicies calls it — so a regression here surfaces as a hard seed
// failure on org creation rather than a silent block-everything rule. This
// test moves that failure to build time.
func TestDemoPolicies_EveryRuleCarriesACondition(t *testing.T) {
	t.Parallel()

	for _, p := range DemoPolicies() {
		if !hasPolicyCondition(p.Conditions) {
			t.Errorf("demo policy %q ships with no condition; with the */*/* identifier "+
				"a zero-condition rule matches every package", p.Name)
		}
		if err := validatePolicy(p); err != nil {
			t.Errorf("demo policy %q fails the seed-time validator: %v", p.Name, err)
		}
	}
}

// REGRESSION (QA Phase 4): the seeded "Demo: Cooldown" rule shipped with the
// description "Demo policy (MONITOR mode — flags, doesn't block)". Mode is a
// MUTABLE column — the monitor->enforce promotion (policyRolloutAPI sets
// next.Mode = ModeBlock) and any operator edit flip it without touching
// Description. A production screenshot then showed that rule rendering
// MODE=BLOCK beside prose insisting it only flags.
//
// The failure direction that matters is prose claiming the rule does NOT
// enforce: an operator who believes a live BLOCK rule is observe-only will not
// investigate it. The Mode column is the single source of truth, so a
// description must never make an absolute negative-enforcement claim.
func TestDemoPolicies_DescriptionsMakeNoAbsoluteModeClaim(t *testing.T) {
	t.Parallel()

	// Phrases that assert the rule does not enforce. Matched case-insensitively.
	banned := []string{
		"doesn't block",
		"does not block",
		"won't block",
		"will not block",
		"never blocks",
		"only flags",
		"monitor mode —",
		"monitor mode -",
		"(monitor mode",
	}

	for _, p := range DemoPolicies() {
		desc := strings.ToLower(p.Description)
		for _, phrase := range banned {
			if strings.Contains(desc, phrase) {
				t.Errorf("demo policy %q description contains the absolute mode claim %q; "+
					"Mode is mutable and this prose becomes false the moment the rule is "+
					"promoted to enforce. Describe what the rule MATCHES, not what mode it is in.",
					p.Name, phrase)
			}
		}
	}
}
