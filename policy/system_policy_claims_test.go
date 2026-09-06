package policy

import (
	"strings"
	"testing"
)

// A system policy's Description is operator-facing copy: it is what renders
// in the dashboard and what someone reads before deciding whether to touch
// the rule. When it says "disabled by default" and the Status constant eight
// lines below says enabled, the product lies to the person best placed to
// catch the problem.
//
// That is exactly what shipped: SystemPolicies' own doc comment said
// "created with status=disabled by default", the Description said "Disabled
// by default", and the constant said StatusEnabled. Three statements of
// intent against one line of code, and nothing compared them.
//
// KNOWN OPEN: system:slsa-baseline-tier1 currently fails both checks below,
// and that is a product decision rather than a typo — TestSLSABaselineTier1Shape
// asserts Status=enabled with the comment "(block-by-default)", so the design
// was chosen deliberately even though this file's SystemPolicies doc comment
// and the policy's own Description both say "disabled by default".
//
// It is listed in knownContradictions with the reason, rather than silently
// excluded, so a NEW system policy with the same defect still fails. Delete
// the entry when the decision lands. See the SLSA polarity note in
// docs/plan_qa_phase9_fresh_remediation.md.
var knownContradictions = map[string]string{
	"system:slsa-baseline-tier1": "block-by-default is asserted by TestSLSABaselineTier1Shape; " +
		"the enabled/disabled contradiction and the inverted RequireAttestation polarity " +
		"are one open decision, not two independent bugs",
}

// The domain here is enumerable — every system policy — so this is a real
// guard rather than an annotation someone can delete.
func TestSystemPolicyDescriptionAgreesWithStatus(t *testing.T) {
	t.Parallel()
	policies := SystemPolicies()
	if len(policies) == 0 {
		t.Fatal("SystemPolicies() returned nothing — this guard would pass vacuously")
	}
	for _, p := range policies {
		if reason, known := knownContradictions[string(p.ID)]; known {
			t.Logf("SKIPPING KNOWN: %s — %s", p.ID, reason)
			continue
		}
		desc := strings.ToLower(p.Description)
		claimsDisabled := strings.Contains(desc, "disabled by default")
		claimsEnabled := strings.Contains(desc, "enabled by default")

		if claimsDisabled && p.Status == StatusEnabled {
			t.Errorf("%s: Description says \"disabled by default\" but Status is StatusEnabled", p.ID)
		}
		if claimsEnabled && p.Status != StatusEnabled {
			t.Errorf("%s: Description says \"enabled by default\" but Status is %v", p.ID, p.Status)
		}
	}
}

// A block-mode system policy that matches every coordinate is the highest
// blast-radius object this package can produce. It must not ship enabled
// without a deliberate, visible decision — which for the one that does today
// means an entry in knownContradictions carrying the reason.
func TestNoWildcardBlockSystemPolicyShipsEnabled(t *testing.T) {
	t.Parallel()
	for _, p := range SystemPolicies() {
		if _, known := knownContradictions[string(p.ID)]; known {
			continue
		}
		wildcard := p.Identifier.TargetPackageName == "*" || p.Identifier.TargetPackageName == ""
		if p.Mode == ModeBlock && p.Status == StatusEnabled && wildcard {
			t.Errorf("%s ships enabled in block mode against a wildcard identifier (%+v) — "+
				"a fresh install would enforce it on day one", p.ID, p.Identifier)
		}
	}
}

// The exemption list must not outlive what it exempts. If a policy named in
// knownContradictions stops existing, or stops having the defect, the entry
// is dead and must be deleted — otherwise the map slowly becomes a place to
// hide new problems, which is how every allowlist rots.
func TestKnownContradictionsAreStillTrue(t *testing.T) {
	t.Parallel()
	live := map[string]Policy{}
	for _, p := range SystemPolicies() {
		live[string(p.ID)] = p
	}
	for id, reason := range knownContradictions {
		p, ok := live[id]
		if !ok {
			t.Errorf("knownContradictions names %q, which is not a system policy any more — delete the entry", id)
			continue
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%s: exemption carries no reason", id)
		}
		desc := strings.ToLower(p.Description)
		contradicts := strings.Contains(desc, "disabled by default") && p.Status == StatusEnabled
		wildcardBlock := p.Mode == ModeBlock && p.Status == StatusEnabled &&
			(p.Identifier.TargetPackageName == "*" || p.Identifier.TargetPackageName == "")
		if !contradicts && !wildcardBlock {
			t.Errorf("%s no longer has the defect it is exempted for — delete the entry", id)
		}
	}
}
