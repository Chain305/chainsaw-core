package pgstore

import (
	"encoding/json"
	"testing"
)

// TestSeededPlansGrantSCIMWhereverSSO pins the founder ruling: "SCIM is for Pro
// and Enterprise — basically any plan that includes SSO should also have SCIM."
//
// SSO and SCIM travel together. This is the invariant that stops the two
// drifting apart when someone edits one plan literal and forgets the other, or
// adds a fourth tier and only remembers `sso`.
//
// It asserts on the DERIVED features (what actually lands in
// pricing_plans.features), not on the raw literals in pricingPlanSeeds — the
// raw literals deliberately omit `scim`. Asserting on the derived value means
// the test still holds if someone later hardcodes `scim` in a plan literal
// instead of relying on the derivation.
func TestSeededPlansGrantSCIMWhereverSSO(t *testing.T) {
	sawSSO := false
	for _, p := range pricingPlanSeeds() {
		features := deriveBundledFeatures(p.features)
		if !features["sso"] {
			// A plan without SSO must not pick up SCIM by accident.
			if features["scim"] {
				t.Errorf("plan %q grants scim but not sso: SCIM is bundled with SSO, so a plan "+
					"granting scim alone is either a typo or an intentional unbundling that has "+
					"to be argued for explicitly (see bundledFeatureDerivations)", p.id)
			}
			continue
		}
		sawSSO = true
		if !features["scim"] {
			t.Errorf("plan %q grants sso but NOT scim.\n"+
				"  founder ruling: any plan that includes SSO must also include SCIM.\n"+
				"  derived features for %q: %v\n"+
				"  fix: do not hand-add \"scim\" to the plan literal — check that\n"+
				"  bundledFeatureDerivations still maps \"sso\" -> \"scim\" and that\n"+
				"  seedPricingPlans still runs deriveBundledFeatures before writing.",
				p.id, p.id, features)
		}
	}
	if !sawSSO {
		t.Fatal("no seeded plan grants sso — the SSO/SCIM bundling invariant was " +
			"vacuously true, which means this test stopped protecting anything. " +
			"If SSO was genuinely removed from every tier, delete this test " +
			"deliberately rather than letting it pass empty.")
	}
}

// TestSeededPlanFeaturesSerialiseToValidJSON guards the wire format the gate
// reads back. billingapi.PlanFeature json.Unmarshals this column into
// map[string]any and treats a non-bool as "not granted", so a plan whose
// features serialise to anything but a flat bool object would fail open-ended:
// the feature silently reads as denied for every org on that tier.
func TestSeededPlanFeaturesSerialiseToValidJSON(t *testing.T) {
	for _, p := range pricingPlanSeeds() {
		raw, err := json.Marshal(deriveBundledFeatures(p.features))
		if err != nil {
			t.Fatalf("plan %q: marshal features: %v", p.id, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("plan %q: features %s do not round-trip: %v", p.id, raw, err)
		}
		for k, v := range decoded {
			if _, ok := v.(bool); !ok {
				t.Errorf("plan %q: feature %q is %T, want bool — billingapi.PlanFeature "+
					"only honours bool values and would read this as denied", p.id, k, v)
			}
		}
	}
}

// TestDeriveBundledFeaturesDoesNotGrantUnasked pins the one-way direction of
// the derivation: it only ever ADDS a child grant to a plan that already has
// the parent. Free must not acquire SCIM (or anything else) as a side effect.
func TestDeriveBundledFeaturesDoesNotGrantUnasked(t *testing.T) {
	got := deriveBundledFeatures(map[string]bool{})
	if len(got) != 0 {
		t.Errorf("deriveBundledFeatures({}) = %v, want empty: a plan granting nothing "+
			"must stay granting nothing, or Free silently acquires paid features", got)
	}

	// An explicit false parent is not a grant.
	got = deriveBundledFeatures(map[string]bool{"sso": false})
	if got["scim"] {
		t.Errorf(`deriveBundledFeatures({"sso":false}) granted scim: a disabled parent `+
			`must not bundle its children (got %v)`, got)
	}

	// The input map must not be mutated — callers may reuse it.
	in := map[string]bool{"sso": true}
	_ = deriveBundledFeatures(in)
	if _, leaked := in["scim"]; leaked {
		t.Error("deriveBundledFeatures mutated its argument; it must return a copy")
	}
}
