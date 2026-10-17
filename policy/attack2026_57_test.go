package policy

import "testing"

// @apexacc/cli (2026-09-17, row 57). apex.cjs adds a Defender exclusion and
// turns Smart App Control off. sc.defender_tamper is warn-capped (MaxImpact
// 40, core/risk/registry_supplychain.go) and has no policy condition of its
// own, so the only policy knob that refuses it is a trustScoreMax rule
// (score <= 40). The default seed does not carry one.
//
// FINDING (F1, fixed in v0.22.103): a monitor match used to end evaluation,
// so this knob placed BELOW the seeded cooldown monitor (precedence 140)
// never fired on a fresh version. It now applies wherever it is ranked.
func TestAttack2026_57_ApexaccCLI_PolicyKnob(t *testing.T) {
	score := 40
	tamper := atkBCtx("@apexacc/cli", "1.5.121", 2*atkBYear, 30*60e9)
	tamper.TrustScore = &score

	atkBWantNotBlock(t, atkBEval(t, atkBSeedPolicies(t), tamper), "default seed")

	max40 := 40
	knob := atkBWith(t, "Block warn-capped scores", Conditions{TrustScoreMax: &max40})
	atkBWantBlock(t, atkBEval(t, knob, tamper), "Block warn-capped scores")

	clean := atkBCtx("@apexacc/cli", "1.5.120", 2*atkBYear, 30*60e9)
	good := 88
	clean.TrustScore = &good
	atkBWantNotBlock(t, atkBEval(t, knob, clean), "1.5.120 scored 88")

	// No shadowing since F1: the same rule at precedence 200 still applies
	// to a 30-minute-old version that the cooldown monitor (140) matches first.
	late := atkBSeedPolicies(t)
	late = append(late, Policy{ID: "late", Name: "late", Mode: ModeBlock, Status: StatusEnabled,
		Precedence: 200, Conditions: Conditions{TrustScoreMax: &max40}})
	atkBWantBlock(t, atkBEval(t, late, tamper), "late")
}
