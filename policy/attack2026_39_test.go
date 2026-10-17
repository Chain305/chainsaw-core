package policy

import "testing"

// IronWorm (2026-06-03, row 39): weavedb-sdk@0.45.3 and 36 siblings added
// "preinstall": "./tools/setup", a 976 KB UPX-packed Rust ELF. The install
// script body is a binary, so no fetch/eval heuristic applies and the
// default seed serves it (only the cooldown monitor rule matches).
//
// PREVENTED_CONFIG: a block rule on hasInstallScript AND nativeBinaryPresent
// (both SupportFull on npm in SupportMatrix) refuses it on the bytes, day 0.
// The rule must sit ABOVE the seeded monitor rules (lower precedence number):
// first match wins, monitor included.
func TestAttack2026_39_IronWorm_PolicyKnob(t *testing.T) {
	for _, c := range []ConditionType{ConditionHasInstallScript, ConditionNativeBinaryPresent} {
		if SupportMatrix[EcoNPM][c] != SupportFull {
			t.Fatalf("%s is not SupportFull on npm; the knob would be skipped", c)
		}
	}
	worm := atkBCtx("weavedb-sdk", "0.45.3", 3*atkBYear, 2*60*60e9)
	worm.HasInstallScript = true
	worm.NativeBinaryPresent = true

	atkBWantNotBlock(t, atkBEval(t, atkBSeedPolicies(t), worm), "default seed")

	knob := atkBWith(t, "Block native binary run by an install hook",
		Conditions{HasInstallScript: atkBTrue(), NativeBinaryPresent: atkBTrue()})
	atkBWantBlock(t, atkBEval(t, knob, worm), "Block native binary run by an install hook")

	// Negative controls: a prebuilt addon with no install hook (sharp-style
	// optional-dependency binaries), and a hook with no native binary.
	addon := atkBCtx("some-addon", "2.0.0", 3*atkBYear, 2*60*60e9)
	addon.NativeBinaryPresent = true
	atkBWantNotBlock(t, atkBEval(t, knob, addon), "native binary without an install hook")
	hook := atkBCtx("husky", "9.1.7", 8*atkBYear, 30*atkBDay)
	hook.HasInstallScript = true
	atkBWantNotBlock(t, atkBEval(t, knob, hook), "install hook without a native binary")
}
