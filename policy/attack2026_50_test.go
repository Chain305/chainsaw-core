package policy

import "testing"

// @badzz88/baileys PhantomSub fork (row 50). The channel-follow code runs
// after the WhatsApp socket connects (runtime, not install), and no detector
// recognises it. What the manifest does show is an unpinned git dependency
// ("whatsapp-rust-bridge-baron": "github:7ucg/whatsapp-rust-bridge"), which
// internal/server/artifact_scan.go hydrateDependencyHygiene turns into
// EvaluationContext.GitDependency (see internal/server/attack2026_50_test.go).
//
// PREVENTED_CONFIG: a block rule on gitDependency refuses the fork, but for
// the git dependency, not for the malice; the default seed serves it.
func TestAttack2026_50_BadzzBaileys_PolicyKnob(t *testing.T) {
	if SupportMatrix[EcoNPM][ConditionGitDependency] != SupportFull {
		t.Fatal("gitDependency is not SupportFull on npm")
	}
	fork := atkBCtx("@badzz88/baileys", "8.4.9", 200*atkBDay, 120*atkBDay)
	fork.GitDependency = true

	atkBWantNotBlock(t, atkBEval(t, atkBSeedPolicies(t), fork), "default seed")
	knob := atkBWith(t, "Block git-URL dependencies", Conditions{GitDependency: atkBTrue()})
	atkBWantBlock(t, atkBEval(t, knob, fork), "Block git-URL dependencies")

	// Negative control: the upstream library with registry-only deps.
	upstream := atkBCtx("@whiskeysockets/baileys", "6.7.9", 3*atkBYear, 90*atkBDay)
	atkBWantNotBlock(t, atkBEval(t, knob, upstream), "upstream baileys")
}
