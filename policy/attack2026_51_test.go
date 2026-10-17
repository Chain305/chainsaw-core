package policy

import "testing"

// ChainDrop / keyv-cacheable worm (2026-08-04, row 51). keyv@6.0.0 is a
// fresh version of a 10+-year-old package from its real maintainer with
// valid provenance, so packageAge, typosquat and publisher rules cannot see
// it. The default seed refuses it only through "Block install scripts that
// fetch remote URLs", which needs the byte scan of the referenced loader to
// say fetches_remote (core/intelligence/attack2026_51_test.go shows when it
// does and when it does not).
func TestAttack2026_51_ChainDrop_SeedPolicy(t *testing.T) {
	pols := atkBSeedPolicies(t)

	keyv := atkBCtx("keyv", "6.0.0", 10*atkBYear, 30*60e9)
	keyv.HasInstallScript = true
	keyv.InstallScriptFetchesRemote = true
	keyv.HasProvenance = true
	keyv.ProvenanceStatus = "verified"
	atkBWantBlock(t, atkBEval(t, pols, keyv), "Block install scripts that fetch remote URLs")

	// Loader not escalated (string-table obfuscation the detector does not
	// recognise): the same request is only matched by the cooldown MONITOR
	// rule and is served.
	weak := keyv
	weak.InstallScriptFetchesRemote = false
	res := atkBEval(t, pols, weak)
	atkBWantNotBlock(t, res, "keyv@6.0.0 with a present-only preinstall")
	if res.Action != ModeMonitor {
		t.Errorf("want the cooldown monitor rule to record it, got %s", res.Action)
	}

	// Negative control: keyv@5.6.0, no install script, old.
	clean := atkBCtx("keyv", "5.6.0", 10*atkBYear, 200*atkBDay)
	atkBWantNotBlock(t, atkBEval(t, pols, clean), "keyv@5.6.0")
}
