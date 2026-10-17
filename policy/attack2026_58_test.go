package policy

import "testing"

// Tensorlake SDK (2026-10-08, row 58): tensorlake@0.5.144 added
// "preinstall": "node lib/setup.mjs" (obfuscated Bun loader for
// lib/Math_Symbol.js, the ChainDrop toolkit). Same default-seed path as row
// 51: refused only when the referenced loader scans as fetches_remote.
func TestAttack2026_58_Tensorlake_SeedPolicy(t *testing.T) {
	pols := atkBSeedPolicies(t)

	bad := atkBCtx("tensorlake", "0.5.144", 2*atkBYear, 11*60e9)
	bad.HasInstallScript = true
	bad.InstallScriptFetchesRemote = true
	atkBWantBlock(t, atkBEval(t, pols, bad), "Block install scripts that fetch remote URLs")

	clean := atkBCtx("tensorlake", "0.5.143", 2*atkBYear, 20*atkBDay)
	atkBWantNotBlock(t, atkBEval(t, pols, clean), "tensorlake@0.5.143")
}
