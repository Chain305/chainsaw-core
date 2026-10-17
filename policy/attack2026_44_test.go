package policy

import "testing"

// Mastra npm org (2026-06-17, attacks.csv row 44). Every republished
// @mastra/* version gained a dependency on easy-day-js@^1.11.21; the attacker
// created that name 2026-06-16 07:05Z (1.11.21, clean) and published the
// dropper 1.11.22 at 2026-06-17 01:01Z. @mastra packages were republished
// 01:12-02:39Z, so every install in the attack window fetched an
// easy-day-js tarball whose PACKAGE was under 18 hours old.
//
// Two default seed rules refuse that tarball at the proxy:
//   - "Block packages released within 1 day" (packageAge: 1, block) keys on
//     the package's creation date only, so it fires with no byte evidence.
//   - "Block install scripts that fetch remote URLs" fires when the
//     referenced setup.cjs scans as fetches_remote (see the byte test in
//     core/intelligence/attack2026_44_test.go).
//
// Refusing the transitive easy-day-js tarball fails `npm install
// @mastra/core@1.42.1`; the @mastra tarball itself (old package, no install
// script) is served — only its cooldown monitor rule matches.
func TestAttack2026_44_Mastra_SeedPolicy(t *testing.T) {
	pols := atkBSeedPolicies(t)

	// easy-day-js@1.11.22, fetched at 01:20Z: package created 18h14m ago,
	// version 19 minutes old, install-script fetch not yet known (manifest only).
	dropper := atkBCtx("easy-day-js", "1.11.22", 18*60*60e9, 19*60e9)
	dropper.HasInstallScript = true
	atkBWantBlock(t, atkBEval(t, pols, dropper), "Block packages released within 1 day")

	// The package-age rule truncates to whole days (evaluator.go: int(hours/24)
	// > packageAge), so packageAge: 1 matches until the package is 48h old —
	// 2026-06-18 07:05Z here. After that the byte rule is what still refuses
	// the tarball, once the referenced setup.cjs is scanned.
	edge := atkBCtx("easy-day-js", "1.11.22", 47*60*60e9, 30*60*60e9)
	atkBWantBlock(t, atkBEval(t, pols, edge), "Block packages released within 1 day")
	later := atkBCtx("easy-day-js", "1.11.22", 50*60*60e9, 32*60*60e9)
	later.HasInstallScript = true
	later.InstallScriptFetchesRemote = true
	atkBWantBlock(t, atkBEval(t, pols, later), "Block install scripts that fetch remote URLs")

	// Negative controls. dayjs (real, 8 years old) with a fresh release and no
	// install script must not be refused; neither may the @mastra tarball.
	dayjs := atkBCtx("dayjs", "1.11.19", 8*atkBYear, 3*atkBDay)
	atkBWantNotBlock(t, atkBEval(t, pols, dayjs), "dayjs fresh release")
	core := atkBCtx("@mastra/core", "1.42.1", 2*atkBYear, 5*60e9)
	atkBWantNotBlock(t, atkBEval(t, pols, core), "@mastra/core tarball itself")
	// The dropper with only a present (non-fetching) script, after 48h, is
	// served: the package-age rule is the byte-independent half.
	present := atkBCtx("easy-day-js", "1.11.22", 50*60*60e9, 32*60*60e9)
	present.HasInstallScript = true
	atkBWantNotBlock(t, atkBEval(t, pols, present), "easy-day-js after day 1, script not escalated")
}
