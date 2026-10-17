package policy

import "testing"

// helpersutils-dev-tools (2026-09-02, row 56): index.js beacons the host
// page's domain to http://5.189.173.113:8899/csp-edu on require. When
// iocscan reports it (the documented `new Image()` beacon is a recognised
// send since v0.22.106, F9 — see core/intelligence/attack2026_56_test.go),
// MaliciousIOC is set; no default seed rule blocks on it. PREVENTED_CONFIG
// via a maliciousIOC block rule.
func TestAttack2026_56_HelpersutilsDevTools_PolicyKnob(t *testing.T) {
	if SupportMatrix[EcoNPM][ConditionMaliciousIOC] != SupportFull {
		t.Fatal("maliciousIOC is not SupportFull on npm")
	}
	// Package created 2026-09-02; versions 1.0.0-1.0.17 within 2.5h, so by
	// the second day packageAge no longer fires.
	beacon := atkBCtx("helpersutils-dev-tools", "1.0.11", 3*atkBDay, 3*atkBDay)
	beacon.MaliciousIOC = true
	atkBWantNotBlock(t, atkBEval(t, atkBSeedPolicies(t), beacon), "default seed")

	knob := atkBWith(t, "Block embedded malicious indicators", Conditions{MaliciousIOC: atkBTrue()})
	atkBWantBlock(t, atkBEval(t, knob, beacon), "Block embedded malicious indicators")

	clean := atkBCtx("lodash", "4.17.21", 10*atkBYear, 2*atkBYear)
	atkBWantNotBlock(t, atkBEval(t, knob, clean), "lodash")

	// Day 0 (first ~24h after the name existed): the seeded package-age rule
	// refuses every helpersutils-dev-tools version with no byte evidence.
	day0 := atkBCtx("helpersutils-dev-tools", "1.0.11", 2*60*60e9, 1*60*60e9)
	atkBWantBlock(t, atkBEval(t, atkBSeedPolicies(t), day0), "Block packages released within 1 day")
}
