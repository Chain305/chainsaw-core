package risk

import "testing"

// Creative Commons, decided 2026-10-03: ShareAlike is copyleft,
// NonCommercial and NoDerivatives are non-permissive, plain BY and CC0 are
// permissive. First seen as "CC BY-NC-SA 4.0" on npm
// xg-xiaogang-erlingerlingyiling-erlingersanlinger, which fired
// license.unidentified while socket.dev flagged it copyleft.
func TestCreativeCommons(t *testing.T) {
	cases := []struct {
		raw, id                 string
		copyleft, nonPermissive bool
		strength                LicenseStrength
	}{
		{"CC BY-NC-SA 4.0", "CC-BY-NC-SA-4.0", true, true, LicenseStrengthSourceAvailable},
		{"CC-BY-NC-SA-4.0", "CC-BY-NC-SA-4.0", true, true, LicenseStrengthSourceAvailable},
		{"Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International", "CC-BY-NC-SA-4.0", true, true, LicenseStrengthSourceAvailable},
		{"CC BY-SA 4.0", "CC-BY-SA-4.0", true, true, LicenseStrengthWeakCopyleft},
		{"Creative Commons Attribution Share Alike 3.0 Unported", "CC-BY-SA-3.0", true, true, LicenseStrengthWeakCopyleft},
		{"CC BY-NC 4.0", "CC-BY-NC-4.0", false, true, LicenseStrengthSourceAvailable},
		{"CC BY-ND 4.0", "CC-BY-ND-4.0", false, true, LicenseStrengthSourceAvailable},
		{"CC BY-NC-ND 4.0", "CC-BY-NC-ND-4.0", false, true, LicenseStrengthSourceAvailable},
		{"CC BY 4.0", "CC-BY-4.0", false, false, LicenseStrengthPermissive},
		{"Creative Commons Attribution 4.0 International", "CC-BY-4.0", false, false, LicenseStrengthPermissive},
		{"CC0 1.0", "CC0-1.0", false, false, LicenseStrengthPermissive},
		{"CC0", "CC0-1.0", false, false, LicenseStrengthPermissive},
	}
	for _, tc := range cases {
		if tc.raw != tc.id {
			if got := NormalizeLicenseExpression(tc.raw); got != tc.id {
				t.Errorf("NormalizeLicenseExpression(%q) = %q, want %q", tc.raw, got, tc.id)
			}
		}
		tags := Classify(tc.raw)
		if hasTag(tags, LicenseTagUnidentified) {
			t.Errorf("Classify(%q) = %v, unidentified", tc.raw, tags)
		}
		if hasTag(tags, LicenseTagCopyleft) != tc.copyleft || hasTag(tags, LicenseTagNonPermissive) != tc.nonPermissive {
			t.Errorf("Classify(%q) = %v, want copyleft=%v non_permissive=%v", tc.raw, tags, tc.copyleft, tc.nonPermissive)
		}
		if got := LicenseStrengthOf(tc.raw); got != tc.strength {
			t.Errorf("LicenseStrengthOf(%q) = %d, want %d", tc.raw, got, tc.strength)
		}
	}
	// A permissive choice that includes ShareAlike is not all-permissive.
	if IsAllPermissive("MIT OR CC-BY-SA-4.0") {
		t.Error("MIT OR CC-BY-SA-4.0 counted as all-permissive")
	}
	if !IsAllPermissive("MIT OR CC-BY-4.0") {
		t.Error("MIT OR CC-BY-4.0 should be all-permissive")
	}
	// Inside brackets the operand is still found and the brackets kept.
	if got := NormalizeLicenseExpression("(MIT OR CC0 1.0)"); got != "(MIT OR CC0-1.0)" {
		t.Errorf("NormalizeLicenseExpression((MIT OR CC0 1.0)) = %q", got)
	}
	// Unknown words give no answer rather than a guess.
	for _, raw := range []string{"CC BY-XYZ 4.0", "Creative Commons", "CC BY-ND-SA 4.0"} {
		if _, ok := creativeCommonsID(licenseNameKey(raw)); ok {
			t.Errorf("creativeCommonsID(%q) guessed an id", raw)
		}
	}
}
