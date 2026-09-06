package risk

import "testing"

// lic.spdx_present used to fire on any non-empty string, so a licence URL
// earned "+5 Package declares an SPDX license" on the same row where
// license.unidentified fired -15 for that field not being recognisable as
// SPDX. Measured on production: 339 rows across six ecosystems (nuget 240,
// gradle 36, cargo 24, maven 19, pip 15, npm 5) rendered both to operators.
func TestSPDXPresentAndUnidentifiedCannotBothFire(t *testing.T) {
	t.Parallel()
	for _, expr := range []string{
		"https://raw.github.com/JamesNK/Newtonsoft.Json/master/LICENSE.md",
		"https://example.com/eula",
		"LICENSE.txt",
		"NOASSERTION",
		"see license file",
	} {
		in := Input{LicenseSPDX: expr}
		present, _, _ := Registry[SignalLicSPDXPresent].Fires(in)
		unidentified, _, _ := Registry[SignalLicUnidentified].Fires(in)
		if present && unidentified {
			t.Errorf("%q fires BOTH lic.spdx_present and license.unidentified — the contradiction operators see", expr)
		}
		if present {
			t.Errorf("%q was credited as an SPDX declaration", expr)
		}
	}
}

// The control. Gating on the classifier must not silence the signal for
// real SPDX expressions — that would trade a cosmetic contradiction for a
// scoring regression on every correctly-licensed package.
func TestSPDXPresentStillFiresForRealExpressions(t *testing.T) {
	t.Parallel()
	for _, expr := range []string{"MIT", "Apache-2.0", "BSD-3-Clause", "MIT OR Apache-2.0"} {
		in := Input{LicenseSPDX: expr}
		present, _, _ := Registry[SignalLicSPDXPresent].Fires(in)
		if !present {
			t.Errorf("%q no longer counts as an SPDX declaration — the gate is too tight", expr)
		}
	}
}
