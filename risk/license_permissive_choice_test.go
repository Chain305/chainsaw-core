package risk

import "testing"

// Expressions from rev5 rows and the server FP corpus that fired
// license.ambiguous_classifier.
func TestAllPermissiveIsNotAmbiguous(t *testing.T) {
	fires := func(spdx string) bool {
		in := Input{Ecosystem: "cargo", Package: "x", Version: "1.0.0", LicenseSPDX: spdx, LicenseTags: Classify(spdx)}
		for _, f := range EvaluatePackage(in, Options{}).DirectScore.Categories[CategoryLicense].FiredSignals {
			if f.ID == SignalLicAmbiguousClassifier {
				return true
			}
		}
		return false
	}
	for _, spdx := range []string{
		"MIT OR Apache-2.0", "Apache-2.0 OR MIT", "MIT/Apache-2.0", "MIT OR BSD-3-Clause",
		"BSD-3-Clause OR MIT", "Apache-2.0 OR BSD-3-Clause", "Ruby OR BSD-2-Clause", "(MIT OR Apache-2.0)",
		// AND of permissives asks no choice: aiohttp, greenlet, numpy.
		"Apache-2.0 AND MIT", "MIT AND PSF-2.0", "BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0",
		"(MIT OR Apache-2.0) AND Unicode-DFS-2016",
	} {
		if fires(spdx) {
			t.Errorf("%q: a combination of permissive licences fired license.ambiguous_classifier", spdx)
		}
		// The policy tag is unchanged.
		if !hasTag(Classify(spdx), LicenseTagAmbiguous) {
			t.Errorf("%q lost the Ambiguous TAG; that is a policy change, not a scoring one", spdx)
		}
	}
	for _, spdx := range []string{
		"(ISC OR GPL-3.0)", "GPL-2.0 OR BSD-3-Clause", "Apache-2.0 OR BSD-3-Clause OR GPL-2.0",
		"GPL-2.0-or-later OR LGPL-2.1-or-later OR MPL-1.1", "NOASSERTION OR MIT",
		"Apache-2.0 OR BUSL-1.1",
		// tqdm: an AND with a copyleft licence in it.
		"MPL-2.0 AND MIT", "MIT AND GPL-3.0-only",
	} {
		if !fires(spdx) {
			t.Errorf("%q: a combination with a copyleft, source-available or NOASSERTION part must still fire", spdx)
		}
	}
}

// "or later" in a free-text name is a version range, not a disjunction.
func TestOrLaterNameIsOneLicence(t *testing.T) {
	cases := map[string]string{
		"GNU Lesser General Public License v2.1 or later": "LGPL-2.1-or-later",
		"GNU General Public License v3 or later":          "GPL-3.0-or-later",
		"GNU General Public License version 2 or later":   "GPL-2.0-or-later",
	}
	for raw, want := range cases {
		if got := NormalizeLicenseExpression(raw); got != want {
			t.Errorf("NormalizeLicenseExpression(%q) = %q, want %q", raw, got, want)
		}
		if hasTag(Classify(raw), LicenseTagAmbiguous) {
			t.Errorf("Classify(%q) = %v, split on its \"or\"", raw, Classify(raw))
		}
	}
}
