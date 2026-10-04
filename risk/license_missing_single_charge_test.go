package risk

import "testing"

// A licence nobody declared is one fact and is charged once, by lic.missing.
// Shapes from corpus-v1-rev4: gollum@2.2.7 and deep_cloneable@1.6.0 on
// rubygems declare no licence at the registry; the projection hands the
// engine an empty expression and Classify's Unidentified tag with it.
func TestEmptyLicenceIsChargedOnce(t *testing.T) {
	fired := func(spdx string) map[string]bool {
		in := Input{Ecosystem: "rubygems", Package: "gollum", Version: "2.2.7",
			LicenseSPDX: spdx, LicenseTags: Classify(spdx)}
		out := map[string]bool{}
		for _, f := range EvaluatePackage(in, Options{}).DirectScore.Categories[CategoryLicense].FiredSignals {
			out[f.ID] = true
		}
		return out
	}

	got := fired("")
	if !got[SignalLicMissing] || got[SignalLicUnidentified] {
		t.Fatalf("empty licence: want lic.missing alone, got %v", got)
	}
	// The policy tag is unchanged: a LicenseUnidentified condition still
	// matches an undeclared licence.
	if !hasTag(Classify(""), LicenseTagUnidentified) {
		t.Fatal("Classify(\"\") lost the Unidentified tag; that is a policy change, not a scoring one")
	}

	// Declared but unrecognisable stays unidentified, and is not missing.
	for _, spdx := range []string{"NOASSERTION", "Commercial", "https://github.com/dotnet/corefx/blob/master/LICENSE.TXT"} {
		got := fired(spdx)
		if got[SignalLicMissing] || !got[SignalLicUnidentified] {
			t.Errorf("%q: want license.unidentified alone, got %v", spdx, got)
		}
	}
}
