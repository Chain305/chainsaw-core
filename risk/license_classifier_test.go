package risk

import (
	"sort"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		expr string
		want []LicenseTag
	}{
		{"empty", "", []LicenseTag{LicenseTagUnidentified}},
		{"noassertion", "NOASSERTION", []LicenseTag{LicenseTagUnidentified}},
		{"permissive MIT", "MIT", nil},
		{"permissive Apache", "Apache-2.0", nil},
		{"permissive BSD-3-Clause", "BSD-3-Clause", nil},
		{"copyleft GPL", "GPL-2.0-only", []LicenseTag{LicenseTagCopyleft, LicenseTagNonPermissive}},
		{"copyleft AGPL", "AGPL-3.0-or-later", []LicenseTag{LicenseTagCopyleft, LicenseTagNonPermissive}},
		{"copyleft MPL", "MPL-2.0", []LicenseTag{LicenseTagCopyleft, LicenseTagNonPermissive}},
		{"exception", "GPL-2.0-only WITH Classpath-exception-2.0", []LicenseTag{LicenseTagExceptionPresent, LicenseTagCopyleft, LicenseTagNonPermissive}},
		{"ambiguous compound", "MIT OR GPL-2.0-only", []LicenseTag{LicenseTagCopyleft, LicenseTagNonPermissive, LicenseTagAmbiguous}},
		{"same family AND", "Apache-2.0 AND Apache-2.0", nil},
		{"noassertion mixed", "NOASSERTION AND MIT", []LicenseTag{LicenseTagAmbiguous}},
		{"source-available BUSL", "BUSL-1.1", []LicenseTag{LicenseTagNonPermissive}},
		{"commons clause rider", "Apache-2.0 AND Commons-Clause", []LicenseTag{LicenseTagAmbiguous, LicenseTagNonPermissive}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.expr)
			if !sameSet(got, tc.want) {
				t.Errorf("Classify(%q)=%v want %v", tc.expr, got, tc.want)
			}
		})
	}
}

func sameSet(a, b []LicenseTag) bool {
	if len(a) != len(b) {
		return false
	}
	ca := append([]LicenseTag(nil), a...)
	cb := append([]LicenseTag(nil), b...)
	sort.Slice(ca, func(i, j int) bool { return ca[i] < ca[j] })
	sort.Slice(cb, func(i, j int) bool { return cb[i] < cb[j] })
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}
