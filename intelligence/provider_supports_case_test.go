package intelligence

// P8-33 — every provider's Supports() whitelist must be case-insensitive.
//
// Key.Ecosystem is never normalised by the caller: it arrives verbatim from
// a URL path segment (`/api/v1/intel/packages/PyPI/requests/2.31.0`), a
// lockfile parser, a policy row, or a proxy repository config. Four
// providers compared the raw string against a lower-case whitelist, so a
// display-cased coordinate silently lost those lanes — and scanner.go's
// skip is a bare `continue`, so the loss leaves no warning, no timing entry
// and no trace in the Report.
//
// The malware lane is the one that makes this load-bearing rather than
// cosmetic: P8-44 routes IsKnownMalicious past EvaluatePackage's
// SignalsUnavailable short-circuit, so a lookup that never happens is a
// block that never happens.

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/metadata"
	"github.com/chain305/chainsaw-core/typosquat"
)

// caseVariants returns the spellings a real caller can produce for an
// ecosystem: the canonical lower-case form plus the two display forms that
// appear in registry documentation and in URLs users type by hand.
func caseVariants(eco string) []string {
	upper := strings.ToUpper(eco)
	title := eco
	if len(eco) > 0 {
		title = strings.ToUpper(eco[:1]) + eco[1:]
	}
	return []string{upper, title, " " + eco + " "}
}

func TestProviderSupportsIsCaseInsensitive(t *testing.T) {
	idx := malware.NewIndex(nil)

	cases := []struct {
		name     string
		supports func(string) bool
		// covered is an ecosystem the provider's whitelist carries.
		covered string
	}{
		{"cve", newCVEProvider(&metadata.Store{}).Supports, "pypi"},
		{"typosquat", newTyposquatProvider(typosquat.NewDetector(nil)).Supports, "npm"},
		{"malware", newMalwareProvider(idx).Supports, "pypi"},
		{"checksum", newChecksumProvider().Supports, "pypi"},
		// The four that were already correct, pinned so a future edit
		// cannot regress them back into the broken half.
		{"osv", (&osvProvider{}).Supports, "npm"},
		{"registrymetadata", (&registryMetadataProvider{}).Supports, "npm"},
		{"installscripts", (&installScriptsProvider{}).Supports, "npm"},
		{"hiddenunicode", (&hiddenUnicodeProvider{}).Supports, "npm"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.supports(tc.covered) {
				t.Fatalf("precondition: %s must support %q", tc.name, tc.covered)
			}
			for _, v := range caseVariants(tc.covered) {
				if !tc.supports(v) {
					t.Errorf("%s.Supports(%q) = false, want true — "+
						"a display-cased coordinate silently loses this lane (P8-33)",
						tc.name, v)
				}
			}
			// An ecosystem nobody covers must stay uncovered in every
			// casing: the normaliser must not widen coverage.
			for _, v := range append([]string{"definitely-not-an-ecosystem"},
				caseVariants("definitely-not-an-ecosystem")...) {
				if tc.supports(v) {
					t.Errorf("%s.Supports(%q) = true, want false", tc.name, v)
				}
			}
		})
	}
}

// The malware provider's Run guard is a SECOND case-sensitive lookup on the
// same registry (hasDefinitiveCoverage), and it is the one that decides
// whether a verdict may be stamped at all. Supports() passing is not enough.
func TestMalwareDefinitiveCoverageIsCaseInsensitive(t *testing.T) {
	p := newMalwareProvider(malware.NewIndex(nil))
	if !p.coverage.hasDefinitiveCoverage("pypi") {
		t.Fatal("precondition: pypi must have definitive malware coverage")
	}
	for _, v := range caseVariants("pypi") {
		if !p.coverage.hasDefinitiveCoverage(v) {
			t.Errorf("hasDefinitiveCoverage(%q) = false, want true — "+
				"Run would return early and never stamp a malware verdict", v)
		}
	}
}
