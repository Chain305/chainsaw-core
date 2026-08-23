package osv

import "testing"

// Regression cover for the mixed-prefix comparator inversion found by running
// the upgrade promotion against production data on 2026-08-23.
//
// compareVersions used to answer confidently AND WRONGLY whenever its two
// operands disagreed about carrying a leading "v" — returning a nil error, so
// every caller's error branch was blind to it. Because advisoryAffectsEx
// compares the queried version against `introduced`, `fixed` and
// `lastAffected`, an inverted answer silently mis-evaluates a CVE bound.
//
// The `default` (SemVer) branch was always fine: parseSemver strips the
// prefix. The Maven family was not — mvn.NewVersion reads a leading
// non-numeric run as a QUALIFIER, which sorts BELOW numeric versions.
func TestCompareVersions_MixedPrefixOrdering(t *testing.T) {
	cases := []struct {
		name string
		eco  string
		a, b string
		want int
	}{
		// The exact production case: swiftmailer at v6.3.0 against a
		// bare 5.4.5. Old answer was +1 (5.4.5 "above" v6.3.0), which
		// is how the promotion came to advise a downgrade.
		{"composer bare vs v-prefixed, bare lower", "composer", "5.4.5", "v6.3.0", -1},
		{"composer v-prefixed vs bare, prefixed higher", "composer", "v6.3.0", "5.4.5", 1},
		// Real prod coordinate: composer v1.37.0 against an advisory
		// `introduced: 1.0.0`. Old answer was -1 — below the introduced
		// bound, so the advisory was CLEARED. A false negative.
		{"composer v1.37.0 vs introduced 1.0.0", "composer", "v1.37.0", "1.0.0", 1},
		{"maven bare vs v-prefixed", "maven", "3.2.2", "v2.0", 1},
		// Same-shape pairs were always right and must stay right.
		{"composer both v-prefixed", "composer", "v6.3.0", "v5.4.5", 1},
		{"composer neither prefixed", "composer", "6.3.0", "5.4.5", 1},
		// Ecosystems whose parser already normalised, unchanged.
		{"go v-prefixed vs bare", "go", "v1.2.3", "1.3.0", -1},
		{"npm bare vs v-prefixed", "npm", "4.18.0", "v4.17.11", 1},
		{"nuget bare vs v-prefixed", "nuget", "4.3.4", "v4.3.0", 1},
		{"equal across shapes", "composer", "v1.2.3", "1.2.3", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := compareVersions(tc.eco, tc.a, tc.b)
			if err != nil {
				t.Fatalf("compareVersions(%s, %q, %q) errored: %v", tc.eco, tc.a, tc.b, err)
			}
			if got != tc.want {
				t.Errorf("compareVersions(%s, %q, %q) = %+d, want %+d — an inverted "+
					"comparison here mis-evaluates an advisory bound in advisoryAffectsEx",
					tc.eco, tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// A non-numeric lead must be REFUSED by the Maven family rather than read as
// a qualifier. The error becomes `undecidable` in advisoryAffectsEx, which
// LookupEx deliberately keeps out of the `cleared` bucket — so an unorderable
// coordinate can never veto a real advisory.
//
// Every string here is a real production version from intelligence_reports:
// unresolved Maven POM property placeholders, the literal "metadata", and a
// package-name-prefixed Composer tag. The old code silently ordered all of
// them against advisory bounds.
func TestCompareVersions_RefusesNonNumericLead(t *testing.T) {
	junk := []struct{ eco, ver string }{
		{"maven", "${slf4jVersion}"},
		{"maven", "${commons.lang3.version}"},
		{"gradle", "${jsr305.version}"},
		{"maven", "metadata"},
		{"gradle", "metadata"},
		{"composer", "swiftmailer-6.2.5"},
	}
	for _, j := range junk {
		t.Run(j.eco+"/"+j.ver, func(t *testing.T) {
			if _, err := compareVersions(j.eco, j.ver, "1.0.0"); err == nil {
				t.Errorf("compareVersions(%s, %q, \"1.0.0\") returned no error — "+
					"the Maven parser reads a non-numeric lead as a qualifier and "+
					"orders it BELOW every numeric version, which silently clears "+
					"real advisories", j.eco, j.ver)
			}
		})
	}
}

// normalizeVersionPrefix must strip exactly one leading v/V before a digit,
// and nothing else.
func TestNormalizeVersionPrefix(t *testing.T) {
	cases := [][2]string{
		{"v1.2.3", "1.2.3"},
		{"V1.2.3", "1.2.3"},
		{"  v1.2.3  ", "1.2.3"},
		{"1.2.3", "1.2.3"},
		// Only stripped when a DIGIT follows, so "vv..." is left alone
		// and refused downstream rather than half-normalised into a
		// shape the Maven parser would then misread as a qualifier.
		{"vv1.2.3", "vv1.2.3"},
		{"version-1", "version-1"},
		{"v", "v"},         // no digit follows
		{"valid", "valid"}, // 'a' is not a digit
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeVersionPrefix(c[0]); got != c[1] {
			t.Errorf("normalizeVersionPrefix(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}
