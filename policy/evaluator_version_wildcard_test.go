package policy

import "testing"

// matchesVersion had NO direct test coverage before this file, which is
// how the "*" wildcard defect below survived: five DEFAULT-ON rules
// (core/policy/demo_policies.go:74,89,110,125 and
// core/policy/system_policies.go:86 — including the block-enabled "Block
// known malware" and "Block suspected typosquats") declare
// TargetPackageVersion: "*", and none of them fired for a version that
// is not plain X.Y.Z.
//
// Two distinct failure modes shared one root cause — "*" was handed to
// the semver machinery instead of being treated as an identifier
// wildcard:
//
//  1. PRE-RELEASE semver. Masterminds/semver deliberately refuses to
//     match a pre-release version against a constraint that carries no
//     pre-release of its own, so `c.Check(v)` returned false for
//     0.0.1-security (the shape npm publishes for taken-down malware),
//     1.0.0-rc.1, 1.0-SNAPSHOT and gomod pseudo-versions.
//
//  2. NON-SEMVER entirely. semver.NewVersion fails, and the fallback is
//     `strings.EqualFold(version, constraint)` — comparing the version
//     against the literal string "*", which is false for everything.
//     That covered Docker tags (latest, sha-abc123), PyPI dev/rc
//     spellings (1.0.dev1, 1.0.0rc1) and Maven's 1.0.0.RELEASE.
//
// Measured against the real Masterminds/semver before the fix, "*"
// matched ONLY plain release semver: every other row in the table below
// returned false. The fix short-circuits "*" before any parsing, exactly
// as matchesPattern already does for repo/name.
func TestMatchesVersionWildcardMatchesEveryVersionShape(t *testing.T) {
	// Every one of these returned FALSE against constraint "*" before
	// the short-circuit landed, except where noted.
	tests := []struct {
		name    string
		version string
	}{
		// --- plain release semver: the ONLY shape that worked before ---
		{"plain semver", "1.0.0"},
		{"plain semver, larger", "2.3.4"},
		{"zero version", "0.0.0"},

		// --- pre-release semver: parsed fine, refused by the constraint ---
		{"npm malware takedown shape", "0.0.1-security"},
		{"rc pre-release", "1.0.0-rc.1"},
		{"maven snapshot", "1.0-SNAPSHOT"},
		{"gomod pseudo-version", "v0.0.0-20230101000000-abcdefabcdef"},
		{"pre-release with build metadata", "1.2.3-beta.4+build.5"},

		// --- non-semver: parse failed, fell back to EqualFold(v, "*") ---
		{"pypi rc without separator", "1.0.0rc1"},
		{"pypi dev release", "1.0.dev1"},
		{"maven release qualifier", "1.0.0.RELEASE"},
		{"docker floating tag", "latest"},
		{"docker digest-ish tag", "sha-abc123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !matchesVersion(tt.version, "*") {
				t.Errorf("matchesVersion(%q, \"*\") = false, want true — "+
					"a rule declaring version \"*\" must cover every version shape, "+
					"or default-on block rules silently exempt this coordinate",
					tt.version)
			}
		})
	}
}

// The wildcard must be recognised after trimming, since policy documents
// round-trip through YAML/JSON where trailing whitespace survives.
func TestMatchesVersionWildcardIsTrimmed(t *testing.T) {
	for _, constraint := range []string{"*", " *", "* ", "  *  ", "\t*\n"} {
		if !matchesVersion("1.0.0rc1", constraint) {
			t.Errorf("matchesVersion(%q, %q) = false, want true", "1.0.0rc1", constraint)
		}
	}
}

// The short-circuit must not turn matchesVersion into "always true". A
// real constraint has to keep discriminating, and a non-semver version
// against a non-wildcard constraint must stay an exact-match comparison.
func TestMatchesVersionNonWildcardConstraintsStillDiscriminate(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		constraint string
		want       bool
	}{
		{"exact match", "1.2.3", "1.2.3", true},
		{"exact mismatch", "1.2.3", "1.2.4", false},
		{"caret in range", "1.2.3", "^1.0.0", true},
		{"caret out of range", "2.0.0", "^1.0.0", false},
		{"less-than satisfied", "2.14.1", "<2.15.0", true},
		{"less-than not satisfied", "2.15.0", "<2.15.0", false},
		{"non-semver exact match", "latest", "latest", true},
		{"non-semver mismatch", "latest", "stable", false},
		{"non-semver vs range is not a match", "latest", "^1.0.0", false},
		// "*" embedded in a larger constraint is NOT the identifier
		// wildcard and must not short-circuit.
		{"partial wildcard is a semver range, not the identifier wildcard", "2.0.0", "1.*", false},
		{"partial wildcard in range", "1.4.0", "1.*", true},
		// Empty constraint must not be treated as a wildcard.
		{"empty constraint does not match a version", "1.0.0", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesVersion(tt.version, tt.constraint); got != tt.want {
				t.Errorf("matchesVersion(%q, %q) = %v, want %v",
					tt.version, tt.constraint, got, tt.want)
			}
		})
	}
}
