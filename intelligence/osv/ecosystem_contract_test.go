package osv

import "testing"

// CanonicalEcosystem and the OSV provider's supportedOSVEcosystems are two
// hand-maintained lists describing the SAME fact: which caller-facing
// ecosystem names the OSV feed covers. They live in different packages, so
// nothing structural keeps them in step.
//
// Divergence is silent and asymmetric:
//   - in Supports() but not the canonicaliser → the provider runs, canonicalKey
//     returns "", Lookup finds nothing, and the coordinate reads as CLEAN
//     rather than uncovered. That is a false-clean verdict, the exact failure
//     the canonicaliser's own doc comment says this design exists to prevent.
//   - in the canonicaliser but not Supports() → the provider never runs and
//     real advisory coverage is quietly forfeited.
//
// This test pins the canonicaliser half. Its counterpart in
// core/intelligence pins the provider half against this list.
func TestCanonicalEcosystemCoversExactlyTheSupportedAliases(t *testing.T) {
	// Every alias the OSV feed is expected to cover, and the canonical key
	// it must fold onto. Adding a row here without teaching
	// CanonicalEcosystem about it fails; so does the reverse.
	want := map[string]string{
		"npm": "npm", "yarn": "npm", "bun": "npm",
		"pip": "pypi", "pypi": "pypi",
		"maven": "maven", "gradle": "maven",
		"cargo": "cargo", "crates": "cargo", "crates.io": "cargo",
		"rubygems": "rubygems", "gem": "rubygems",
		"nuget":    "nuget",
		"composer": "packagist", "packagist": "packagist",
		"go": "go", "gomod": "go",
		"pub": "pub",
	}
	for alias, canonical := range want {
		if got := CanonicalEcosystem(alias); got != canonical {
			t.Errorf("CanonicalEcosystem(%q) = %q, want %q", alias, got, canonical)
		}
	}

	// Ecosystems present in production that OSV does NOT cover must keep
	// returning "" — so the provider stays absent rather than producing a
	// clean verdict from an empty lookup. `maven-hosted` is in this list
	// deliberately: it is a REPOSITORY NAME that older code wrote into the
	// ecosystem column (5 historical rows; the same probe packages appear
	// under both "maven" and "maven-hosted", which is the fingerprint of
	// the code change). Both upload paths now write repo.Format, so it
	// cannot recur — and teaching the canonicaliser to accept it would be
	// wrong, because it would make a repo-name leak look supported.
	for _, uncovered := range []string{
		"docker", "cocoapods", "apt", "dnf", "yum", "huggingface",
		"maven-hosted", "crates-hosted", "apt-hosted", "", "  ", "not-an-ecosystem",
		// "dart" is deliberately NOT an alias: the upstream bucket is
		// "Pub", the repository format is "pub", and inventing an alias
		// nothing emits is how these two lists drift apart.
		"dart",
	} {
		if got := CanonicalEcosystem(uncovered); got != "" {
			t.Errorf("CanonicalEcosystem(%q) = %q, want \"\" — a name OSV does not "+
				"cover must not canonicalise, or an empty lookup reads as clean",
				uncovered, got)
		}
	}
}
