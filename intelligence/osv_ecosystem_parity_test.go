package intelligence

import (
	"testing"

	"github.com/chain305/chainsaw-core/intelligence/osv"
)

// supportedOSVEcosystems (this package) and osv.CanonicalEcosystem (that one)
// are two hand-maintained lists of the same fact. Nothing structural keeps
// them in step, and divergence is silent in BOTH directions:
//
//   - supported but not canonical → the provider runs, canonicalKey returns
//     "", Lookup finds nothing, and the coordinate reads CLEAN instead of
//     uncovered. A false-clean verdict.
//   - canonical but not supported → the provider never runs and real advisory
//     coverage is quietly forfeited.
//
// The canonicaliser's own doc comment says Supports() reads it "so unsupported
// ecosystems stay silently absent rather than producing a false-clean
// verdict". This test is what makes that sentence true rather than aspirational.
func TestSupportedOSVEcosystemsMatchesCanonicaliser(t *testing.T) {
	for alias := range supportedOSVEcosystems {
		if osv.CanonicalEcosystem(alias) == "" {
			t.Errorf("supportedOSVEcosystems lists %q but osv.CanonicalEcosystem(%q) = \"\" — "+
				"the provider would run, the lookup would key on nothing, and the "+
				"coordinate would read as clean rather than uncovered", alias, alias)
		}
	}

	// Reverse direction, over every alias the canonicaliser is known to
	// accept. One missing from supportedOSVEcosystems means the provider
	// never runs for it and its advisory coverage is silently forfeited.
	for _, alias := range []string{
		"npm", "yarn", "bun", "pip", "pypi", "maven", "gradle",
		"cargo", "crates", "crates.io", "rubygems", "gem", "nuget",
		"composer", "packagist", "go", "gomod", "pub",
	} {
		if osv.CanonicalEcosystem(alias) == "" {
			continue // not claimed as covered; nothing to require
		}
		if _, ok := supportedOSVEcosystems[alias]; !ok {
			t.Errorf("osv.CanonicalEcosystem(%q) is non-empty but supportedOSVEcosystems "+
				"does not list it — the OSV provider will never run for this ecosystem", alias)
		}
	}
}

// A coordinate in an ecosystem OSV does not cover must not resolve to a
// confident clean Allow off the back of an empty advisory lookup.
//
// "maven-hosted" is the motivating case: it is a REPOSITORY NAME that older
// code wrote into the ecosystem column. 5 such rows are in production, and
// the same probe packages appear under BOTH "maven" and "maven-hosted" —
// the fingerprint of the code change. Both upload paths now write
// repo.Format, so it cannot recur.
func TestUncoveredEcosystemIsNotClaimedAsSupported(t *testing.T) {
	for _, eco := range []string{"maven-hosted", "docker", "cocoapods", "apt", "dnf", "yum"} {
		if _, ok := supportedOSVEcosystems[eco]; ok {
			t.Errorf("supportedOSVEcosystems claims %q — OSV has no coverage for it, so "+
				"an empty lookup would be reported as a clean result", eco)
		}
		if got := osv.CanonicalEcosystem(eco); got != "" {
			t.Errorf("osv.CanonicalEcosystem(%q) = %q, want \"\"", eco, got)
		}
	}
}

// Guard against the historical defect itself: a repository NAME must never be
// accepted where an ecosystem is expected. Repository names in this
// deployment follow "<format>-<flavour>" (maven-hosted, crates-hosted,
// apt-hosted, dnf-baseos, maven-central), while the ecosystem field must
// carry the bare format.
func TestRepositoryNamesAreNotEcosystems(t *testing.T) {
	// The first four are the names that actually appear in the ecosystem
	// column of the 2026-08-25 production export, which is how the leak was
	// found. Note that the prefix is NOT the format for three of them
	// (npmjs->npm, crates->cargo, rubygems->rubygems), so no string
	// transform can recover the format: name to format is a database fact.
	repoNames := []string{
		"maven-hosted", "npmjs-hosted", "rubygems-hosted", "crates-hosted",
		"maven-central", "apt-hosted",
		"dnf-hosted", "dnf-baseos", "yum-hosted", "docker-hub", "cocoapods-trunk",
	}
	for _, name := range repoNames {
		if osv.CanonicalEcosystem(name) != "" {
			t.Errorf("osv.CanonicalEcosystem(%q) is non-empty — %q is a repository "+
				"name, not an ecosystem. Accepting it would make a repo-name leak "+
				"into the ecosystem column look supported instead of failing loudly.",
				name, name)
		}
		if _, ok := supportedOSVEcosystems[name]; ok {
			t.Errorf("supportedOSVEcosystems lists repository name %q", name)
		}
		// knownEcosystems is the domain markNoAdvisoryCoverage takes its
		// complement over. A repository name inside it would make P8-05
		// state "no advisory source covers ecosystem maven-hosted" about
		// packages that are ordinary Maven packages with full coverage.
		if isKnownEcosystem(name) {
			t.Errorf("isKnownEcosystem(%q) = true — %q is a repository name. "+
				"Admitting it lets the no-advisory-coverage stamp make a "+
				"COVERAGE claim about a ROUTING bug.", name, name)
		}
	}
	// And the formats those names carry MUST be recognised, so the fix
	// (writing repo.Format instead of repo.Name) actually restores coverage.
	for _, format := range []string{"maven", "cargo", "npm", "pypi", "nuget", "go"} {
		if osv.CanonicalEcosystem(format) == "" {
			t.Errorf("osv.CanonicalEcosystem(%q) = \"\" — this is a repository FORMAT "+
				"and must canonicalise, or writing repo.Format gains nothing", format)
		}
	}
	// Every bare FORMAT must also be inside the P8-05 domain, or the same
	// fix (writing repo.Format) would trade one wrong stamp for another.
	for _, format := range []string{
		"maven", "gradle", "cargo", "npm", "pypi", "pip", "nuget", "go",
		"rubygems", "composer", "cocoapods", "pub", "swift", "docker",
		"huggingface", "apt", "yum", "dnf",
	} {
		if !isKnownEcosystem(format) {
			t.Errorf("isKnownEcosystem(%q) = false — this is a repository "+
				"FORMAT and must be in the domain", format)
		}
	}
	if isKnownEcosystem("") {
		t.Error("isKnownEcosystem(\"\") = true — an unresolved refresher row " +
			"carries no ecosystem and nothing may be claimed about it")
	}
}
