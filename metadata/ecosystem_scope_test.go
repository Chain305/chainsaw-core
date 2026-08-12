package metadata

import (
	"strings"
	"testing"
)

// TestSearchVulnerabilityQueryLegacyShapeIsUnchanged is the BACKWARDS-COMPAT
// guard for the ecosystem dimension.
//
// An older CLI POSTs {name, version} with no ecosystem field. That decodes to
// an empty ecosystem, which must reach the store as "" and produce the exact
// SQL the store has always issued — not a join that is merely believed to be
// equivalent. If this assertion ever fails, an old CLI's scan changed shape.
func TestSearchVulnerabilityQueryLegacyShapeIsUnchanged(t *testing.T) {
	const want = `SELECT repository, package, version, is_vulnerable, cvss_score, epss_score,
		cves, cve_details, scanner_db_digest, scanned_at, created_at, updated_at
		FROM vulnerability_metadata WHERE org_id=? AND package=? AND version=?`

	for _, ecosystem := range []string{"", "   ", "\t\n"} {
		got := searchVulnerabilityQuery(ecosystem)
		if got != want {
			t.Fatalf("searchVulnerabilityQuery(%q) changed the legacy lookup.\n got: %s\nwant: %s", ecosystem, got, want)
		}
		if strings.Contains(strings.ToUpper(got), "JOIN") {
			t.Errorf("searchVulnerabilityQuery(%q) must not join for an ecosystem-less caller", ecosystem)
		}
	}
}

// TestSearchVulnerabilityQueryScopesByRepositoryFormat pins the shape of the
// ecosystem-aware lookup: a LEFT JOIN onto repositories to recover the format,
// on the repositories PRIMARY KEY (org_id, name) so the join can neither drop
// nor duplicate a vulnerability_metadata row.
func TestSearchVulnerabilityQueryScopesByRepositoryFormat(t *testing.T) {
	got := searchVulnerabilityQuery("npm")
	for _, want := range []string{
		"LEFT JOIN repositories r",
		"r.org_id = vm.org_id",
		"r.name = vm.repository",
		"r.format",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("ecosystem query missing %q:\n%s", want, got)
		}
	}
	// The predicate must stay org+package+version; the ecosystem is applied
	// row-wise in Go (see vulnerabilityRowMatchesEcosystem) because the
	// format→ecosystem folding is not expressible as a plain equality.
	if !strings.Contains(got, "WHERE vm.org_id=? AND vm.package=? AND vm.version=?") {
		t.Errorf("ecosystem query lost the org/package/version predicate:\n%s", got)
	}
}

// TestVulnerabilityRowMatchesEcosystem covers the row-scoping rule, including
// the alias folding that the two ecosystem spellings in this tree have burned
// us on before (pypi/pip, gradle/maven, yarn+bun/npm, gomod/go).
func TestVulnerabilityRowMatchesEcosystem(t *testing.T) {
	cases := []struct {
		name       string
		repoFormat string
		want       string
		keep       bool
	}{
		// The defect this exists for: an npm row must not answer a PyPI
		// question, and vice versa.
		{"npm row, npm asked", "npm", "npm", true},
		{"npm row, pip asked", "npm", "pip", false},
		{"pip row, npm asked", "pip", "npm", false},
		{"pip row, pip asked", "pip", "pip", true},

		// Alias folding, both sides of the comparison.
		{"yarn row folds to npm", "yarn", "npm", true},
		{"bun row folds to npm", "bun", "npm", true},
		{"pip row answers pypi", "pip", "pypi", true},
		{"pypi row answers pip", "pypi", "pip", true},
		{"gradle row folds to maven", "gradle", "maven", true},
		{"maven row answers gradle", "maven", "gradle", true},
		{"gomod row folds to go", "gomod", "go", true},
		{"npm row does not answer maven", "npm", "maven", false},

		// Case and whitespace insensitivity on both sides.
		{"uppercase row format", "NPM", "npm", true},
		{"uppercase requested", "npm", "NPM", true},
		{"padded requested", "npm", "  npm  ", true},
		{"uppercase mismatch still excluded", "NPM", "PyPI", false},

		// No ecosystem requested → legacy behaviour, keep everything.
		{"no ecosystem asked keeps npm row", "npm", "", true},
		{"no ecosystem asked keeps orphan row", "", "", true},

		// Exclusion requires POSITIVE evidence. An orphaned row (repository
		// deleted → NULL format) or a format this build cannot map is not
		// proof of a different registry, so it is retained rather than
		// silently hiding a CVE.
		{"orphan row retained", "", "npm", true},
		{"unmappable format retained", "some-future-format", "npm", true},
		{"whitespace format retained", "   ", "pip", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := vulnerabilityRowMatchesEcosystem(tc.repoFormat, tc.want); got != tc.keep {
				t.Errorf("vulnerabilityRowMatchesEcosystem(%q, %q) = %v, want %v",
					tc.repoFormat, tc.want, got, tc.keep)
			}
		})
	}
}

// TestSearchVulnerabilityDelegatesWithoutEcosystem documents that the
// pre-existing exported entry point is now literally the ecosystem-less case
// of the new one — external callers of SearchVulnerability keep the old
// behaviour without a signature change.
func TestSearchVulnerabilityDelegatesWithoutEcosystem(t *testing.T) {
	var s *Store
	legacyErr := func() error {
		_, err := s.SearchVulnerability("commander", "2.20.3")
		return err
	}()
	scopedErr := func() error {
		_, err := s.SearchVulnerabilityInEcosystem("commander", "2.20.3", "")
		return err
	}()
	if legacyErr != scopedErr {
		t.Fatalf("SearchVulnerability does not delegate to the ecosystem-less path: %v vs %v", legacyErr, scopedErr)
	}
	if legacyErr != ErrUnavailable {
		t.Fatalf("nil store should report ErrUnavailable, got %v", legacyErr)
	}
}
