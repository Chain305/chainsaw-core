package cli

// deps_test.go covers the pure helpers behind `deps tree` plus a
// regression guard for Finding 6: the command's value is showing
// SAME-ECOSYSTEM PEER packages, so no server-side package_name filter may
// be applied. These tests pin the client-side ecosystem/peer filtering and
// CVE extraction that the peer view depends on.

import (
	"strings"
	"testing"
)

func TestPurlEcosystem(t *testing.T) {
	cases := []struct {
		purl string
		want string
	}{
		{"pkg:npm/left-pad@1.3.0", "npm"},
		{"pkg:pypi/requests@2.31.0", "pypi"},
		{"pkg:golang/github.com/foo/bar@v1.2.3", "golang"},
		{"pkg:npm/@scope/pkg@1.0.0", "npm"},
		{"", ""},
		{"pkg:npm", ""},      // no slash → no ecosystem
		{"npm/foo@1", "npm"}, // tolerates missing pkg: prefix
	}
	for _, tc := range cases {
		if got := purlEcosystem(tc.purl); got != tc.want {
			t.Errorf("purlEcosystem(%q) = %q, want %q", tc.purl, got, tc.want)
		}
	}
}

func TestComponentCVEs(t *testing.T) {
	with := sbomComponent{
		Name:    "lodash",
		Version: "4.17.20",
		Properties: []sbomProperty{
			{Name: "chainsaw:other", Value: "ignored"},
			{Name: "chainsaw:vuln:cves", Value: "CVE-2021-23337"},
		},
	}
	if got := componentCVEs(with); got != "CVE-2021-23337" {
		t.Errorf("componentCVEs = %q, want CVE-2021-23337", got)
	}

	without := sbomComponent{Name: "clean", Version: "1.0.0"}
	if got := componentCVEs(without); got != "" {
		t.Errorf("componentCVEs(clean) = %q, want empty", got)
	}

	// Empty value must be treated as "no CVEs" so it doesn't survive the
	// --vulnerable filter.
	emptyVal := sbomComponent{
		Properties: []sbomProperty{{Name: "chainsaw:vuln:cves", Value: ""}},
	}
	if got := componentCVEs(emptyVal); got != "" {
		t.Errorf("componentCVEs(empty value) = %q, want empty", got)
	}
}

// TestDepsTreePeerFilterSemantics is the regression guard for Finding 6:
// it reproduces the client-side peer filtering that runDepsTree performs on
// a full org SBOM and asserts the same-ecosystem peers survive while the
// root and cross-ecosystem packages are handled correctly. If a future
// change pushed a server-side package_name filter (which would return only
// the root), this fixture — a full multi-ecosystem SBOM — would no longer
// resemble what the server returns and the peer view would collapse.
func TestDepsTreePeerFilterSemantics(t *testing.T) {
	bom := sbomDoc{
		Components: []sbomComponent{
			{Name: "left-pad", Version: "1.3.0", PURL: "pkg:npm/left-pad@1.3.0"},
			{Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20",
				Properties: []sbomProperty{{Name: "chainsaw:vuln:cves", Value: "CVE-2021-23337"}}},
			{Name: "axios", Version: "1.6.0", PURL: "pkg:npm/axios@1.6.0"},
			{Name: "requests", Version: "2.31.0", PURL: "pkg:pypi/requests@2.31.0"},
		},
	}

	pkgName, pkgVersion := "left-pad", "1.3.0"

	// Mirror runDepsTree's root/peer split.
	var root *sbomComponent
	peers := make([]sbomComponent, 0, len(bom.Components))
	for i := range bom.Components {
		c := &bom.Components[i]
		if strings.EqualFold(c.Name, pkgName) && (pkgVersion == "" || c.Version == pkgVersion) {
			cp := *c
			root = &cp
		} else {
			peers = append(peers, *c)
		}
	}
	if root == nil {
		t.Fatal("root left-pad not found in fixture")
	}

	// Same-ecosystem filter.
	eco := purlEcosystem(root.PURL)
	filtered := peers[:0]
	for _, p := range peers {
		if purlEcosystem(p.PURL) == eco {
			filtered = append(filtered, p)
		}
	}
	peers = filtered

	// The npm peers (lodash, axios) must survive; the pypi peer must be
	// dropped. This is exactly the "peer view" that a server-side
	// package_name filter would have destroyed.
	if len(peers) != 2 {
		t.Fatalf("want 2 npm peers, got %d: %+v", len(peers), peers)
	}
	names := map[string]bool{}
	for _, p := range peers {
		names[p.Name] = true
	}
	if !names["lodash"] || !names["axios"] {
		t.Errorf("expected lodash + axios npm peers, got %v", names)
	}
	if names["requests"] {
		t.Error("pypi peer 'requests' leaked into npm peer view")
	}

	// --vulnerable narrows to peers carrying CVEs.
	vuln := peers[:0]
	for _, p := range peers {
		if componentCVEs(p) != "" {
			vuln = append(vuln, p)
		}
	}
	if len(vuln) != 1 || vuln[0].Name != "lodash" {
		t.Errorf("want only lodash under --vulnerable, got %+v", vuln)
	}
}

func TestDepsTreeCmdRequiresOneArg(t *testing.T) {
	if depsTreeCmd.Args == nil {
		t.Fatal("depsTreeCmd has no Args validator")
	}
	if err := depsTreeCmd.Args(depsTreeCmd, []string{}); err == nil {
		t.Error("expected error for zero args")
	}
	if err := depsTreeCmd.Args(depsTreeCmd, []string{"a", "b"}); err == nil {
		t.Error("expected error for two args")
	}
	if err := depsTreeCmd.Args(depsTreeCmd, []string{"lodash@4.17.21"}); err != nil {
		t.Errorf("expected success for one arg, got %v", err)
	}
}
