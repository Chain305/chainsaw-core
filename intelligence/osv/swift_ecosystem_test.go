package osv

import (
	"bytes"
	"testing"
)

// OSV's SwiftURL records name the repository ("github.com/Owner/Repo");
// Swift coordinates carry the SE-0292 identity ("owner.repo") the proxy and
// the Package.resolved parser emit. Driven through Load → Lookup, not the
// tables, so a fold that only one half applies fails here.
func TestSwiftURLAdvisoryMatchesOwnerRepoCoordinate(t *testing.T) {
	idx, err := Load(bytes.NewReader(gzippedJSON(t, []Advisory{{
		Ecosystem:        "SwiftURL",
		Package:          "github.com/Apple/swift-nio",
		VulnerableRanges: []VulnerableRange{{Introduced: "2.0.0", Fixed: "2.29.1"}},
		AdvisoryID:       "GHSA-swift-test-0001",
		Aliases:          []string{"CVE-2026-0002"},
	}})))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !idx.HasEcosystem("swift") {
		t.Fatal("HasEcosystem(swift) = false after loading a SwiftURL advisory")
	}
	for _, name := range []string{"apple.swift-nio", "Apple.Swift-NIO", "github.com/apple/swift-nio", "https://github.com/Apple/swift-nio.git"} {
		if hits := idx.Lookup("swift", name, "2.10.0"); len(hits) != 1 {
			t.Errorf("Lookup(swift, %q, 2.10.0) = %d advisories, want 1", name, len(hits))
		}
	}
	if hits := idx.Lookup("swift", "apple.swift-nio", "2.29.1"); len(hits) != 0 {
		t.Errorf("fixed version matched %d advisories, want 0", len(hits))
	}
	if idx.HasPackage("swift", "swift-nio") {
		t.Error("bare SwiftPM identity matched the owner-keyed advisory")
	}
}

// A covered Swift index proves nothing about a name it could never key.
func TestSwiftAbsenceIsNegativeOnlyForOwnerRepo(t *testing.T) {
	cases := map[string]bool{
		"apple.swift-nio":            true,
		"github.com/apple/swift-nio": true,
		"alamofire":                  false,
		"gitlab.com/x/y":             false,
		"":                           false,
		".x":                         false,
	}
	for name, want := range cases {
		if got := AbsenceIsNegative("swift", name); got != want {
			t.Errorf("AbsenceIsNegative(swift, %q) = %v, want %v", name, got, want)
		}
	}
	if !AbsenceIsNegative("npm", "left-pad") {
		t.Error("non-swift ecosystems must keep the clean-absence stamp")
	}
}
