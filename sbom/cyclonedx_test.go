package sbom

import (
	"strings"
	"testing"
)

// TestGenerate_EmitsSupplyChainProperties asserts that each of the
// 13-PR supply-chain fields on PackageEntry lands as a CycloneDX
// property with the canonical `chainsaw:supplychain:*` name. Downstream
// SBOM consumers (Dependency-Track etc.) pin on these names, so drift
// here is a visible break.
func TestGenerate_EmitsSupplyChainProperties(t *testing.T) {
	entry := PackageEntry{
		Ecosystem:           "npm",
		Name:                "malicious-pkg",
		Version:             "1.0.0",
		SHA256:              "abc",
		InstallScriptKind:   "fetches_remote",
		PublisherSet:        []string{"alice", "bob"},
		PublisherChanged:    true,
		VersionAnomalyFlags: []string{"semver_regression", "major_skip"},
		HiddenUnicodeHits:   3,
		PublishVelocity24h:  42,
		RepoLinkStatus:      "missing",
		ChecksumDeclared:    "sha256:declared",
		ChecksumActual:      "sha256:actual",
		MalwareStatus:       "malicious",
		TyposquatStatus:     "suspected",
	}
	bom := Generate([]PackageEntry{entry}, "")
	if len(bom.Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(bom.Components))
	}

	props := make(map[string]string)
	for _, p := range bom.Components[0].Properties {
		props[p.Name] = p.Value
	}

	wantContains := map[string]string{
		"chainsaw:supplychain:installScriptKind":   "fetches_remote",
		"chainsaw:supplychain:publisherSet":        "alice,bob",
		"chainsaw:supplychain:publisherChanged":    "true",
		"chainsaw:supplychain:versionAnomalyFlags": "semver_regression,major_skip",
		"chainsaw:supplychain:hiddenUnicodeHits":   "3",
		"chainsaw:supplychain:publishVelocity24h":  "42",
		"chainsaw:supplychain:repoLinkStatus":      "missing",
		"chainsaw:supplychain:checksumDeclared":    "sha256:declared",
		"chainsaw:supplychain:checksumActual":      "sha256:actual",
		"chainsaw:supplychain:malware":             "true",
		"chainsaw:supplychain:typosquat":           "suspected",
	}
	for name, want := range wantContains {
		got, ok := props[name]
		if !ok {
			t.Errorf("missing property %q; have: %v", name, props)
			continue
		}
		if !strings.Contains(got, want) {
			t.Errorf("property %q = %q, want contains %q", name, got, want)
		}
	}
}

// TestGenerate_CleanPackageHasNoSupplyChainProperties confirms that a
// package with no supply-chain concerns produces a component with no
// "chainsaw:supplychain:*" properties — no empty props, no false
// alarms — so the SBOM stays small for the ubiquitous clean case.
func TestGenerate_CleanPackageHasNoSupplyChainProperties(t *testing.T) {
	entry := PackageEntry{
		Ecosystem:         "npm",
		Name:              "clean-pkg",
		Version:           "1.0.0",
		SHA256:            "abc",
		InstallScriptKind: "none", // explicitly "none" should NOT emit
		RepoLinkStatus:    "ok",   // "ok" is the default, suppressed
	}
	bom := Generate([]PackageEntry{entry}, "")
	for _, p := range bom.Components[0].Properties {
		if strings.HasPrefix(p.Name, "chainsaw:supplychain:") {
			t.Errorf("unexpected supply-chain property for clean package: %s=%s", p.Name, p.Value)
		}
	}
}
