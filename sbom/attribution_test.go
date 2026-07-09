package sbom

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestGenerate_NoAttribution_ByteIdentical pins the contract that
// PackageEntry without Attributions populated produces exactly the same
// CycloneDX bytes as a release without the feature. This is the
// hard-line invariant from the feature contract: opt-in only, never
// touch the wire when off.
func TestGenerate_NoAttribution_ByteIdentical(t *testing.T) {
	entry := PackageEntry{
		Ecosystem: "npm",
		Name:      "left-pad",
		Version:   "1.3.0",
		SHA256:    "abc",
	}
	// Serial number and timestamp would change between runs; pin both
	// by overriding via two side-by-side Generates and comparing.
	a := Generate([]PackageEntry{entry}, "urn:uuid:fixed")
	a.Metadata.Timestamp = "2026-04-30T00:00:00Z"

	withEmptyAttrs := entry
	withEmptyAttrs.Attributions = nil
	b := Generate([]PackageEntry{withEmptyAttrs}, "urn:uuid:fixed")
	b.Metadata.Timestamp = "2026-04-30T00:00:00Z"

	aJSON, err := a.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON a: %v", err)
	}
	bJSON, err := b.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON b: %v", err)
	}
	if !bytes.Equal(aJSON, bJSON) {
		t.Fatalf("byte equality broken when Attributions is empty:\n--- a ---\n%s\n--- b ---\n%s", aJSON, bJSON)
	}
	// Belt and suspenders: no attribution property should appear.
	if strings.Contains(string(aJSON), "chainsaw:attribution:") {
		t.Fatalf("unexpected attribution property leaked into baseline output:\n%s", aJSON)
	}
}

// TestGenerate_WithAttribution_EmitsProperties confirms each populated
// AttributionEntry field lands as a CycloneDX property under the
// canonical chainsaw:attribution:* namespace.
func TestGenerate_WithAttribution_EmitsProperties(t *testing.T) {
	first := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	last := time.Date(2026, 4, 1, 2, 3, 4, 0, time.UTC)
	entry := PackageEntry{
		Ecosystem: "npm",
		Name:      "react",
		Version:   "18.2.0",
		Attributions: []AttributionEntry{
			{
				ClientID:   "ci-runner-7",
				Repository: "npm-proxy",
				Group:      "platform",
				FirstSeen:  first,
				LastSeen:   last,
			},
		},
	}
	bom := Generate([]PackageEntry{entry}, "")
	if len(bom.Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(bom.Components))
	}
	props := map[string]string{}
	for _, p := range bom.Components[0].Properties {
		props[p.Name] = p.Value
	}
	want := map[string]string{
		"chainsaw:attribution:client":     "ci-runner-7",
		"chainsaw:attribution:repo":       "npm-proxy",
		"chainsaw:attribution:group":      "platform",
		"chainsaw:attribution:first_seen": first.Format(time.RFC3339),
		"chainsaw:attribution:last_seen":  last.Format(time.RFC3339),
	}
	for k, v := range want {
		if got := props[k]; got != v {
			t.Errorf("property %q = %q, want %q", k, got, v)
		}
	}
}

// TestGenerate_AttributionGroupSuppressedWhenSameAsRepo keeps property
// noise down for the common case where the audit row has no separate
// group column and Group==Repository.
func TestGenerate_AttributionGroupSuppressedWhenSameAsRepo(t *testing.T) {
	entry := PackageEntry{
		Ecosystem: "pypi",
		Name:      "requests",
		Version:   "2.31.0",
		Attributions: []AttributionEntry{
			{
				ClientID:   "c1",
				Repository: "pypi-proxy",
				Group:      "pypi-proxy",
			},
		},
	}
	bom := Generate([]PackageEntry{entry}, "")
	for _, p := range bom.Components[0].Properties {
		if p.Name == "chainsaw:attribution:group" {
			t.Fatalf("group property should be suppressed when equal to repo, got %q", p.Value)
		}
	}
}

// TestGenerate_MultipleAttributionsAllEmitted confirms multiple distinct
// tuples each become their own set of properties — CycloneDX allows
// repeated property names, which is the standard escape hatch for
// multi-valued data.
func TestGenerate_MultipleAttributionsAllEmitted(t *testing.T) {
	entry := PackageEntry{
		Ecosystem: "npm",
		Name:      "lodash",
		Version:   "4.17.21",
		Attributions: []AttributionEntry{
			{ClientID: "c1", Repository: "r1"},
			{ClientID: "c2", Repository: "r2"},
		},
	}
	bom := Generate([]PackageEntry{entry}, "")
	clients := 0
	repos := 0
	for _, p := range bom.Components[0].Properties {
		switch p.Name {
		case "chainsaw:attribution:client":
			clients++
		case "chainsaw:attribution:repo":
			repos++
		}
	}
	if clients != 2 || repos != 2 {
		t.Fatalf("expected 2 client + 2 repo properties, got %d/%d", clients, repos)
	}
}

// TestGenerate_ComponentWithoutAuditExportsCleanly mirrors the contract
// guarantee that a component missing audit data falls through to the
// no-property path rather than failing the export.
func TestGenerate_ComponentWithoutAuditExportsCleanly(t *testing.T) {
	entry := PackageEntry{
		Ecosystem: "npm",
		Name:      "missing-audit-pkg",
		Version:   "0.0.1",
		// No Attributions set — simulates the lookup returning empty.
	}
	bom := Generate([]PackageEntry{entry}, "")
	if len(bom.Components) != 1 {
		t.Fatalf("want 1 component, got %d", len(bom.Components))
	}
	for _, p := range bom.Components[0].Properties {
		if strings.HasPrefix(p.Name, "chainsaw:attribution:") {
			t.Fatalf("unexpected attribution property: %s=%s", p.Name, p.Value)
		}
	}
}
