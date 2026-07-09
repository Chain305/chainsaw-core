package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/sbom"
)

// sampleCDX builds a small CycloneDX 1.6 BOM with two components — one fully
// populated (hash + license + purl) and one minimal — so the SPDX projection is
// exercised across the "rich" and "sparse" paths in one document.
func sampleCDX() *sbom.CycloneDXBOM {
	return &sbom.CycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		Version:      1,
		SerialNumber: "urn:uuid:1111-2222",
		Metadata: sbom.CycloneDXMetadata{
			Timestamp: "2026-07-01T00:00:00Z",
			Tools: []sbom.CycloneDXTool{
				{Vendor: "chainsaw", Name: "chainsaw-proxy", Version: "1.0.0"},
			},
		},
		Components: []sbom.CycloneDXComponent{
			{
				Type:    "library",
				Name:    "lodash",
				Version: "4.17.21",
				PURL:    "pkg:npm/lodash@4.17.21",
				Hashes: []sbom.CycloneDXHash{
					{Algorithm: "SHA-256", Content: "abc123"},
				},
				Licenses: []sbom.CycloneDXLicense{
					{License: sbom.CycloneDXLicenseID{ID: "MIT"}},
				},
			},
			{
				Type:    "library",
				Name:    "left-pad",
				Version: "1.3.0",
			},
		},
	}
}

// TestCycloneDXToSPDX_DocumentShape pins the required SPDX 2.3 top-level fields:
// version literal, fixed CC0-1.0 data license, the document SPDXID, and a
// creationInfo with a creator. These are the fields the SPDX schema and the
// online validator hard-require.
func TestCycloneDXToSPDX_DocumentShape(t *testing.T) {
	doc := cycloneDXToSPDX(sampleCDX())

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("spdxVersion = %q, want SPDX-2.3", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("dataLicense = %q, want CC0-1.0", doc.DataLicense)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %q, want SPDXRef-DOCUMENT", doc.SPDXID)
	}
	if doc.CreationInfo.Created != "2026-07-01T00:00:00Z" {
		t.Errorf("created = %q, want carried from CycloneDX timestamp", doc.CreationInfo.Created)
	}
	if len(doc.CreationInfo.Creators) == 0 {
		t.Fatal("creationInfo.creators must be non-empty (SPDX requires >=1)")
	}
	if !strings.HasPrefix(doc.CreationInfo.Creators[0], "Tool:") {
		t.Errorf("creator[0] = %q, want a Tool: entry", doc.CreationInfo.Creators[0])
	}
	if !strings.HasPrefix(doc.DocumentNamespace, "https://") {
		t.Errorf("documentNamespace = %q, want an absolute URI", doc.DocumentNamespace)
	}
}

// TestCycloneDXToSPDX_Packages verifies per-package projection: identity,
// version, the PURL externalRef, the translated checksum algorithm (SHA-256 ->
// SHA256), the declared license, and the NOASSERTION sentinels SPDX requires
// where CycloneDX is silent.
func TestCycloneDXToSPDX_Packages(t *testing.T) {
	doc := cycloneDXToSPDX(sampleCDX())

	if len(doc.Packages) != 2 {
		t.Fatalf("packages = %d, want 2", len(doc.Packages))
	}

	lodash := doc.Packages[0]
	if lodash.Name != "lodash" || lodash.VersionInfo != "4.17.21" {
		t.Errorf("lodash identity drift: %+v", lodash)
	}
	if lodash.DownloadLocation != "NOASSERTION" {
		t.Errorf("downloadLocation = %q, want NOASSERTION", lodash.DownloadLocation)
	}
	if lodash.LicenseDeclared != "MIT" {
		t.Errorf("licenseDeclared = %q, want MIT", lodash.LicenseDeclared)
	}
	if lodash.LicenseConcluded != "NOASSERTION" {
		t.Errorf("licenseConcluded = %q, want NOASSERTION", lodash.LicenseConcluded)
	}
	if len(lodash.Checksums) != 1 || lodash.Checksums[0].Algorithm != "SHA256" ||
		lodash.Checksums[0].ChecksumValue != "abc123" {
		t.Errorf("checksum projection wrong: %+v", lodash.Checksums)
	}
	if len(lodash.ExternalRefs) != 1 ||
		lodash.ExternalRefs[0].ReferenceType != "purl" ||
		lodash.ExternalRefs[0].ReferenceLocator != "pkg:npm/lodash@4.17.21" {
		t.Errorf("purl externalRef wrong: %+v", lodash.ExternalRefs)
	}
	if !strings.HasPrefix(lodash.SPDXID, "SPDXRef-Package-") {
		t.Errorf("package SPDXID = %q, want SPDXRef-Package- prefix", lodash.SPDXID)
	}

	// Sparse component: no hash, no license, no purl. Must still be valid —
	// license falls back to NOASSERTION, no checksums/externalRefs emitted.
	leftpad := doc.Packages[1]
	if leftpad.LicenseDeclared != "NOASSERTION" {
		t.Errorf("sparse licenseDeclared = %q, want NOASSERTION", leftpad.LicenseDeclared)
	}
	if len(leftpad.Checksums) != 0 {
		t.Errorf("sparse package should have no checksums, got %+v", leftpad.Checksums)
	}
	if len(leftpad.ExternalRefs) != 0 {
		t.Errorf("sparse package should have no externalRefs, got %+v", leftpad.ExternalRefs)
	}
}

// TestCycloneDXToSPDX_Relationships checks every package gets a DESCRIBES edge
// from the document root, so the SPDX relationship graph has a defined root.
func TestCycloneDXToSPDX_Relationships(t *testing.T) {
	doc := cycloneDXToSPDX(sampleCDX())
	if len(doc.Relationships) != len(doc.Packages) {
		t.Fatalf("relationships = %d, want one DESCRIBES per package (%d)",
			len(doc.Relationships), len(doc.Packages))
	}
	for i, r := range doc.Relationships {
		if r.SPDXElementID != "SPDXRef-DOCUMENT" {
			t.Errorf("rel[%d].spdxElementId = %q, want SPDXRef-DOCUMENT", i, r.SPDXElementID)
		}
		if r.RelationshipType != "DESCRIBES" {
			t.Errorf("rel[%d].relationshipType = %q, want DESCRIBES", i, r.RelationshipType)
		}
		if r.RelatedSPDXElement != doc.Packages[i].SPDXID {
			t.Errorf("rel[%d] relatedSpdxElement = %q, want %q",
				i, r.RelatedSPDXElement, doc.Packages[i].SPDXID)
		}
	}
}

// TestCycloneDXToSPDX_JSONKeys serializes the document and asserts the literal
// JSON key names downstream SPDX consumers pin on — a struct-tag typo would
// silently break Syft/Trivy/the SPDX validator, so this catches it.
func TestCycloneDXToSPDX_JSONKeys(t *testing.T) {
	doc := cycloneDXToSPDX(sampleCDX())
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)
	for _, key := range []string{
		`"spdxVersion":"SPDX-2.3"`,
		`"dataLicense":"CC0-1.0"`,
		`"SPDXID":"SPDXRef-DOCUMENT"`,
		`"documentNamespace":`,
		`"creationInfo":`,
		`"packages":`,
		`"relationships":`,
		`"downloadLocation":"NOASSERTION"`,
		`"referenceType":"purl"`,
		`"relationshipType":"DESCRIBES"`,
	} {
		if !strings.Contains(s, key) {
			t.Errorf("SPDX JSON missing %s\nfull:\n%s", key, s)
		}
	}
}

// TestCycloneDXToSPDX_Deterministic confirms the converter is pure: the same
// input yields byte-identical output across calls (no clock, no UUID), which
// the namespace/diff-stability contract depends on.
func TestCycloneDXToSPDX_Deterministic(t *testing.T) {
	a, _ := json.Marshal(cycloneDXToSPDX(sampleCDX()))
	b, _ := json.Marshal(cycloneDXToSPDX(sampleCDX()))
	if string(a) != string(b) {
		t.Errorf("SPDX conversion not deterministic:\nA: %s\nB: %s", a, b)
	}
}

// TestCycloneDXToSPDX_UniqueIDs guards SPDXRef id uniqueness when two components
// share name@version (duplicate ids make the document invalid).
func TestCycloneDXToSPDX_UniqueIDs(t *testing.T) {
	bom := &sbom.CycloneDXBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Metadata:    sbom.CycloneDXMetadata{Timestamp: "2026-07-01T00:00:00Z"},
		Components: []sbom.CycloneDXComponent{
			{Name: "dup", Version: "1.0.0"},
			{Name: "dup", Version: "1.0.0"},
		},
	}
	doc := cycloneDXToSPDX(bom)
	if doc.Packages[0].SPDXID == doc.Packages[1].SPDXID {
		t.Errorf("duplicate SPDXID %q for same-coordinate components", doc.Packages[0].SPDXID)
	}
}

// TestSPDXChecksumAlgorithm covers the CycloneDX->SPDX algorithm spelling map,
// including the dropped (empty) case for unknown algorithms.
func TestSPDXChecksumAlgorithm(t *testing.T) {
	cases := map[string]string{
		"SHA-256": "SHA256",
		"sha256":  "SHA256",
		"SHA-1":   "SHA1",
		"SHA-512": "SHA512",
		"MD5":     "MD5",
		"BLAKE3":  "", // unknown -> dropped
		"":        "",
	}
	for in, want := range cases {
		if got := spdxChecksumAlgorithm(in); got != want {
			t.Errorf("spdxChecksumAlgorithm(%q) = %q, want %q", in, got, want)
		}
	}
}
