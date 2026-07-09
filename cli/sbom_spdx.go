package cli

// sbom_spdx.go — client-side SPDX 2.3 rendering for `chainsaw sbom export
// --format spdx` (P2.11).
//
// The server renders SBOMs in CycloneDX only. Rather than wait on a server-side
// SPDX generator, we fetch the canonical CycloneDX document the server already
// produces and project it into a tag-value-equivalent SPDX 2.3 JSON document.
// The mapping is intentionally lossless for the fields SPDX and CycloneDX both
// model (component identity, version, hashes, license, PURL) and uses SPDX's
// NOASSERTION sentinel everywhere CycloneDX is silent, so the output validates
// against the SPDX 2.3 schema without inventing data.
//
// Conversion is a pure function (cycloneDXToSPDX) over an already-parsed
// sbom.CycloneDXBOM, which keeps it unit-testable with no network or server.

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/chain305/chainsaw-core/sbom"
)

// SPDX 2.3 constants. dataLicense is fixed to CC0-1.0 by the spec (§6.2); any
// other value makes the document non-conformant.
const (
	spdxVersion        = "SPDX-2.3"
	spdxDataLicense    = "CC0-1.0"
	spdxNoAssertion    = "NOASSERTION"
	spdxDocumentSPDXID = "SPDXRef-DOCUMENT"
	spdxDocumentName   = "chainsaw-sbom"
)

// spdxDocument is the top-level SPDX 2.3 JSON document. Field names and casing
// follow the SPDX 2.3 JSON schema exactly — consumers (Syft, Trivy, the SPDX
// online validator) key off these literal names.
type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

// spdxCreationInfo records who/what/when produced the document (SPDX §6.8–6.10).
type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// spdxPackage is one SPDX package (§7). downloadLocation is required and set to
// NOASSERTION because the proxy-side SBOM does not carry a fetch URL.
type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	Checksums        []spdxChecksum    `json:"checksums,omitempty"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

// spdxChecksum mirrors SPDX §7.10. algorithm uses SPDX's uppercase, dashless
// form (SHA256), distinct from CycloneDX's "SHA-256".
type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// spdxExternalRef carries the PURL as a PACKAGE-MANAGER/purl reference (§7.21),
// the SPDX-canonical way to attach a Package URL.
type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// spdxRelationship models SPDX §11. We emit the required DESCRIBES edges from
// the document to each package so the graph has a defined root.
type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// spdxIDSanitizeRe strips characters not allowed in an SPDX element id. Per the
// spec an SPDXRef id may contain only letters, digits, ".", and "-"; anything
// else (scopes, slashes, "@") is replaced with "-" so ids stay valid and
// dereferenceable.
var spdxIDSanitizeRe = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// cycloneDXToSPDX projects a parsed CycloneDX 1.6 BOM into an SPDX 2.3 document.
//
// Pure and deterministic: no clock, no network. The document timestamp and the
// per-package data come straight from the input BOM, so the same CycloneDX
// input always yields byte-identical SPDX output (important for diffing and for
// the tests). namespaceSeed makes the documentNamespace stable yet unique per
// content — we hash the serial number (or, when absent, the component set) so a
// regenerated SBOM with the same content keeps the same namespace.
func cycloneDXToSPDX(bom *sbom.CycloneDXBOM) *spdxDocument {
	created := strings.TrimSpace(bom.Metadata.Timestamp)
	if created == "" {
		// SPDX requires a created timestamp; fall back to the SPDX zero-ish
		// sentinel rather than emitting an empty (invalid) field.
		created = "1970-01-01T00:00:00Z"
	}

	creators := spdxCreatorsFromTools(bom.Metadata.Tools)

	packages := make([]spdxPackage, 0, len(bom.Components))
	relationships := make([]spdxRelationship, 0, len(bom.Components))
	usedIDs := make(map[string]int, len(bom.Components))

	for _, c := range bom.Components {
		id := uniqueSPDXID(spdxPackageID(c.Name, c.Version), usedIDs)

		pkg := spdxPackage{
			SPDXID:           id,
			Name:             c.Name,
			VersionInfo:      c.Version,
			DownloadLocation: spdxNoAssertion,
			FilesAnalyzed:    false,
			LicenseConcluded: spdxNoAssertion,
			LicenseDeclared:  spdxLicense(c.Licenses),
			CopyrightText:    spdxNoAssertion,
			Checksums:        spdxChecksums(c.Hashes),
		}
		if c.PURL != "" {
			pkg.ExternalRefs = []spdxExternalRef{{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  c.PURL,
			}}
		}
		packages = append(packages, pkg)

		// The document DESCRIBES each top-level package (SPDX §11.1). This
		// gives the relationship graph a defined root so validators don't warn
		// about orphaned packages.
		relationships = append(relationships, spdxRelationship{
			SPDXElementID:      spdxDocumentSPDXID,
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: id,
		})
	}

	return &spdxDocument{
		SPDXVersion:       spdxVersion,
		DataLicense:       spdxDataLicense,
		SPDXID:            spdxDocumentSPDXID,
		Name:              spdxDocumentName,
		DocumentNamespace: spdxNamespace(bom),
		CreationInfo: spdxCreationInfo{
			Created:  created,
			Creators: creators,
		},
		Packages:      packages,
		Relationships: relationships,
	}
}

// spdxCreatorsFromTools maps CycloneDX metadata.tools[] onto SPDX creators[].
// SPDX requires at least one creator; we always include the Tool: entry for
// chainsaw so the document is attributable even when the source BOM listed no
// tools.
func spdxCreatorsFromTools(tools []sbom.CycloneDXTool) []string {
	creators := make([]string, 0, len(tools)+1)
	for _, t := range tools {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			continue
		}
		entry := "Tool: " + name
		if v := strings.TrimSpace(t.Version); v != "" {
			entry += "-" + v
		}
		creators = append(creators, entry)
	}
	if len(creators) == 0 {
		creators = append(creators, "Tool: chainsaw")
	}
	return creators
}

// spdxLicense returns the declared license id for an SPDX package from the
// CycloneDX licenses[]. SPDX uses NOASSERTION (not an empty string) to mean
// "license not stated", so an empty CycloneDX license maps to NOASSERTION.
func spdxLicense(licenses []sbom.CycloneDXLicense) string {
	for _, l := range licenses {
		if id := strings.TrimSpace(l.License.ID); id != "" {
			return id
		}
	}
	return spdxNoAssertion
}

// spdxChecksums maps CycloneDX hashes[] to SPDX checksums[], translating the
// algorithm spelling (CycloneDX "SHA-256" → SPDX "SHA256"). Algorithms SPDX
// does not recognize are dropped rather than emitted in an invalid form.
func spdxChecksums(hashes []sbom.CycloneDXHash) []spdxChecksum {
	if len(hashes) == 0 {
		return nil
	}
	out := make([]spdxChecksum, 0, len(hashes))
	for _, h := range hashes {
		alg := spdxChecksumAlgorithm(h.Algorithm)
		if alg == "" || strings.TrimSpace(h.Content) == "" {
			continue
		}
		out = append(out, spdxChecksum{Algorithm: alg, ChecksumValue: h.Content})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// spdxChecksumAlgorithm translates a CycloneDX hash algorithm to the SPDX 2.3
// checksum algorithm enum. Returns "" for algorithms outside the SPDX set so
// the caller can skip them. CycloneDX writes "SHA-256"; SPDX expects "SHA256".
func spdxChecksumAlgorithm(cdx string) string {
	switch strings.ToUpper(strings.TrimSpace(cdx)) {
	case "SHA-1", "SHA1":
		return "SHA1"
	case "SHA-256", "SHA256":
		return "SHA256"
	case "SHA-384", "SHA384":
		return "SHA384"
	case "SHA-512", "SHA512":
		return "SHA512"
	case "MD5":
		return "MD5"
	default:
		return ""
	}
}

// spdxPackageID builds the per-package SPDXRef id from name + version,
// sanitizing characters the SPDX id grammar forbids.
func spdxPackageID(name, version string) string {
	base := name
	if version != "" {
		base += "-" + version
	}
	base = spdxIDSanitizeRe.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-")
	if base == "" {
		base = "pkg"
	}
	return "SPDXRef-Package-" + base
}

// uniqueSPDXID guarantees SPDXRef ids are unique within a document. Two
// components with the same name@version (or names that collapse to the same
// sanitized id) would otherwise collide; we suffix "-2", "-3", … on repeats.
func uniqueSPDXID(id string, used map[string]int) string {
	n := used[id]
	used[id] = n + 1
	if n == 0 {
		return id
	}
	return fmt.Sprintf("%s-%d", id, n+1)
}

// spdxNamespace returns a stable, content-derived documentNamespace URI. SPDX
// §6.5 requires a unique namespace; deriving it from the BOM's serial number
// (or a hash of the component set when no serial is present) keeps it unique
// per content without a random UUID, so regenerating an unchanged SBOM yields
// the same namespace and the output stays diff-stable.
func spdxNamespace(bom *sbom.CycloneDXBOM) string {
	seed := strings.TrimSpace(bom.SerialNumber)
	if seed == "" {
		var b strings.Builder
		comps := make([]string, 0, len(bom.Components))
		for _, c := range bom.Components {
			comps = append(comps, c.PURL+"|"+c.Name+"@"+c.Version)
		}
		sort.Strings(comps)
		for _, s := range comps {
			b.WriteString(s)
			b.WriteByte('\n')
		}
		sum := sha256.Sum256([]byte(b.String()))
		seed = encodeHexLower(sum[:])
	}
	seed = spdxIDSanitizeRe.ReplaceAllString(seed, "-")
	return "https://chain305.com/spdx/" + spdxDocumentName + "-" + seed
}
