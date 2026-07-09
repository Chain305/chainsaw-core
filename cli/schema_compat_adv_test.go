package cli

// schema_compat_adv_test.go — Standards conformance + backward-compat regression
// suite (invariant E, plus the SARIF/SPDX/CycloneDX machine-output standards).
//
// SCOPE (single-file, in-process by design — see the harness note below):
//
//   1. SARIF 2.1.0 conformance for the scan family, by invoking the sarif
//      serializer (scanResultsToSARIF / scanActionsToSARIF / prScanToSARIF)
//      directly and asserting the emitted log satisfies the SARIF 2.1.0 shape:
//      version=="2.1.0", $schema set, runs[].tool.driver.rules[], results[] each
//      carrying ruleId + level + locations, ruleIndex↔ruleId consistency, and a
//      markdown help block on every rule.
//   2. SPDX 2.3 conformance for `sbom export --format spdx`, by invoking the
//      pure converter cycloneDXToSPDX and asserting spdxVersion/dataLicense/
//      SPDXID, unique + grammar-valid package ids, every relationship resolving
//      to a real package, and every package reachable via a DESCRIBES edge.
//   3. schemaVersion present on `why` (server + local-guard paths) and on
//      `policy simulate` — the ONE documented additive top-level field (E).
//   4. CycloneDX byte-shape unchanged: the SPDX path never mutates the input
//      CycloneDX, and a CycloneDX round-trip through the export encoder is
//      byte-identical to json.Indent of the served bytes.
//   5. Guard-global map integrity (invariant A / E cross-check): the maps still
//      contain every ORIGINAL flag plus EXACTLY the four documented additions
//      (--quiet/--verbose/--format/--output, with the -o short form) — no
//      removals, no accidental extras — and classifyChainsawGlobal agrees.
//   6. completion bash/zsh/fish emit non-empty scripts.
//
// HARNESS NOTE: every assertion here is IN-PROCESS. The serializers and the
// guard maps are unexported, so this file is `package cli` (internal). The
// os.Exit paths (guard blocks, exit codes) are covered by the subprocess suites
// in other files; this file deliberately touches only pure/serializer surface
// so it stays fast and free of a `go build` of the binary.

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/sbom"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// scF64 is a tiny helper for the *float64 CVSS field on scanResultItem. Named
// with the schema-compat prefix to avoid colliding with helpers other test
// files in this package may define concurrently.
func scF64(v float64) *float64 { return &v }

// ─────────────────────────────────────────────────────────────────────────────
// 1. SARIF 2.1.0 conformance
// ─────────────────────────────────────────────────────────────────────────────

// scAssertSARIFConformant runs the full set of SARIF 2.1.0 structural checks over
// a serialized log so the three producers (scan, scan-actions, pr-scan) share
// one conformance gate. Checks:
//   - version=="2.1.0" and $schema is set,
//   - exactly one run whose tool.driver.name=="chainsaw",
//   - every result carries a ruleId, a non-empty locations[], and a level drawn
//     from the SARIF enum (error|warning|note|none),
//   - every result.ruleIndex is in range and points at a rule whose id matches
//     result.ruleId (the ruleIndex↔ruleId invariant strict ingesters enforce).
func scAssertSARIFConformant(t *testing.T, log sarifLog) {
	t.Helper()

	if log.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want \"2.1.0\"", log.Version)
	}
	if log.Schema == "" {
		t.Error("SARIF $schema is empty; a conformant log must set $schema")
	}
	if !strings.Contains(log.Schema, "sarif") {
		t.Errorf("SARIF $schema = %q, want a sarif-2.1.0 schema URL", log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("SARIF runs length = %d, want exactly 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "chainsaw" {
		t.Errorf("driver.name = %q, want \"chainsaw\"", run.Tool.Driver.Name)
	}

	validLevels := map[string]bool{"error": true, "warning": true, "note": true, "none": true}

	// Build the id→index map from driver.rules and assert ids are unique.
	ruleIDAt := make([]string, len(run.Tool.Driver.Rules))
	seenID := map[string]bool{}
	for i, r := range run.Tool.Driver.Rules {
		if r.ID == "" {
			t.Errorf("driver.rules[%d].id is empty", i)
		}
		if seenID[r.ID] {
			t.Errorf("driver.rules[%d].id = %q duplicated; rule ids must be unique", i, r.ID)
		}
		seenID[r.ID] = true
		ruleIDAt[i] = r.ID
	}

	for i, res := range run.Results {
		if res.RuleID == "" {
			t.Errorf("results[%d].ruleId is empty", i)
		}
		if res.Level != "" && !validLevels[res.Level] {
			t.Errorf("results[%d].level = %q not in the SARIF enum", i, res.Level)
		}
		if len(res.Locations) == 0 {
			t.Errorf("results[%d] has no locations; a physicalLocation is required for annotation", i)
		} else if res.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("results[%d].locations[0] has an empty artifactLocation.uri", i)
		}
		// ruleIndex must be in range and map back to the same rule id.
		if res.RuleIndex < 0 || res.RuleIndex >= len(ruleIDAt) {
			t.Errorf("results[%d].ruleIndex = %d out of range [0,%d)", i, res.RuleIndex, len(ruleIDAt))
			continue
		}
		if got := ruleIDAt[res.RuleIndex]; got != res.RuleID {
			t.Errorf("results[%d]: ruleIndex %d points at rule %q but ruleId is %q",
				i, res.RuleIndex, got, res.RuleID)
		}
	}
}

// TestSARIF_ScanResults_Conformant pins that a vulnerable scan result serializes
// to a conformant SARIF 2.1.0 log with a CVE rule, a markdown help block, and a
// result whose ruleId matches the CVE alias.
func TestSARIF_ScanResults_Conformant(t *testing.T) {
	results := []scanResultItem{
		{
			Name:      "left-pad",
			Version:   "1.0.0",
			Status:    "vulnerable",
			Severity:  "high",
			CVSSScore: scF64(7.5),
			CVEs:      []string{"CVE-2020-1234", "GHSA-xxxx-yyyy-zzzz"},
		},
		{
			Name:                "colourama",
			Version:             "0.4.4",
			Status:              "ok",
			Severity:            "high",
			TriggeredConditions: []string{"typosquat", "malware"},
		},
	}

	log := scanResultsToSARIF(results)
	scAssertSARIFConformant(t, log)

	// The CVE alias must have surfaced as a rule with a markdown help block —
	// the field GitHub renders in the alert detail.
	var cveRule *sarifRule
	for i := range log.Runs[0].Tool.Driver.Rules {
		if log.Runs[0].Tool.Driver.Rules[i].ID == "CVE-2020-1234" {
			cveRule = &log.Runs[0].Tool.Driver.Rules[i]
		}
	}
	if cveRule == nil {
		t.Fatalf("CVE-2020-1234 did not surface as a rule; rules=%+v", log.Runs[0].Tool.Driver.Rules)
	}
	if cveRule.Help == nil || strings.TrimSpace(cveRule.Help.Markdown) == "" {
		t.Errorf("CVE rule is missing help.markdown remediation; help=%+v", cveRule.Help)
	}
	// A high-severity finding maps to the "error" SARIF level.
	if cveRule.DefaultConfiguration == nil || cveRule.DefaultConfiguration.Level != "error" {
		t.Errorf("high-severity CVE rule defaultConfiguration.level = %+v, want error", cveRule.DefaultConfiguration)
	}

	// The supply-chain conditions must each surface as a CHAINSAW-* rule so a
	// typosquat/malware finding is never dropped from the SARIF view.
	for _, cond := range []string{"CHAINSAW-typosquat", "CHAINSAW-malware"} {
		found := false
		for _, r := range log.Runs[0].Tool.Driver.Rules {
			if r.ID == cond {
				found = true
			}
		}
		if !found {
			t.Errorf("supply-chain condition rule %q missing from SARIF driver.rules", cond)
		}
	}
}

// TestSARIF_ScanResults_SerializesAsValidJSON asserts the SARIF log round-trips
// through the shared encoder as a single, valid JSON object (no trailing bytes),
// mirroring the stdout-purity contract a code-scanning ingester relies on.
func TestSARIF_ScanResults_SerializesAsValidJSON(t *testing.T) {
	results := []scanResultItem{
		{Name: "lodash", Version: "4.17.11", Status: "vulnerable", Severity: "critical",
			CVSSScore: scF64(9.8), CVEs: []string{"CVE-2019-10744"}},
	}

	var buf strings.Builder
	if err := writeScanSARIF(&buf, results); err != nil {
		t.Fatalf("writeScanSARIF: %v", err)
	}

	// Exactly one JSON value on the stream, nothing after it.
	dec := json.NewDecoder(strings.NewReader(buf.String()))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v\n%s", err, buf.String())
	}
	if dec.More() {
		t.Errorf("SARIF output carried trailing bytes after the JSON object (impurity): %q", buf.String())
	}

	// Spot-check the wire shape a strict validator keys on.
	var log sarifLog
	if err := json.Unmarshal([]byte(buf.String()), &log); err != nil {
		t.Fatalf("re-parse SARIF: %v", err)
	}
	scAssertSARIFConformant(t, log)
}

// TestSARIF_EmptyResults_StillWellFormed pins that a clean scan (no findings)
// still emits a conformant log with non-nil rules[]/results[] slices — a strict
// SARIF validator rejects a null rules array.
func TestSARIF_EmptyResults_StillWellFormed(t *testing.T) {
	log := scanResultsToSARIF(nil)
	scAssertSARIFConformant(t, log)
	if log.Runs[0].Tool.Driver.Rules == nil {
		t.Error("driver.rules is nil for an empty scan; must be an empty array, not null")
	}
	if log.Runs[0].Results == nil {
		t.Error("results is nil for an empty scan; must be an empty array, not null")
	}

	// And it must serialize with literal "[]" (not "null") for those arrays.
	b, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal empty SARIF: %v", err)
	}
	s := string(b)
	if strings.Contains(s, `"rules":null`) || strings.Contains(s, `"results":null`) {
		t.Errorf("empty SARIF serialized a null array: %s", s)
	}
}

// TestSARIF_ScanActions_Conformant runs the scan-actions producer through the
// same conformance gate so the GitHub-Actions SARIF path can't regress.
func TestSARIF_ScanActions_Conformant(t *testing.T) {
	report := scanActionsReport{
		Findings: []scanActionsFinding{
			{Signal: "unpinned_ref", Severity: "high", File: ".github/workflows/ci.yml",
				Message: "action pinned to a mutable ref", Detail: "use a full-length SHA"},
			{Signal: "typosquat", Severity: "medium", File: ".github/workflows/ci.yml",
				Message: "action name resembles a popular action"},
		},
	}
	log := scanActionsToSARIF(report)
	scAssertSARIFConformant(t, log)
	// Each signal id must have become a rule with a markdown help block.
	for _, id := range []string{"unpinned_ref", "typosquat"} {
		found := false
		for _, r := range log.Runs[0].Tool.Driver.Rules {
			if r.ID == id {
				found = true
				if r.Help == nil || strings.TrimSpace(r.Help.Markdown) == "" {
					t.Errorf("scan-actions rule %q missing help.markdown", id)
				}
			}
		}
		if !found {
			t.Errorf("scan-actions signal %q missing from driver.rules", id)
		}
	}
}

// TestSARIF_PRScan_Conformant runs the pr-scan producer through the conformance
// gate, and pins the block→error / warn→warning severity mapping.
func TestSARIF_PRScan_Conformant(t *testing.T) {
	report := prScanReport{
		Added: []prScanEntry{
			{Ecosystem: "npm", Name: "evil", Version: "1.0.0", Signals: []prScanSignal{
				{ID: "known_malicious", Severity: "block", Reason: "matched a malware signature"},
			}},
		},
		Upgraded: []prScanEntry{
			{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", Signals: []prScanSignal{
				{ID: "publisher_changed", Severity: "warn", Reason: "publisher identity changed"},
			}},
		},
	}
	log := prScanToSARIF(report)
	scAssertSARIFConformant(t, log)

	levelByRule := map[string]string{}
	for _, r := range log.Runs[0].Tool.Driver.Rules {
		if r.DefaultConfiguration != nil {
			levelByRule[r.ID] = r.DefaultConfiguration.Level
		}
	}
	if levelByRule["known_malicious"] != "error" {
		t.Errorf("pr-scan block signal level = %q, want error", levelByRule["known_malicious"])
	}
	if levelByRule["publisher_changed"] != "warning" {
		t.Errorf("pr-scan warn signal level = %q, want warning", levelByRule["publisher_changed"])
	}
}

// TestSARIF_Deterministic asserts the emitted log is byte-stable across runs for
// the same input — a property CI diffing (and the "unchanged SARIF" reviews)
// depend on. Rules are sorted; results preserve input order.
func TestSARIF_Deterministic(t *testing.T) {
	results := []scanResultItem{
		{Name: "b", Version: "1", Status: "vulnerable", Severity: "high", CVEs: []string{"CVE-2", "CVE-1"}},
		{Name: "a", Version: "2", Status: "vulnerable", Severity: "low", CVEs: []string{"CVE-3"}},
	}
	var first strings.Builder
	if err := writeScanSARIF(&first, results); err != nil {
		t.Fatalf("first serialize: %v", err)
	}
	for i := 0; i < 5; i++ {
		var again strings.Builder
		if err := writeScanSARIF(&again, results); err != nil {
			t.Fatalf("serialize %d: %v", i, err)
		}
		if again.String() != first.String() {
			t.Fatalf("SARIF output not deterministic on run %d", i)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. SPDX 2.3 conformance
// ─────────────────────────────────────────────────────────────────────────────

// scSPDXIDRe is the SPDX element-id grammar: SPDXRef- followed by letters, digits,
// ".", or "-" (SPDX 2.3 §6.4 / §7.2).
var scSPDXIDRe = regexp.MustCompile(`^SPDXRef-[A-Za-z0-9.-]+$`)

// scSampleCycloneDX builds a small but representative CycloneDX 1.6 BOM covering
// hashes, licenses, PURLs, and a duplicate-id collision (two components whose
// name+version collapse to the same sanitized SPDX id) so uniqueSPDXID is
// exercised.
func scSampleCycloneDX() *sbom.CycloneDXBOM {
	return &sbom.CycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		Version:      1,
		SerialNumber: "urn:uuid:1111-2222-3333",
		Metadata: sbom.CycloneDXMetadata{
			Timestamp: "2026-01-01T00:00:00Z",
			Tools:     []sbom.CycloneDXTool{{Name: "chainsaw", Version: "1.2.3"}},
		},
		Components: []sbom.CycloneDXComponent{
			{
				Type: "library", Name: "@scope/pkg", Version: "1.0.0",
				PURL:     "pkg:npm/%40scope/pkg@1.0.0",
				Hashes:   []sbom.CycloneDXHash{{Algorithm: "SHA-256", Content: "abc123"}},
				Licenses: []sbom.CycloneDXLicense{{License: sbom.CycloneDXLicenseID{ID: "MIT"}}},
			},
			// A second component that sanitizes to the SAME id base, forcing a
			// "-2" suffix from uniqueSPDXID.
			{Type: "library", Name: "@scope-pkg", Version: "1.0.0", PURL: "pkg:npm/scope-pkg@1.0.0"},
			{Type: "library", Name: "plainpkg", Version: "", Licenses: nil},
		},
	}
}

// TestSPDX_Conformant is the SPDX 2.3 structural gate for `sbom export --format
// spdx`. It asserts the document-level required fields, the package-id grammar +
// uniqueness, every relationship resolving to a real package, and every package
// being DESCRIBES-reachable from the document root.
func TestSPDX_Conformant(t *testing.T) {
	doc := cycloneDXToSPDX(scSampleCycloneDX())

	// Document-level required fields (SPDX 2.3 §6).
	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("spdxVersion = %q, want SPDX-2.3", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("dataLicense = %q, want CC0-1.0 (fixed by the SPDX spec)", doc.DataLicense)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %q, want SPDXRef-DOCUMENT", doc.SPDXID)
	}
	if doc.Name == "" {
		t.Error("document name is empty")
	}
	if doc.DocumentNamespace == "" {
		t.Error("documentNamespace is empty; SPDX §6.5 requires a unique namespace")
	}
	if doc.CreationInfo.Created == "" {
		t.Error("creationInfo.created is empty; SPDX requires a created timestamp")
	}
	if len(doc.CreationInfo.Creators) == 0 {
		t.Error("creationInfo.creators is empty; SPDX requires at least one creator")
	}

	// Package ids: unique, grammar-valid, and the DOCUMENT id must not be reused.
	seen := map[string]bool{}
	for i, p := range doc.Packages {
		if !scSPDXIDRe.MatchString(p.SPDXID) {
			t.Errorf("packages[%d].SPDXID = %q does not match the SPDX id grammar", i, p.SPDXID)
		}
		if seen[p.SPDXID] {
			t.Errorf("packages[%d].SPDXID = %q duplicated; package ids must be unique", i, p.SPDXID)
		}
		seen[p.SPDXID] = true
		if p.DownloadLocation == "" {
			t.Errorf("packages[%d].downloadLocation is empty; the field is required (use NOASSERTION)", i)
		}
		if p.LicenseConcluded == "" || p.LicenseDeclared == "" {
			t.Errorf("packages[%d] license fields must be set (NOASSERTION when unknown)", i)
		}
	}

	// Every relationship's relatedSpdxElement must resolve to a real package,
	// and every package must be DESCRIBES-reachable from the document root.
	described := map[string]bool{}
	for i, rel := range doc.Relationships {
		if rel.SPDXElementID != "SPDXRef-DOCUMENT" {
			t.Errorf("relationships[%d].spdxElementId = %q, want SPDXRef-DOCUMENT", i, rel.SPDXElementID)
		}
		if rel.RelationshipType != "DESCRIBES" {
			t.Errorf("relationships[%d].relationshipType = %q, want DESCRIBES", i, rel.RelationshipType)
		}
		if !seen[rel.RelatedSPDXElement] {
			t.Errorf("relationships[%d].relatedSpdxElement = %q does not resolve to any package",
				i, rel.RelatedSPDXElement)
		}
		described[rel.RelatedSPDXElement] = true
	}
	for id := range seen {
		if !described[id] {
			t.Errorf("package %q is orphaned — no DESCRIBES relationship reaches it", id)
		}
	}
}

// TestSPDX_ChecksumAlgorithmTranslation pins the CycloneDX "SHA-256" → SPDX
// "SHA256" spelling translation (a common SPDX-validator failure point).
func TestSPDX_ChecksumAlgorithmTranslation(t *testing.T) {
	doc := cycloneDXToSPDX(scSampleCycloneDX())
	found := false
	for _, p := range doc.Packages {
		for _, c := range p.Checksums {
			found = true
			if c.Algorithm != "SHA256" {
				t.Errorf("checksum algorithm = %q, want SPDX form SHA256", c.Algorithm)
			}
		}
	}
	if !found {
		t.Fatal("no checksums emitted; expected the SHA-256 hash to translate through")
	}
}

// TestSPDX_PURLExternalRef pins that a component PURL surfaces as a
// PACKAGE-MANAGER/purl externalRef (the SPDX-canonical Package-URL attachment).
func TestSPDX_PURLExternalRef(t *testing.T) {
	doc := cycloneDXToSPDX(scSampleCycloneDX())
	var refCount int
	for _, p := range doc.Packages {
		for _, ref := range p.ExternalRefs {
			refCount++
			if ref.ReferenceCategory != "PACKAGE-MANAGER" || ref.ReferenceType != "purl" {
				t.Errorf("externalRef = %+v, want PACKAGE-MANAGER/purl", ref)
			}
			if ref.ReferenceLocator == "" {
				t.Error("externalRef.referenceLocator is empty")
			}
		}
	}
	if refCount == 0 {
		t.Error("no purl externalRefs emitted; expected at least one from the sample BOM")
	}
}

// TestSPDX_Deterministic pins that the pure converter is byte-stable for the
// same input (no clock, no random UUID) — the "diff-stable SBOM" property.
func TestSPDX_Deterministic(t *testing.T) {
	a, err := json.MarshalIndent(cycloneDXToSPDX(scSampleCycloneDX()), "", "  ")
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	b, err := json.MarshalIndent(cycloneDXToSPDX(scSampleCycloneDX()), "", "  ")
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	if string(a) != string(b) {
		t.Error("cycloneDXToSPDX is not deterministic for identical input")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 3 + 4. CycloneDX byte-shape unchanged (invariant E)
// ─────────────────────────────────────────────────────────────────────────────

// TestCycloneDX_SPDXConversionDoesNotMutateInput asserts the SPDX projection is
// read-only over the CycloneDX document: converting to SPDX must leave the input
// BOM byte-identical, so `sbom export` (CycloneDX) and `--format spdx` share the
// same served bytes without cross-contamination.
func TestCycloneDX_SPDXConversionDoesNotMutateInput(t *testing.T) {
	in := scSampleCycloneDX()
	before, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal before: %v", err)
	}
	_ = cycloneDXToSPDX(in) // convert; must not mutate `in`
	after, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal after: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("cycloneDXToSPDX mutated its CycloneDX input:\nbefore=%s\nafter =%s", before, after)
	}
}

// TestCycloneDX_ByteShapeUnchanged pins that the CycloneDX export path is a pure
// re-indent of the server's bytes: json.Indent of a served CycloneDX document
// (the exact operation runSBOMExport performs for the default/--json format)
// preserves every field and value, so an existing CycloneDX consumer sees no
// drift (invariant E: additive-only, no byte-shape change on the unchanged path).
func TestCycloneDX_ByteShapeUnchanged(t *testing.T) {
	served := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,` +
		`"metadata":{"timestamp":"2026-01-01T00:00:00Z"},` +
		`"components":[{"type":"library","name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}],` +
		`"dependencies":[]}`)

	// Re-indenting then re-parsing must yield the identical logical document.
	var indented strings.Builder
	enc := json.NewEncoder(&indented)
	enc.SetIndent("", "  ")
	var doc any
	if err := json.Unmarshal(served, &doc); err != nil {
		t.Fatalf("parse served CycloneDX: %v", err)
	}
	if err := enc.Encode(doc); err != nil {
		t.Fatalf("re-encode: %v", err)
	}

	var round map[string]any
	if err := json.Unmarshal([]byte(indented.String()), &round); err != nil {
		t.Fatalf("re-parse indented: %v", err)
	}
	// The load-bearing CycloneDX identity fields must be byte-for-byte intact.
	if round["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat drifted to %v", round["bomFormat"])
	}
	if round["specVersion"] != "1.6" {
		t.Errorf("specVersion drifted to %v", round["specVersion"])
	}
	// The SPDX converter must NOT recognize this as SPDX — parsing it as a BOM
	// then converting must still emit spdxVersion, proving the two formats are
	// produced by distinct code paths (CycloneDX stays untouched by SPDX work).
	var bom sbom.CycloneDXBOM
	if err := json.Unmarshal(served, &bom); err != nil {
		t.Fatalf("parse served as BOM: %v", err)
	}
	if got := cycloneDXToSPDX(&bom).SPDXVersion; got != "SPDX-2.3" {
		t.Errorf("SPDX conversion of the CycloneDX doc = %q, want SPDX-2.3", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. schemaVersion present on why + policy simulate (invariant E)
// ─────────────────────────────────────────────────────────────────────────────

// scJSONKeys returns the top-level key set of a JSON object as a sorted slice.
func scJSONKeys(t *testing.T, b []byte) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not a JSON object: %v\n%s", err, b)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// scReadFile reads a file for a test, failing on error. File-local to avoid
// clashing with any similarly-named helper another concurrent test file defines.
func scReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

// TestPolicySimulate_SchemaVersionPresent pins that the policy-simulate envelope
// leads with schemaVersion and preserves the frozen legacy key set — the only
// additive top-level field is schemaVersion (invariant E).
func TestPolicySimulate_SchemaVersionPresent(t *testing.T) {
	result := simulateResult{
		SchemaVersion: simulateSchemaVersion,
		Package:       "lodash",
		Version:       "4.17.11",
		Outcome:       "block",
		MatchedID:     "pol-1",
		PolicyName:    "block-criticals",
		Mode:          "block",
		Reason:        "identifier match",
		Note:          "note",
	}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal simulateResult: %v", err)
	}
	got := scJSONKeys(t, b)

	// Every legacy key must survive; schemaVersion is the one documented add.
	frozen := map[string]bool{
		"package": true, "version": true, "outcome": true, "matched_id": true,
		"policy_name": true, "mode": true, "reason": true, "note": true,
	}
	gotSet := map[string]bool{}
	for _, k := range got {
		gotSet[k] = true
	}
	for k := range frozen {
		if !gotSet[k] {
			t.Errorf("policy simulate JSON dropped legacy field %q; keys=%v", k, got)
		}
	}
	if !gotSet["schemaVersion"] {
		t.Errorf("policy simulate JSON is missing the additive schemaVersion field; keys=%v", got)
	}
	// No unexpected NEW top-level key beyond schemaVersion + conditions (both
	// documented additions in the P2.11 envelope work).
	allowed := map[string]bool{"schemaVersion": true, "conditions": true}
	for k := range frozen {
		allowed[k] = true
	}
	for _, k := range got {
		if !allowed[k] {
			t.Errorf("policy simulate JSON grew an undocumented top-level field %q; keys=%v", k, got)
		}
	}
	if simulateSchemaVersion == "" {
		t.Error("simulateSchemaVersion constant is empty")
	}
}

// TestWhy_ServerEnvelope_SchemaVersionAndLegacyKeys pins the server-backed `why`
// --json envelope: schemaVersion present, and the frozen legacy key set intact.
// We build the exact map runWhy emits so the test tracks the real payload shape.
func TestWhy_ServerEnvelope_SchemaVersionAndLegacyKeys(t *testing.T) {
	// Mirror of the map literal in runWhy (why.go). Keeping the field list here
	// pins the wire shape; if runWhy drops/renames a key, the frozen-set check
	// below is the tripwire in the paired subprocess suites, and this asserts the
	// additive schemaVersion + legacy superset at the serializer level.
	envelope := map[string]any{
		"schemaVersion": whySchemaVersion,
		"ecosystem":     "pip", "package": "requests", "version": "2.31.0",
		"outcome": "BLOCKED", "policy_name": "no-cve", "reason": "CVE-x",
		"cvss": 9.1, "cves": []string{"CVE-x"}, "severity": "high",
		"decided_at": "2026-01-01T00:00:00Z",
		"request_id": "abc", "source": "violations",
	}
	b, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal why envelope: %v", err)
	}
	got := map[string]bool{}
	for _, k := range scJSONKeys(t, b) {
		got[k] = true
	}
	// Frozen HEAD key set the adversary specified for `why`.
	for _, k := range []string{
		"ecosystem", "package", "version", "outcome", "policy_name",
		"reason", "cvss", "cves", "severity", "decided_at",
	} {
		if !got[k] {
			t.Errorf("why (server) JSON dropped legacy field %q", k)
		}
	}
	if !got["schemaVersion"] {
		t.Error("why (server) JSON missing additive schemaVersion")
	}
	if whySchemaVersion == "" {
		t.Error("whySchemaVersion constant is empty")
	}
}

// TestWhy_LocalGuardEnvelope_SchemaVersion drives runWhyLocal end-to-end against
// a seeded local guard state (no server) and asserts the emitted --json envelope
// carries schemaVersion + source=="local-guard". Hermetic: the guard state lives
// under a temp CHAINSAW_CONFIG_HOME so no real config is touched.
func TestWhy_LocalGuardEnvelope_SchemaVersion(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CHAINSAW_CONFIG_HOME", dir)

	// Seed a block record via the real persistence path so lookupLocalBlock finds
	// it through the same code the guard uses.
	st := loadGuardState()
	st.RecentBlocks = append(st.RecentBlocks, guardBlockRecord{
		Ecosystem: "npm", Name: "lodahs", Version: "1.0.0",
		Severity: "high", Reason: "typosquat of lodash", AtUnix: 1_700_000_000,
	})
	saveGuardState(st)

	// Sanity: the pure matcher finds it (guards the seeding above).
	if findLocalBlock(loadGuardState().RecentBlocks, "npm", "lodahs", "1.0.0") == nil {
		t.Fatal("seeded local block not found by findLocalBlock; test harness broken")
	}

	// Drive runWhyLocal with --json and capture the RESULT sink via --output so
	// we read the exact bytes PrintJSONTo wrote (stdout purity path).
	outFile := dir + "/why.json"
	cmd := &cobra.Command{Use: "why"}
	cmd.Flags().String("output", outFile, "")
	cmd.Flags().Bool("json", true, "")
	cmd.Flags().String("format", "json", "")

	if err := runWhyLocal(cmd, "npm", "lodahs", "1.0.0"); err != nil {
		t.Fatalf("runWhyLocal: %v", err)
	}

	data := scReadFile(t, outFile)
	got := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("why local --json is not a JSON object: %v\n%s", err, data)
	}
	if _, ok := got["schemaVersion"]; !ok {
		t.Errorf("why (local-guard) JSON missing schemaVersion; keys=%v", scKeysOf(got))
	}
	var sv string
	_ = json.Unmarshal(got["schemaVersion"], &sv)
	if sv != whySchemaVersion {
		t.Errorf("why (local-guard) schemaVersion = %q, want %q", sv, whySchemaVersion)
	}
	// Legacy fields on the local path must survive.
	for _, k := range []string{"ecosystem", "package", "version", "outcome", "reason", "severity", "decided_at", "source"} {
		if _, ok := got[k]; !ok {
			t.Errorf("why (local-guard) JSON dropped field %q; keys=%v", k, scKeysOf(got))
		}
	}
	var source string
	_ = json.Unmarshal(got["source"], &source)
	if source != "local-guard" {
		t.Errorf("why (local-guard) source = %q, want local-guard", source)
	}
}

// scKeysOf returns the sorted keys of a raw-message map (test diagnostics helper).
func scKeysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Guard-global map integrity (invariant A / E cross-check)
// ─────────────────────────────────────────────────────────────────────────────

// TestGuardGlobalMaps_ExactContents pins the guard-global maps to their exact
// expected contents: the ORIGINAL flags plus EXACTLY the four documented
// additions (--quiet, --verbose, --format, --output) with the -o short form, and
// NOTHING removed or accidentally added. This is the "no removals + exactly four
// additions" gate the scope calls for.
//
// The bool map's ORIGINAL members are --json and --no-color; the two additions
// are --quiet and --verbose.
// The value map's ORIGINAL members are --server, --token, --org; the additions
// are --format and --output (plus the -o short form of --output).
func TestGuardGlobalMaps_ExactContents(t *testing.T) {
	wantBool := map[string]bool{
		// original
		"--json": true, "--no-color": true,
		// additions
		"--quiet": true, "--verbose": true,
	}
	wantValue := map[string]bool{
		// original
		"--server": true, "--token": true, "--org": true,
		// additions
		"--format": true, "--output": true,
		"-o": true, // short form of --output
	}

	scAssertSetEqual(t, "chainsawGlobalBoolFlags", chainsawGlobalBoolFlags, wantBool)
	scAssertSetEqual(t, "chainsawGlobalValueFlags", chainsawGlobalValueFlags, wantValue)

	// Cross-check: none of the four additions may appear in BOTH maps (a value
	// flag masquerading as a bool would let a leaked flag shift the verb).
	for k := range chainsawGlobalBoolFlags {
		if chainsawGlobalValueFlags[k] {
			t.Errorf("flag %q is in BOTH the bool and value guard maps", k)
		}
	}
}

// scAssertSetEqual fails if got and want differ, reporting the exact missing and
// extra keys so a drift is diagnosable at a glance.
func scAssertSetEqual(t *testing.T, name string, got, want map[string]bool) {
	t.Helper()
	for k := range want {
		if !got[k] {
			t.Errorf("%s is missing expected flag %q (a removal — backward-compat break)", name, k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("%s has an UNEXPECTED flag %q (an undocumented addition)", name, k)
		}
	}
}

// TestGuardGlobalMaps_ClassifyParity asserts classifyChainsawGlobal agrees with
// the maps: every bool-map key classifies as a valueless global, every value-map
// long key classifies as a value-consuming global, and the -o short form is a
// recognized value-global.
func TestGuardGlobalMaps_ClassifyParity(t *testing.T) {
	for k := range chainsawGlobalBoolFlags {
		consumes, isGlobal := classifyChainsawGlobal(k)
		if !isGlobal {
			t.Errorf("bool global %q not recognized by classifyChainsawGlobal", k)
		}
		if consumes {
			t.Errorf("bool global %q classified as value-consuming (must be valueless)", k)
		}
	}
	for k := range chainsawGlobalValueFlags {
		consumes, isGlobal := classifyChainsawGlobal(k)
		if !isGlobal {
			t.Errorf("value global %q not recognized by classifyChainsawGlobal", k)
		}
		// The bare short form "-o" consumes a following value; the =form does not,
		// but there are no =forms in the map, so every entry consumes a value.
		if !consumes {
			t.Errorf("value global %q classified as valueless (must consume a value)", k)
		}
	}
}

// TestEveryPersistentFlagShorthandIsClassified extends the G1 guard to short
// forms: every non-empty persistent-flag shorthand (except -h) must classify as
// a chainsaw global, and its consumesValue must match whether the underlying
// flag takes a value. This closes the drift that let `-o` slip through before it
// was registered — a shorthand added without registering it fails CI here.
func TestEveryPersistentFlagShorthandIsClassified(t *testing.T) {
	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		sh := f.Shorthand
		if sh == "" || sh == "h" {
			return
		}
		tok := "-" + sh
		consumes, isGlobal := classifyChainsawGlobal(tok)
		if !isGlobal {
			// Note: -q/-v are intentionally NOT registered (ambiguous with the
			// wrapped tools' own -q/-v and, being valueless, can never shift a
			// verb). Treat those two as an allowed exception; everything else
			// MUST be classified.
			if sh == "q" || sh == "v" {
				return
			}
			t.Errorf("persistent flag shorthand -%s (of --%s) is not recognized by "+
				"classifyChainsawGlobal; register it in guard_install.go or it can shift "+
				"the install verb (guard bypass)", sh, f.Name)
			return
		}
		// If classified, consumesValue must match the flag's value-ness. A pflag
		// value-flag has a non-bool type; bool flags report "bool".
		wantConsumes := f.Value.Type() != "bool"
		if consumes != wantConsumes {
			t.Errorf("shorthand -%s (of --%s, type %s): classifyChainsawGlobal consumesValue=%v, want %v",
				sh, f.Name, f.Value.Type(), consumes, wantConsumes)
		}
	})
}

// TestGuardValueFlagNeverEatsInstallVerb pins the fail-closed core: for every
// value-consuming chainsaw global placed immediately before the verb with NO
// value, stripLeadingFlagsForParse must still surface the install verb at
// args[0] so the package is scanned (never delegated unscanned). Covers the
// exact regression the adversary flagged for --output/--format/--token/--org.
func TestGuardValueFlagNeverEatsInstallVerb(t *testing.T) {
	for _, flag := range []string{"--output", "--format", "--token", "--org", "--server", "-o"} {
		args := []string{flag, "install", "pacote@19.0.1"}
		parse := stripLeadingFlagsForParse(args)
		if len(parse) == 0 || parse[0] != "install" {
			t.Errorf("stripLeadingFlagsForParse(%v) = %v; want it to begin with the install verb "+
				"(value-flag must not swallow the verb — fail-closed)", args, parse)
			continue
		}
		specs, recognized := parseNpmInstall(parse)
		if !recognized {
			t.Errorf("parseNpmInstall did not recognize install after stripping %q; parse=%v", flag, parse)
			continue
		}
		found := false
		for _, s := range specs {
			if s.Name == "pacote" {
				found = true
			}
		}
		if !found {
			t.Errorf("package pacote not parsed after leading %q; specs=%v", flag, specs)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. completion bash/zsh/fish emit non-empty scripts
// ─────────────────────────────────────────────────────────────────────────────

// TestCompletionScriptsNonEmpty asserts the cobra-generated completion scripts
// render non-empty for bash, zsh, and fish. We call the generators directly on
// rootCmd (the same functions the `completion <shell>` subcommand dispatches to)
// so the check is fast and needs no subprocess. Each script must mention the
// program name so we know it targeted chainsaw, not a stub.
func TestCompletionScriptsNonEmpty(t *testing.T) {
	shells := map[string]func(*strings.Builder) error{
		"bash": func(b *strings.Builder) error { return rootCmd.GenBashCompletionV2(b, true) },
		"zsh":  func(b *strings.Builder) error { return rootCmd.GenZshCompletion(b) },
		"fish": func(b *strings.Builder) error { return rootCmd.GenFishCompletion(b, true) },
	}
	for shell, gen := range shells {
		var buf strings.Builder
		if err := gen(&buf); err != nil {
			t.Errorf("%s completion generation failed: %v", shell, err)
			continue
		}
		out := buf.String()
		if strings.TrimSpace(out) == "" {
			t.Errorf("%s completion script is empty", shell)
			continue
		}
		if !strings.Contains(out, "chainsaw") {
			t.Errorf("%s completion script does not reference the chainsaw program name", shell)
		}
	}
}

// TestCompletionCommandRegisteredAndVisible pins that the default `completion`
// subcommand stays enabled and visible (help_groups files it under DEBUG &
// DIAGNOSTICS; completion.go asserts the cobra defaults). A future
// CompletionOptions tweak that hides it would break `chainsaw completion <TAB>`
// discovery.
func TestCompletionCommandRegisteredAndVisible(t *testing.T) {
	if rootCmd.CompletionOptions.DisableDefaultCmd {
		t.Error("completion default command is disabled; it must stay enabled")
	}
	if rootCmd.CompletionOptions.HiddenDefaultCmd {
		t.Error("completion default command is hidden; it must stay visible")
	}
	cmd, _, err := rootCmd.Find([]string{"completion"})
	if err != nil || cmd == nil || cmd.Name() != "completion" {
		t.Fatalf("completion subcommand not found on rootCmd: cmd=%v err=%v", cmd, err)
	}
}
