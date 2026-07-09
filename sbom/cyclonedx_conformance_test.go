package sbom

// cyclonedx_conformance_test.go — byte-stream conformance for the
// CycloneDX 1.6 output the dashboard /sbom page (and the
// chainsaw_export_sbom MCP tool) advertise to operators.
//
// Background: the original SBOM tests covered field-level invariants
// (supply-chain properties, link-back fields, dependency-edge shape).
// They never loaded the *bytes* `Generate(...).ToJSON()` produces and
// validated them against the CycloneDX 1.6 contract end-to-end. The
// dashboard SBOM page promises "CycloneDX 1.6" specifically, the MCP
// tool returns Content-Type `application/vnd.cyclonedx+json`, and the
// snapshot store persists the bytes verbatim — so a regression in the
// emitter would silently ship malformed compliance artifacts to every
// downstream consumer (Dependency-Track, Snyk, Grype, in-toto verifier).
//
// Approach choice (a/b/c from the audit playbook):
//   - (a) cyclonedx-go round-trip: rejected — not in go.mod, would add
//     a heavyweight dependency for one test.
//   - (b) JSON Schema validation against bom-1.6.schema.json: rejected
//     — santhosh-tekuri/jsonschema not in go.mod either, same reason.
//   - (c) MANUAL STRUCTURAL ASSERTIONS — chosen. Decode the produced
//     bytes as map[string]any, walk the document, assert every
//     CycloneDX 1.6 mandatory and contract-relevant field (bomFormat,
//     specVersion, version, metadata.timestamp, metadata.tools,
//     components[].type/name/version/purl, dependencies[].ref/dependsOn)
//     against the spec text. Also re-decode into the typed
//     CycloneDXBOM and assert byte-equivalence of a re-emit, which
//     catches any field that the typed struct silently drops.
//
// The test fixture is a non-trivial 4-component graph (root, two
// direct deps, one transitive leaf reached via both direct deps —
// the diamond shape that exercises dependsOn[] dedup logic). It
// also pins specific PURLs, hashes, licenses, and supply-chain
// properties so the test asserts not just "valid SBOM" but "valid
// SBOM that contains the expected data for this fixture".

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/depgraph"
)

// conformanceFixture builds a deterministic 4-component diamond:
//
//	root@1.0.0 ──> child-a@2.0.0 ──┐
//	     │                          ├──> leaf@3.0.0
//	     └────> child-b@2.1.0 ─────┘
//
// Each entry pins a SHA-256 hash, an SPDX license, and at least one
// supply-chain property so the conformance test asserts the optional
// blocks survive the round-trip.
func conformanceFixture() ([]PackageEntry, *depgraph.Graph) {
	g := depgraph.NewGraph()
	root := depgraph.Key{Ecosystem: "npm", Name: "root", Version: "1.0.0"}
	childA := depgraph.Key{Ecosystem: "npm", Name: "child-a", Version: "2.0.0"}
	childB := depgraph.Key{Ecosystem: "npm", Name: "child-b", Version: "2.1.0"}
	leaf := depgraph.Key{Ecosystem: "npm", Name: "leaf", Version: "3.0.0"}
	g.AddNode(root, true, true)
	g.AddNode(childA, false, true)
	g.AddNode(childB, false, true)
	g.AddNode(leaf, false, true)
	g.AddEdge(root, childA)
	g.AddEdge(root, childB)
	g.AddEdge(childA, leaf)
	g.AddEdge(childB, leaf)
	g.AddRoot(root)

	entries := []PackageEntry{
		{
			Ecosystem:   "npm",
			Name:        "root",
			Version:     "1.0.0",
			SHA256:      "1111111111111111111111111111111111111111111111111111111111111111",
			LicenseSPDX: "MIT",
		},
		{
			Ecosystem:        "npm",
			Name:             "child-a",
			Version:          "2.0.0",
			SHA256:           "2222222222222222222222222222222222222222222222222222222222222222",
			LicenseSPDX:      "Apache-2.0",
			ProvenanceStatus: "verified",
			TrustScore:       87,
		},
		{
			Ecosystem:           "npm",
			Name:                "child-b",
			Version:             "2.1.0",
			SHA256:              "3333333333333333333333333333333333333333333333333333333333333333",
			LicenseSPDX:         "BSD-3-Clause",
			InstallScriptKind:   "fetches_remote",
			VersionAnomalyFlags: []string{"semver_regression"},
		},
		{
			Ecosystem:    "npm",
			Name:         "leaf",
			Version:      "3.0.0",
			SHA256:       "4444444444444444444444444444444444444444444444444444444444444444",
			LicenseSPDX:  "MIT",
			IsVulnerable: true,
			CVEs:         []string{"CVE-2024-99999"},
		},
	}
	return entries, g
}

// TestCycloneDXConformance_ByteStream is the load-bearing test for the
// /sbom dashboard page's "CycloneDX 1.6" claim. It produces real bytes
// from the production code path (Generate → ToJSON, the same call the
// snapshot store and MCP tool use), then validates them against the
// CycloneDX 1.6 spec contract via map[string]any decoding so the test
// catches ANY drift the typed CycloneDXBOM struct might silently absorb.
func TestCycloneDXConformance_ByteStream(t *testing.T) {
	entries, graph := conformanceFixture()
	bom := GenerateWithGraph(entries, "urn:uuid:00000000-0000-0000-0000-000000000001", graph)

	bytesOut, err := bom.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	if len(bytesOut) == 0 {
		t.Fatal("ToJSON produced empty byte stream")
	}

	// --- Phase 1: decode as map[string]any and walk against the CycloneDX
	// 1.6 spec contract. This catches any field that the typed struct
	// might silently rename or drop on emit.
	var doc map[string]any
	if err := json.Unmarshal(bytesOut, &doc); err != nil {
		t.Fatalf("emitted bytes do not parse as JSON: %v", err)
	}

	// Required top-level fields per CycloneDX 1.6 §4.1.
	bomFormat, ok := doc["bomFormat"].(string)
	if !ok {
		t.Fatalf("bomFormat missing or not a string; doc keys: %v", keys(doc))
	}
	if bomFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want %q (CycloneDX 1.6 §4.1)", bomFormat, "CycloneDX")
	}

	specVersion, ok := doc["specVersion"].(string)
	if !ok {
		t.Fatalf("specVersion missing or not a string; doc keys: %v", keys(doc))
	}
	if specVersion != "1.6" {
		t.Errorf("specVersion = %q, want %q — the dashboard /sbom page "+
			"advertises CycloneDX 1.6 specifically", specVersion, "1.6")
	}

	versionField, ok := doc["version"].(float64)
	if !ok {
		t.Fatalf("version missing or not numeric; got %T", doc["version"])
	}
	if int(versionField) < 1 {
		t.Errorf("version = %v, want >= 1 (CycloneDX 1.6 §4.1)", versionField)
	}

	if serial, ok := doc["serialNumber"].(string); !ok || serial == "" {
		t.Errorf("serialNumber missing or empty; conformance fixture pinned a urn:uuid")
	} else if !strings.HasPrefix(serial, "urn:") {
		// CycloneDX 1.6 §4.1 says serialNumber SHOULD be a URN. We pinned a
		// urn:uuid in the fixture — surfacing a regression here means the
		// emitter is rewriting the field.
		t.Errorf("serialNumber = %q, want urn:* prefix", serial)
	}

	// metadata.timestamp must be RFC3339 (CycloneDX 1.6 metadata schema).
	metadata, ok := doc["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata missing or not an object; got %T", doc["metadata"])
	}
	timestamp, ok := metadata["timestamp"].(string)
	if !ok || timestamp == "" {
		t.Fatalf("metadata.timestamp missing or empty")
	}
	if _, err := time.Parse(time.RFC3339, timestamp); err != nil {
		t.Errorf("metadata.timestamp %q is not RFC3339: %v", timestamp, err)
	}

	tools, ok := metadata["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Errorf("metadata.tools missing/empty — operators rely on this to "+
			"identify the producing tool. got: %v", metadata["tools"])
	} else {
		tool, ok := tools[0].(map[string]any)
		if !ok {
			t.Fatalf("metadata.tools[0] is not an object; got %T", tools[0])
		}
		if name, _ := tool["name"].(string); name == "" {
			t.Errorf("metadata.tools[0].name is missing or empty")
		}
		if vendor, _ := tool["vendor"].(string); vendor == "" {
			t.Errorf("metadata.tools[0].vendor is missing or empty")
		}
		if version, _ := tool["version"].(string); version == "" {
			t.Errorf("metadata.tools[0].version is missing or empty")
		}
	}

	// components[] — every entry MUST have type, name, version per
	// CycloneDX 1.6 §6.2. We additionally require purl because the
	// dependency-graph wiring uses purl as bom-ref.
	rawComponents, ok := doc["components"].([]any)
	if !ok {
		t.Fatalf("components missing or not an array; got %T", doc["components"])
	}
	if len(rawComponents) != len(entries) {
		t.Fatalf("components length = %d, want %d (one per fixture entry)",
			len(rawComponents), len(entries))
	}

	expectedPURLs := map[string]bool{
		"pkg:npm/root@1.0.0":    false,
		"pkg:npm/child-a@2.0.0": false,
		"pkg:npm/child-b@2.1.0": false,
		"pkg:npm/leaf@3.0.0":    false,
	}
	for i, raw := range rawComponents {
		comp, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("components[%d] is not an object; got %T", i, raw)
		}
		ctype, _ := comp["type"].(string)
		if ctype != "library" {
			t.Errorf("components[%d].type = %q, want %q", i, ctype, "library")
		}
		name, _ := comp["name"].(string)
		if name == "" {
			t.Errorf("components[%d].name is empty (CycloneDX 1.6 §6.2 required)", i)
		}
		ver, _ := comp["version"].(string)
		if ver == "" {
			t.Errorf("components[%d].version is empty", i)
		}
		purl, _ := comp["purl"].(string)
		if purl == "" {
			t.Errorf("components[%d] (%s) is missing purl — the dependency "+
				"graph keys off purl as bom-ref", i, name)
			continue
		}
		// Validate the purl is well-formed (parseable as a URL with the
		// `pkg:` scheme per the PURL spec).
		if !strings.HasPrefix(purl, "pkg:") {
			t.Errorf("components[%d].purl = %q, want pkg:* prefix", i, purl)
		}
		if _, err := url.Parse(purl); err != nil {
			t.Errorf("components[%d].purl = %q is not a valid URL: %v", i, purl, err)
		}
		if _, expected := expectedPURLs[purl]; expected {
			expectedPURLs[purl] = true
		} else {
			t.Errorf("components[%d].purl = %q not in expected set", i, purl)
		}

		// hashes[] — fixture pinned SHA-256 on every entry.
		hashes, ok := comp["hashes"].([]any)
		if !ok || len(hashes) == 0 {
			t.Errorf("components[%d] (%s) missing hashes; fixture pinned SHA-256",
				i, name)
		} else {
			h, ok := hashes[0].(map[string]any)
			if !ok {
				t.Fatalf("components[%d].hashes[0] is not an object", i)
			}
			alg, _ := h["alg"].(string)
			if alg != "SHA-256" {
				t.Errorf("components[%d].hashes[0].alg = %q, want SHA-256", i, alg)
			}
			content, _ := h["content"].(string)
			if len(content) != 64 { // sha256 hex
				t.Errorf("components[%d].hashes[0].content len = %d, want 64 (sha256 hex)",
					i, len(content))
			}
		}

		// licenses[] — fixture pinned SPDX on every entry.
		licenses, ok := comp["licenses"].([]any)
		if !ok || len(licenses) == 0 {
			t.Errorf("components[%d] (%s) missing licenses; fixture pinned SPDX",
				i, name)
		}
	}
	for purl, seen := range expectedPURLs {
		if !seen {
			t.Errorf("expected purl %q never appeared in components[]", purl)
		}
	}

	// dependencies[] — diamond fixture must produce 3 rows: root → {a,b},
	// child-a → {leaf}, child-b → {leaf}. leaf has no children so it gets
	// no row (the implementation skips leaves).
	rawDeps, ok := doc["dependencies"].([]any)
	if !ok {
		t.Fatalf("dependencies missing or not an array; got %T (graph fixture "+
			"was supplied so dependencies[] MUST be populated)", doc["dependencies"])
	}
	if len(rawDeps) != 3 {
		t.Errorf("dependencies length = %d, want 3 (root, child-a, child-b rows)",
			len(rawDeps))
	}
	depsByRef := map[string][]string{}
	for i, raw := range rawDeps {
		dep, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("dependencies[%d] is not an object", i)
		}
		ref, _ := dep["ref"].(string)
		if ref == "" {
			t.Errorf("dependencies[%d].ref is empty (CycloneDX 1.6 §7.6 required)", i)
			continue
		}
		dependsOn, _ := dep["dependsOn"].([]any)
		strs := make([]string, 0, len(dependsOn))
		for _, child := range dependsOn {
			if s, ok := child.(string); ok {
				strs = append(strs, s)
			}
		}
		depsByRef[ref] = strs
	}
	// root → {child-a, child-b}, NOT leaf (leaf is transitive)
	if rootChildren := depsByRef["pkg:npm/root@1.0.0"]; len(rootChildren) != 2 {
		t.Errorf("root dependsOn = %v, want exactly {child-a, child-b}", rootChildren)
	} else {
		for _, c := range rootChildren {
			if strings.Contains(c, "/leaf@") {
				t.Errorf("root.dependsOn must NOT contain transitive leaf; got %v",
					rootChildren)
			}
		}
	}
	if aChildren := depsByRef["pkg:npm/child-a@2.0.0"]; len(aChildren) != 1 ||
		!strings.Contains(aChildren[0], "/leaf@") {
		t.Errorf("child-a dependsOn = %v, want [leaf]", aChildren)
	}
	if bChildren := depsByRef["pkg:npm/child-b@2.1.0"]; len(bChildren) != 1 ||
		!strings.Contains(bChildren[0], "/leaf@") {
		t.Errorf("child-b dependsOn = %v, want [leaf]", bChildren)
	}
	if _, leafHasRow := depsByRef["pkg:npm/leaf@3.0.0"]; leafHasRow {
		t.Errorf("leaf is a leaf node and must not have a dependencies row")
	}

	// --- Phase 2: round-trip through the typed struct and re-emit. The
	// re-emit must produce the same bytes (or at minimum decode to the
	// same map). Asserting byte-equivalence catches any field the typed
	// struct silently drops.
	var roundTrip CycloneDXBOM
	if err := json.Unmarshal(bytesOut, &roundTrip); err != nil {
		t.Fatalf("emitted bytes do not parse as CycloneDXBOM: %v", err)
	}
	reEmitted, err := roundTrip.ToJSON()
	if err != nil {
		t.Fatalf("re-emit failed: %v", err)
	}
	if !bytes.Equal(bytesOut, reEmitted) {
		// Fall back to map equivalence in case the diff is purely
		// formatting (encoding/json should be deterministic on the same
		// struct, so this should not trigger; if it does, that's the
		// real bug).
		var docA, docB map[string]any
		_ = json.Unmarshal(bytesOut, &docA)
		_ = json.Unmarshal(reEmitted, &docB)
		// We compare encoded canonical forms.
		jsonA, _ := json.Marshal(docA)
		jsonB, _ := json.Marshal(docB)
		if !bytes.Equal(jsonA, jsonB) {
			t.Errorf("round-trip is not byte-equivalent. The typed struct is "+
				"silently dropping a field present in the emitted bytes.\n"+
				"  original len=%d  re-emit len=%d", len(bytesOut), len(reEmitted))
		}
	}

	// --- Phase 3: Content-Type sanity. The HTTP handler and MCP tool both
	// label this byte stream as application/vnd.cyclonedx+json. Confirm
	// the emitted body is valid JSON (already done above) and starts with
	// `{` so a strict JSON consumer accepts it as an object literal.
	trimmed := bytes.TrimSpace(bytesOut)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		t.Errorf("emitted body does not start with '{' — application/"+
			"vnd.cyclonedx+json consumers expect a JSON object. first byte: %q",
			trimmed[0:min(8, len(trimmed))])
	}
}

// TestCycloneDXConformance_FlatPathStillValid asserts the back-compat
// flat-output path (Generate without a graph) produces a CycloneDX 1.6
// document that conforms to the same spec. The dashboard /sbom page
// hits this code path when no per-snapshot dependency graph is available
// (e.g. the events-ledger fresh-export path used by chainsaw_export_sbom
// when no snapshot_id is supplied).
func TestCycloneDXConformance_FlatPathStillValid(t *testing.T) {
	entries, _ := conformanceFixture()
	bom := Generate(entries, "urn:uuid:00000000-0000-0000-0000-000000000002")
	bytesOut, err := bom.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(bytesOut, &doc); err != nil {
		t.Fatalf("flat-path bytes do not parse as JSON: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", doc["bomFormat"])
	}
	if doc["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v, want 1.6", doc["specVersion"])
	}
	// regression-check: F17 — dependencies[] must be PRESENT (as an empty
	// array on the flat path) so CycloneDX 1.6 §5.3 consumers see a
	// canonical "no relationships declared" form rather than key-absent.
	rawDeps, present := doc["dependencies"]
	if !present {
		t.Errorf("flat-path output must include dependencies[] (empty array per F17 fix); got key absent")
	} else if arr, ok := rawDeps.([]any); !ok {
		t.Errorf("flat-path dependencies must be an array; got %T (%v)", rawDeps, rawDeps)
	} else if len(arr) != 0 {
		t.Errorf("flat-path dependencies must be empty (no graph supplied); got %d entries", len(arr))
	}
	rawComponents, ok := doc["components"].([]any)
	if !ok || len(rawComponents) != len(entries) {
		t.Errorf("components count mismatch on flat path: got %d want %d",
			len(rawComponents), len(entries))
	}
}

// TestCycloneDXConformance_SupplyChainPropertiesPreserved asserts the
// chainsaw:supply-chain:* and chainsaw:supplychain:* properties survive
// the byte-stream round trip. These property names are pinned by
// downstream consumers (Dependency-Track config, internal dashboards),
// so a renamed/dropped property that stayed in the typed struct test
// would still ship a broken artifact.
func TestCycloneDXConformance_SupplyChainPropertiesPreserved(t *testing.T) {
	entries, graph := conformanceFixture()
	bom := GenerateWithGraph(entries, "urn:uuid:00000000-0000-0000-0000-000000000003", graph)
	bytesOut, err := bom.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	// Walk the emitted bytes (not the typed struct) so a silently-dropped
	// JSON tag would surface here.
	if !bytes.Contains(bytesOut, []byte("chainsaw:provenance:status")) {
		t.Error("emitted bytes missing chainsaw:provenance:status property")
	}
	if !bytes.Contains(bytesOut, []byte("chainsaw:trust:score")) {
		t.Error("emitted bytes missing chainsaw:trust:score property")
	}
	if !bytes.Contains(bytesOut, []byte("chainsaw:supplychain:installScriptKind")) {
		t.Error("emitted bytes missing chainsaw:supplychain:installScriptKind property")
	}
	if !bytes.Contains(bytesOut, []byte("chainsaw:supplychain:versionAnomalyFlags")) {
		t.Error("emitted bytes missing chainsaw:supplychain:versionAnomalyFlags property")
	}
	if !bytes.Contains(bytesOut, []byte("chainsaw:vuln:cves")) {
		t.Error("emitted bytes missing chainsaw:vuln:cves property")
	}
	if !bytes.Contains(bytesOut, []byte("CVE-2024-99999")) {
		t.Error("emitted bytes missing fixture CVE")
	}
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
