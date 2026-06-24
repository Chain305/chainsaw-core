package sbom

// cyclonedx_regression_test.go — regression tests for the SBOM-export
// findings tracked under fix/sbom-F17-F18-F19-F15.
//
// Each test is anchored to a specific finding via the
// "regression-check: F<NN>" tag in the doc comment so the link from a
// future drift back to the originating verdict stays intact.

import (
	"encoding/json"
	"testing"
)

// TestSBOM_DependenciesGraphPresent — regression-check: F17.
//
// CycloneDX 1.6 §5.3 specifies a `dependencies[]` array of
// {ref, dependsOn[]} relationships. The earlier emitter omitted the key
// entirely on the flat path and only populated it when a *depgraph.Graph
// was supplied. Per finding F17, the array must always be PRESENT (empty
// or otherwise) so consumers can distinguish "no dependencies declared"
// (empty array) from "dependencies field absent" (data corruption).
//
// This test exports a fixture inventory with known transitive deps and
// asserts the resulting CycloneDX document carries a non-empty,
// structurally correct `dependencies[]`.
func TestSBOM_DependenciesGraphPresent(t *testing.T) {
	entries, graph := conformanceFixture()
	bom := GenerateWithGraph(entries, "urn:uuid:F17-regression", graph)
	out, err := bom.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	rawDeps, present := doc["dependencies"]
	if !present {
		t.Fatalf("dependencies key MUST be present per F17; got key absent")
	}
	deps, ok := rawDeps.([]any)
	if !ok {
		t.Fatalf("dependencies must be an array; got %T", rawDeps)
	}
	if len(deps) == 0 {
		t.Fatalf("dependencies must be non-empty for the diamond fixture; got 0 entries")
	}
	// Spot-check the structure of one entry.
	first, ok := deps[0].(map[string]any)
	if !ok {
		t.Fatalf("dependencies[0] is not an object; got %T", deps[0])
	}
	if ref, _ := first["ref"].(string); ref == "" {
		t.Errorf("dependencies[0].ref is empty (CycloneDX 1.6 §7.6 required)")
	}
	if _, ok := first["dependsOn"].([]any); !ok {
		t.Errorf("dependencies[0].dependsOn must be an array; got %T", first["dependsOn"])
	}
}

// TestSBOM_DependenciesGraphPresent_FlatFallback — regression-check: F17.
//
// When no graph is supplied, the emitter must still ship an EMPTY array
// rather than dropping the key. The CycloneDX 1.6 spec treats an absent
// dependencies[] and an empty one as semantically distinct.
func TestSBOM_DependenciesGraphPresent_FlatFallback(t *testing.T) {
	entries, _ := conformanceFixture()
	bom := Generate(entries, "urn:uuid:F17-regression-flat")
	out, err := bom.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rawDeps, present := doc["dependencies"]
	if !present {
		t.Fatalf("dependencies key MUST be present per F17 even without a graph; got key absent")
	}
	deps, ok := rawDeps.([]any)
	if !ok {
		t.Fatalf("dependencies must be an array; got %T", rawDeps)
	}
	if len(deps) != 0 {
		t.Errorf("flat-path dependencies must be empty; got %d", len(deps))
	}
}

// TestSBOM_ComponentPropertiesPreserved — regression-check: F18.
//
// The CycloneDX components array MUST carry a `properties[]` block on
// every component with non-empty supply-chain metadata. The earlier
// conformance test (TestCycloneDXConformance_SupplyChainPropertiesPreserved)
// passed because its fixture explicitly populated the supply-chain
// fields on every PackageEntry, but the live MCP handler did NOT enrich
// entries from the metadata store, so the production response shipped
// components with empty `properties` for the (overwhelming) clean-package
// case. The fix lives in the MCP handler; this test pins the lower-level
// invariant — given populated entry fields, the emitted CycloneDX bytes
// carry properties[] with chainsaw:* namespaces.
func TestSBOM_ComponentPropertiesPreserved(t *testing.T) {
	entries := []PackageEntry{
		{
			Ecosystem:        "npm",
			Name:             "regression-pkg",
			Version:          "1.0.0",
			LicenseSPDX:      "MIT",
			ProvenanceStatus: "verified",
			TrustScore:       42,
			MalwareStatus:    "malicious",
			ClientID:         "client-abc",
		},
	}
	bom := Generate(entries, "urn:uuid:F18-regression")
	out, err := bom.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	comps, _ := doc["components"].([]any)
	if len(comps) != 1 {
		t.Fatalf("expected 1 component; got %d", len(comps))
	}
	comp, _ := comps[0].(map[string]any)
	props, ok := comp["properties"].([]any)
	if !ok {
		t.Fatalf("components[0].properties must be present; got %T (%v)", comp["properties"], comp["properties"])
	}
	if len(props) == 0 {
		t.Fatalf("components[0].properties must be non-empty; got 0 entries")
	}

	// Assert the chainsaw: namespace is honoured for at least one
	// supply-chain entry (covers the F18 "namespace per CycloneDX
	// property naming convention" sub-requirement).
	var sawChainsawNamespace bool
	var sawSupplyChain bool
	for _, raw := range props {
		p, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := p["name"].(string)
		if len(name) >= len("chainsaw:") && name[:len("chainsaw:")] == "chainsaw:" {
			sawChainsawNamespace = true
		}
		if name == "chainsaw:supply-chain:client-id" {
			sawSupplyChain = true
		}
	}
	if !sawChainsawNamespace {
		t.Errorf("expected at least one chainsaw:* property; got %v", props)
	}
	if !sawSupplyChain {
		t.Errorf("expected chainsaw:supply-chain:client-id property when ClientID is set; got %v", props)
	}
}
