package sbom

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestBuildVEX_MappingTable pins the exception → VEX statement mapping
// rules documented at the top of vex.go. Drift in any of these rows means
// downstream consumers (Dependency-Track, Grype) silently misclassify the
// org's stance on a CVE — so each row is its own table entry, named.
func TestBuildVEX_MappingTable(t *testing.T) {
	future := time.Now().UTC().Add(30 * 24 * time.Hour)
	past := time.Now().UTC().Add(-1 * time.Hour)

	tests := []struct {
		name              string
		ex                Exception
		wantIncluded      bool
		wantState         string
		wantJustification string
	}{
		{
			name: "allow + cve, no note → not_affected/code_not_present",
			ex: Exception{
				ID: "e1", Decision: "allow", Ecosystem: "npm",
				Name: "lodash", Version: "4.17.20",
				CVE: "CVE-2024-12345", ExpiresAt: future,
			},
			wantIncluded:      true,
			wantState:         "not_affected",
			wantJustification: "code_not_present",
		},
		{
			name: "allow + cve + execution-path note → vulnerable_code_not_in_execute_path",
			ex: Exception{
				ID: "e2", Decision: "allow", Ecosystem: "npm",
				Name: "lodash", Version: "4.17.20",
				CVE:       "CVE-2024-99999",
				Note:      "the affected sink is not in execution path for our usage",
				ExpiresAt: future,
			},
			wantIncluded:      true,
			wantState:         "not_affected",
			wantJustification: "vulnerable_code_not_in_execute_path",
		},
		{
			name: "monitor → in_triage",
			ex: Exception{
				ID: "e3", Decision: "monitor", Ecosystem: "pypi",
				Name: "requests", Version: "2.31.0",
				CVE: "CVE-2024-22222", ExpiresAt: future,
			},
			wantIncluded: true,
			wantState:    "in_triage",
		},
		{
			name: "expired → excluded",
			ex: Exception{
				ID: "e4", Decision: "allow", Ecosystem: "npm",
				Name: "expired-pkg", Version: "1.0.0",
				CVE: "CVE-2023-00001", ExpiresAt: past,
			},
			wantIncluded: false,
		},
		{
			name: "missing CVE → excluded",
			ex: Exception{
				ID: "e5", Decision: "allow", Ecosystem: "npm",
				Name: "no-cve", Version: "1.0.0",
				ExpiresAt: future,
			},
			wantIncluded: false,
		},
		{
			name: "deny → excluded",
			ex: Exception{
				ID: "e6", Decision: "deny", Ecosystem: "npm",
				Name: "blocked", Version: "1.0.0",
				CVE: "CVE-2024-44444", ExpiresAt: future,
			},
			wantIncluded: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vex, err := BuildVEX("org-test", []Exception{tc.ex})
			if err != nil {
				t.Fatalf("BuildVEX: %v", err)
			}
			if !tc.wantIncluded {
				if len(vex.Vulnerabilities) != 0 {
					t.Fatalf("want exception excluded, got %d vulns: %+v", len(vex.Vulnerabilities), vex.Vulnerabilities)
				}
				return
			}
			if len(vex.Vulnerabilities) != 1 {
				t.Fatalf("want 1 vuln, got %d", len(vex.Vulnerabilities))
			}
			got := vex.Vulnerabilities[0]
			if got.ID != tc.ex.CVE {
				t.Errorf("vuln.ID = %q, want %q", got.ID, tc.ex.CVE)
			}
			if got.Analysis.State != tc.wantState {
				t.Errorf("Analysis.State = %q, want %q", got.Analysis.State, tc.wantState)
			}
			if tc.wantJustification != "" && got.Analysis.Justification != tc.wantJustification {
				t.Errorf("Analysis.Justification = %q, want %q", got.Analysis.Justification, tc.wantJustification)
			}
			if len(got.Affects) != 1 || got.Affects[0].Ref == "" {
				t.Errorf("want a single non-empty affects ref, got %+v", got.Affects)
			}
		})
	}
}

// TestBuildVEX_EnvelopeShape validates the top-level CycloneDX envelope
// because the schema validator on the consumer side checks these exact
// strings. specVersion drift would silently break ingestion.
func TestBuildVEX_EnvelopeShape(t *testing.T) {
	vex, err := BuildVEX("org-test", nil)
	if err != nil {
		t.Fatalf("BuildVEX: %v", err)
	}
	if vex.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", vex.BOMFormat)
	}
	if vex.SpecVersion != "1.6" {
		t.Errorf("specVersion = %q, want 1.6", vex.SpecVersion)
	}
	if vex.Version != 1 {
		t.Errorf("version = %d, want 1", vex.Version)
	}
	if len(vex.Metadata.Tools) == 0 || vex.Metadata.Tools[0].Vendor != "chainsaw" {
		t.Errorf("metadata.tools missing chainsaw entry: %+v", vex.Metadata.Tools)
	}

	// Round-trip JSON to make sure tags and shapes are valid.
	b, err := vex.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON: %v", err)
	}
	if !strings.Contains(string(b), `"vulnerabilities"`) {
		t.Errorf("VEX JSON missing vulnerabilities key: %s", string(b))
	}
	var roundTrip CycloneDXVEX
	if err := json.Unmarshal(b, &roundTrip); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
}

// TestBuildVEX_MixedDecisionBatch confirms BuildVEX produces multiple
// distinct analysis.state values when the input batch contains a mix of
// decisions. Pre-Wave-2 the adapter pinned every exception to "allow", so
// the VEX output was homogenous — this test guards against regressing
// back to that single-state behavior now that exceptionEntry carries the
// decision verbatim.
func TestBuildVEX_MixedDecisionBatch(t *testing.T) {
	future := time.Now().UTC().Add(30 * 24 * time.Hour)
	past := time.Now().UTC().Add(-1 * time.Hour)
	exceptions := []Exception{
		{
			ID: "a1", Decision: "allow", Ecosystem: "npm",
			Name: "lodash", Version: "4.17.20",
			CVE: "CVE-2024-1", ExpiresAt: future,
		},
		{
			ID: "m1", Decision: "monitor", Ecosystem: "pypi",
			Name: "requests", Version: "2.31.0",
			CVE: "CVE-2024-2", ExpiresAt: future,
		},
		{
			ID: "a2", Decision: "allow", Ecosystem: "npm",
			Name: "left-pad", Version: "1.0.0",
			CVE:       "CVE-2024-3",
			Note:      "vulnerable sink not in execution path",
			ExpiresAt: future,
		},
		{
			// Deny → excluded.
			ID: "d1", Decision: "deny", Ecosystem: "npm",
			Name: "blocked", Version: "1.0.0",
			CVE: "CVE-2024-4", ExpiresAt: future,
		},
		{
			// Expired → excluded.
			ID: "x1", Decision: "allow", Ecosystem: "npm",
			Name: "expired", Version: "1.0.0",
			CVE: "CVE-2024-5", ExpiresAt: past,
		},
	}

	vex, err := BuildVEX("org-mixed", exceptions)
	if err != nil {
		t.Fatalf("BuildVEX: %v", err)
	}
	if len(vex.Vulnerabilities) != 3 {
		t.Fatalf("want 3 vulns (2 allow + 1 monitor), got %d: %+v", len(vex.Vulnerabilities), vex.Vulnerabilities)
	}

	// Collect distinct analysis states; both not_affected and in_triage
	// must appear so the downstream consumer can branch on them.
	stateCounts := map[string]int{}
	justifCounts := map[string]int{}
	for _, v := range vex.Vulnerabilities {
		stateCounts[v.Analysis.State]++
		if v.Analysis.Justification != "" {
			justifCounts[v.Analysis.Justification]++
		}
	}
	if stateCounts["not_affected"] != 2 {
		t.Errorf("want 2 not_affected, got %d (states=%v)", stateCounts["not_affected"], stateCounts)
	}
	if stateCounts["in_triage"] != 1 {
		t.Errorf("want 1 in_triage, got %d (states=%v)", stateCounts["in_triage"], stateCounts)
	}
	// The reachability-note allow should pick the stronger justification.
	if justifCounts["vulnerable_code_not_in_execute_path"] != 1 {
		t.Errorf("want 1 vulnerable_code_not_in_execute_path justification, got %v", justifCounts)
	}
	if justifCounts["code_not_present"] != 1 {
		t.Errorf("want 1 code_not_present justification, got %v", justifCounts)
	}
}

// TestBuildVEX_PurlFallback covers the case where the caller has no PURL
// on hand: BuildVEX must derive one from ecosystem/name/version so the
// affects[].ref is still pinnable. Without this, VEX statements about
// older exceptions (created before PURLs were stored) would have empty
// refs and be useless to consumers.
func TestBuildVEX_PurlFallback(t *testing.T) {
	future := time.Now().UTC().Add(24 * time.Hour)
	ex := Exception{
		ID: "e1", Decision: "allow", Ecosystem: "npm",
		Name: "lodash", Version: "4.17.20",
		CVE: "CVE-2024-12345", ExpiresAt: future,
	}
	vex, err := BuildVEX("org", []Exception{ex})
	if err != nil {
		t.Fatalf("BuildVEX: %v", err)
	}
	if len(vex.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vuln, got %d", len(vex.Vulnerabilities))
	}
	ref := vex.Vulnerabilities[0].Affects[0].Ref
	if !strings.HasPrefix(ref, "pkg:npm/lodash@") {
		t.Errorf("affects ref = %q, want pkg:npm/lodash@…", ref)
	}
}
