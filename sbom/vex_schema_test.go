package sbom

import (
	"testing"
	"time"
)

// CycloneDX 1.6 enums, transcribed from the published schema.
//
// These exist because nothing in this repo validated VEX output against
// the schema, and as a result the product shipped
// "vulnerable_code_not_in_execute_path" as a justification for months —
// a string that is not a member of impactAnalysisJustification. The
// document was invalid whenever an operator's exception note happened to
// match a regex. A consumer that validates before ingesting (rather than
// parsing leniently) would have rejected the whole document.
var (
	cdxImpactAnalysisState = map[string]bool{
		"resolved":               true,
		"resolved_with_pedigree": true,
		"exploitable":            true,
		"in_triage":              true,
		"false_positive":         true,
		"not_affected":           true,
	}
	cdxImpactAnalysisJustification = map[string]bool{
		"code_not_present":                true,
		"code_not_reachable":              true,
		"requires_configuration":          true,
		"requires_dependency":             true,
		"requires_environment":            true,
		"protected_by_compiler":           true,
		"protected_at_runtime":            true,
		"protected_at_perimeter":          true,
		"protected_by_mitigating_control": true,
	}
	cdxImpactAnalysisResponse = map[string]bool{
		"can_not_fix":          true,
		"will_not_fix":         true,
		"update":               true,
		"rollback":             true,
		"workaround_available": true,
	}
)

// TestBuildVEXEmitsOnlySchemaEnumMembers walks every decision kind the
// exception model can carry and asserts the emitted analysis block uses
// only strings the CycloneDX 1.6 schema defines.
//
// It fails if anyone reintroduces a hand-written state, justification or
// response — which is exactly how the previous defect arrived.
func TestBuildVEXEmitsOnlySchemaEnumMembers(t *testing.T) {
	future := time.Now().Add(720 * time.Hour)

	// Notes chosen to include the phrases the deleted regex matched, so a
	// revival of that behaviour trips this test rather than shipping.
	notes := []string{
		"",
		"accepted for Q3, tracked in SEC-1042",
		"the affected sink is not in execution path for our usage",
		"unreachable from our call graph",
		"not reachable",
	}

	for _, decision := range []string{"allow", "monitor"} {
		for _, note := range notes {
			vex, err := BuildVEX("org-schema", []Exception{{
				ID: "e1", Decision: decision, Ecosystem: "npm",
				Name: "lodash", Version: "4.17.20",
				CVE: "CVE-2024-12345", Note: note, ExpiresAt: future,
			}})
			if err != nil {
				t.Fatalf("BuildVEX(%s, %q): %v", decision, note, err)
			}
			if len(vex.Vulnerabilities) != 1 {
				t.Fatalf("BuildVEX(%s, %q): want 1 vuln, got %d", decision, note, len(vex.Vulnerabilities))
			}
			a := vex.Vulnerabilities[0].Analysis

			if !cdxImpactAnalysisState[a.State] {
				t.Errorf("decision=%s note=%q: state %q is not a CycloneDX impactAnalysisState member", decision, note, a.State)
			}
			if a.Justification != "" && !cdxImpactAnalysisJustification[a.Justification] {
				t.Errorf("decision=%s note=%q: justification %q is not a CycloneDX impactAnalysisJustification member", decision, note, a.Justification)
			}
			// Enum membership alone is not enough. In CycloneDX 1.6
			// `justification` is only valid alongside `not_affected`, so a
			// schema-enum-member justification sitting next to
			// `exploitable` is still an invalid document — and that is
			// precisely the shape someone re-adds when they "reconcile"
			// the package doc by restoring code_not_present. Enum
			// membership passes it; this does not.
			if a.Justification != "" && a.State != "not_affected" {
				t.Errorf("decision=%s note=%q: justification %q emitted alongside state %q; justification is only valid with not_affected",
					decision, note, a.Justification, a.State)
			}
			for _, r := range a.Response {
				if !cdxImpactAnalysisResponse[r] {
					t.Errorf("decision=%s note=%q: response %q is not a CycloneDX impactAnalysisResponse member", decision, note, r)
				}
			}

			// A risk acceptance must never claim the vulnerable code is
			// absent — that is the semantic defect, distinct from schema
			// validity, and a consumer suppresses the finding on it.
			if decision == "allow" && a.State == "not_affected" {
				t.Errorf("note=%q: an accepted risk was encoded as not_affected", note)
			}
		}
	}
}
