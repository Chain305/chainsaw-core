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
		wantResponse      string
		wantJustification string
	}{
		{
			name: "allow + cve, no note → exploitable/will_not_fix",
			ex: Exception{
				ID: "e1", Decision: "allow", Ecosystem: "npm",
				Name: "lodash", Version: "4.17.20",
				CVE: "CVE-2024-12345", ExpiresAt: future,
			},
			wantIncluded: true,
			wantState:    "exploitable",
			wantResponse: "will_not_fix",
		},
		{
			name: "allow + reachability note → still exploitable, note is not promoted to a claim",
			ex: Exception{
				ID: "e2", Decision: "allow", Ecosystem: "npm",
				Name: "lodash", Version: "4.17.20",
				CVE:       "CVE-2024-99999",
				Note:      "the affected sink is not in execution path for our usage",
				ExpiresAt: future,
			},
			wantIncluded: true,
			wantState:    "exploitable",
			wantResponse: "will_not_fix",
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
		{
			// The F2 defect: an exception the product itself prints as
			// "NOT yet in effect — it is awaiting approval" was being
			// exported into a client-facing CycloneDX attestation. The
			// policy evaluator skips any rule that is not StatusEnabled,
			// so enforcement refuses the carve-out while the compliance
			// document asserted the org accepted it.
			name: "status=pending_approval → excluded even though decision=allow",
			ex: Exception{
				ID: "e7", Decision: "allow", Ecosystem: "npm",
				Name: "unapproved", Version: "1.0.0",
				CVE: "CVE-2024-55555", Status: "pending_approval",
				ExpiresAt: future,
			},
			wantIncluded: false,
		},
		{
			// A pending row is not required to carry an expiry —
			// approveException sets one, drafting does not — so the
			// timestamp compare alone would export this forever.
			name: "status=pending_approval with zero ExpiresAt → excluded (not exported forever)",
			ex: Exception{
				ID: "e8", Decision: "allow", Ecosystem: "npm",
				Name: "unapproved-no-expiry", Version: "1.0.0",
				CVE: "CVE-2024-55556", Status: "pending_approval",
				// ExpiresAt deliberately zero.
			},
			wantIncluded: false,
		},
		{
			name: "status=denied → excluded",
			ex: Exception{
				ID: "e9", Decision: "allow", Ecosystem: "npm",
				Name: "refused", Version: "1.0.0",
				CVE: "CVE-2024-55557", Status: "denied",
				ExpiresAt: future,
			},
			wantIncluded: false,
		},
		{
			// ALLOW-LIST REGRESSION GUARD. An allow-list of {"", "active"}
			// passes every other row in this table and silently deletes
			// this one: a live, enforced carve-out inside the 14-day renew
			// window. Losing it is a compliance document quietly dropping
			// a true statement, which nothing detects at runtime.
			name: "status=expiring_soon → INCLUDED (still enforced inside the renew window)",
			ex: Exception{
				ID: "e10", Decision: "allow", Ecosystem: "npm",
				Name: "renewing", Version: "1.0.0",
				CVE: "CVE-2024-55558", Status: "expiring_soon",
				ExpiresAt: time.Now().UTC().Add(3 * 24 * time.Hour),
			},
			wantIncluded: true,
			wantState:    "exploitable",
			wantResponse: "will_not_fix",
		},
		{
			// The canary: core/cli/sbom_test.go builds exceptionItems with
			// no Status at all. Empty means in effect.
			name: "empty status → included",
			ex: Exception{
				ID: "e11", Decision: "allow", Ecosystem: "npm",
				Name: "no-status", Version: "1.0.0",
				CVE: "CVE-2024-55559", Status: "",
				ExpiresAt: future,
			},
			wantIncluded: true,
			wantState:    "exploitable",
			wantResponse: "will_not_fix",
		},
		{
			// Trap 2: the wire status truncates DaysRemaining to whole
			// days and stamps "expired" at <= 0, so an exception with
			// hours left reads "expired" while ExpiresAt.After(now) is
			// still true and the evaluator still honours it. The filter
			// must not touch the expiry axis.
			name: "status=expired but ExpiresAt still in the future → INCLUDED (expiry axis is BuildVEX's own compare)",
			ex: Exception{
				ID: "e12", Decision: "allow", Ecosystem: "npm",
				Name: "hours-left", Version: "1.0.0",
				CVE: "CVE-2024-55560", Status: "expired",
				ExpiresAt: time.Now().UTC().Add(6 * time.Hour),
			},
			wantIncluded: true,
			wantState:    "exploitable",
			wantResponse: "will_not_fix",
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
			if tc.wantResponse != "" {
				if len(got.Analysis.Response) != 1 || got.Analysis.Response[0] != tc.wantResponse {
					t.Errorf("Analysis.Response = %v, want [%q]", got.Analysis.Response, tc.wantResponse)
				}
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

	// Collect distinct analysis states; both exploitable and in_triage
	// must appear so the downstream consumer can branch on them.
	stateCounts := map[string]int{}
	justifCounts := map[string]int{}
	for _, v := range vex.Vulnerabilities {
		stateCounts[v.Analysis.State]++
		if v.Analysis.Justification != "" {
			justifCounts[v.Analysis.Justification]++
		}
	}
	if stateCounts["exploitable"] != 2 {
		t.Errorf("want 2 exploitable, got %d (states=%v)", stateCounts["exploitable"], stateCounts)
	}
	if stateCounts["not_affected"] != 0 {
		t.Errorf("not_affected must never be emitted for a risk acceptance, got %d", stateCounts["not_affected"])
	}
	if stateCounts["in_triage"] != 1 {
		t.Errorf("want 1 in_triage, got %d (states=%v)", stateCounts["in_triage"], stateCounts)
	}
	// No justification at all: `justification` is only meaningful next to
	// `not_affected`, and an operator's free-text note must never be
	// promoted into a machine claim about reachability.
	if len(justifCounts) != 0 {
		t.Errorf("want no justifications emitted, got %v", justifCounts)
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

// TestBuildVEX_ZeroValueDTOIsExported pins Trap 4 as a fact rather than a
// promise. Defaulting Exception.Status == "" to "in effect" moves the
// fail-open up a level: a Go caller that populates the DTO from a new
// source and forgets Status exports everything, unfiltered.
//
// The alternative — an allow-list that requires an explicit "active" —
// is worse (see the expiring_soon row in the mapping table), so the
// behaviour is deliberate and stays. This test exists so the exposure is
// recorded in the suite and a future caller can be found by grepping for
// it, not so it can be silently changed.
func TestBuildVEX_ZeroValueDTOIsExported(t *testing.T) {
	vex, err := BuildVEX("org", []Exception{{
		ID: "z1", Decision: "allow", Ecosystem: "npm",
		Name: "zero-value", Version: "1.0.0",
		CVE: "CVE-2024-00000",
		// Status and ExpiresAt both zero.
	}})
	if err != nil {
		t.Fatalf("BuildVEX: %v", err)
	}
	if len(vex.Vulnerabilities) != 1 {
		t.Fatalf("a DTO with no Status is exported (documented fail-open); got %d vulns", len(vex.Vulnerabilities))
	}
	// Every producer of sbom.Exception must therefore forward Status.
	// There is exactly one today (core/cli/sbom.go exceptionItemsToVEXInput),
	// pinned by TestExceptionItemsToVEXInput_ForwardsStatus.
}

// TestExceptionStatusNotInEffect_Classification pins the deny-list shape
// directly, independent of BuildVEX, so the server-side cross-module
// guard has a stable function to assert against.
func TestExceptionStatusNotInEffect_Classification(t *testing.T) {
	cases := map[string]bool{
		"":                 false,
		"active":           false,
		"expiring_soon":    false, // in effect; expiry is BuildVEX's own compare
		"expired":          false, // ditto — Trap 2
		"pending_approval": true,
		"denied":           true,
		// Case/whitespace tolerance: the filter must not be defeated by
		// a producer that upper-cases or pads the wire value.
		"  Pending_Approval  ": true,
		"DENIED":               true,
		// "rejected" appears nowhere in the tree and must not be
		// introduced as a synonym for denied (internal/server/entries.go).
		"rejected": false,
	}
	for status, want := range cases {
		if got := ExceptionStatusNotInEffect(status); got != want {
			t.Errorf("ExceptionStatusNotInEffect(%q) = %v, want %v", status, got, want)
		}
	}
}
