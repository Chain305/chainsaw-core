package cli

// why_test.go — table-driven coverage for `chainsaw why`. Three scenarios:
//   - happy path: /api/violations/blocked returns a matching row, the
//     command picks the most-recent one for the requested coordinate.
//   - --request-id with no audit-buffer match: returns the expected error
//     so CI can detect "request expired" without parsing the message.
//   - --request-id with audit-buffer match: pulls the row from
//     /api/audit/logs and synthesises a blockedViolation from metadata.
//
// We exercise lookupBlock directly rather than running cobra end-to-end —
// the cobra plumbing (flag wiring, AddCommand) is exercised by the rest of
// the suite, and the interesting branching all lives in lookupBlock /
// blockedFromAuditEvent.

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestWhyLookupBlock(t *testing.T) {
	now := time.Date(2026, 5, 17, 13, 44, 42, 0, time.UTC)
	older := now.Add(-1 * time.Hour)

	cases := []struct {
		name         string
		ecosystem    string
		pkg, version string
		requestID    string
		// handler returns the JSON bodies the test server should serve;
		// keyed by URL path.
		responses map[string]any
		wantHit   bool
		wantErr   bool
		wantSrc   string
		// extra assertions
		check func(t *testing.T, v *blockedViolation)
	}{
		{
			name:      "happy_path_most_recent_match",
			ecosystem: "pip",
			pkg:       "requests",
			version:   "2.31.0",
			responses: map[string]any{
				"/api/violations/blocked": blockedViolationsResponse{
					Violations: []blockedViolation{
						{
							ID: 1, RecordedAt: older,
							Format: "pip", PackageID: "requests", Version: "2.31.0",
							Reason: "stale", PolicyName: "Block vulnerable packages",
							CVEIDs: []string{"CVE-2024-OLD"}, CVSS: 5.0,
						},
						{
							ID: 2, RecordedAt: now,
							Format: "pip", PackageID: "requests", Version: "2.31.0",
							Reason: "is_vulnerable=true", PolicyName: "Block vulnerable packages",
							CVEIDs: []string{"CVE-2024-35195"}, CVSS: 5.6,
						},
						// Mismatched format: must be ignored.
						{
							ID: 3, RecordedAt: now,
							Format: "npm", PackageID: "requests", Version: "2.31.0",
						},
					},
				},
			},
			wantHit: true,
			wantSrc: "violations",
			check: func(t *testing.T, v *blockedViolation) {
				if v.ID != 2 {
					t.Errorf("expected most-recent row id=2, got %d", v.ID)
				}
				if len(v.CVEIDs) != 1 || v.CVEIDs[0] != "CVE-2024-35195" {
					t.Errorf("CVEs: want [CVE-2024-35195], got %v", v.CVEIDs)
				}
			},
		},
		{
			name:      "request_id_no_match_returns_nil",
			ecosystem: "pip",
			pkg:       "requests",
			version:   "2.31.0",
			requestID: "missing-id-deadbeef",
			responses: map[string]any{
				"/api/audit/logs": auditLogResponseCorr{
					Events: []auditEventWithCorr{
						{ID: "a", CorrelationID: "different-id", Status: "blocked"},
					},
				},
			},
			wantHit: false,
			wantSrc: "audit",
		},
		{
			name:      "request_id_match_uses_audit_metadata",
			ecosystem: "pip",
			pkg:       "requests",
			version:   "2.31.0",
			requestID: "a22794f3a2134e13",
			responses: map[string]any{
				"/api/audit/logs": auditLogResponseCorr{
					Events: []auditEventWithCorr{
						{
							ID: "e1", CorrelationID: "a22794f3a2134e13",
							Status: "blocked", Timestamp: now,
							Metadata: map[string]interface{}{
								"policy_name": "Block vulnerable packages",
								"reason":      "is_vulnerable=true",
								"cvss_score":  5.6,
								"cves":        []interface{}{"CVE-2024-35195", "CVE-2024-47081"},
							},
						},
					},
				},
			},
			wantHit: true,
			wantSrc: "audit",
			check: func(t *testing.T, v *blockedViolation) {
				if v.PolicyName != "Block vulnerable packages" {
					t.Errorf("policy_name from metadata not picked up: %q", v.PolicyName)
				}
				if v.CVSS != 5.6 {
					t.Errorf("cvss: want 5.6, got %v", v.CVSS)
				}
				if len(v.CVEIDs) != 2 {
					t.Errorf("CVEs: want 2 entries, got %v", v.CVEIDs)
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				body, ok := c.responses[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(body)
			})
			client := clientAt(srv.URL)

			got, src, err := lookupBlock(client, c.ecosystem, c.pkg, c.version, c.requestID)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("lookupBlock: %v", err)
			}
			if src != c.wantSrc {
				t.Errorf("source: want %q, got %q", c.wantSrc, src)
			}
			if c.wantHit && got == nil {
				t.Fatal("expected a row, got nil")
			}
			if !c.wantHit && got != nil {
				t.Fatalf("expected nil, got row id=%d", got.ID)
			}
			if c.check != nil && got != nil {
				c.check(t, got)
			}
		})
	}
}

// TestWhyParsePackageAtVersion covers the small splitter — particularly the
// npm-scoped-name edge case (@scope/name@version must split on the LAST @).
func TestWhyParsePackageAtVersion(t *testing.T) {
	cases := []struct {
		in          string
		wantName    string
		wantVersion string
		wantErr     bool
	}{
		{"requests@2.31.0", "requests", "2.31.0", false},
		{"requests", "requests", "", false},
		{"@babel/core@7.24.0", "@babel/core", "7.24.0", false},
		{"", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			name, ver, err := parsePackageAtVersion(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if name != c.wantName || ver != c.wantVersion {
				t.Errorf("want (%q,%q), got (%q,%q)", c.wantName, c.wantVersion, name, ver)
			}
		})
	}
}
