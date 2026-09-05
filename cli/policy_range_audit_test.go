package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
)

// newPolicyAuditTestCmd mirrors newSimulateTestCmd: the flags
// runPolicyAudit reads, with output routed to a buffer.
func newPolicyAuditTestCmd(buf *bytes.Buffer, asJSON bool) *cobra.Command {
	cmd := &cobra.Command{Use: "audit"}
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("output", "", "")
	if asJSON {
		_ = cmd.Flags().Set("json", "true")
	}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	return cmd
}

// policyAuditHandler serves the given policy JSON bodies from
// /api/policies and records every request, so a test can prove the
// command only ever READS.
func policyAuditHandler(t *testing.T, seen *[]string, mu *sync.Mutex, policies ...map[string]any) http.HandlerFunc {
	t.Helper()
	if policies == nil {
		policies = []map[string]any{}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*seen = append(*seen, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.URL.Path != "/api/policies" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"policies": policies})
	}
}

func neverFiresPolicy() map[string]any {
	return map[string]any{
		"id": "test-999", "name": "block criticals", "mode": "block", "status": "enabled",
		"conditions": map[string]any{"cvssMin": 999},
	}
}

func matchAllPolicy() map[string]any {
	return map[string]any{
		"id": "test-neg", "name": "block vulnerable", "mode": "block", "status": "enabled",
		"conditions": map[string]any{"cvssMin": 0},
	}
}

// TestPolicyAudit_TextSeparatesNeverFiresFromMatchAll is the operator-facing
// half of the residual: the two rows the QA org actually holds must read as
// opposite problems, not as one generic "bad threshold" line.
func TestPolicyAudit_TextSeparatesNeverFiresFromMatchAll(t *testing.T) {
	var (
		seen []string
		mu   sync.Mutex
	)
	srv := withTestServer(t, policyAuditHandler(t, &seen, &mu, neverFiresPolicy(), matchAllPolicy()))
	withConfiguredServer(t, srv.URL)

	var buf bytes.Buffer
	cmd := newPolicyAuditTestCmd(&buf, false)
	err := runPolicyAudit(cmd, nil)

	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != lintExitError {
		t.Fatalf("an out-of-range row is an error-level finding; want ExitCodeError{%d}, got %v (%T)", lintExitError, err, err)
	}

	out := buf.String()
	for _, want := range []string{
		"test-999", "block criticals", "conditions.cvssMin", "999",
		"blocks nothing", "0 to 10",
		"test-neg", "blocks every request that reaches it",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output is missing %q:\n%s", want, out)
		}
	}
	// Read-only: nothing but the GET.
	mu.Lock()
	defer mu.Unlock()
	for _, req := range seen {
		if !strings.HasPrefix(req, "GET ") {
			t.Errorf("policy audit must never write; saw %s", req)
		}
	}
	if len(seen) == 0 {
		t.Error("expected the command to fetch the live policies")
	}
}

// TestPolicyAudit_JSONEnvelope pins the machine shape a CI gate reads.
func TestPolicyAudit_JSONEnvelope(t *testing.T) {
	var (
		seen []string
		mu   sync.Mutex
	)
	srv := withTestServer(t, policyAuditHandler(t, &seen, &mu, neverFiresPolicy(), matchAllPolicy()))
	withConfiguredServer(t, srv.URL)

	var buf bytes.Buffer
	cmd := newPolicyAuditTestCmd(&buf, true)
	if err := runPolicyAudit(cmd, nil); err == nil {
		t.Fatal("findings present must still carry a non-zero exit code")
	}

	var got struct {
		SchemaVersion string `json:"schemaVersion"`
		Policies      int    `json:"policies"`
		Errors        int    `json:"errors"`
		Warnings      int    `json:"warnings"`
		Findings      []struct {
			PolicyID    string  `json:"policyId"`
			Field       string  `json:"field"`
			Value       float64 `json:"value"`
			ValidRange  string  `json:"validRange"`
			Effect      string  `json:"effect"`
			Severity    string  `json:"severity"`
			Consequence string  `json:"consequence"`
			Comparison  string  `json:"comparison"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode envelope: %v\n%s", err, buf.String())
	}
	if got.SchemaVersion != policyAuditSchemaVersion {
		t.Errorf("schemaVersion = %q, want %q", got.SchemaVersion, policyAuditSchemaVersion)
	}
	if got.Policies != 2 || got.Errors != 1 || got.Warnings != 1 {
		t.Errorf("counts: policies=%d errors=%d warnings=%d, want 2/1/1", got.Policies, got.Errors, got.Warnings)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d: %s", len(got.Findings), buf.String())
	}
	if got.Findings[0].Effect != "never_fires" || got.Findings[1].Effect != "matches_everything" {
		t.Errorf("effects: %q / %q", got.Findings[0].Effect, got.Findings[1].Effect)
	}
	if got.Findings[0].Value != 999 || got.Findings[0].ValidRange != "0 to 10" {
		t.Errorf("first finding: %+v", got.Findings[0])
	}
	for i, f := range got.Findings {
		if f.Consequence == "" || f.Comparison == "" || f.PolicyID == "" || f.Field == "" {
			t.Errorf("finding %d is missing a required field: %+v", i, f)
		}
	}
}

// TestPolicyAudit_CleanOrgIsQuietAndExitsZero — the common case. `findings`
// must be an empty ARRAY, not null: `jq '.findings[]'` errors on null, and
// this command exists to be run from CI.
func TestPolicyAudit_CleanOrgIsQuietAndExitsZero(t *testing.T) {
	var (
		seen []string
		mu   sync.Mutex
	)
	clean := map[string]any{
		"id": "ok-1", "name": "block criticals", "mode": "block", "status": "enabled",
		"conditions": map[string]any{"cvssMin": 9, "epssMin": 0.5},
	}
	srv := withTestServer(t, policyAuditHandler(t, &seen, &mu, clean))
	withConfiguredServer(t, srv.URL)

	var buf bytes.Buffer
	if err := runPolicyAudit(newPolicyAuditTestCmd(&buf, false), nil); err != nil {
		t.Fatalf("a clean org must exit 0, got %v", err)
	}
	if !strings.Contains(buf.String(), "No out-of-range") {
		t.Errorf("clean run must say so plainly, got:\n%s", buf.String())
	}

	buf.Reset()
	if err := runPolicyAudit(newPolicyAuditTestCmd(&buf, true), nil); err != nil {
		t.Fatalf("clean --json must exit 0, got %v", err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("clean --json must emit an empty array, not null:\n%s", buf.String())
	}
}

// TestPolicyAudit_WarningsOnlyExitOne keeps the ladder in step with
// `policy lint`: 0 clean, 1 warnings only, 2 any errors.
func TestPolicyAudit_WarningsOnlyExitOne(t *testing.T) {
	var (
		seen []string
		mu   sync.Mutex
	)
	srv := withTestServer(t, policyAuditHandler(t, &seen, &mu, matchAllPolicy()))
	withConfiguredServer(t, srv.URL)

	var buf bytes.Buffer
	err := runPolicyAudit(newPolicyAuditTestCmd(&buf, false), nil)
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != lintExitWarning {
		t.Fatalf("cvssMin: 0 is inside the bound Create enforces, so it is warning-only; want %d, got %v", lintExitWarning, err)
	}
}

// TestPolicyAudit_HelpRefusesToPromiseRepair — the command must say, in the
// help an operator reads before running it, that it changes nothing.
// Rewriting a block policy's threshold changes what that policy refuses.
func TestPolicyAudit_HelpRefusesToPromiseRepair(t *testing.T) {
	long := policyAuditCmd.Long
	for _, want := range []string{"read-only", "does not"} {
		if !strings.Contains(strings.ToLower(long), want) {
			t.Errorf("policy audit --help must contain %q:\n%s", want, long)
		}
	}
	for _, code := range []string{"0", "1", "2"} {
		if !strings.Contains(long, code) {
			t.Errorf("the exit ladder must be published in --help; %q missing", code)
		}
	}
}

// TestPolicyAudit_NoServerConfigured keeps the unconfigured path on the
// shared error rather than a bare connection failure.
func TestPolicyAudit_NoServerConfigured(t *testing.T) {
	withConfiguredServer(t, "")
	var buf bytes.Buffer
	if err := runPolicyAudit(newPolicyAuditTestCmd(&buf, false), nil); err == nil {
		t.Fatal("expected an error with no server configured")
	}
}
