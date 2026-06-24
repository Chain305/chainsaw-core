package cli

// Tests for `chainsaw policy preflight` (Gap #3).
//
// We exercise three layers:
//   1. filterPreflightRows / unsupportedConditions — pure functions, table
//      driven, no network.
//   2. The full RunE against an httptest stub of /api/policies/support-matrix
//      — this is the only way to prove the URL we hit and the JSON shape we
//      decode haven't drifted from the server's policy_support_matrix.go.
//   3. The exit-code contract: a row with at least one "none" cell must
//      surface as an ExitCodeError{Code: preflightUnsupportedExitCode} so CI
//      pipelines can gate on it, while an all-supported response returns nil.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func sampleMatrixResponse() supportMatrixResponseDTO {
	return supportMatrixResponseDTO{
		Ecosystems: []string{"npm", "pip", "maven"},
		Conditions: []string{"isVulnerable", "hasInstallScript", "hasHiddenUnicode"},
		Matrix: []supportMatrixRowDTO{
			{
				Ecosystem: "npm",
				Conditions: map[string]string{
					"isVulnerable":     "full",
					"hasInstallScript": "full",
					"hasHiddenUnicode": "partial",
				},
			},
			{
				Ecosystem: "pip",
				Conditions: map[string]string{
					"isVulnerable":     "full",
					"hasInstallScript": "full",
					"hasHiddenUnicode": "none",
				},
			},
			{
				Ecosystem: "maven",
				Conditions: map[string]string{
					"isVulnerable":     "full",
					"hasInstallScript": "none",
					"hasHiddenUnicode": "none",
				},
			},
		},
	}
}

// TestFilterPreflightRows_NoFilters returns every row untouched.
func TestFilterPreflightRows_NoFilters(t *testing.T) {
	rows, err := filterPreflightRows(sampleMatrixResponse(), "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d", len(rows))
	}
}

// TestFilterPreflightRows_EcosystemFilter narrows to a single ecosystem and
// is case-insensitive on the flag value.
func TestFilterPreflightRows_EcosystemFilter(t *testing.T) {
	rows, err := filterPreflightRows(sampleMatrixResponse(), "NPM", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 1 || rows[0].Ecosystem != "npm" {
		t.Fatalf("want only npm row, got %+v", rows)
	}
}

// TestFilterPreflightRows_UnknownEcosystem fails loudly so a CI typo
// (`--ecosystem nmp`) doesn't silently print zero rows and exit 0.
func TestFilterPreflightRows_UnknownEcosystem(t *testing.T) {
	_, err := filterPreflightRows(sampleMatrixResponse(), "nmp", false)
	if err == nil {
		t.Fatalf("expected error for unknown ecosystem")
	}
	if !strings.Contains(err.Error(), "nmp") {
		t.Fatalf("error should mention bad value, got: %v", err)
	}
	if !strings.Contains(err.Error(), "npm") {
		t.Fatalf("error should list known ecosystems, got: %v", err)
	}
}

// TestFilterPreflightRows_UnsupportedOnly drops rows that have only
// full/partial cells. npm has only full+partial here so it must drop.
func TestFilterPreflightRows_UnsupportedOnly(t *testing.T) {
	rows, err := filterPreflightRows(sampleMatrixResponse(), "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 rows (pip, maven), got %d", len(rows))
	}
	for _, r := range rows {
		if r.Ecosystem == "npm" {
			t.Fatalf("npm should have been filtered out, has no none cells")
		}
	}
}

// TestUnsupportedConditions_DeterministicOrder pins the column order to the
// server's published Conditions list — operators reading this output should
// see the same column order as POLICY_PROXY_MATRIX.md.
func TestUnsupportedConditions_DeterministicOrder(t *testing.T) {
	row := supportMatrixRowDTO{
		Ecosystem: "maven",
		Conditions: map[string]string{
			"isVulnerable":     "full",
			"hasInstallScript": "none",
			"hasHiddenUnicode": "none",
		},
	}
	got := unsupportedConditions(row, []string{"isVulnerable", "hasInstallScript", "hasHiddenUnicode"})
	want := []string{"hasInstallScript", "hasHiddenUnicode"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("position %d: want %q, got %q", i, want[i], got[i])
		}
	}
}

// TestRunPolicyPreflight_HitsSupportMatrixEndpoint stubs the server, runs
// the command, and asserts (a) we hit the same path the UI uses, (b) the
// row that has a "none" cell surfaces as an unsupported exit code, and
// (c) the printed table contains the offending condition name.
func TestRunPolicyPreflight_HitsSupportMatrixEndpoint(t *testing.T) {
	withHookEnv(t)

	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		if r.URL.Path != "/api/policies/support-matrix" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(sampleMatrixResponse())
	}))
	t.Cleanup(srv.Close)

	// Use viper to point newClient() at the stub server. cli.NewAPIClient
	// reads cfgServerURL() which is backed by viper.GetString("server_url").
	prev := viper.GetString("server_url")
	viper.Set("server_url", srv.URL)
	t.Cleanup(func() { viper.Set("server_url", prev) })

	var buf bytes.Buffer
	cmd := &cobra.Command{Use: "preflight", RunE: runPolicyPreflight}
	cmd.Flags().String("ecosystem", "", "")
	cmd.Flags().Bool("unsupported-only", false, "")
	cmd.Flags().Bool("json", false, "")
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	err := runPolicyPreflight(cmd, nil)

	if seenPath != "/api/policies/support-matrix" {
		t.Fatalf("expected hit on /api/policies/support-matrix, got %q", seenPath)
	}
	if err == nil {
		t.Fatalf("expected non-nil error (sample matrix has 'none' cells), got nil")
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) {
		t.Fatalf("expected *ExitCodeError, got %T: %v", err, err)
	}
	if coded.Code != preflightUnsupportedExitCode {
		t.Fatalf("expected exit code %d, got %d", preflightUnsupportedExitCode, coded.Code)
	}
	out := buf.String()
	if !strings.Contains(out, "hasInstallScript") {
		t.Fatalf("expected output to list hasInstallScript as unsupported, got: %s", out)
	}
	if !strings.Contains(out, "maven") {
		t.Fatalf("expected output to include maven row, got: %s", out)
	}
}

// TestRunPolicyPreflight_AllSupportedReturnsNil — when the server reports
// every cell as full/partial for the filtered scope, exit code is 0.
func TestRunPolicyPreflight_AllSupportedReturnsNil(t *testing.T) {
	withHookEnv(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(supportMatrixResponseDTO{
			Ecosystems: []string{"npm"},
			Conditions: []string{"isVulnerable"},
			Matrix: []supportMatrixRowDTO{{
				Ecosystem:  "npm",
				Conditions: map[string]string{"isVulnerable": "full"},
			}},
		})
	}))
	t.Cleanup(srv.Close)

	prev := viper.GetString("server_url")
	viper.Set("server_url", srv.URL)
	t.Cleanup(func() { viper.Set("server_url", prev) })

	var buf bytes.Buffer
	cmd := &cobra.Command{Use: "preflight", RunE: runPolicyPreflight}
	cmd.Flags().String("ecosystem", "", "")
	cmd.Flags().Bool("unsupported-only", false, "")
	cmd.Flags().Bool("json", false, "")
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := runPolicyPreflight(cmd, nil); err != nil {
		t.Fatalf("expected nil error when every cell is supported, got: %v", err)
	}
}
