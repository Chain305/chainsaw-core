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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/policy"
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
	prevTok := viper.GetString("token")
	viper.Set("server_url", srv.URL)
	// newClient() refuses before the network call with no token (X4); the
	// stub server ignores Authorization.
	viper.Set("token", "test-token")
	t.Cleanup(func() {
		viper.Set("server_url", prev)
		viper.Set("token", prevTok)
	})

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
	// P9: with no --policy this is an informational dump and MUST exit 0.
	// It used to gate on "does any printed cell say none", which is a
	// property of the product's coverage matrix, not of the operator's
	// policies — and every one of the 16 ecosystem rows has at least one
	// none, so the command exited 1 for every org and every filter,
	// forever. A CI job wired as the help text documents failed 100% of
	// the time. The gate now lives on --policy; see the tests below.
	if err != nil {
		t.Fatalf("preflight without --policy is informational and must exit 0, got: %v", err)
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
	prevTok := viper.GetString("token")
	viper.Set("server_url", srv.URL)
	// newClient() refuses before the network call with no token (X4); the
	// stub server ignores Authorization.
	viper.Set("token", "test-token")
	t.Cleanup(func() {
		viper.Set("server_url", prev)
		viper.Set("token", prevTok)
	})

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

// newPreflightTestCmd builds a command carrying the flag set
// runPolicyPreflight reads, pointed at a stub support-matrix server.
func newPreflightTestCmd(t *testing.T, buf *bytes.Buffer, resp supportMatrixResponseDTO) *cobra.Command {
	t.Helper()
	withHookEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)

	prevURL := viper.GetString("server_url")
	prevTok := viper.GetString("token")
	viper.Set("server_url", srv.URL)
	viper.Set("token", "test-token")
	t.Cleanup(func() {
		viper.Set("server_url", prevURL)
		viper.Set("token", prevTok)
	})

	cmd := &cobra.Command{Use: "preflight", RunE: runPolicyPreflight}
	cmd.Flags().String("ecosystem", "", "")
	cmd.Flags().Bool("unsupported-only", false, "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("policy", "", "")
	cmd.Flags().String("output", "", "")
	cmd.Flags().String("format", "table", "")
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	return cmd
}

// realConditionMatrix uses the ACTUAL condition keys the server publishes
// (string(policy.ConditionType) — "HasInstallScript", not
// "hasInstallScript"), because the whole point of --policy is joining
// policy.ConditionsUsedBy output against those keys. A fixture with
// invented names would let a key-casing bug pass.
func realConditionMatrix() supportMatrixResponseDTO {
	return supportMatrixResponseDTO{
		Ecosystems: []string{"npm", "maven"},
		Conditions: []string{
			string(policy.ConditionHasInstallScript),
			string(policy.ConditionCVE),
		},
		Matrix: []supportMatrixRowDTO{
			{Ecosystem: "npm", Conditions: map[string]string{
				string(policy.ConditionHasInstallScript): "full",
				string(policy.ConditionCVE):              "full",
			}},
			{Ecosystem: "maven", Conditions: map[string]string{
				string(policy.ConditionHasInstallScript): "none",
				string(policy.ConditionCVE):              "full",
			}},
		},
	}
}

func writePreflightPolicy(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	fp := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(fp, []byte(body), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return dir
}

// TestRunPolicyPreflight_PolicyGateFires is the positive half of P9: a
// rule that USES hasInstallScript, previewed against maven where that
// condition is inert, exits 1 — and the message names the rule, the
// condition and the ecosystem so the operator can act on it.
func TestRunPolicyPreflight_PolicyGateFires(t *testing.T) {
	dir := writePreflightPolicy(t, `{
		"id":"p1","name":"block-install-scripts","mode":"block","status":"enabled","precedence":100,
		"conditions":{"hasInstallScript":true}
	}`)

	var buf bytes.Buffer
	cmd := newPreflightTestCmd(t, &buf, realConditionMatrix())
	_ = cmd.Flags().Set("policy", dir)
	_ = cmd.Flags().Set("ecosystem", "maven")

	err := runPolicyPreflight(cmd, nil)
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != preflightUnsupportedExitCode {
		t.Fatalf("expected ExitCodeError{%d}, got %v\n%s", preflightUnsupportedExitCode, err, buf.String())
	}
	out := buf.String()
	for _, want := range []string{"block-install-scripts", "HasInstallScript", "maven"} {
		if !strings.Contains(out, want) {
			t.Errorf("report must name %q, got:\n%s", want, out)
		}
	}
}

// TestRunPolicyPreflight_PolicyGateIgnoresUnusedConditions is the whole
// point of the change: maven has an inert cell, but the operator's policy
// does not use it, so there is nothing to fail on. Under the old gate
// this exited 1.
func TestRunPolicyPreflight_PolicyGateIgnoresUnusedConditions(t *testing.T) {
	dir := writePreflightPolicy(t, `{
		"id":"p1","name":"block-criticals","mode":"block","status":"enabled","precedence":100,
		"conditions":{"cvssMin":9.0}
	}`)

	var buf bytes.Buffer
	cmd := newPreflightTestCmd(t, &buf, realConditionMatrix())
	_ = cmd.Flags().Set("policy", dir)
	_ = cmd.Flags().Set("ecosystem", "maven")

	if err := runPolicyPreflight(cmd, nil); err != nil {
		t.Fatalf("a condition the policy does not use must not fail the gate, got %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "every condition used by") {
		t.Errorf("expected the all-clear line, got:\n%s", buf.String())
	}
}

// TestRunPolicyPreflight_PolicyGateScopedByEcosystem: a run scoped to npm
// must not fail because maven has the hole — same scoping rule the old
// anyUnsupported applied to printed rows.
func TestRunPolicyPreflight_PolicyGateScopedByEcosystem(t *testing.T) {
	dir := writePreflightPolicy(t, `{
		"id":"p1","name":"block-install-scripts","mode":"block","status":"enabled","precedence":100,
		"conditions":{"hasInstallScript":true}
	}`)

	var buf bytes.Buffer
	cmd := newPreflightTestCmd(t, &buf, realConditionMatrix())
	_ = cmd.Flags().Set("policy", dir)
	_ = cmd.Flags().Set("ecosystem", "npm")

	if err := runPolicyPreflight(cmd, nil); err != nil {
		t.Fatalf("--ecosystem npm must not fail on maven's hole, got %v\n%s", err, buf.String())
	}
}

// TestRunPolicyPreflight_UnreadablePolicyIsAnError: gating on a
// partially-parsed policy set would silently under-report, so a bad
// --policy is an operational failure, not a pass.
func TestRunPolicyPreflight_UnreadablePolicyIsAnError(t *testing.T) {
	var buf bytes.Buffer
	cmd := newPreflightTestCmd(t, &buf, realConditionMatrix())
	_ = cmd.Flags().Set("policy", filepath.Join(t.TempDir(), "does-not-exist"))

	err := runPolicyPreflight(cmd, nil)
	if err == nil {
		t.Fatal("a --policy path that cannot be read must fail, not silently pass the gate")
	}
	var coded *ExitCodeError
	if errors.As(err, &coded) && coded.Code == preflightUnsupportedExitCode {
		t.Errorf("an unreadable policy is an operational error, not a gate failure: %v", err)
	}
}

// TestRunPolicyPreflight_SurfacesSkippedPaths: preflight's answer is a GATE,
// and this file's own header says gating on a partially-parsed policy set
// silently under-reports. So a --policy DIRECTORY whose tree could not be
// fully read must (a) name the unreadable paths in the operator's output and
// (b) refuse to print the all-clear — it exits with the shared
// policyScanIncompleteExitCode instead.
func TestRunPolicyPreflight_SurfacesSkippedPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-000 does not model Windows ACL denial")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny access")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(`{
		"id":"p1","name":"block-criticals","mode":"block","status":"enabled","precedence":100,
		"conditions":{"cvssMin":9.0}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "more-policies")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "extra.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	var buf bytes.Buffer
	cmd := newPreflightTestCmd(t, &buf, realConditionMatrix())
	_ = cmd.Flags().Set("policy", dir)
	_ = cmd.Flags().Set("ecosystem", "maven")

	err := runPolicyPreflight(cmd, nil)
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != policyScanIncompleteExitCode {
		t.Fatalf("expected ExitCodeError{%d} for a half-read policy tree, got %v\n%s",
			policyScanIncompleteExitCode, err, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "more-policies") || !strings.Contains(out, "permission denied") {
		t.Errorf("the skipped path and its reason must be surfaced, got:\n%s", out)
	}
	if strings.Contains(out, "✓ every condition used by") {
		t.Errorf("must not print the all-clear over a policy set it only half read, got:\n%s", out)
	}
}

// TestRunPolicyPreflight_SweepIgnoresNonPolicyFiles: `--policy .` inside a
// repo used to die on the first tsconfig.json it walked past. The sweep now
// skips it (and node_modules entirely) and gates on the real policy only.
func TestRunPolicyPreflight_SweepIgnoresNonPolicyFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "tsconfig.json"),
		[]byte("{\n  // a comment, legal in tsconfig, fatal to a YAML parser\n  \"compilerOptions\": {}\n}"),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte(`{"name":"my-app","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), []byte(`{
		"id":"p1","name":"block-install-scripts","mode":"block","status":"enabled","precedence":100,
		"conditions":{"hasInstallScript":true}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	cmd := newPreflightTestCmd(t, &buf, realConditionMatrix())
	_ = cmd.Flags().Set("policy", dir)
	_ = cmd.Flags().Set("ecosystem", "maven")

	// The real policy still drives the gate: hasInstallScript is "none" on
	// maven, so this is exit 1 — the honest answer, not a parse crash.
	err := runPolicyPreflight(cmd, nil)
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != preflightUnsupportedExitCode {
		t.Fatalf("expected the real policy to drive the gate (exit %d), got %v\n%s",
			preflightUnsupportedExitCode, err, buf.String())
	}
	if !strings.Contains(buf.String(), "block-install-scripts") {
		t.Errorf("gate must name the real rule, got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "tsconfig.json") {
		t.Errorf("the skipped non-policy files must still be surfaced, got:\n%s", buf.String())
	}
}

// TestPreflightTable_CoverageColumnVaries is the L-26 guard.
//
// The second column used to be a STATUS cell that read "unsupported" whenever
// a row had ANY hole. Measured on the real matrix (16 ecosystems x 46
// conditions, 281 "none" cells) every row has at least one, so the column was
// the same literal sixteen times — zero information, and it implied nothing
// was supported when 455 of the 736 cells are. A coverage count has to VARY
// with the row or it is the same defect in new clothes.
func TestPreflightTable_CoverageColumnVaries(t *testing.T) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	resp := sampleMatrixResponse()
	// pip has one "none" of three, maven has two of three — different
	// counts on purpose.
	rows := []supportMatrixRowDTO{resp.Matrix[1], resp.Matrix[2]}
	printPreflightTable(cmd, rows, resp.Conditions)

	out := buf.String()
	cells := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if fields[0] == "pip" || fields[0] == "maven" {
			cells[fields[0]] = fields[1]
		}
	}
	if len(cells) != 2 {
		t.Fatalf("expected a coverage cell for pip and maven, got %v in:\n%s", cells, out)
	}
	if cells["pip"] != "2/3" {
		t.Errorf("pip coverage cell = %q, want 2/3 (one of three conditions is none)", cells["pip"])
	}
	if cells["maven"] != "1/3" {
		t.Errorf("maven coverage cell = %q, want 1/3 (two of three conditions are none)", cells["maven"])
	}
	if cells["pip"] == cells["maven"] {
		t.Errorf("both rows render the same cell %q — a column that cannot vary carries no information", cells["pip"])
	}
	// The literal that used to fill the column must be gone as a STATUS
	// value. It legitimately survives in the header ("UNSUPPORTED
	// CONDITIONS"), so match the lower-case cell form.
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "unsupported" {
			t.Errorf("row still renders a constant %q status cell: %q", "unsupported", line)
		}
	}
}

// TestConditionCoverage_ComplementsUnsupportedList pins the invariant the two
// columns share: whatever the third column lists as a hole is exactly what the
// second column declines to count as supported. If they drift, the table
// contradicts itself row by row.
func TestConditionCoverage_ComplementsUnsupportedList(t *testing.T) {
	resp := sampleMatrixResponse()
	for _, row := range resp.Matrix {
		supported, total := conditionCoverage(row, resp.Conditions)
		unsupported := unsupportedConditions(row, resp.Conditions)
		if supported+len(unsupported) != total {
			t.Errorf("%s: supported=%d + unsupported=%d != total=%d", row.Ecosystem, supported, len(unsupported), total)
		}
		// Same invariant with no canonical condition order (the fallback
		// branch that ranges the map).
		supported, total = conditionCoverage(row, nil)
		unsupported = unsupportedConditions(row, nil)
		if supported+len(unsupported) != total {
			t.Errorf("%s (unordered): supported=%d + unsupported=%d != total=%d", row.Ecosystem, supported, len(unsupported), total)
		}
	}
}
