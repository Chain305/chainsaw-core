package cli

// scan-actions
//
// Tests for `chainsaw scan-actions`. We avoid the cobra Execute / os.Exit
// wrapper entirely and call runScanActions directly so we can assert on
// the exit code in-process. Fixtures live under internal/githubactions/
// testdata/ — reusing them keeps the parser <-> CLI contract honest.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newScanActionsTestCmd builds an isolated *cobra.Command that mirrors
// scanActionsCmd's flag surface but does NOT call os.Exit on a non-zero
// exit code — RunE-bound tests need to inspect that code in-process.
func newScanActionsTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "scan-actions"}
	cmd.Flags().String("format", "text", "")
	return cmd
}

func TestScanActions_Directory_HappyPath(t *testing.T) {
	// Use a single Wave-4 fixture: simple.yml has two unpinned remote refs
	// (actions/checkout@v4 and actions/setup-node@v3) which the stub Scan
	// flags as medium-severity action.unpinned_ref findings.
	fixture := filepath.Join("..", "githubactions", "testdata", "simple.yml")

	cmd := newScanActionsTestCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if err := cmd.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set format: %v", err)
	}

	code, err := runScanActions(cmd, []string{fixture})
	if err != nil {
		t.Fatalf("runScanActions: %v", err)
	}
	// simple.yml has only unpinned (medium) findings — no high — so exit 0.
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (no high-severity findings expected)", code)
	}

	var report scanActionsReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v\nbody=%s", err, out.String())
	}
	// simple.yml has two `uses:` entries (actions/checkout@v4, actions/setup-node@v3)
	// — both are unpinned (no SHA), so the stub Scan emits at least 2 findings.
	if report.Summary.Total < 2 {
		t.Errorf("summary.total = %d, want >= 2 (got findings: %+v)", report.Summary.Total, report.Findings)
	}
	if report.Summary.Workflows != 1 {
		t.Errorf("summary.workflows = %d, want 1 (single-file mode)", report.Summary.Workflows)
	}
	// Every finding must reference the fixture path.
	for _, f := range report.Findings {
		if !strings.HasSuffix(f.File, "simple.yml") {
			t.Errorf("finding.file = %q, want suffix simple.yml", f.File)
		}
		if f.Line == 0 {
			t.Errorf("finding.line is zero: %+v", f)
		}
	}
	// Wave-7 risk-block: simple.yml's two unpinned actions must drive
	// action.unpinned_ref through the v2 engine, and the projected
	// Action input fields must surface ActionRefUnpinned=true.
	foundUnpinned := false
	for _, sig := range report.Risk.Signals {
		if sig == "action.unpinned_ref" {
			foundUnpinned = true
			break
		}
	}
	if !foundUnpinned {
		t.Errorf("risk.signals missing action.unpinned_ref: %v", report.Risk.Signals)
	}
	if v, _ := report.Risk.Fields["ActionRefUnpinned"].(bool); !v {
		t.Errorf("risk.fields.ActionRefUnpinned not true: %+v", report.Risk.Fields)
	}
	if refs, ok := report.Risk.Fields["ActionRefUnpinnedRefs"].([]any); !ok || len(refs) == 0 {
		t.Errorf("risk.fields.ActionRefUnpinnedRefs missing or empty: %+v", report.Risk.Fields)
	}
}

func TestScanActions_TextOutput_PrintsSummary(t *testing.T) {
	fixture := filepath.Join("..", "githubactions", "testdata", "simple.yml")

	cmd := newScanActionsTestCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	// default format = text

	code, err := runScanActions(cmd, []string{fixture})
	if err != nil {
		t.Fatalf("runScanActions: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	body := out.String()
	if !strings.Contains(body, "Found ") || !strings.Contains(body, "workflows") {
		t.Errorf("text output missing summary line:\n%s", body)
	}
	if !strings.Contains(body, "simple.yml") {
		t.Errorf("text output missing file path:\n%s", body)
	}
}

func TestScanActions_HighSeverity_ExitsOne(t *testing.T) {
	// tj-actions/changed-files is in the malicious-Action feed seeded by
	// Wave 4 (GHSA-mrrh-fwg8-r2c3 / CVE-2025-30066 — March 2025 token-leak
	// incident). Scan emits SignalActionMalicious at high severity, which
	// must drive the CLI exit code to 1.
	dir := t.TempDir()
	wf := filepath.Join(dir, "evil.yml")
	const yaml = `name: evil
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v1
`
	if err := os.WriteFile(wf, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cmd := newScanActionsTestCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if err := cmd.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set format: %v", err)
	}

	code, err := runScanActions(cmd, []string{wf})
	if err != nil {
		t.Fatalf("runScanActions: %v", err)
	}
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (high-severity finding present)\nbody=%s", code, out.String())
	}
	var report scanActionsReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.Summary.High < 1 {
		t.Errorf("summary.high = %d, want >= 1", report.Summary.High)
	}
}

// TestScanActions_RunOnlyWorkflowsAreCounted is the L-06 guard.
//
// The workflow count was derived from the distinct SourceFile values of the
// parsed ActionRefs, so a workflow whose steps are all `run:` — which yields
// no refs at all — counted as zero workflows, and the risk line reported
// "no workflows found" about a file it had just parsed end to end. A repo of
// run-only workflows was indistinguishable from a repo with none.
func TestScanActions_RunOnlyWorkflowsAreCounted(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const yaml = `name: build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
      - run: make test
`
	if err := os.WriteFile(filepath.Join(wfDir, "build.yml"), []byte(yaml), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cmd := newScanActionsTestCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if err := cmd.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set format: %v", err)
	}

	code, err := runScanActions(cmd, []string{dir})
	if err != nil {
		t.Fatalf("runScanActions: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (a run-only workflow is clean, not a failure)", code)
	}
	var report scanActionsReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v\nbody=%s", err, out.String())
	}
	if report.Summary.Workflows != 1 {
		t.Errorf("summary.workflows = %d, want 1 — the file was parsed, it just uses no Actions", report.Summary.Workflows)
	}
	if report.Summary.ActionRefs != 0 {
		t.Errorf("summary.action_refs = %d, want 0 (no `uses:` steps)", report.Summary.ActionRefs)
	}

	// And the text rendering must not claim the directory was empty.
	textCmd := newScanActionsTestCmd()
	var textOut, textErr bytes.Buffer
	textCmd.SetOut(&textOut)
	textCmd.SetErr(&textErr)
	if _, err := runScanActions(textCmd, []string{dir}); err != nil {
		t.Fatalf("runScanActions (text): %v", err)
	}
	body := textOut.String()
	if strings.Contains(body, "no workflows found") {
		t.Errorf("text output claims no workflows over a directory it parsed:\n%s", body)
	}
	if !strings.Contains(body, "clean") {
		t.Errorf("text output should report a clean verdict for a parsed run-only workflow:\n%s", body)
	}
}

// TestScanActions_EmptyDirStillReportsNoWorkflows is the other half of the
// L-06 contract: the "found nothing to scan" wording must survive for the case
// it was written for, and the exit code stays 0 (an absent .github/workflows
// is the majority case for a repo, not an error).
func TestScanActions_EmptyDirStillReportsNoWorkflows(t *testing.T) {
	dir := t.TempDir()

	cmd := newScanActionsTestCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	code, err := runScanActions(cmd, []string{dir})
	if err != nil {
		t.Fatalf("runScanActions: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 — an absent workflows dir is not a failure", code)
	}
	if !strings.Contains(out.String(), "no workflows found") {
		t.Errorf("text output should still say 'no workflows found' for an empty dir:\n%s", out.String())
	}
}

// TestScanActions_MultipleFilesCounted proves the count follows FILES, not
// refs: two workflows where only one uses an Action still counts as two.
func TestScanActions_MultipleFilesCounted(t *testing.T) {
	dir := t.TempDir()
	wfDir := filepath.Join(dir, ".github", "workflows")
	if err := os.MkdirAll(wfDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const runOnly = `name: build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make build
`
	const withUses = `name: ci
on: [push]
jobs:
  ci:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	if err := os.WriteFile(filepath.Join(wfDir, "build.yml"), []byte(runOnly), 0o644); err != nil {
		t.Fatalf("write build.yml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(wfDir, "ci.yml"), []byte(withUses), 0o644); err != nil {
		t.Fatalf("write ci.yml: %v", err)
	}

	cmd := newScanActionsTestCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if err := cmd.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set format: %v", err)
	}

	if _, err := runScanActions(cmd, []string{dir}); err != nil {
		t.Fatalf("runScanActions: %v", err)
	}
	var report scanActionsReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v\nbody=%s", err, out.String())
	}
	if report.Summary.Workflows != 2 {
		t.Errorf("summary.workflows = %d, want 2 — only one file has a `uses:`, but both were parsed", report.Summary.Workflows)
	}
	if report.Summary.ActionRefs != 1 {
		t.Errorf("summary.action_refs = %d, want 1", report.Summary.ActionRefs)
	}
}

// runScanActionsJSON runs scan-actions over target with --format json and
// the given --fail-on ("" leaves the flag at its default).
func runScanActionsJSON(t *testing.T, target, failOn string) (int, scanActionsReport, error) {
	t.Helper()
	cmd := newScanActionsTestCmd()
	cmd.Flags().String("fail-on", "high", "")
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	_ = cmd.Flags().Set("format", "json")
	if failOn != "" {
		_ = cmd.Flags().Set("fail-on", failOn)
	}
	code, err := runScanActions(cmd, []string{target})
	var report scanActionsReport
	if err == nil {
		if jerr := json.Unmarshal(out.Bytes(), &report); jerr != nil {
			t.Fatalf("decode report: %v\nbody=%s", jerr, out.String())
		}
	}
	return code, report, err
}

// TestScanActions_FailOn: action.unpinned_ref is medium, so with the old
// high-only gate tag pinning could not be enforced in CI at all.
func TestScanActions_FailOn(t *testing.T) {
	fixture := filepath.Join("..", "githubactions", "testdata", "simple.yml")
	for _, tc := range []struct {
		failOn string
		want   int
	}{
		{"", 0}, // default high: unchanged behaviour
		{"high", 0},
		{"medium", 1},
		{"MEDIUM", 1},
		{"low", 1},
	} {
		code, _, err := runScanActionsJSON(t, fixture, tc.failOn)
		if err != nil {
			t.Fatalf("--fail-on %q: %v", tc.failOn, err)
		}
		if code != tc.want {
			t.Errorf("--fail-on %q: exit %d, want %d", tc.failOn, code, tc.want)
		}
	}
	if _, _, err := runScanActionsJSON(t, fixture, "critical"); err == nil {
		t.Error("--fail-on critical: want a usage error")
	}
}

// TestScanActions_DangerousTriggers: the workflow-structure lint reaches the
// CLI report, its exit code, the risk block and SARIF.
func TestScanActions_DangerousTriggers(t *testing.T) {
	fixture := filepath.Join("..", "githubactions", "testdata", "dangerous_triggers.yml")
	code, report, err := runScanActionsJSON(t, fixture, "")
	if err != nil {
		t.Fatalf("runScanActions: %v", err)
	}
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	want := []string{"action.pwn_request", "action.comment_trigger_unguarded", "action.script_injection"}
	for _, sig := range want {
		var found bool
		for _, f := range report.Findings {
			if f.Signal == sig && f.Severity == "high" && f.Line > 0 && strings.HasSuffix(f.File, "dangerous_triggers.yml") {
				found = true
			}
		}
		if !found {
			t.Errorf("no high %s finding in %+v", sig, report.Findings)
		}
		if !strings.Contains(strings.Join(report.Risk.Signals, ","), sig) {
			t.Errorf("risk.signals %v missing %s", report.Risk.Signals, sig)
		}
	}
	var sarif bytes.Buffer
	if err := writeScanActionsSARIF(&sarif, report); err != nil {
		t.Fatal(err)
	}
	for _, sig := range want {
		if !strings.Contains(sarif.String(), `"ruleId": "`+sig+`"`) {
			t.Errorf("SARIF has no result for %s", sig)
		}
	}
}

// TestScanActions_LocalAdvisorySnapshot: the CLI used only the three-entry
// static seed. A GitHub Actions OSV snapshot next to the guard cache must be
// loaded — offline, no network.
func TestScanActions_LocalAdvisorySnapshot(t *testing.T) {
	cache := t.TempDir()
	t.Setenv(guardDBEnv, filepath.Join(cache, "known_malicious.json"))
	wf := filepath.Join(t.TempDir(), "ci.yml")
	const yml = "on: [push]\njobs:\n  b:\n    steps:\n      - uses: evil-org/evil-action@v2.0.0\n"
	if err := os.WriteFile(wf, []byte(yml), 0o644); err != nil {
		t.Fatal(err)
	}
	malicious := func(r scanActionsReport) bool {
		for _, f := range r.Findings {
			if f.Signal == "action.malicious" {
				return true
			}
		}
		return false
	}
	if _, r, err := runScanActionsJSON(t, wf, ""); err != nil || malicious(r) {
		t.Fatalf("before snapshot: err=%v malicious=%v", err, malicious(r))
	}

	dir := filepath.Join(cache, scanActionsOSVDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	adv := `{"id":"GHSA-test-snap","summary":"evil","affected":[{"package":{"ecosystem":"GitHub Actions","name":"evil-org/evil-action"},` +
		`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.0"}]}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "GHSA-test-snap.json"), []byte(adv), 0o644); err != nil {
		t.Fatal(err)
	}
	code, r, err := runScanActionsJSON(t, wf, "")
	if err != nil {
		t.Fatal(err)
	}
	if !malicious(r) || code != 1 {
		t.Fatalf("after snapshot: malicious=%v exit=%d, want true/1; findings=%+v", malicious(r), code, r.Findings)
	}
}

// scan-actions end
