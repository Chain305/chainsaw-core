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

// scan-actions end
