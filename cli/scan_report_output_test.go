package cli

// Regression tests for the output/format plumbing on the scan / SBOM / report
// surface:
//
//	S8  scan-actions and the four `report` subcommands read only their LOCAL
//	    --format and ignored the documented global --json
//	S9  --output was ignored on several machine-readable paths, so the result
//	    went to stdout and no file was created
//	S10 `sbom export -o <file>` hard-errored because a local --output
//	    declaration made cobra drop the persistent flag AND its `o` shorthand

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// ── S8 / S9: scan-actions ──────────────────────────────────────────────────

// newScanActionsFullFlagCmd mirrors scanActionsCmd's local flags PLUS the root
// persistent flags it inherits at runtime, which the older test helper omits.
func newScanActionsFullFlagCmd(out, errOut *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{Use: "scan-actions"}
	cmd.Flags().String("format", "text", "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("output", "", "")
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	return cmd
}

func actionsFixture() string {
	return filepath.Join("..", "githubactions", "testdata", "simple.yml")
}

// TestScanActions_GlobalJSONFlagHonored is the S8 guard. --json is a root
// persistent flag documented as "alias for --format=json", and scan /
// scan-repo / deps / affected all honor it; scan-actions read only its local
// --format, so `chainsaw scan-actions ./wf --json` printed the human table
// plus a "Risk evaluation: …" line to a consumer expecting JSON.
func TestScanActions_GlobalJSONFlagHonored(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := newScanActionsFullFlagCmd(&out, &errOut)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json: %v", err)
	}
	if _, err := runScanActions(cmd, []string{actionsFixture()}); err != nil {
		t.Fatalf("runScanActions: %v", err)
	}
	if strings.Contains(out.String(), "Risk evaluation:") {
		t.Fatalf("--json must not emit the human table, got:\n%s", out.String())
	}
	var report scanActionsReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", err, out.String())
	}
}

// TestScanActions_JSONHonorsOutputFlag is the S9 guard: the SARIF branch
// already used outWriter(cmd); its JSON sibling two lines above did not, so
// `scan-actions --format json -o out.json` created no file and printed to
// stdout.
func TestScanActions_JSONHonorsOutputFlag(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "actions.json")

	var out, errOut bytes.Buffer
	cmd := newScanActionsFullFlagCmd(&out, &errOut)
	if err := cmd.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set format: %v", err)
	}
	if err := cmd.Flags().Set("output", outFile); err != nil {
		t.Fatalf("set output: %v", err)
	}
	if _, err := runScanActions(cmd, []string{actionsFixture()}); err != nil {
		t.Fatalf("runScanActions: %v", err)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("--output file not created: %v", err)
	}
	var report scanActionsReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("output file is not the JSON report: %v\n%s", err, data)
	}
	if strings.TrimSpace(out.String()) != "" {
		t.Errorf("with --output set the command sink must stay empty, got %q", out.String())
	}
}

// ── S8 / S9: report subcommands ────────────────────────────────────────────

func newReportSLATestCmd(out, errOut *bytes.Buffer) *cobra.Command {
	cmd := &cobra.Command{Use: "sla", RunE: runReportSLA}
	cmd.Flags().String("since", "", "")
	cmd.Flags().String("format", "text", "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("output", "", "")
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetArgs(nil)
	return cmd
}

func reportSLAServer(t *testing.T) string {
	t.Helper()
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{
				{"owners": []string{"team-a"}, "resolved": 3, "meanSeconds": 120.0, "medianSeconds": 90.0},
			},
		})
	})
	pointViperAt(t, srv.URL)
	return srv.URL
}

// TestReportSLA_GlobalJSONFlagHonored is the S8 guard for the report family.
// `chainsaw report sla --json | jq` used to receive a tabwriter table.
func TestReportSLA_GlobalJSONFlagHonored(t *testing.T) {
	reportSLAServer(t)

	var out, errOut bytes.Buffer
	cmd := newReportSLATestCmd(&out, &errOut)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json: %v", err)
	}
	if err := runReportSLA(cmd, nil); err != nil {
		t.Fatalf("runReportSLA: %v", err)
	}
	if strings.Contains(out.String(), "OWNERS") {
		t.Fatalf("--json must not emit the text table, got:\n%s", out.String())
	}
	var rows []reportSLAEntry
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("--json output is not JSON: %v\n%s", err, out.String())
	}
	if len(rows) != 1 || rows[0].Resolved != 3 {
		t.Errorf("unexpected rows: %+v", rows)
	}
}

// TestReportSLA_JSONHonorsOutputFlag is the S9 guard for the report family:
// the JSON branch went through a bare fmt.Println (always os.Stdout), so
// `report ... --format json -o rep.json` created no file.
func TestReportSLA_JSONHonorsOutputFlag(t *testing.T) {
	reportSLAServer(t)
	outFile := filepath.Join(t.TempDir(), "sla.json")

	var out, errOut bytes.Buffer
	cmd := newReportSLATestCmd(&out, &errOut)
	_ = cmd.Flags().Set("format", "json")
	_ = cmd.Flags().Set("output", outFile)
	if err := runReportSLA(cmd, nil); err != nil {
		t.Fatalf("runReportSLA: %v", err)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("--output file not created: %v", err)
	}
	var rows []reportSLAEntry
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatalf("output file is not the JSON report: %v\n%s", err, data)
	}
	if strings.TrimSpace(out.String()) != "" {
		t.Errorf("with --output set the command sink must stay empty, got %q", out.String())
	}
}

// ── S9: sbom diff ──────────────────────────────────────────────────────────

// TestSBOMDiff_JSONHonorsOutputFlag: the diff's JSON branch wrote to
// cmd.OutOrStdout() and ignored --output.
func TestSBOMDiff_JSONHonorsOutputFlag(t *testing.T) {
	a := filepath.Join("..", "sbom", "testdata", "diff", "added_a.json")
	b := filepath.Join("..", "sbom", "testdata", "diff", "added_b.json")
	outFile := filepath.Join(t.TempDir(), "diff.json")

	var buf bytes.Buffer
	cmd := &cobra.Command{Use: "diff"}
	cmd.Flags().String("format", "json", "")
	cmd.Flags().String("output", outFile, "")
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := runSBOMDiff(cmd, []string{a, b}); err != nil {
		t.Fatalf("runSBOMDiff: %v", err)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("--output file not created: %v", err)
	}
	if !strings.Contains(string(data), "lodash") {
		t.Errorf("output file missing the diff payload: %s", data)
	}
	if strings.TrimSpace(buf.String()) != "" {
		t.Errorf("with --output set the command sink must stay empty, got %q", buf.String())
	}
}

// ── S9: finding feedback wire shape ────────────────────────────────────────

// TestFindingFeedback_JSONIsIndentedAndHonorsOutput pins the wire-shape fix.
// The branch's own comment claimed it encoded "through the shared helper so we
// get the canonical indented form", but it called json.Marshal (COMPACT) and
// fmt.Println (stdout, ignoring --output).
//
// WIRE-SHAPE CHANGE: `finding feedback --json` output goes compact → indented.
func TestFindingFeedback_JSONIsIndentedAndHonorsOutput(t *testing.T) {
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": "fnd-1"})
	})
	pointViperAt(t, srv.URL)
	outFile := filepath.Join(t.TempDir(), "feedback.json")

	var out, errOut bytes.Buffer
	cmd := &cobra.Command{Use: "feedback", RunE: runFindingFeedback}
	cmd.Flags().String("action", "", "")
	cmd.Flags().String("note", "", "")
	cmd.Flags().String("reason-chip", "", "")
	cmd.Flags().String("referencing-event-id", "", "")
	cmd.Flags().Bool("json", true, "")
	cmd.Flags().String("output", outFile, "")
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs([]string{"fnd-1", "--action=false_positive"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("--output file not created: %v", err)
	}
	if !strings.Contains(string(data), "\n  \"") {
		t.Errorf("payload should be indented (canonical form), got: %s", data)
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		t.Fatalf("output file is not JSON: %v\n%s", err, data)
	}
}

// ── S10: the -o shorthand class guard ──────────────────────────────────────

// TestSBOMExportResolvesDashOShorthand is the direct S10 guard:
// `chainsaw sbom export -o /tmp/x.json` returned "unknown shorthand flag: 'o'
// in -o" (exit 4) while -o worked on every other command, because
// sbomExportCmd declared its own `output` and cobra's AddFlagSet skips a
// persistent flag whose name already exists locally — dropping the persistent
// flag AND its shorthand registration.
func TestSBOMExportResolvesDashOShorthand(t *testing.T) {
	_ = sbomExportCmd.InheritedFlags() // force cobra's persistent-flag merge
	f := sbomExportCmd.Flags().ShorthandLookup("o")
	if f == nil {
		t.Fatal("sbom export: -o resolves to nothing")
	}
	if f.Name != "output" {
		t.Fatalf("sbom export: -o resolves to --%s, want --output", f.Name)
	}
}

// TestEveryCommandResolvesDashOToOutput is the CLASS guard: any command that
// exposes an `output` flag at all must have `-o` resolve to it. Declaring a
// local `output` without the shorthand silently un-registers the persistent
// flag for that one command, which is invisible until a user types -o.
func TestEveryCommandResolvesDashOToOutput(t *testing.T) {
	// Commands known to still shadow --output. EMPTY — the debt is paid:
	// `chainsaw policy export` was the last entry, and dropping its local
	// --output (core/cli/policy.go, same one-line deletion applied to sbom
	// export) made `policy export -o file` work. The map and the tolerant
	// branches below stay so a future workstream can park a defect it does
	// not own; an empty map means this guard is strict today.
	knownShadowed := map[string]bool{}

	// Deliberately does NOT force cobra's persistent-flag merge: mutating every
	// command's flag set as a side effect of a test is how you get order-
	// dependent failures elsewhere in the package. The check works either way,
	// because the DEFECT is always a locally-declared `output` whose shorthand
	// is empty — and a merge only ever ADDS root's persistent flag, which
	// AddFlagSet skips when the name is already taken. So a shadowed command
	// reads Shorthand=="" before and after the merge; a healthy one either has
	// no `output` entry yet (skipped) or root's, whose shorthand is "o".
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		f := c.Flags().Lookup("output")
		if f == nil {
			return
		}
		path := c.CommandPath()
		if f.Shorthand == "o" {
			if knownShadowed[path] {
				// Logged, not failed: another workstream fixing its own file
				// must never turn this build red. The stale entry is harmless
				// — it only suppresses a failure for a command that no longer
				// has the defect.
				t.Logf("STALE: %s is on the knownShadowed list but now resolves -o correctly — drop the entry", path)
			}
			return
		}
		if knownShadowed[path] {
			t.Logf("KNOWN (not this workstream's file): %s declares a local --output with no shorthand, so -o fails", path)
			return
		}
		t.Errorf("%s: --output is declared locally with no shorthand, which makes cobra drop root's "+
			"persistent --output AND its `o` registration for this command — `-o` fails with "+
			"\"unknown shorthand flag\". Drop the local flag, or declare it with StringP(\"output\", \"o\", …).", path)
	}
	walk(rootCmd)
}
