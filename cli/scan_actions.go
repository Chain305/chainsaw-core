package cli

// scan-actions
//
// `chainsaw scan-actions <path>` is the user-facing command that runs the
// GitHub Actions Wave 4 scanner against either a single workflow file or a
// directory of workflows (auto-walking <path>/.github/workflows/). Findings
// are printed in human-readable text by default (with terminal colors when
// stderr is a TTY) or as JSON when --format=json is passed.
//
// Exit code 1 when any high-severity finding is reported, 0 otherwise — so
// CI jobs can `chainsaw scan-actions . && echo ok` to gate on supply-chain
// signals from Actions usage. Document this in the help text so users
// don't get surprised.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/chain305/chainsaw-core/githubactions"
	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

var scanActionsCmd = &cobra.Command{
	Use:   "scan-actions <path>",
	Short: "Scan GitHub Actions workflows for supply-chain risk",
	Long: `Scan one or more GitHub Actions workflow YAML files for supply-chain
issues — unpinned refs, typosquats, unknown publishers, and known-malicious
actions.

<path> may be either a directory (the command walks <path>/.github/workflows/)
or a single workflow YAML file.

Exit codes:
  0 — no high-severity findings (low/medium are still reported)
  1 — at least one high-severity finding (suitable for ` + "`set -e`" + ` CI gates)`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		code, err := runScanActions(cmd, args)
		if err != nil {
			return err
		}
		if code != 0 {
			// Set the cobra exit code without printing a redundant error.
			os.Exit(code)
		}
		return nil
	},
}

func init() {
	scanActionsCmd.Flags().String("format", "text", "Output format: text or json")
	rootCmd.AddCommand(scanActionsCmd)
}

// scanActionsFinding is the wire-shape projection of githubactions.Finding
// used in JSON output. Mirrors the API shape so CLI and server JSON look
// identical to consumers.
type scanActionsFinding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Signal   string `json:"signal"`
	Message  string `json:"message"`
	Detail   string `json:"detail,omitempty"`
	Owner    string `json:"owner,omitempty"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
}

// scanActionsSummary aggregates per-severity counts plus the workflow-file
// count so callers can render a one-line summary.
type scanActionsSummary struct {
	Total     int `json:"total"`
	High      int `json:"high"`
	Medium    int `json:"medium"`
	Low       int `json:"low"`
	Workflows int `json:"workflows"`
}

type scanActionsReport struct {
	Findings []scanActionsFinding `json:"findings"`
	Summary  scanActionsSummary   `json:"summary"`
	// Risk surfaces the v2 risk-engine view of the same findings — which
	// signal IDs fired and the projected Action-related risk.Input fields.
	// Lets CI consumers gate on signal IDs (`vuln.fix_available`,
	// `action.unpinned_ref`, …) the way they already do for /api/v1/intel
	// endpoints, instead of re-deriving them from the findings list.
	Risk githubactions.RiskBlock `json:"risk"`
}

// runScanActions is the inner entrypoint for `chainsaw scan-actions`. It
// returns (exitCode, err) so the cobra wrapper can call os.Exit on a
// high-severity finding without polluting the test surface — tests call
// runScanActions directly and assert on the returned exitCode.
func runScanActions(cmd *cobra.Command, args []string) (int, error) {
	format, _ := cmd.Flags().GetString("format")
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "text"
	}
	if format != "text" && format != "json" {
		return 0, fmt.Errorf("unknown format %q — supported values: text, json", format)
	}

	target := args[0]
	refs, workflowCount, err := parseTargetForScanActions(target)
	if err != nil {
		return 0, err
	}

	deps := githubactions.ScanDeps{
		Typosquat: githubactions.NewTyposquatAdapter(typosquat.NewDetector(nil)),
		Malware:   githubactions.NewMalwareAdapter(malware.NewGitHubActionsFeed()),
		// KnownPublishers nil -> Scan uses DefaultKnownPublishers().
	}
	findings, err := githubactions.Scan(context.Background(), refs, deps)
	if err != nil {
		return 0, fmt.Errorf("scan: %w", err)
	}

	report := buildScanActionsReport(findings, workflowCount)
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()

	if format == "json" {
		if err := writeScanActionsJSON(out, report); err != nil {
			return 0, err
		}
	} else {
		writeScanActionsText(out, errOut, report)
	}

	if report.Summary.High > 0 {
		return 1, nil
	}
	return 0, nil
}

// parseTargetForScanActions accepts either a directory or a single workflow
// file and returns the parsed []ActionRef plus the number of distinct
// workflow files contributing to that list.
func parseTargetForScanActions(target string) ([]githubactions.ActionRef, int, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, 0, fmt.Errorf("stat %s: %w", target, err)
	}
	if info.IsDir() {
		refs, err := githubactions.ParseWorkflowDir(target)
		if err != nil {
			return nil, 0, err
		}
		// Distinct SourceFile count == workflow count.
		seen := make(map[string]struct{})
		for _, r := range refs {
			if r.SourceFile != "" {
				seen[r.SourceFile] = struct{}{}
			}
		}
		return refs, len(seen), nil
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", target, err)
	}
	refs, err := githubactions.ParseWorkflowFile(target, data)
	if err != nil {
		return nil, 0, err
	}
	return refs, 1, nil
}

// buildScanActionsReport projects []githubactions.Finding into the wire
// shape and computes the summary counters.
func buildScanActionsReport(findings []githubactions.Finding, workflowCount int) scanActionsReport {
	out := scanActionsReport{
		Findings: make([]scanActionsFinding, 0, len(findings)),
		Summary:  scanActionsSummary{Workflows: workflowCount},
	}
	for _, f := range findings {
		out.Findings = append(out.Findings, scanActionsFinding{
			File:     f.Ref.SourceFile,
			Line:     f.Ref.SourceLine,
			Severity: f.Severity,
			Signal:   f.Signal,
			Message:  f.Message,
			Detail:   f.Detail,
			Owner:    f.Ref.Owner,
			Name:     f.Ref.Name,
			Version:  f.Ref.Version,
		})
		switch strings.ToLower(f.Severity) {
		case "high":
			out.Summary.High++
		case "medium":
			out.Summary.Medium++
		case "low":
			out.Summary.Low++
		}
	}
	out.Summary.Total = len(out.Findings)
	// Stable order: by file, then line, then signal.
	sort.SliceStable(out.Findings, func(i, j int) bool {
		a, b := out.Findings[i], out.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Signal < b.Signal
	})
	// Project findings through the v2 risk engine so the CLI surfaces
	// the same `risk` block the /api/v1/intel/evaluate-actions endpoint
	// returns. Calling EvaluateRisk on the original scanner findings (not
	// the wire-shape projection) keeps the BuildReport -> ProjectToRiskInput
	// pipeline the single source of truth for scanner→engine translation.
	out.Risk = githubactions.EvaluateRisk(findings)
	return out
}

func writeScanActionsJSON(w io.Writer, report scanActionsReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// writeScanActionsText prints one finding per line followed by a summary.
// Color is applied via stderr-TTY detection so piped output stays clean.
func writeScanActionsText(out io.Writer, errOut io.Writer, report scanActionsReport) {
	colored := stderrIsTerminalForScanActions(errOut)
	for _, f := range report.Findings {
		sev := f.Severity
		if colored {
			sev = colorizeSeverityForScanActions(sev)
		}
		file := f.File
		if file == "" {
			file = "<unknown>"
		}
		fmt.Fprintf(out, "%s:%d %s %s %s\n", file, f.Line, sev, f.Signal, f.Message)
	}
	fmt.Fprintf(out, "Found %d findings (%d high, %d medium, %d low) across %d workflows\n",
		report.Summary.Total, report.Summary.High, report.Summary.Medium, report.Summary.Low, report.Summary.Workflows)
	// Risk evaluation line — keeps text output a near-superset of the
	// JSON `risk` block so a `grep ^Risk` in CI logs surfaces the
	// engine's verdict without having to re-run with --format=json.
	verdict := "clean"
	if len(report.Risk.Signals) > 0 {
		verdict = strings.Join(report.Risk.Signals, ", ")
	}
	fmt.Fprintf(out, "Risk evaluation: %s\n", verdict)
}

// stderrIsTerminalForScanActions reports whether the given writer is os.Stderr
// AND that stderr is attached to a terminal. Tests pass a *bytes.Buffer so
// this returns false and output is plain.
func stderrIsTerminalForScanActions(w io.Writer) bool {
	if w == nil {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func colorizeSeverityForScanActions(sev string) string {
	const (
		red    = "\033[31m"
		yellow = "\033[33m"
		dim    = "\033[2m"
		reset  = "\033[0m"
	)
	switch strings.ToLower(sev) {
	case "high":
		return red + sev + reset
	case "medium":
		return yellow + sev + reset
	case "low":
		return dim + sev + reset
	}
	return sev
}

// scan-actions end
