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
	Use:     "scan-actions <path>",
	GroupID: GrpScan,
	Short:   "Scan GitHub Actions workflows for supply-chain risk",
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
			// Y3/Y4 — returned, not os.Exit'd. The bare exit left the process
			// before Execute() reached markSessionEnd + flushTelemetry, so the
			// ONE outcome CI cares about (a high-severity finding, exit 1)
			// emitted zero cli.session.completed events — the event that
			// carries exit_code and error_class. It also bypassed the
			// exitcodes.go contract entirely. Err stays nil so renderError
			// prints nothing on top of the findings table the command already
			// wrote (see root.go::renderError).
			return &ExitCodeError{Code: code}
		}
		return nil
	},
}

func init() {
	scanActionsCmd.Flags().String("format", "text", "Output format: text, json, or sarif")
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
//
// Workflows counts FILES PARSED; ActionRefs counts the `uses:` entries found
// inside them. They are separate numbers because they answer different
// questions and used to be conflated: Workflows was derived from the distinct
// SourceFile values of the refs, so a workflow of `run:`-only steps — which
// yields no refs at all — vanished from the count and a repo full of them
// reported identically to a repo with no workflows. Reporting both makes
// "scanned 3 files, none of them use an Action" expressible.
type scanActionsSummary struct {
	Total     int `json:"total"`
	High      int `json:"high"`
	Medium    int `json:"medium"`
	Low       int `json:"low"`
	Workflows int `json:"workflows"`
	// ActionRefs is additive: consumers that only read the fields above are
	// unaffected.
	ActionRefs int `json:"action_refs"`
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
// returns (exitCode, err) and the cobra wrapper converts a non-zero code into
// an &ExitCodeError. Tests may call either half: runScanActions directly for
// the code, or the wrapper's RunE for the returned error. (The wrapper used to
// os.Exit on the code, which is why the split exists at all — a test that
// reached it killed the test binary.)
func runScanActions(cmd *cobra.Command, args []string) (int, error) {
	// S8 — resolveFormat, not a bare GetString("format"): --json is a root
	// persistent flag documented as "alias for --format=json" (root.go), and
	// scan / scan-repo / deps / affected all honor it. Reading only the local
	// --format meant `chainsaw scan-actions ./wf --json` printed the human
	// table plus "Risk evaluation: …" to a consumer expecting JSON.
	format := strings.ToLower(strings.TrimSpace(resolveFormat(cmd)))
	switch format {
	case "", "table":
		// resolveFormat's no-format default is "table"; this command's human
		// format is spelled "text". Treat them as the same thing rather than
		// erroring on a value the user never typed.
		format = "text"
	}
	if format != "text" && format != "json" && format != "sarif" {
		return 0, fmt.Errorf("unknown format %q — supported values: text, json, sarif", format)
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

	report := buildScanActionsReport(findings, workflowCount, len(refs))
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()

	switch format {
	case "json":
		// S9 — JSON is a machine-readable result, so it honors --output the
		// same way the SARIF branch below already did (`scan-actions --format
		// json -o out.json` used to create no file and print to stdout).
		// cmd.OutOrStdout() stays the fallback so tests capturing via
		// cmd.SetOut keep working.
		if err := writeScanActionsJSON(outWriterOr(cmd, out), report); err != nil {
			return 0, err
		}
	case "sarif":
		// SARIF is a machine artifact normally redirected to a file via
		// --output; outWriter honors that and falls back to stdout otherwise.
		// We deliberately bypass cmd.OutOrStdout() (used by text/json for test
		// capture) because --output is the documented SARIF sink.
		if err := writeScanActionsSARIF(outWriter(cmd), report); err != nil {
			return 0, err
		}
	default:
		// S9b — the text result honors --output too. It used to write straight
		// to cmd.OutOrStdout(), so `scan-actions . --format text --output R`
		// exited 0, created no file, and put the findings on stdout. root.go's
		// formatIsMachineReadable lets a --format-shadowing command through the
		// --output validator on the grounds that it routes its result through a
		// sink; that has to hold for every format in the vocabulary, not just
		// the two machine ones.
		//
		// Color is decided from errOut (stderr TTY, see
		// stderrIsTerminalForScanActions). A redirected result is a FILE, which
		// must never receive ANSI, so the probe is withheld when --output is
		// set — stderrIsTerminalForScanActions(nil) is false by construction.
		colorProbe := errOut
		if path, _ := cmd.Flags().GetString("output"); path != "" {
			colorProbe = nil
		}
		writeScanActionsText(outWriterOr(cmd, out), colorProbe, report)
	}

	if report.Summary.High > 0 {
		return 1, nil
	}
	return 0, nil
}

// parseTargetForScanActions accepts either a directory or a single workflow
// file and returns the parsed []ActionRef plus the number of workflow files
// that were READ.
//
// The count comes from the parser's own file list, not from the distinct
// SourceFile values of the refs. Deriving it from the refs made the count a
// function of whether the workflows happened to reference an Action: a
// workflow whose steps are all `run:` produces no refs, so it contributed no
// SourceFile, so a directory of them counted zero workflows and the report
// said "no workflows found" about files it had just parsed.
func parseTargetForScanActions(target string) ([]githubactions.ActionRef, int, error) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, 0, fmt.Errorf("stat %s: %w", target, err)
	}
	if info.IsDir() {
		refs, files, err := githubactions.ParseWorkflowDirFiles(target)
		if err != nil {
			return nil, 0, err
		}
		return refs, len(files), nil
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
func buildScanActionsReport(findings []githubactions.Finding, workflowCount, actionRefCount int) scanActionsReport {
	out := scanActionsReport{
		Findings: make([]scanActionsFinding, 0, len(findings)),
		Summary: scanActionsSummary{
			Workflows:  workflowCount,
			ActionRefs: actionRefCount,
		},
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
	// Two-pass render so multi-finding output stays column-aligned. Widths are
	// computed on display width (the severity cell may carry ANSI color), so the
	// coloured token doesn't throw off the location/severity columns.
	type findingRow struct{ loc, sev, signal, msg string }
	rows := make([]findingRow, 0, len(report.Findings))
	locW, sevW := 0, 0
	for _, f := range report.Findings {
		file := f.File
		if file == "" {
			file = "<unknown>"
		}
		loc := fmt.Sprintf("%s:%d", file, f.Line)
		sev := f.Severity
		if colored {
			sev = colorizeSeverityForScanActions(sev)
		}
		rows = append(rows, findingRow{loc, sev, f.Signal, f.Message})
		if w := displayWidth(loc); w > locW {
			locW = w
		}
		if w := displayWidth(sev); w > sevW {
			sevW = w
		}
	}
	for _, r := range rows {
		fmt.Fprintf(out, "%s%s  %s%s  %s  %s\n",
			r.loc, strings.Repeat(" ", locW-displayWidth(r.loc)),
			r.sev, strings.Repeat(" ", sevW-displayWidth(r.sev)),
			r.signal, r.msg)
	}
	fmt.Fprintf(out, "Found %d findings (%d high, %d medium, %d low) across %d workflows (%d action references)\n",
		report.Summary.Total, report.Summary.High, report.Summary.Medium, report.Summary.Low,
		report.Summary.Workflows, report.Summary.ActionRefs)
	// Risk evaluation line — keeps text output a near-superset of the
	// JSON `risk` block so a `grep ^Risk` in CI logs surfaces the
	// engine's verdict without having to re-run with --format=json.
	verdict := "clean"
	if len(report.Risk.Signals) > 0 {
		verdict = strings.Join(report.Risk.Signals, ", ")
	}
	// Zero parsed workflows means the risk verdict isn't meaningful —
	// "clean" would falsely imply we evaluated something. This wins over
	// the (unlikely) signals-with-zero-workflows case on purpose.
	//
	// Workflows>0 with no refs is the case the old wording could not express:
	// we DID evaluate something and it was clean, there was simply no `uses:`
	// to pin or attribute. Saying "no workflows found" there was a factual
	// error about files we had just read.
	//
	// It overrides the signal list for the same reason the zero-workflow case
	// above does, one step further out: with no action references there are no
	// action findings by construction, so every signal the engine reports is
	// an artifact of projecting an EMPTY input (it emits license.unidentified
	// and friends on nothing at all). Printing those as the verdict for a
	// clean run would attribute them to workflows that never made a claim.
	switch {
	case report.Summary.Workflows == 0:
		verdict = "no workflows found"
	case report.Summary.ActionRefs == 0:
		verdict = fmt.Sprintf("clean (%d workflow(s) parsed, no action references to evaluate)", report.Summary.Workflows)
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
