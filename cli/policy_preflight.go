package cli

// policy preflight — Gap #3 from docs/plan_v1_production_readiness.md.
//
// Operators authoring policies in CI or via `chainsaw policy create` need a
// way to validate which conditions actually fire on which ecosystems before
// applying. The Web UI already does this via GET /api/policies/support-matrix
// (see ui_new/src/app/(dashboard)/protect/policies/unsupported-condition-warning.tsx);
// this subcommand reuses the exact same endpoint — no new server surface — so
// the matrix shown to operators is byte-identical to what the UI renders.
//
// We chose mode 2 (dump matrix, optionally filter by --ecosystem) because the
// existing endpoint serves the static SupportMatrix; it does not accept a
// policy body to validate against. That keeps this CLI strictly additive: no
// new server work, no new shared types, and the same drift test
// (TestSupportMatrixMatchesMarkdown) keeps everyone honest.
//
// Exit codes follow the policy-simulate convention so this is CI-safe:
//
//	0 — nothing YOUR policies depend on is unsupported on the printed
//	    ecosystems (and, with no --policy, always: the bare matrix dump
//	    is informational)
//	1 — a condition one of your --policy rules USES is "none" on a
//	    printed ecosystem (CI signal)
//	2 — usage / network / other errors (cobra/RunE default)
//	12 — the gate did not cover the whole policy set, either because the
//	    --policy tree could not be fully read OR because a condition your
//	    rules use is absent from this proxy's support matrix (CLI newer
//	    than proxy). policyScanIncompleteExitCode, shared with
//	    `policy lint`. Distinct from 1 on purpose: a fleet mid-upgrade
//	    must not fail the way a genuinely inert condition does.
//
// The "none" gate matters because the UI treats partial as supported (the
// signal is wired, it just may be empty in practice) — preflight does the
// same so operator expectations match the UI.
//
// The gate used to be "does ANY printed cell say none", which read as a
// policy check but was really a property of the product's coverage
// matrix. Measured: 16 ecosystems × 46 conditions = 736 cells, 281 of
// them none, and all 16 rows contain at least one — so preflight exited 1
// for every org, every ecosystem filter and every policy set, forever. A
// CI job wired exactly as this file's help text documents failed 100% of
// the time, which means anybody actually running it has already muted it.
// Gating on the conditions a supplied --policy USES (policy.ConditionsUsedBy)
// is what the help text always claimed; the bare dump goes back to being a
// dump, and exits 0.

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/policy"
)

// supportMatrixRowDTO mirrors the JSON returned by /api/policies/support-matrix
// (see internal/server/policy_support_matrix.go). Kept local to this file so
// the CLI binary doesn't take a dependency on internal/server types.
type supportMatrixRowDTO struct {
	Ecosystem  string            `json:"ecosystem"`
	Conditions map[string]string `json:"conditions"`
}

type supportMatrixResponseDTO struct {
	Ecosystems []string              `json:"ecosystems"`
	Conditions []string              `json:"conditions"`
	Matrix     []supportMatrixRowDTO `json:"matrix"`
}

// preflightUnsupportedExitCode is the exit status returned when the printed
// matrix contains at least one "none" cell. Picked to match the simulate
// convention (block/quarantine outcomes are non-zero on the CI surface).
const preflightUnsupportedExitCode = 1

// ExitCodeError moved to exitcodes.go (the exit-code contract now lives in one
// place). It is still the type a RunE returns to request a specific process
// exit code; this command keeps using it via preflightUnsupportedExitCode.

var policyPreflightCmd = &cobra.Command{
	Use:   "preflight",
	Short: "Show which policy conditions are supported per ecosystem",
	Long: `Fetch the proxy policy compatibility matrix from the server and report
which conditions are unsupported for which ecosystems. Reuses the same
GET /api/policies/support-matrix endpoint the Web UI uses, so what you see
here is byte-identical to the inline warnings rendered next to policy
condition inputs in the dashboard.

Use this in CI to catch policies that reference conditions silently inert
on the target ecosystem before applying them. Pass --policy <file-or-dir>
and the command exits 1 when a condition YOUR rules use is unsupported on
a printed ecosystem — and names the rule, the condition and the ecosystem.

When --policy names a DIRECTORY, the sweep skips .git/node_modules/vendor
and friends and ignores JSON/YAML that is not a policy document; anything it
could not READ is listed and exits 12 (the gate covered only part of your
policy set). Naming a single file keeps the strict reading: it must parse.

Without --policy it is a pure informational dump of the compatibility
matrix and exits 0. (Every ecosystem has at least one unsupported
condition, so gating on the raw matrix would fail every run for every
org — which is what it used to do.)

Examples:
  chainsaw policy preflight
  chainsaw policy preflight --ecosystem npm
  chainsaw policy preflight --ecosystem npm --json
  chainsaw policy preflight --unsupported-only
  chainsaw policy preflight --policy ./policies --ecosystem npm`,
	SilenceUsage: true,
	RunE:         runPolicyPreflight,
}

func init() {
	policyPreflightCmd.Flags().String("ecosystem", "",
		"Filter to a single ecosystem (e.g. npm, pip, maven). Default: all ecosystems.")
	policyPreflightCmd.Flags().Bool("unsupported-only", false,
		"Only print rows containing at least one unsupported (none) cell.")
	policyPreflightCmd.Flags().Bool("json", false, "Output the raw matrix response as JSON.")
	policyPreflightCmd.Flags().String("policy", "",
		"Policy file or directory to gate on. Only conditions these rules actually use drive the exit code. Without it the command is an informational dump and exits 0.")
	policyCmd.AddCommand(policyPreflightCmd)
}

func runPolicyPreflight(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	var resp supportMatrixResponseDTO
	if err := client.Get("/api/policies/support-matrix", &resp); err != nil {
		return err
	}
	emit("cli.policy.preflight", nil)

	ecoFilter, _ := cmd.Flags().GetString("ecosystem")
	ecoFilter = strings.ToLower(strings.TrimSpace(ecoFilter))
	unsupportedOnly, _ := cmd.Flags().GetBool("unsupported-only")
	policyPath := strings.TrimSpace(mustString(cmd, "policy"))
	asJSON := useJSON(cmd)

	rows, err := filterPreflightRows(resp, ecoFilter, unsupportedOnly)
	if err != nil {
		return err
	}

	// Load --policy BEFORE rendering: an unreadable or malformed policy
	// file is an operational error, and emitting a matrix followed by a
	// parse failure would read as "the gate passed, then something else
	// broke".
	var (
		usage   []preflightConditionUse
		skipped []policySkip
	)
	if policyPath != "" {
		usage, skipped, err = collectPreflightConditionUsage(policyPath)
		if err != nil {
			return err
		}
	}

	if asJSON {
		// Round-trip through a fresh response so consumers see the same
		// {ecosystems, conditions, matrix} envelope they get from the
		// server, just trimmed by the filter flags.
		filtered := supportMatrixResponseDTO{
			Ecosystems: make([]string, 0, len(rows)),
			Conditions: jsonArray(append([]string(nil), resp.Conditions...)),
			Matrix:     jsonArray(rows),
		}
		for _, r := range rows {
			filtered.Ecosystems = append(filtered.Ecosystems, r.Ecosystem)
		}
		enc := json.NewEncoder(outWriterOr(cmd, cmd.OutOrStdout()))
		enc.SetIndent("", "  ")
		if err := enc.Encode(filtered); err != nil {
			return err
		}
	} else {
		printPreflightTable(cmd, rows, resp.Conditions)
	}

	// No --policy: informational dump, exit 0. See the file header for
	// why the old unconditional gate was worse than no gate.
	if policyPath == "" {
		return nil
	}

	// Under --json stdout is a machine-readable envelope, so the
	// gate's human report goes to stderr and the parser is unaffected.
	// The EXIT CODE is identical in both renderings — that is the
	// property this whole change exists to protect.
	out := cmd.OutOrStdout()
	if asJSON {
		out = cmd.ErrOrStderr()
	}

	// SURFACE what the sweep declined, before the verdict. This command's own
	// contract (see collectPreflightConditionUsage) is that gating on a
	// partially-parsed policy set silently under-reports — so the paths that
	// were not parsed have to appear in the operator's output, not just in the
	// walker's head.
	if len(skipped) > 0 {
		fmt.Fprintln(out)
		printPolicySkips(out, skipped)
	}
	lost := unreadablePolicySkips(skipped)

	g := glyphs()
	inert := inertPolicyConditions(rows, usage)

	// SURFACE version skew before the verdict, for the same reason the
	// skipped paths above are surfaced: a gate that could not evaluate
	// part of the policy set has to say so in the operator's output.
	unknown := unknownPolicyConditions(rows, usage)
	if len(unknown) > 0 {
		fmt.Fprintf(out, "\n%s conditions your policies use that this proxy does not report on at all:\n", g.fail)
		for _, u := range unknown {
			fmt.Fprintf(out, "  - %s: condition %s is absent from the support matrix (%s:%d)\n",
				u.Rule, u.Condition, u.File, u.Line)
		}
		fmt.Fprintf(out, "  %s this CLI is newer than the proxy it asked. Those rules cannot fire there.\n", g.dash)
	}

	if len(inert) == 0 {
		if len(lost) > 0 {
			// Never "✓ every condition is supported" over a policy set we
			// only half read — that sentence is the gate's answer, and it
			// would be an answer about files we never opened.
			fmt.Fprintf(out, "\n%s no unsupported condition found in what could be read, but %d path(s) under %s were unreadable %s this gate is INCOMPLETE.\n",
				g.fail, len(lost), policyPath, g.dash)
			return &ExitCodeError{
				Code: policyScanIncompleteExitCode,
				Err: fmt.Errorf("policy preflight: %d path(s) under %s could not be read; the gate did not cover the whole policy set",
					len(lost), policyPath),
			}
		}
		if len(unknown) > 0 {
			// Never "\u2713 every condition is supported" over conditions the
			// proxy never listed. Same doctrine as the unreadable-path
			// branch above: the tick is the gate's ANSWER, and this gate
			// has no answer for these.
			fmt.Fprintf(out, "\n%s no unsupported condition found among the ones this proxy reports, but %d rule/condition pair(s) are absent from its matrix %s this gate is INCOMPLETE.\n",
				g.fail, len(unknown), g.dash)
			return &ExitCodeError{
				Code: policyScanIncompleteExitCode,
				Err: fmt.Errorf("policy preflight: %d rule/condition pair(s) are absent from the proxy's support matrix; the gate could not cover the whole policy set",
					len(unknown)),
			}
		}
		fmt.Fprintf(out, "\n%s every condition used by %s is supported on the printed ecosystem(s).\n", g.ok, policyPath)
		return nil
	}
	fmt.Fprintf(out, "\n%s conditions your policies use that are inert on the printed ecosystem(s):\n", g.fail)
	for _, i := range inert {
		fmt.Fprintf(out, "  - %s: condition %s is unsupported on %s (%s:%d)\n",
			i.Rule, i.Condition, i.Ecosystem, i.File, i.Line)
	}
	return &ExitCodeError{
		Code: preflightUnsupportedExitCode,
		Err: fmt.Errorf("policy preflight: %d rule/ecosystem pair(s) reference a condition the proxy cannot populate",
			len(inert)),
	}
}

// preflightConditionUse records that a named rule (at file:line) depends
// on a condition. One entry per (rule, condition) pair so the report can
// name the rule that will silently never fire, not just the condition.
type preflightConditionUse struct {
	File      string
	Line      int
	Rule      string
	Condition policy.ConditionType
}

// preflightInertCondition is one (rule, condition, ecosystem) triple that
// will never fire.
type preflightInertCondition struct {
	File      string
	Line      int
	Rule      string
	Condition policy.ConditionType
	Ecosystem string
}

// collectPreflightConditionUsage parses the policies under path and
// returns every condition they use. It reuses `policy lint`'s file
// collection and parser so both commands accept exactly the same inputs —
// an operator who can lint a directory can preflight it.
//
// A parse error on an EXPLICITLY NAMED file is fatal here (unlike in lint,
// which reports it as a finding and continues): preflight's answer is a GATE,
// and gating on a partially-parsed policy set would silently under-report.
//
// That reasoning is exactly why a DIRECTORY SWEEP cannot be fatal and cannot
// be silent either. `--policy ./policies` inside a repo used to die on the
// first tsconfig.json it walked past, and (before that) on the first
// unreadable directory. Now the sweep tolerates both and returns the skip list
// as a second value — the caller must render it, and unreadable paths escalate
// the exit code, so "gating on a partially-parsed policy set" stays impossible
// by construction rather than by aborting.
func collectPreflightConditionUsage(path string) ([]preflightConditionUse, []policySkip, error) {
	set, err := collectPolicyFiles(path)
	if err != nil {
		return nil, nil, fmt.Errorf("--policy %s: %w", path, err)
	}
	skipped := append([]policySkip(nil), set.Skipped...)
	if len(set.Files) == 0 {
		if len(skipped) > 0 {
			return nil, skipped, fmt.Errorf("--policy %s: no .json/.yaml/.yml policy files found (%d path(s) skipped or unreadable)",
				path, len(skipped))
		}
		return nil, skipped, fmt.Errorf("--policy %s: no .json/.yaml/.yml policy files found", path)
	}
	explicit := !set.Swept
	var out []preflightConditionUse
	for _, f := range set.Files {
		entries, skip, lerr := loadPolicyEntries(f, explicit)
		if lerr != nil {
			return nil, skipped, fmt.Errorf("--policy: %w", lerr)
		}
		if skip != nil {
			skipped = append(skipped, *skip)
		}
		for _, e := range entries {
			for _, c := range policy.ConditionsUsedBy(e.policy.Conditions) {
				out = append(out, preflightConditionUse{File: f, Line: e.line, Rule: e.name, Condition: c})
			}
		}
	}
	sort.SliceStable(skipped, func(i, j int) bool { return skipped[i].Path < skipped[j].Path })
	return out, skipped, nil
}

// inertPolicyConditions intersects "conditions your rules use" with
// "cells the server reports as none", over the rows actually printed. A
// run scoped to --ecosystem npm must not fail because some other
// ecosystem has a hole — same scoping rule the old anyUnsupported used.
//
// A condition the server does not list at all is NOT reported HERE:
// absence from the matrix means version skew between CLI and server,
// which is a different problem from a known-inert cell and must not turn
// into a fleet-wide CI failure (exit 1). It is not nothing either — see
// unknownPolicyConditions, which routes it to the INCOMPLETE exit instead.
func inertPolicyConditions(rows []supportMatrixRowDTO, usage []preflightConditionUse) []preflightInertCondition {
	var out []preflightInertCondition
	for _, row := range rows {
		for _, u := range usage {
			if row.Conditions[string(u.Condition)] != "none" {
				continue
			}
			out = append(out, preflightInertCondition{
				File: u.File, Line: u.Line, Rule: u.Rule,
				Condition: u.Condition, Ecosystem: row.Ecosystem,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Condition < out[j].Condition
	})
	return out
}

// unknownPolicyConditions returns the conditions a --policy rule uses that
// NO printed matrix row mentions at all.
//
// This is the third outcome the gate was missing. inertPolicyConditions
// answers "the server says this cell is none" (exit 1, a real finding).
// The bare `✓ every condition is supported` answers "every cell said
// partial or full". A condition the server never listed is NEITHER, and
// it was falling into the second bucket — so a CLI newer than its proxy
// printed a green tick over a rule the proxy has no code to evaluate.
// Silence read as verification.
//
// It cannot be a typo in a policy file: ConditionsUsedBy
// (core/policy/proxy_matrix.go:1456) derives conditions from typed struct
// fields, so an unrecognised JSON key deserialises to nil and never gets
// here. Absence therefore means exactly one thing — this CLI knows a
// condition this server does not.
//
// Reported as INCOMPLETE (exit 12, shared with `policy lint` and with the
// unreadable-path branch), never as unsupported (exit 1). That preserves
// the original concern this comment block used to justify staying silent:
// a fleet mid-upgrade must not fail the way a genuinely inert condition
// does. It just no longer gets told everything is fine.
func unknownPolicyConditions(rows []supportMatrixRowDTO, usage []preflightConditionUse) []preflightConditionUse {
	// No rows means no matrix to judge against — every condition would
	// look "unknown" and the report would be noise, not a finding.
	if len(rows) == 0 {
		return nil
	}
	known := make(map[string]bool)
	for _, row := range rows {
		for cond := range row.Conditions {
			known[cond] = true
		}
	}
	seen := make(map[preflightConditionUse]bool, len(usage))
	var out []preflightConditionUse
	for _, u := range usage {
		if known[string(u.Condition)] || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		return out[i].Condition < out[j].Condition
	})
	return out
}

// filterPreflightRows applies the --ecosystem and --unsupported-only flags to
// the raw matrix response. Returns an error when --ecosystem names a row that
// the server doesn't list (caught at flag time so CI fails loud rather than
// silently skipping the check the operator asked for).
func filterPreflightRows(resp supportMatrixResponseDTO, ecoFilter string, unsupportedOnly bool) ([]supportMatrixRowDTO, error) {
	out := make([]supportMatrixRowDTO, 0, len(resp.Matrix))
	// Normalise the filter once; tests call this directly without going
	// through the RunE wrapper, so we can't rely on the caller to lower-
	// case the value.
	ecoFilter = strings.ToLower(strings.TrimSpace(ecoFilter))
	if ecoFilter != "" {
		known := make(map[string]struct{}, len(resp.Ecosystems))
		for _, e := range resp.Ecosystems {
			known[strings.ToLower(e)] = struct{}{}
		}
		if _, ok := known[ecoFilter]; !ok {
			allowed := append([]string(nil), resp.Ecosystems...)
			sort.Strings(allowed)
			return nil, fmt.Errorf("--ecosystem %q is not a known ecosystem; server reports: %s",
				ecoFilter, strings.Join(allowed, ", "))
		}
	}
	for _, row := range resp.Matrix {
		if ecoFilter != "" && !strings.EqualFold(row.Ecosystem, ecoFilter) {
			continue
		}
		if unsupportedOnly && !rowHasUnsupported(row) {
			continue
		}
		out = append(out, row)
	}
	return out, nil
}

// rowHasUnsupported is true when the row contains at least one "none" cell.
// Partial is treated as supported, mirroring the UI's
// unsupported-condition-warning.tsx logic.
func rowHasUnsupported(row supportMatrixRowDTO) bool {
	for _, level := range row.Conditions {
		if level == "none" {
			return true
		}
	}
	return false
}

// anyUnsupported reports whether any PRINTED row has a hole. It no
// longer drives the exit code — gating on it failed every run for every
// org (see the file header) — but it is the honest summary predicate for
// the informational dump, so it stays as the renderer's helper.
func anyUnsupported(rows []supportMatrixRowDTO) bool {
	for _, row := range rows {
		if rowHasUnsupported(row) {
			return true
		}
	}
	return false
}

// printPreflightTable renders one row per ecosystem with a CONDITIONS column
// listing only the unsupported ("none") condition keys, sorted for stable
// output. The full grid would be too wide to be readable on a terminal — the
// operator wants to know "which cells are red", not the whole matrix.
//
// The second column is a SUPPORTED coverage count, not a status word. It used
// to be a STATUS cell reading "unsupported" whenever the row had any hole —
// and by the measurement in this file's header EVERY row has at least one, so
// the column was the literal string "unsupported" sixteen times: zero
// information, and it read as "nothing is supported" when 455 of the 736 cells
// ARE. A count varies per row and states the true proportion.
//
// We write through cmd.OutOrStdout() rather than the package-level PrintTable
// helper so tests can capture output via cmd.SetOut, and so a piped CI run
// (where stdout is redirected) sees the same bytes.
//
// Pass --json to get the full envelope.
func printPreflightTable(cmd *cobra.Command, rows []supportMatrixRowDTO, allConditions []string) {
	out := cmd.OutOrStdout()
	if len(rows) == 0 {
		fmt.Fprintln(out, "No matching ecosystems.")
		return
	}
	g := glyphs()
	headers := []string{"ECOSYSTEM", "SUPPORTED", "UNSUPPORTED CONDITIONS"}
	tableRows := make([][]string, 0, len(rows))
	for _, row := range rows {
		unsupported := unsupportedConditions(row, allConditions)
		// The "nothing unsupported here" cell. It is the LAST column, which
		// writeTable never pads, so the two-byte fallback cannot disturb the
		// grid — and it is strictly better for tabwriter, which measures bytes
		// and therefore counted the three-byte em dash as three columns.
		conds := g.dash
		if len(unsupported) > 0 {
			conds = strings.Join(unsupported, ", ")
		}
		supported, total := conditionCoverage(row, allConditions)
		// Deliberately ASCII "%d/%d" and never the dash glyph, even at
		// total==0: this is a MIDDLE column, which tabwriter pads by byte
		// count, so a three-byte em dash here would shift the grid by two.
		tableRows = append(tableRows, []string{
			row.Ecosystem,
			fmt.Sprintf("%d/%d", supported, total),
			conds,
		})
	}
	writeTable(out, headers, tableRows)
}

// writeTable is the cmd-writer-aware twin of PrintTable. Same column-aligned
// output, but routes through any io.Writer so we can target a test buffer.
func writeTable(out io.Writer, headers []string, rows [][]string) {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	sep := make([]string, len(headers))
	for i, h := range headers {
		sep[i] = strings.Repeat("-", len(h))
	}
	fmt.Fprintln(w, strings.Join(sep, "\t"))
	for _, row := range rows {
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	w.Flush()
}

// conditionCoverage counts how many of the row's conditions are supported out
// of how many were measured. "Supported" is the exact complement of what
// unsupportedConditions lists — a cell counts as a hole only when it is
// literally "none", so partial counts as supported (mirroring the UI, see
// rowHasUnsupported) and a condition the row simply does not carry is not
// invented as a failure. Keeping the two in lockstep is what makes
// `supported + len(unsupported) == total` hold in every printed row.
func conditionCoverage(row supportMatrixRowDTO, allConditions []string) (supported, total int) {
	if len(allConditions) == 0 {
		for _, level := range row.Conditions {
			total++
			if level != "none" {
				supported++
			}
		}
		return supported, total
	}
	for _, cond := range allConditions {
		total++
		if row.Conditions[cond] != "none" {
			supported++
		}
	}
	return supported, total
}

// unsupportedConditions returns the sorted list of condition keys that are
// "none" for the given row. We iterate the canonical condition order from the
// response (rather than ranging the map) so the output is deterministic and
// matches the column order the server published.
func unsupportedConditions(row supportMatrixRowDTO, allConditions []string) []string {
	if len(allConditions) == 0 {
		out := make([]string, 0, len(row.Conditions))
		for cond, level := range row.Conditions {
			if level == "none" {
				out = append(out, cond)
			}
		}
		sort.Strings(out)
		return out
	}
	out := make([]string, 0, len(allConditions))
	for _, cond := range allConditions {
		if row.Conditions[cond] == "none" {
			out = append(out, cond)
		}
	}
	return out
}
