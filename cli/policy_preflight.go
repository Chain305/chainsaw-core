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
//   0 — every (ecosystem, condition) cell printed is supported (full/partial)
//   1 — at least one "none" cell appears in the printed slice (CI signal)
//   2 — usage / network / other errors (cobra/RunE default)
//
// The "none" gate matters because the UI treats partial as supported (the
// signal is wired, it just may be empty in practice) — preflight does the
// same so operator expectations match the UI.

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
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

// ExitCodeError lets a Cobra RunE bubble up a specific process exit code
// without losing the error message. main.go (or root) inspects the type via
// errors.As and calls os.Exit with the embedded code.
type ExitCodeError struct {
	Code int
	Err  error
}

func (e *ExitCodeError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("exit %d", e.Code)
	}
	return e.Err.Error()
}

func (e *ExitCodeError) Unwrap() error { return e.Err }

var policyPreflightCmd = &cobra.Command{
	Use:   "preflight",
	Short: "Show which policy conditions are supported per ecosystem",
	Long: `Fetch the proxy policy compatibility matrix from the server and report
which conditions are unsupported for which ecosystems. Reuses the same
GET /api/policies/support-matrix endpoint the Web UI uses, so what you see
here is byte-identical to the inline warnings rendered next to policy
condition inputs in the dashboard.

Use this in CI to catch policies that reference conditions silently inert
on the target ecosystem before applying them — the command exits non-zero
when at least one "none" cell appears in the printed matrix.

Examples:
  chainsaw policy preflight
  chainsaw policy preflight --ecosystem npm
  chainsaw policy preflight --ecosystem npm --json
  chainsaw policy preflight --unsupported-only`,
	SilenceUsage: true,
	RunE:         runPolicyPreflight,
}

func init() {
	policyPreflightCmd.Flags().String("ecosystem", "",
		"Filter to a single ecosystem (e.g. npm, pip, maven). Default: all ecosystems.")
	policyPreflightCmd.Flags().Bool("unsupported-only", false,
		"Only print rows containing at least one unsupported (none) cell.")
	policyPreflightCmd.Flags().Bool("json", false, "Output the raw matrix response as JSON.")
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
	asJSON, _ := cmd.Flags().GetBool("json")

	rows, err := filterPreflightRows(resp, ecoFilter, unsupportedOnly)
	if err != nil {
		return err
	}

	if asJSON {
		// Round-trip through a fresh response so consumers see the same
		// {ecosystems, conditions, matrix} envelope they get from the
		// server, just trimmed by the filter flags.
		filtered := supportMatrixResponseDTO{
			Ecosystems: make([]string, 0, len(rows)),
			Conditions: append([]string(nil), resp.Conditions...),
			Matrix:     rows,
		}
		for _, r := range rows {
			filtered.Ecosystems = append(filtered.Ecosystems, r.Ecosystem)
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if err := enc.Encode(filtered); err != nil {
			return err
		}
	} else {
		printPreflightTable(cmd, rows, resp.Conditions)
	}

	if anyUnsupported(rows) {
		return &ExitCodeError{
			Code: preflightUnsupportedExitCode,
			Err:  fmt.Errorf("policy preflight: at least one condition is unsupported on the printed ecosystems"),
		}
	}
	return nil
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

// anyUnsupported drives the non-zero exit code. We only count the rows we
// actually printed: a CI run scoped to --ecosystem npm shouldn't fail because
// some other ecosystem has a hole.
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
	headers := []string{"ECOSYSTEM", "STATUS", "UNSUPPORTED CONDITIONS"}
	tableRows := make([][]string, 0, len(rows))
	for _, row := range rows {
		unsupported := unsupportedConditions(row, allConditions)
		status := "ok"
		conds := "—"
		if len(unsupported) > 0 {
			status = "unsupported"
			conds = strings.Join(unsupported, ", ")
		}
		tableRows = append(tableRows, []string{row.Ecosystem, status, conds})
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
