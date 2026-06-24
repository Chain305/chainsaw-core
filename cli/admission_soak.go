package cli

// `chainsaw admission soak {status,clear}` — staged-rollout helpers
// for flipping the K8s admission webhook from failurePolicy=Ignore
// (shadow mode, default) to failurePolicy=Fail.
//
// status is read-only: prints days observed, request counts, deny
// rate, and the per-criterion gate verdict.
//
// clear runs the same evaluator and either:
//   * prints the kubectl patch the operator should run, OR
//   * prints which criterion failed plus a one-line suggestion.
//
// The CLI NEVER applies the patch itself. The flip-to-Fail action
// stays in the operator's hands so the staged-rollout invariant
// ("we never silently take prod down") holds across surfaces.

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/spf13/cobra"
)

// soakStatusDTO mirrors internal/server.soakStatusResponse on the
// wire. Inlined here so the CLI does not import the server package
// (which would pull in pgstore + the universe). Fields are the
// JSON-decoded shape of the API response.
type soakStatusDTO struct {
	DaysObserved    int                `json:"days_observed"`
	DaysRequired    int                `json:"days_required"`
	TotalAdmissions int                `json:"total_admissions"`
	WouldAllow      int                `json:"would_allow"`
	WouldBlock      int                `json:"would_block"`
	InternalError   int                `json:"internal_error"`
	ErrorsLast24h   int                `json:"errors_last_24h"`
	DenyRate        float64            `json:"deny_rate"`
	MaxDenyRate     float64            `json:"max_deny_rate"`
	RequestsPerDay  int                `json:"requests_per_day"`
	Conditions      []soakConditionDTO `json:"conditions"`
	Cleared         bool               `json:"cleared"`
}

type soakConditionDTO struct {
	Name     string `json:"name"`
	Met      bool   `json:"met"`
	Evidence string `json:"evidence"`
}

type soakClearDTO struct {
	Cleared      bool               `json:"cleared"`
	Status       soakStatusDTO      `json:"status"`
	KubectlPatch string             `json:"kubectl_patch,omitempty"`
	Missing      []soakConditionDTO `json:"missing,omitempty"`
	Suggestion   string             `json:"suggestion,omitempty"`
}

var admissionCmd = &cobra.Command{
	Use:   "admission",
	Short: "K8s admission webhook helpers (shadow-mode soak gate, etc)",
	Long: `Helpers for the K8s ValidatingAdmissionWebhook emitted by the hardening wizard (/admin/hardening).

The webhook ships in shadow mode (failurePolicy: Ignore) by default. Use
` + "`chainsaw admission soak status`" + ` to see how much soak it has accumulated,
and ` + "`chainsaw admission soak clear`" + ` to check whether it's safe to flip
to fail-closed (failurePolicy: Fail).`,
}

var admissionSoakCmd = &cobra.Command{
	Use:   "soak",
	Short: "Shadow-mode soak gate (status / clear before flipping failurePolicy: Fail)",
}

var admissionSoakStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Report the shadow-mode soak window and would-block counts",
	Long: `Report soak progress for the K8s admission webhook in shadow mode.

Prints days observed, total admission requests seen, would-deny counts,
and the per-criterion gate verdict. Exit code is 0 even when the gate
is not yet cleared — use ` + "`chainsaw admission soak clear`" + ` for an
exit-code-based check.

Flags:
  --days INT          minimum soak window (default 7)
  --max-deny-rate F   ceiling for would-deny/total (default 0.0)
  --json              emit raw JSON instead of a human table`,
	RunE: runAdmissionSoakStatus,
}

var admissionSoakClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Check the soak gate and print the kubectl patch if it passes",
	Long: `Run the soak gate. On pass, prints a single ` + "`kubectl patch`" + ` command
the operator should run to flip failurePolicy: Ignore → Fail. On fail,
prints which criterion failed and a suggested next step.

This command NEVER applies the patch itself. The flip-to-Fail action
stays in the operator's hands.

Exit codes:
  0  gate cleared; kubectl patch printed to stdout
  3  gate not cleared; conditions printed to stderr
  2  HTTP / auth / unreachable`,
	RunE: runAdmissionSoakClear,
}

func init() {
	admissionSoakStatusCmd.Flags().Int("days", 0, "Soak window minimum in days (default server-side: 7)")
	admissionSoakStatusCmd.Flags().Float64("max-deny-rate", -1, "Maximum would-deny / total ratio (default server-side: 0.0)")
	admissionSoakStatusCmd.Flags().Bool("json", false, "Output raw JSON")
	admissionSoakClearCmd.Flags().Int("days", 0, "Soak window minimum in days (default server-side: 7)")
	admissionSoakClearCmd.Flags().Float64("max-deny-rate", -1, "Maximum would-deny / total ratio (default server-side: 0.0)")
	admissionSoakClearCmd.Flags().Bool("json", false, "Output raw JSON")

	admissionSoakCmd.AddCommand(admissionSoakStatusCmd)
	admissionSoakCmd.AddCommand(admissionSoakClearCmd)
	admissionCmd.AddCommand(admissionSoakCmd)
	rootCmd.AddCommand(admissionCmd)
}

// soakQuery turns --days / --max-deny-rate into a query string. Empty
// values are omitted so the server falls back to its defaults.
func soakQuery(cmd *cobra.Command) string {
	q := url.Values{}
	if d, _ := cmd.Flags().GetInt("days"); d > 0 {
		q.Set("days", fmt.Sprintf("%d", d))
	}
	if r, _ := cmd.Flags().GetFloat64("max-deny-rate"); r >= 0 {
		q.Set("max_deny_rate", fmt.Sprintf("%g", r))
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}

func runAdmissionSoakStatus(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	var resp soakStatusDTO
	if err := client.Get("/api/admission/soak/status"+soakQuery(cmd), &resp); err != nil {
		return err
	}
	if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
		return PrintJSON(resp)
	}
	printSoakStatus(cmd, resp)
	return nil
}

func runAdmissionSoakClear(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	var resp soakClearDTO
	if err := client.Post("/api/admission/soak/clear"+soakQuery(cmd), nil, &resp); err != nil {
		return err
	}
	if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
		return PrintJSON(resp)
	}
	if resp.Cleared {
		fmt.Fprintln(cmd.OutOrStdout(), "Soak gate cleared.")
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), "Review the conditions one more time, then run:")
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), "  "+resp.KubectlPatch)
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), "After the patch lands, failurePolicy=Fail means the webhook is fail-closed:")
		fmt.Fprintln(cmd.OutOrStdout(), "pod admission will be BLOCKED if the webhook becomes unreachable.")
		return nil
	}
	// Print missing conditions to stderr so a CI consumer can tee
	// stdout (which stays empty on the unhappy path) and grep stderr.
	fmt.Fprintln(cmd.ErrOrStderr(), "Soak gate NOT cleared. Missing criteria:")
	for _, c := range resp.Missing {
		fmt.Fprintf(cmd.ErrOrStderr(), "  - %s: %s\n", c.Name, c.Evidence)
	}
	if resp.Suggestion != "" {
		fmt.Fprintln(cmd.ErrOrStderr())
		fmt.Fprintf(cmd.ErrOrStderr(), "Suggestion: %s\n", resp.Suggestion)
	}
	// Exit code 3 distinguishes "gate not cleared" from "HTTP / auth
	// failure" (exit 2) and "happy path" (exit 0). Cobra surfaces
	// any non-nil error as exit 1; we use SilenceUsage + ExitCodeError
	// so the operator sees just the message we printed and CI can
	// branch on the exit code.
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	return &ExitCodeError{Code: 3, Err: errors.New("soak gate not cleared")}
}

func printSoakStatus(cmd *cobra.Command, s soakStatusDTO) {
	out := cmd.OutOrStdout()
	state := "NOT CLEARED"
	if s.Cleared {
		state = "CLEARED"
	}
	fmt.Fprintf(out, "Soak gate: %s\n", state)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "  Days observed:        %d / %d\n", s.DaysObserved, s.DaysRequired)
	fmt.Fprintf(out, "  Total admissions:     %d (%d/day steady-state)\n", s.TotalAdmissions, s.RequestsPerDay)
	fmt.Fprintf(out, "  Would-allow:          %d\n", s.WouldAllow)
	fmt.Fprintf(out, "  Would-deny:           %d (%.2f%% of total; ceiling %.2f%%)\n",
		s.WouldBlock, s.DenyRate*100, s.MaxDenyRate*100)
	fmt.Fprintf(out, "  Webhook errors (24h): %d\n", s.ErrorsLast24h)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Conditions:")
	for _, c := range s.Conditions {
		mark := "FAIL"
		if c.Met {
			mark = "PASS"
		}
		fmt.Fprintf(out, "  [%s] %s — %s\n", mark, c.Name, c.Evidence)
	}
}
