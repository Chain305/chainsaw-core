package cli

// `chainsaw coverage` subcommands — opt-in coverage reporting CLI.
//
// Hard contract (mirrored from internal/coverage):
//   - The feature is OFF by default. When the server has
//     `coverage.enabled: false` (or is unset), every /api/coverage/*
//     request returns 404. The CLI surfaces that as a plain "coverage
//     is not enabled on the server" message rather than dumping a
//     stack trace, so an operator running these commands against a
//     dark deployment gets a clear signal.
//   - The CLI is read + admin-CRUD only. Nothing here ever causes the
//     server to block an install or change a policy decision. The
//     `expected` subcommand mutates the coverage_expected metadata
//     table — pure declarative state, no enforcement side-effects.

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var coverageCmd = &cobra.Command{
	Use:   "coverage",
	Short: "Inspect install-coverage measurements (opt-in)",
	Long: `View tracked install sources, ecosystem breakdown, and clients that have
gone silent. Coverage is an opt-in measurement feature — it is purely
informational and never blocks installs. When the server hasn't enabled
coverage, every subcommand prints "coverage is not enabled" and exits
without contacting the API further.`,
	SilenceUsage: true,
}

var coverageSummaryCmd = &cobra.Command{
	Use:          "summary",
	Short:        "Show tracked install sources for a window (default 7d)",
	SilenceUsage: true,
	RunE:         runCoverageSummary,
}

var coverageSilentCmd = &cobra.Command{
	Use:          "silent",
	Short:        "List declared sources with no traffic in the window",
	SilenceUsage: true,
	RunE:         runCoverageSilent,
}

var coverageExpectedCmd = &cobra.Command{
	Use:          "expected",
	Short:        "Manage the admin-declared expected install surface",
	SilenceUsage: true,
}

var coverageExpectedListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List declared expected install sources",
	SilenceUsage: true,
	RunE:         runCoverageExpectedList,
}

var coverageExpectedAddCmd = &cobra.Command{
	Use:          "add <client-pattern>",
	Short:        "Declare a client as part of the expected install surface",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runCoverageExpectedAdd,
}

var coverageExpectedRemoveCmd = &cobra.Command{
	Use:          "remove <id>",
	Short:        "Remove a declared expected source by id",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runCoverageExpectedRemove,
}

// D.12 — bypass-report triage subcommands.
//
// `chainsaw coverage bypass list` shows the ingested rows above a
// confidence threshold (default 0.7 — matches the UI slider). `confirm`
// flips a row to status=confirmed, recording the operator's intent so
// the (deferred) decision-engine gate has a query surface. `dismiss`
// silences a row for 30d.
var coverageBypassCmd = &cobra.Command{
	Use:          "bypass",
	Short:        "Triage ingested bypass-detection reports",
	SilenceUsage: true,
}

var coverageBypassListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List bypass reports above the confidence threshold",
	SilenceUsage: true,
	RunE:         runCoverageBypassList,
}

var coverageBypassConfirmCmd = &cobra.Command{
	Use:          "confirm <id>",
	Short:        "Confirm a bypass report (records intent; quarantine on confirm)",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runCoverageBypassConfirm,
}

var coverageBypassDismissCmd = &cobra.Command{
	Use:          "dismiss <id>",
	Short:        "Dismiss a bypass report as a false alarm (30d suppression)",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runCoverageBypassDismiss,
}

func init() {
	coverageSummaryCmd.Flags().String("window", "7d", "Window: 7d or 30d")
	coverageSummaryCmd.Flags().Bool("json", false, "Output as JSON")
	coverageSilentCmd.Flags().String("window", "7d", "Window: 7d or 30d")
	coverageSilentCmd.Flags().Bool("json", false, "Output as JSON")
	coverageExpectedListCmd.Flags().Bool("json", false, "Output as JSON")
	coverageExpectedAddCmd.Flags().Int("active-within-days", 7, "Expected active window for this source")
	coverageBypassListCmd.Flags().Float64("min-confidence", 0.7, "Confidence threshold (0..1)")
	coverageBypassListCmd.Flags().Bool("include-dismissed", false, "Include dismissed-and-still-suppressed rows")
	coverageBypassListCmd.Flags().Bool("json", false, "Output as JSON")

	coverageCmd.AddCommand(coverageSummaryCmd)
	coverageCmd.AddCommand(coverageSilentCmd)
	coverageExpectedCmd.AddCommand(coverageExpectedListCmd)
	coverageExpectedCmd.AddCommand(coverageExpectedAddCmd)
	coverageExpectedCmd.AddCommand(coverageExpectedRemoveCmd)
	coverageCmd.AddCommand(coverageExpectedCmd)
	coverageBypassCmd.AddCommand(coverageBypassListCmd)
	coverageBypassCmd.AddCommand(coverageBypassConfirmCmd)
	coverageBypassCmd.AddCommand(coverageBypassDismissCmd)
	coverageCmd.AddCommand(coverageBypassCmd)
	rootCmd.AddCommand(coverageCmd)
}

// coverageDisabledMessage is what the CLI prints when the server
// returns 404 for any /api/coverage/* path. The wording is neutral and
// instructive — partial adoption is fine, we're just letting the
// operator know they haven't opted in to the measurement view.
const coverageDisabledMessage = "coverage is not enabled on this server (set coverage.enabled: true in the server config to opt in)"

func runCoverageSummary(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	window, _ := cmd.Flags().GetString("window")
	asJSON, _ := cmd.Flags().GetBool("json")
	var resp coverageSummary
	path := "/api/coverage/summary"
	if window != "" {
		path += "?window=" + window
	}
	if err := client.Get(path, &resp); err != nil {
		return translateCoverageErr(err)
	}
	out := cmd.OutOrStdout()
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}
	fmt.Fprintf(out, "Tracked install sources (%s):\n", resp.Window)
	fmt.Fprintf(out, "  %d clients · %d repos · %d installs\n", resp.TrackedClients, resp.TrackedRepos, resp.TotalInstalls)
	if len(resp.EcosystemBreakdown) > 0 {
		fmt.Fprintln(out, "\nBy ecosystem:")
		rows := make([][]string, len(resp.EcosystemBreakdown))
		for i, e := range resp.EcosystemBreakdown {
			rows[i] = []string{e.Format, strconv.FormatInt(e.Installs, 10)}
		}
		PrintTable([]string{"FORMAT", "INSTALLS"}, rows)
	}
	if len(resp.Clients) > 0 {
		fmt.Fprintln(out, "\nClients:")
		rows := make([][]string, len(resp.Clients))
		for i, c := range resp.Clients {
			rows[i] = []string{c.ClientID, strconv.FormatInt(c.Installs, 10), c.LastSeen.Format(time.RFC3339)}
		}
		PrintTable([]string{"CLIENT", "INSTALLS", "LAST SEEN"}, rows)
	}
	return nil
}

func runCoverageSilent(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	window, _ := cmd.Flags().GetString("window")
	asJSON, _ := cmd.Flags().GetBool("json")
	var resp struct {
		Window string                `json:"window"`
		Silent []coverageSilentEntry `json:"silent"`
	}
	path := "/api/coverage/silent"
	if window != "" {
		path += "?window=" + window
	}
	if err := client.Get(path, &resp); err != nil {
		return translateCoverageErr(err)
	}
	out := cmd.OutOrStdout()
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}
	if len(resp.Silent) == 0 {
		fmt.Fprintf(out, "All declared sources have been active in the last %s.\n", resp.Window)
		return nil
	}
	fmt.Fprintf(out, "Silent sources (no traffic in last %s):\n", resp.Window)
	rows := make([][]string, len(resp.Silent))
	for i, s := range resp.Silent {
		last := "never observed"
		if !s.LastSeen.IsZero() {
			last = s.LastSeen.Format(time.RFC3339)
		}
		rows[i] = []string{strconv.FormatInt(s.ID, 10), s.ClientPattern, last}
	}
	PrintTable([]string{"ID", "PATTERN", "LAST SEEN"}, rows)
	return nil
}

func runCoverageExpectedList(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	asJSON, _ := cmd.Flags().GetBool("json")
	var resp struct {
		Expected []coverageExpected `json:"expected"`
	}
	if err := client.Get("/api/coverage/expected", &resp); err != nil {
		return translateCoverageErr(err)
	}
	out := cmd.OutOrStdout()
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(resp.Expected)
	}
	if len(resp.Expected) == 0 {
		fmt.Fprintln(out, "No expected sources declared.")
		return nil
	}
	rows := make([][]string, len(resp.Expected))
	for i, e := range resp.Expected {
		rows[i] = []string{strconv.FormatInt(e.ID, 10), e.ClientPattern, strconv.Itoa(e.ExpectedActiveWithinDays), e.AddedAt.Format(time.RFC3339), e.AddedBy}
	}
	PrintTable([]string{"ID", "PATTERN", "ACTIVE WITHIN DAYS", "ADDED AT", "ADDED BY"}, rows)
	return nil
}

func runCoverageExpectedAdd(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	pattern := strings.TrimSpace(args[0])
	if pattern == "" {
		return fmt.Errorf("client pattern required")
	}
	days, _ := cmd.Flags().GetInt("active-within-days")
	body := map[string]any{
		"client_pattern":              pattern,
		"expected_active_within_days": days,
	}
	var resp coverageExpected
	if err := client.Post("/api/coverage/expected", body, &resp); err != nil {
		return translateCoverageErr(err)
	}
	printSuccess(cmd.OutOrStdout(), cmd, fmt.Sprintf("Declared %q (id=%d)", resp.ClientPattern, resp.ID))
	return nil
}

func runCoverageExpectedRemove(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("invalid id %q", args[0])
	}
	if err := client.Delete(fmt.Sprintf("/api/coverage/expected/%d", id)); err != nil {
		return translateCoverageErr(err)
	}
	printSuccess(cmd.OutOrStdout(), cmd, fmt.Sprintf("Removed expected source id=%d", id))
	return nil
}

// --- bypass-report triage runners ---

type coverageBypassReport struct {
	ID              int64     `json:"id"`
	ClientHint      string    `json:"client_hint"`
	Evidence        string    `json:"evidence,omitempty"`
	ConfidenceScore float64   `json:"confidence_score"`
	Source          string    `json:"source"`
	Status          string    `json:"status"`
	SeenAt          time.Time `json:"seen_at"`
	CreatedAt       time.Time `json:"created_at"`
	ConfirmedAt     time.Time `json:"confirmed_at,omitempty"`
	ConfirmedBy     string    `json:"confirmed_by,omitempty"`
}

type coverageBypassListResponse struct {
	Reports       []coverageBypassReport `json:"reports"`
	MinConfidence float64                `json:"min_confidence"`
}

func runCoverageBypassList(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	minConf, _ := cmd.Flags().GetFloat64("min-confidence")
	incDismissed, _ := cmd.Flags().GetBool("include-dismissed")
	asJSON, _ := cmd.Flags().GetBool("json")
	path := fmt.Sprintf("/api/bypass/reports?min_confidence=%g", minConf)
	if incDismissed {
		path += "&include_dismissed=1"
	}
	var resp coverageBypassListResponse
	if err := client.Get(path, &resp); err != nil {
		return translateCoverageErr(err)
	}
	out := cmd.OutOrStdout()
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}
	if len(resp.Reports) == 0 {
		fmt.Fprintf(out, "No bypass reports above confidence %.2f.\n", resp.MinConfidence)
		return nil
	}
	fmt.Fprintf(out, "Bypass reports (confidence >= %.2f):\n", resp.MinConfidence)
	rows := make([][]string, len(resp.Reports))
	for i, r := range resp.Reports {
		rows[i] = []string{
			strconv.FormatInt(r.ID, 10),
			r.ClientHint,
			fmt.Sprintf("%.2f", r.ConfidenceScore),
			r.Source,
			r.Status,
			r.SeenAt.Format(time.RFC3339),
		}
	}
	PrintTable([]string{"ID", "CLIENT", "CONFIDENCE", "SOURCE", "STATUS", "SEEN AT"}, rows)
	return nil
}

func runCoverageBypassConfirm(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("invalid id %q", args[0])
	}
	var resp coverageBypassReport
	if err := client.Post(fmt.Sprintf("/api/bypass/reports/%d/confirm", id), map[string]any{}, &resp); err != nil {
		return translateCoverageErr(err)
	}
	printSuccess(cmd.OutOrStdout(), cmd, fmt.Sprintf("Confirmed bypass report id=%d (client=%q, status=%s)", resp.ID, resp.ClientHint, resp.Status))
	return nil
}

func runCoverageBypassDismiss(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("invalid id %q", args[0])
	}
	var resp coverageBypassReport
	if err := client.Post(fmt.Sprintf("/api/bypass/reports/%d/dismiss", id), map[string]any{}, &resp); err != nil {
		return translateCoverageErr(err)
	}
	printSuccess(cmd.OutOrStdout(), cmd, fmt.Sprintf("Dismissed bypass report id=%d (30d suppression)", resp.ID))
	return nil
}

// translateCoverageErr surfaces "feature off" to the operator with a
// neutral message instead of letting the bare 404 pass through. We
// detect by the literal "404" / "not found" the APIClient emits — the
// shape mirrors the existing classifyCLIError heuristics in root.go.
func translateCoverageErr(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "404") || strings.Contains(msg, "not found") {
		return fmt.Errorf("%s", coverageDisabledMessage)
	}
	return err
}

// --- wire types (mirror internal/coverage shapes) ---

type coverageSummary struct {
	OrgID              string                   `json:"org_id"`
	Window             string                   `json:"window"`
	WindowStart        time.Time                `json:"window_start"`
	WindowEnd          time.Time                `json:"window_end"`
	TrackedClients     int                      `json:"tracked_clients"`
	TrackedRepos       int                      `json:"tracked_repos"`
	TotalInstalls      int64                    `json:"total_installs"`
	EcosystemBreakdown []coverageEcosystemRow   `json:"ecosystem_breakdown"`
	Clients            []coverageClientActivity `json:"clients"`
}

type coverageEcosystemRow struct {
	Format   string `json:"format"`
	Installs int64  `json:"installs"`
}

type coverageClientActivity struct {
	ClientID string    `json:"client_id"`
	Installs int64     `json:"installs"`
	LastSeen time.Time `json:"last_seen"`
}

type coverageSilentEntry struct {
	ID                       int64     `json:"id"`
	ClientPattern            string    `json:"client_pattern"`
	ExpectedActiveWithinDays int       `json:"expected_active_within_days"`
	AddedAt                  time.Time `json:"added_at"`
	AddedBy                  string    `json:"added_by"`
	LastSeen                 time.Time `json:"last_seen,omitempty"`
}

type coverageExpected struct {
	ID                       int64     `json:"id"`
	ClientPattern            string    `json:"client_pattern"`
	ExpectedActiveWithinDays int       `json:"expected_active_within_days"`
	AddedAt                  time.Time `json:"added_at"`
	AddedBy                  string    `json:"added_by"`
}
