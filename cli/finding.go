package cli

// finding.go is the CLI surface for the /api/findings endpoints exposed
// by internal/server/findings_api.go. It mirrors the Web UI's detail
// view (ui_new/src/app/(dashboard)/investigate/findings/[id]/) so an
// operator on the terminal can drive the same triage lifecycle the
// dashboard offers — ack, snooze, resolve, suppress, reopen, assign —
// plus the false-positive / true-positive feedback signal that feeds
// the Bayesian tuner.
//
// Design notes:
//   - All verbs are thin wrappers around the existing server handlers;
//     no new endpoints are introduced. The server is the source of truth
//     for permission gates (PermFindingsRead / PermFindingsManage /
//     PermFindingsSuppress) and state-machine transitions.
//   - Output defaults to a human-readable table or one-line confirmation;
//     `--json` returns the full server payload for scripting.
//   - --dry-run is intentionally NOT plumbed: the destructive surface
//     here (suppress) targets a single row and is reversible via
//     `chainsaw finding reopen`; the dry-run header on the server is
//     scoped to delete-shaped routes (policy delete, exception delete,
//     token revoke).

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// findingItem mirrors the findingDTO emitted by /api/findings. Kept
// field-for-field in sync with internal/server/findings_api.go:findingDTO
// so the CLI never round-trips through a generic map.
type findingItem struct {
	ID               string     `json:"id"`
	OrgID            string     `json:"orgId"`
	EventID          string     `json:"eventId"`
	PolicyID         string     `json:"policyId,omitempty"`
	PackageName      string     `json:"packageName"`
	PackageVersion   string     `json:"packageVersion"`
	Severity         string     `json:"severity"`
	Status           string     `json:"status"`
	SnoozedUntil     *time.Time `json:"snoozedUntil,omitempty"`
	AssigneeID       *string    `json:"assigneeId,omitempty"`
	SuppressedReason *string    `json:"suppressedReason,omitempty"`
	Rank             float64    `json:"rank"`
	HasFix           bool       `json:"hasFix,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
	Decision         string     `json:"decision,omitempty"`
	RepoID           string     `json:"repoId,omitempty"`
	Path             string     `json:"path,omitempty"`
	Owners           []string   `json:"owners,omitempty"`
}

var findingCmd = &cobra.Command{
	Use:   "finding",
	Short: "Manage security findings (triage lifecycle: ack / snooze / resolve / suppress / reopen)",
	Long: "Drive a finding through its lifecycle from the CLI. Mirrors the " +
		"investigate/findings/[id] page in the Web UI. All verbs hit the same " +
		"/api/findings handlers the dashboard uses, so permissions, audit " +
		"trail, and state-machine validation are identical.",
}

// ── list ──────────────────────────────────────────────────────────────────────

var findingListCmd = &cobra.Command{
	Use:   "list",
	Short: "List findings for the caller's org",
	RunE:  runFindingList,
}

func init() {
	findingListCmd.Flags().Bool("json", false, "Output as JSON")
	findingListCmd.Flags().StringSlice("status", nil, "Filter by status (new, acknowledged, snoozed, resolved, suppressed). Repeatable.")
	findingListCmd.Flags().StringSlice("severity", nil, "Filter by severity (critical, high, medium, low, info). Repeatable.")
	findingListCmd.Flags().String("policy-id", "", "Filter by policy id")
	findingListCmd.Flags().String("package", "", "Filter by package name (exact match)")
	findingListCmd.Flags().String("assignee", "", "Filter by assignee user id")
	findingListCmd.Flags().Int("limit", 50, "Maximum rows to return (server caps via ListFilter.normalize)")
	findingListCmd.Flags().Int("offset", 0, "Pagination offset")
	findingListCmd.Flags().String("sort", "", "Sort key (defaults to rank). See internal/finding/finding.go SortBy.")
	findingCmd.AddCommand(findingListCmd)
}

func runFindingList(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	q := buildFindingListQuery(cmd)
	var resp struct {
		Findings []findingItem `json:"findings"`
		Total    int           `json:"total"`
	}
	if err := client.Get("/api/findings"+q, &resp); err != nil {
		return err
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp)
	}

	if len(resp.Findings) == 0 {
		fmt.Println("No findings found.")
		return nil
	}
	rows := make([][]string, len(resp.Findings))
	for i, f := range resp.Findings {
		assignee := "-"
		if f.AssigneeID != nil && *f.AssigneeID != "" {
			assignee = *f.AssigneeID
		}
		rows[i] = []string{
			f.ID,
			f.Severity,
			f.Status,
			fmt.Sprintf("%s@%s", f.PackageName, f.PackageVersion),
			f.PolicyID,
			assignee,
			f.UpdatedAt.Format("2006-01-02"),
		}
	}
	PrintTable([]string{"ID", "SEVERITY", "STATUS", "PACKAGE", "POLICY", "ASSIGNEE", "UPDATED"}, rows)
	if resp.Total > len(resp.Findings) {
		fmt.Printf("\nShowing %d of %d findings. Use --limit/--offset to page.\n", len(resp.Findings), resp.Total)
	}
	return nil
}

// buildFindingListQuery assembles the query string from cobra flags. Kept
// as a free function so it can be exercised by buildFindingListQuery_test
// without a server round-trip.
func buildFindingListQuery(cmd *cobra.Command) string {
	parts := []string{}
	statuses, _ := cmd.Flags().GetStringSlice("status")
	if len(statuses) > 0 {
		parts = append(parts, "status="+strings.Join(statuses, ","))
	}
	severities, _ := cmd.Flags().GetStringSlice("severity")
	if len(severities) > 0 {
		parts = append(parts, "severity="+strings.Join(severities, ","))
	}
	if v, _ := cmd.Flags().GetString("policy-id"); v != "" {
		parts = append(parts, "policy_id="+v)
	}
	if v, _ := cmd.Flags().GetString("package"); v != "" {
		parts = append(parts, "package_name="+v)
	}
	if v, _ := cmd.Flags().GetString("assignee"); v != "" {
		parts = append(parts, "assignee_id="+v)
	}
	if v, _ := cmd.Flags().GetInt("limit"); v > 0 {
		parts = append(parts, fmt.Sprintf("limit=%d", v))
	}
	if v, _ := cmd.Flags().GetInt("offset"); v > 0 {
		parts = append(parts, fmt.Sprintf("offset=%d", v))
	}
	if v, _ := cmd.Flags().GetString("sort"); v != "" {
		parts = append(parts, "sort="+v)
	}
	if len(parts) == 0 {
		return ""
	}
	return "?" + strings.Join(parts, "&")
}

// ── get ───────────────────────────────────────────────────────────────────────

var findingGetCmd = &cobra.Command{
	Use:   "get <finding-id>",
	Short: "Show a single finding's full detail",
	Args:  cobra.ExactArgs(1),
	RunE:  runFindingGet,
}

func init() {
	findingGetCmd.Flags().Bool("json", false, "Output as JSON")
	findingCmd.AddCommand(findingGetCmd)
}

func runFindingGet(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("finding id is required")
	}
	resp, err := getFinding(client, id)
	if err != nil {
		return err
	}
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp)
	}
	printFindingHumanReadable(resp)
	return nil
}

func getFinding(client *APIClient, id string) (findingItem, error) {
	var resp struct {
		Finding findingItem `json:"finding"`
	}
	if err := client.Get("/api/findings/"+id, &resp); err != nil {
		return findingItem{}, err
	}
	return resp.Finding, nil
}

func printFindingHumanReadable(f findingItem) {
	assignee := "(unassigned)"
	if f.AssigneeID != nil && *f.AssigneeID != "" {
		assignee = *f.AssigneeID
	}
	fmt.Printf("Finding %s\n", f.ID)
	fmt.Printf("  Package:   %s@%s\n", f.PackageName, f.PackageVersion)
	fmt.Printf("  Severity:  %s\n", f.Severity)
	fmt.Printf("  Status:    %s\n", f.Status)
	if f.Decision != "" {
		fmt.Printf("  Decision:  %s\n", f.Decision)
	}
	if f.PolicyID != "" {
		fmt.Printf("  Policy:    %s\n", f.PolicyID)
	}
	if f.RepoID != "" {
		fmt.Printf("  Repo:      %s\n", f.RepoID)
	}
	if f.Path != "" {
		fmt.Printf("  Path:      %s\n", f.Path)
	}
	if len(f.Owners) > 0 {
		fmt.Printf("  Owners:    %s\n", strings.Join(f.Owners, ", "))
	}
	fmt.Printf("  Assignee:  %s\n", assignee)
	if f.SnoozedUntil != nil {
		fmt.Printf("  Snoozed until: %s\n", f.SnoozedUntil.Format(time.RFC3339))
	}
	if f.SuppressedReason != nil && *f.SuppressedReason != "" {
		fmt.Printf("  Suppressed: %s\n", *f.SuppressedReason)
	}
	fmt.Printf("  Created:   %s\n", f.CreatedAt.Format(time.RFC3339))
	fmt.Printf("  Updated:   %s\n", f.UpdatedAt.Format(time.RFC3339))
}

// ── status transitions: ack / resolve / reopen ────────────────────────────────

var findingAckCmd = &cobra.Command{
	Use:   "ack <finding-id>",
	Short: "Acknowledge a finding (move to status=acknowledged)",
	Args:  cobra.ExactArgs(1),
	RunE:  runFindingTransitionFactory("ack", "acknowledged"),
}

var findingResolveCmd = &cobra.Command{
	Use:   "resolve <finding-id>",
	Short: "Mark a finding as resolved (status=resolved)",
	Args:  cobra.ExactArgs(1),
	RunE:  runFindingTransitionFactory("resolve", "resolved"),
}

var findingReopenCmd = &cobra.Command{
	Use:   "reopen <finding-id>",
	Short: "Re-open a resolved or suppressed finding (status=new)",
	Args:  cobra.ExactArgs(1),
	RunE:  runFindingTransitionFactory("reopen", "new"),
}

func init() {
	findingAckCmd.Flags().Bool("json", false, "Print updated finding as JSON")
	findingResolveCmd.Flags().Bool("json", false, "Print updated finding as JSON")
	findingReopenCmd.Flags().Bool("json", false, "Print updated finding as JSON")
	findingCmd.AddCommand(findingAckCmd, findingResolveCmd, findingReopenCmd)
}

// runFindingTransitionFactory returns a RunE for status transitions whose
// HTTP path is /api/findings/{id}/{action} and whose request body is
// empty. Used for ack / resolve / reopen — snooze (needs body) and
// suppress (needs body + extra perm gate) have their own handlers.
func runFindingTransitionFactory(action, target string) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		client := newClient()
		if client.baseURL == "" {
			return errServerNotConfigured(cmd)
		}
		id := strings.TrimSpace(args[0])
		if id == "" {
			return fmt.Errorf("finding id is required")
		}
		var resp struct {
			Finding findingItem `json:"finding"`
		}
		if err := client.Post("/api/findings/"+id+"/"+action, nil, &resp); err != nil {
			return err
		}
		asJSON, _ := cmd.Flags().GetBool("json")
		if asJSON {
			return PrintJSON(resp.Finding)
		}
		fmt.Printf("Finding %s → %s\n", resp.Finding.ID, resp.Finding.Status)
		_ = target // captured for documentation; the server is authoritative
		return nil
	}
}

// ── snooze ────────────────────────────────────────────────────────────────────

var findingSnoozeCmd = &cobra.Command{
	Use:   "snooze <finding-id>",
	Short: "Snooze a finding until the given timestamp",
	Long: "Hide a finding from the default queue until --until elapses. The " +
		"server transitions snoozed → acknowledged automatically when the " +
		"deadline passes. --until accepts an RFC3339 timestamp (e.g. " +
		"2026-12-31T15:04:05Z) or a Go-style duration relative to now via " +
		"--for (e.g. --for 168h).",
	Args: cobra.ExactArgs(1),
	RunE: runFindingSnooze,
}

func init() {
	findingSnoozeCmd.Flags().String("until", "", "Wake time as RFC3339 timestamp (mutually exclusive with --for)")
	findingSnoozeCmd.Flags().Duration("for", 0, "Duration from now (e.g. 24h, 7d=168h). Mutually exclusive with --until.")
	findingSnoozeCmd.Flags().Bool("json", false, "Print updated finding as JSON")
	findingCmd.AddCommand(findingSnoozeCmd)
}

func runFindingSnooze(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("finding id is required")
	}
	until, err := resolveSnoozeUntil(cmd)
	if err != nil {
		return err
	}
	var resp struct {
		Finding findingItem `json:"finding"`
	}
	body := map[string]any{"snoozedUntil": until.UTC().Format(time.RFC3339Nano)}
	if err := client.Post("/api/findings/"+id+"/snooze", body, &resp); err != nil {
		return err
	}
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp.Finding)
	}
	fmt.Printf("Finding %s snoozed until %s\n", resp.Finding.ID, until.UTC().Format(time.RFC3339))
	return nil
}

// resolveSnoozeUntil normalises --until and --for into a single absolute
// timestamp. Exactly one of the two flags must be provided; the server
// requires a future RFC3339 stamp so we surface that contract eagerly
// rather than waiting for the 400.
func resolveSnoozeUntil(cmd *cobra.Command) (time.Time, error) {
	until, _ := cmd.Flags().GetString("until")
	dur, _ := cmd.Flags().GetDuration("for")
	if until != "" && dur != 0 {
		return time.Time{}, fmt.Errorf("--until and --for are mutually exclusive")
	}
	if until == "" && dur == 0 {
		return time.Time{}, fmt.Errorf("one of --until (RFC3339) or --for (duration) is required")
	}
	if until != "" {
		t, err := time.Parse(time.RFC3339, until)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse --until as RFC3339: %w", err)
		}
		return t, nil
	}
	if dur <= 0 {
		return time.Time{}, fmt.Errorf("--for must be a positive duration")
	}
	return time.Now().UTC().Add(dur), nil
}

// ── suppress ──────────────────────────────────────────────────────────────────

var findingSuppressCmd = &cobra.Command{
	Use:   "suppress <finding-id>",
	Short: "Suppress a finding (hides it from triage; does NOT bypass enforcement)",
	Long: "Suppression is a triage-only state flag: it hides the finding from the " +
		"default triage view but does NOT bypass policy enforcement. The package " +
		"stays blocked, and future installs of the same package@version mint new " +
		"finding rows. To allow installs, create an exception instead " +
		"(chainsaw exception create). Requires the findings:suppress permission. " +
		"The reason is recorded on the row and shown in audit.",
	Args: cobra.ExactArgs(1),
	RunE: runFindingSuppress,
}

func init() {
	findingSuppressCmd.Flags().String("reason", "", "Justification for suppression (required, recorded in audit)")
	findingSuppressCmd.Flags().Bool("yes", false, "Skip the confirmation prompt")
	findingSuppressCmd.Flags().Bool("json", false, "Print updated finding as JSON")
	findingCmd.AddCommand(findingSuppressCmd)
}

func runFindingSuppress(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("finding id is required")
	}
	reason := strings.TrimSpace(mustGetString(cmd, "reason"))
	if reason == "" {
		return fmt.Errorf("--reason is required")
	}
	yes, _ := cmd.Flags().GetBool("yes")
	if !yes {
		if !PromptConfirm(fmt.Sprintf("Suppress finding %q? This only hides it from triage — the package stays blocked. To allow installs, create an exception (chainsaw exception create).", id)) {
			fmt.Println("Aborted.")
			return nil
		}
	}
	var resp struct {
		Finding findingItem `json:"finding"`
	}
	if err := client.Post("/api/findings/"+id+"/suppress", map[string]any{"reason": reason}, &resp); err != nil {
		return err
	}
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp.Finding)
	}
	fmt.Printf("Finding %s suppressed (%s)\n", resp.Finding.ID, reason)
	return nil
}

// mustGetString is a tiny shim that returns the string flag value without
// requiring every callsite to discard the impossible "flag not found"
// error from cobra (cobra panics on a typo at registration time, so the
// runtime error path is unreachable).
func mustGetString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

// ── assign ────────────────────────────────────────────────────────────────────

var findingAssignCmd = &cobra.Command{
	Use:   "assign <finding-id>",
	Short: "Assign or unassign a finding's owner",
	Long: "Sets the assignee user id for a finding. Pass --user '' (or omit it) " +
		"to clear the assignment. Mirrors the Web UI's PATCH /api/findings/{id} " +
		"behaviour where an empty assigneeId clears the row.",
	Args: cobra.ExactArgs(1),
	RunE: runFindingAssign,
}

func init() {
	findingAssignCmd.Flags().String("user", "", "User id to assign (empty string clears the assignment)")
	findingAssignCmd.Flags().Bool("clear", false, "Clear the assignment (alternative to --user '')")
	findingAssignCmd.Flags().Bool("json", false, "Print updated finding as JSON")
	findingCmd.AddCommand(findingAssignCmd)
}

func runFindingAssign(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("finding id is required")
	}
	user := mustGetString(cmd, "user")
	clear, _ := cmd.Flags().GetBool("clear")
	if clear {
		user = ""
	}
	body := map[string]any{"assigneeId": user}
	var resp struct {
		Finding findingItem `json:"finding"`
	}
	if err := client.Patch("/api/findings/"+id, body, &resp); err != nil {
		return err
	}
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp.Finding)
	}
	if user == "" {
		fmt.Printf("Finding %s unassigned\n", resp.Finding.ID)
	} else {
		fmt.Printf("Finding %s assigned to %s\n", resp.Finding.ID, user)
	}
	return nil
}

// ── feedback ──────────────────────────────────────────────────────────────────

var findingFeedbackCmd = &cobra.Command{
	Use:   "feedback <finding-id>",
	Short: "Submit FP / TP / retract feedback for a finding (Bayesian tuner signal)",
	Long: "Records an explicit operator opinion on a finding without changing its " +
		"lifecycle status. --action accepts: false_positive, true_positive, retract. " +
		"Use 'suppress' instead if you want to permanently exempt the package@version " +
		"from enforcement; feedback is purely a signal for the tuning pipeline.",
	Args: cobra.ExactArgs(1),
	RunE: runFindingFeedback,
}

func init() {
	findingFeedbackCmd.Flags().String("action", "", "Required: false_positive | true_positive | retract")
	findingFeedbackCmd.Flags().String("note", "", "Optional free-text note attached to the feedback event")
	findingFeedbackCmd.Flags().String("reason-chip", "", "Optional one-tap categorization (e.g. 'internal package', 'test fixture', 'known good vendor', 'other')")
	findingFeedbackCmd.Flags().String("referencing-event-id", "", "Required for action=retract: the prior feedback event id being retracted")
	findingFeedbackCmd.Flags().Bool("json", false, "Print server response as JSON")
	findingCmd.AddCommand(findingFeedbackCmd)
}

func runFindingFeedback(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("finding id is required")
	}
	action := strings.TrimSpace(mustGetString(cmd, "action"))
	switch action {
	case "false_positive", "true_positive", "retract":
		// supported
	case "":
		return fmt.Errorf("--action is required (false_positive | true_positive | retract)")
	default:
		return fmt.Errorf("unsupported --action %q (allowed: false_positive | true_positive | retract)", action)
	}
	body := map[string]any{"action": action}
	if v := mustGetString(cmd, "note"); v != "" {
		body["note"] = v
	}
	if v := mustGetString(cmd, "reason-chip"); v != "" {
		body["reason_chip"] = v
	}
	if v := strings.TrimSpace(mustGetString(cmd, "referencing-event-id")); v != "" {
		body["referencing_event_id"] = v
	}
	if action == "retract" && body["referencing_event_id"] == nil {
		return fmt.Errorf("--referencing-event-id is required when --action=retract")
	}
	// The /feedback route returns a small envelope rather than a finding,
	// so decode into a generic map for --json passthrough; in human-mode
	// we just confirm the action.
	var resp map[string]any
	if err := client.Post("/api/findings/"+id+"/feedback", body, &resp); err != nil {
		return err
	}
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		// Encode through the shared helper so we get the canonical
		// indented form the rest of the CLI uses.
		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		return nil
	}
	fmt.Printf("Feedback recorded for finding %s: %s\n", id, action)
	return nil
}

func init() {
	rootCmd.AddCommand(findingCmd)
}
