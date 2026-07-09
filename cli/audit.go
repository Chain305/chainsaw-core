package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// auditEvent mirrors the auditEventPayload returned by GET /api/audit/logs.
type auditEvent struct {
	ID        string                 `json:"id"`
	Action    string                 `json:"action"`
	Actor     string                 `json:"actor"`
	Client    string                 `json:"client,omitempty"`
	Resource  string                 `json:"resource"`
	Decision  string                 `json:"decision,omitempty"`
	Status    string                 `json:"status"`
	Severity  string                 `json:"severity"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

type auditLogResponse struct {
	Events  []auditEvent `json:"events"`
	Actions []string     `json:"actions"`
	Actors  []string     `json:"actors"`
}

// auditViewServerCap is the row ceiling the server applies to the non-export
// /api/audit/logs response. The response carries no total/truncated field, so
// the client cannot precisely detect a cap hit; we treat a returned slab at or
// above this size as "possibly capped" and advise the operator to reach for
// `audit export` (which opts into the larger export ceiling) for the full
// range. Keep this in sync with internal/server/dashboard.go::handleAuditLogs
// — if that handler ever exposes a `truncated`/`total` field, prefer it over
// this heuristic.
const auditViewServerCap = 500

var auditCmd = &cobra.Command{
	Use:     "audit",
	Short:   "Audit event commands",
	GroupID: GrpAudit,
}

var auditViewCmd = &cobra.Command{
	Use:   "view",
	Short: "View audit events for the current org",
	RunE:  runAuditView,
}

func init() {
	auditViewCmd.Flags().String("start", "", "Filter events on or after this date (RFC3339 or YYYY-MM-DD)")
	auditViewCmd.Flags().String("end", "", "Filter events on or before this date (RFC3339 or YYYY-MM-DD)")
	auditViewCmd.Flags().String("since", "", "Relative time window (e.g. 24h, 7d, 30m); mutually exclusive with --start")
	auditViewCmd.Flags().String("action", "", "Filter by action (substring match)")
	auditViewCmd.Flags().String("actor", "", "Filter by actor (substring match)")
	auditViewCmd.Flags().Int("limit", 50, "Maximum number of events to display (default 50; 0 = all). Note: `audit export` defaults to 0/all.")
	auditViewCmd.Flags().Bool("json", false, "Output as JSON")
	auditCmd.AddCommand(auditViewCmd)
	rootCmd.AddCommand(auditCmd)
}

func runAuditView(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	// Parse optional date filters. Read flags before the fetch so the
	// progress notice below can consult --json (it must never contaminate a
	// machine-readable stdout stream).
	startStr, _ := cmd.Flags().GetString("start")
	endStr, _ := cmd.Flags().GetString("end")
	sinceStr, _ := cmd.Flags().GetString("since")
	actionFilter, _ := cmd.Flags().GetString("action")
	actorFilter, _ := cmd.Flags().GetString("actor")
	limit, _ := cmd.Flags().GetInt("limit")
	asJSON := useJSON(cmd)

	// Surface progress on a full-set fetch, but only on an interactive
	// terminal and only to stderr so JSON/piped stdout stays pure.
	if stdoutIsTerminal() {
		fmt.Fprintln(cmd.ErrOrStderr(), "Fetching audit events…")
	}

	var resp auditLogResponse
	if err := client.Get("/api/audit/logs", &resp); err != nil {
		return err
	}

	if sinceStr != "" && startStr != "" {
		return fmt.Errorf("--since and --start are mutually exclusive; pick one")
	}

	var startTime, endTime time.Time
	if startStr != "" {
		t, err := parseDate(startStr)
		if err != nil {
			return fmt.Errorf("--start: %w", err)
		}
		startTime = t
	}
	if endStr != "" {
		t, err := parseDate(endStr)
		if err != nil {
			return fmt.Errorf("--end: %w", err)
		}
		// Include everything up to end of day when only a date is given.
		endTime = t.Add(24*time.Hour - time.Second)
	}
	if sinceStr != "" {
		d, err := parseSinceDuration(sinceStr)
		if err != nil {
			return fmt.Errorf("--since: %w", err)
		}
		now := time.Now()
		startTime = now.Add(-d)
		if endTime.IsZero() {
			endTime = now
		}
	}

	events := filterEvents(resp.Events, startTime, endTime, actionFilter, actorFilter)
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}

	if asJSON {
		// Write to the command's writer (cmd.OutOrStdout, == os.Stdout in
		// production) rather than os.Stdout directly, so the JSON path matches
		// the text path's target and stays testable.
		return writeJSON(cmd, events)
	}

	// The view path fetches a server-capped slab and filters client-side, so a
	// date/since window that lands entirely outside the returned slab yields an
	// empty result that is indistinguishable from "nothing happened." Warn the
	// operator whenever the response looks capped, or whenever a time filter is
	// active and produced no rows, so an empty result is never silently
	// mistaken for a quiet log. (See auditViewServerCap.)
	windowActive := startStr != "" || sinceStr != "" || endStr != ""
	capped := len(resp.Events) >= auditViewServerCap
	if len(events) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No audit events found.")
		if desc := describeAuditFilters(startStr, endStr, sinceStr, actionFilter, actorFilter); desc != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "  (filters: %s)\n", desc)
		}
		if capped || windowActive {
			fmt.Fprintln(cmd.ErrOrStderr(), "note: results are limited to the server's most-recent events; use `chainsaw audit export` for the full range.")
		}
		return nil
	}
	if capped {
		fmt.Fprintln(cmd.ErrOrStderr(), "note: results are limited to the server's most-recent events; use `chainsaw audit export` for the full range.")
	}

	rows := make([][]string, len(events))
	for i, e := range events {
		rows[i] = []string{
			e.Timestamp.Local().Format("2006-01-02 15:04:05"),
			e.Actor,
			e.Action,
			e.Resource,
			e.Decision,
			e.Status,
			e.Severity,
		}
	}
	PrintTable([]string{"TIMESTAMP", "ACTOR", "ACTION", "RESOURCE", "DECISION", "STATUS", "SEVERITY"}, rows)
	return nil
}

func parseDate(s string) (time.Time, error) {
	// Try RFC3339 first.
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	// Fall back to YYYY-MM-DD.
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unrecognised date format %q — use YYYY-MM-DD or RFC3339", s)
}

func filterEvents(events []auditEvent, start, end time.Time, action, actor string) []auditEvent {
	out := make([]auditEvent, 0, len(events))
	for _, e := range events {
		if !start.IsZero() && e.Timestamp.Before(start) {
			continue
		}
		if !end.IsZero() && e.Timestamp.After(end) {
			continue
		}
		if action != "" && !containsFold(e.Action, action) {
			continue
		}
		if actor != "" && !containsFold(e.Actor, actor) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// describeAuditFilters renders the active `audit view` filters as a compact,
// human-readable string (e.g. "start=2026-04-01, action=policy.created"). It
// returns "" when no filter is set, so the caller can omit the suffix entirely.
// Kept as a free function so it is unit-testable without a cobra round-trip.
func describeAuditFilters(start, end, since, action, actor string) string {
	parts := []string{}
	if start != "" {
		parts = append(parts, "start="+start)
	}
	if end != "" {
		parts = append(parts, "end="+end)
	}
	if since != "" {
		parts = append(parts, "since="+since)
	}
	if action != "" {
		parts = append(parts, "action="+action)
	}
	if actor != "" {
		parts = append(parts, "actor="+actor)
	}
	return strings.Join(parts, ", ")
}
