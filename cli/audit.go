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

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit event commands",
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
	auditViewCmd.Flags().Int("limit", 50, "Maximum number of events to display (0 = all)")
	auditViewCmd.Flags().Bool("json", false, "Output as JSON")
	auditCmd.AddCommand(auditViewCmd)
	rootCmd.AddCommand(auditCmd)
}

func runAuditView(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	var resp auditLogResponse
	if err := client.Get("/api/audit/logs", &resp); err != nil {
		return err
	}

	// Parse optional date filters.
	startStr, _ := cmd.Flags().GetString("start")
	endStr, _ := cmd.Flags().GetString("end")
	sinceStr, _ := cmd.Flags().GetString("since")
	actionFilter, _ := cmd.Flags().GetString("action")
	actorFilter, _ := cmd.Flags().GetString("actor")
	limit, _ := cmd.Flags().GetInt("limit")

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

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(events)
	}

	if len(events) == 0 {
		fmt.Println("No audit events found.")
		return nil
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
