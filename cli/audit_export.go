package cli

// `chainsaw audit export` — dump the audit trail to a file (or stdout) in a
// machine-readable format. Built on top of the same /api/audit/logs endpoint
// the dashboard's audit drawer and `chainsaw audit view` already use; the
// existing handler returns the full event set, so filtering happens client-side
// the same way `audit view` does it. Operators and compliance reviewers asked
// for this gap (see docs/plan_v1_production_readiness.md, gap #1).

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit events to a file (CSV/JSON/NDJSON)",
	Long: `Export audit events for the current org to a machine-readable file
(or stdout). Mirrors the filter flags supported by 'audit view' so an export is
"view + machine-readable output". Useful for compliance handoffs and offline
analysis.

Examples:
  chainsaw audit export --format csv --since 24h --out audit.csv
  chainsaw audit export --format json --start 2026-04-01 --end 2026-04-30 --out april.json
  chainsaw audit export --format ndjson --actor alice@example.com`,
	SilenceUsage: true,
	RunE:         runAuditExport,
}

func init() {
	auditExportCmd.Flags().String("format", "csv", "Output format: csv|json|ndjson")
	auditExportCmd.Flags().String("out", "", "Write to file instead of stdout (use - for stdout)")
	auditExportCmd.Flags().String("start", "", "Filter events on or after this date (RFC3339 or YYYY-MM-DD)")
	auditExportCmd.Flags().String("end", "", "Filter events on or before this date (RFC3339 or YYYY-MM-DD)")
	auditExportCmd.Flags().String("since", "", "Relative time window (e.g. 24h, 7d, 30m); overrides --start if set")
	auditExportCmd.Flags().String("action", "", "Filter by action (substring match)")
	auditExportCmd.Flags().String("actor", "", "Filter by actor (substring match)")
	auditExportCmd.Flags().Int("limit", 0, "Maximum number of events to export (0 = all)")
	auditCmd.AddCommand(auditExportCmd)
}

func runAuditExport(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	format := strings.ToLower(strings.TrimSpace(mustString(cmd, "format")))
	if format == "" {
		format = "csv"
	}
	switch format {
	case "csv", "json", "ndjson":
	default:
		return fmt.Errorf("unknown --format %q — supported values: csv, json, ndjson", format)
	}

	startTime, endTime, err := resolveExportWindow(cmd)
	if err != nil {
		return err
	}

	// Tag the request with ?export=true so the server can apply the export-
	// path row ceiling (see internal/server/dashboard.go::handleAuditLogs).
	// The dashboard's `audit view` keeps hitting /api/audit/logs without
	// this query parameter, so its UI behavior is unchanged. Long-term we
	// should move to a streaming /api/audit/export?cursor=… endpoint; until
	// then the ceiling on this code path is the OOM brake.
	var resp auditLogResponse
	if err := client.Get("/api/audit/logs?export=true", &resp); err != nil {
		return err
	}

	actionFilter := mustString(cmd, "action")
	actorFilter := mustString(cmd, "actor")
	events := filterEvents(resp.Events, startTime, endTime, actionFilter, actorFilter)

	limit, _ := cmd.Flags().GetInt("limit")
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}

	out, closer, err := openExportSink(mustString(cmd, "out"))
	if err != nil {
		return err
	}
	if closer != nil {
		defer closer.Close()
	}

	switch format {
	case "csv":
		if err := writeAuditCSV(out, events); err != nil {
			return err
		}
	case "json":
		if err := writeAuditJSON(out, events); err != nil {
			return err
		}
	case "ndjson":
		if err := writeAuditNDJSON(out, events); err != nil {
			return err
		}
	}

	// Only emit a friendly summary when writing to a real file — keep stdout
	// streams pure so they can be piped into other tools without a status line
	// contaminating the output.
	if outFile := mustString(cmd, "out"); outFile != "" && outFile != "-" {
		fmt.Fprintf(cmd.OutOrStderr(), "Exported %d audit event(s) to %s\n", len(events), outFile)
	}
	return nil
}

// resolveExportWindow returns the [start, end) filter window, applying --since
// (a relative duration) on top of --start/--end. --since wins when both are
// supplied, matching the convention used elsewhere (most-specific flag wins).
func resolveExportWindow(cmd *cobra.Command) (time.Time, time.Time, error) {
	var startTime, endTime time.Time

	if startStr := mustString(cmd, "start"); startStr != "" {
		t, err := parseDate(startStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("--start: %w", err)
		}
		startTime = t
	}
	if endStr := mustString(cmd, "end"); endStr != "" {
		t, err := parseDate(endStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("--end: %w", err)
		}
		// Match `audit view`: include the full end-of-day when only a date
		// is supplied.
		endTime = t.Add(24*time.Hour - time.Second)
	}
	if since := mustString(cmd, "since"); since != "" {
		d, err := parseSinceDuration(since)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("--since: %w", err)
		}
		startTime = time.Now().Add(-d)
	}
	return startTime, endTime, nil
}

// parseSinceDuration accepts Go's time.ParseDuration syntax (e.g. 30m, 24h)
// plus a "Nd" extension for whole-day windows. We don't need sub-second
// precision for audit windows, and operators reach for "7d" before "168h".
func parseSinceDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		var n int
		if _, err := fmt.Sscanf(days, "%d", &n); err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid day duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (use 30m, 24h, 7d, …)", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("--since must be positive, got %s", s)
	}
	return d, nil
}

// openExportSink returns the writer to use for export output. Empty path or
// "-" means stdout; for stdout we return a nil closer so the caller's defer
// is a safe no-op (and so we never close os.Stdout out from under the
// process).
func openExportSink(path string) (io.Writer, io.Closer, error) {
	if path == "" || path == "-" {
		return os.Stdout, nil, nil
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("create %s: %w", path, err)
	}
	return f, f, nil
}

// auditCSVHeaders is the canonical column order for CSV export. Pinned here
// (rather than derived from struct tags) so downstream pipelines have a stable
// schema even if we add new fields to auditEvent later.
var auditCSVHeaders = []string{
	"id", "timestamp", "actor", "action", "resource",
	"client", "decision", "status", "severity", "metadata",
}

func writeAuditCSV(w io.Writer, events []auditEvent) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(auditCSVHeaders); err != nil {
		return err
	}
	for _, e := range events {
		meta := ""
		if len(e.Metadata) > 0 {
			if b, err := json.Marshal(e.Metadata); err == nil {
				meta = string(b)
			}
		}
		row := []string{
			e.ID,
			e.Timestamp.UTC().Format(time.RFC3339),
			e.Actor,
			e.Action,
			e.Resource,
			e.Client,
			e.Decision,
			e.Status,
			e.Severity,
			meta,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func writeAuditJSON(w io.Writer, events []auditEvent) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Wrap in an envelope so the payload shape is self-describing — readers
	// can spot at a glance that this is an audit export, not an arbitrary
	// list. Mirrors the {events, count} shape of /api/audit/logs.
	envelope := struct {
		Events []auditEvent `json:"events"`
		Count  int          `json:"count"`
	}{Events: events, Count: len(events)}
	return enc.Encode(envelope)
}

func writeAuditNDJSON(w io.Writer, events []auditEvent) error {
	enc := json.NewEncoder(w)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

// mustString is a thin wrapper around cmd.Flags().GetString to reduce
// boilerplate where we know the flag is registered. Returns "" if the flag
// is absent — which for the export command's optional filters is exactly
// what we want.
func mustString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}
