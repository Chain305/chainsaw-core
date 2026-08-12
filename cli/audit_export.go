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
	auditExportCmd.Flags().Int("limit", 0, "Maximum number of events to export (default 0 = all, unlike `audit view` which defaults to 50)")
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
	// Surface progress on a full-set fetch, but only on an interactive
	// terminal and always to stderr — the export payload itself frequently
	// streams to stdout (openExportSink returns os.Stdout for "" / "-"), so the
	// notice must never land on stdout or it would corrupt a `--out -` pipe.
	// R14: chatter() honors --quiet / CHAINSAW_QUIET; a bare Fprintln did not.
	if stdoutIsTerminal() {
		chatter(cmd, "Fetching audit events…")
	}

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

	sink, err := openExportSink(mustString(cmd, "out"))
	if err != nil {
		return err
	}
	// Unconditional: abort is a no-op once commit has run.
	defer sink.abort()

	switch format {
	case "csv":
		if err := writeAuditCSV(sink.w, events); err != nil {
			return err
		}
	case "json":
		if err := writeAuditJSON(sink.w, events); err != nil {
			return err
		}
	case "ndjson":
		if err := writeAuditNDJSON(sink.w, events); err != nil {
			return err
		}
	}
	if err := sink.commit(); err != nil {
		return err
	}

	// Only emit a friendly summary when writing to a real file — keep stdout
	// streams pure so they can be piped into other tools without a status line
	// contaminating the output.
	if outFile := mustString(cmd, "out"); outFile != "" && outFile != "-" {
		fmt.Fprintf(cmd.OutOrStderr(), "Exported %d audit event(s) to %s\n", len(events), outFile)
	}
	// C9: the export used to report a count and nothing else, which reads as
	// "this is the whole range". It is not — the server caps the export at
	// auditExportServerRowCap rows per source over the last
	// auditExportServerWindowDays days, and the response carries no
	// total/truncated field for the CLI to check. State the real window rather
	// than inferring truncation from len(events) (a brittle guess that would
	// break every working export). Stderr, so a `--out -` pipe stays clean.
	fmt.Fprintf(cmd.ErrOrStderr(), "note: %s\n", auditExportWindowNote)
	return nil
}

// The server's export ceiling, mirrored here so the CLI can describe it
// honestly. internal/server/dashboard.go's handleAuditLogs builds the export
// from events.ForOrg(orgID).ListSince(10000, now-90d), and the violations half
// runs through listViolationEntries with defaultViolationLimit = 10000
// (internal/server/violations_query.go). Neither response reports a total or a
// truncated flag — when they do, prefer the server's own numbers over these
// constants and drop the static note.
const (
	auditExportServerWindowDays = 90
	auditExportServerRowCap     = 10000
)

var auditExportWindowNote = fmt.Sprintf(
	"the server returns at most %d rows per source and only the last %d days, "+
		"so an export cannot cover a longer range than that",
	auditExportServerRowCap, auditExportServerWindowDays)

// resolveExportWindow returns the [start, end) filter window, applying --since
// (a relative duration) on top of --start/--end. --since wins when both are
// supplied, matching the convention used elsewhere (most-specific flag wins).
func resolveExportWindow(cmd *cobra.Command) (time.Time, time.Time, error) {
	var startTime, endTime time.Time

	if startStr := mustString(cmd, "start"); startStr != "" {
		t, _, err := parseDate(startStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("--start: %w", err)
		}
		startTime = t
	}
	if endStr := mustString(cmd, "end"); endStr != "" {
		t, dateOnly, err := parseDate(endStr)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("--end: %w", err)
		}
		// Match `audit view`: include the full end-of-day when ONLY A DATE is
		// supplied. An explicit RFC3339 stamp is honoured verbatim — extending
		// it added an undisclosed extra day of records to a compliance handoff
		// (C6).
		if dateOnly {
			t = t.Add(24*time.Hour - time.Second)
		}
		endTime = t
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

// exportSink is the destination for an export, written through a temp file so a
// failure part-way cannot destroy a previous good export.
//
// C15: this used to be a plain os.Create(path), which TRUNCATES immediately. An
// ENOSPC (or any writer error) half-way through left a partial file where the
// last good audit.csv had been, and the returned error said nothing about the
// file's state. Now the bytes land in <path>.tmp and are renamed into place only
// after the last write succeeds; on any failure the temp file is removed and the
// previous export is still there.
type exportSink struct {
	w       io.Writer
	file    *os.File
	tmpPath string
	dstPath string
}

// openExportSink returns the sink to use for export output. An empty path or "-"
// means stdout, which is written directly (never renamed, and never closed out
// from under the process).
func openExportSink(path string) (*exportSink, error) {
	if path == "" || path == "-" {
		return &exportSink{w: os.Stdout}, nil
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", tmp, err)
	}
	return &exportSink{w: f, file: f, tmpPath: tmp, dstPath: path}, nil
}

// commit flushes the temp file and moves it onto the destination path. A no-op
// for the stdout sink.
func (s *exportSink) commit() error {
	if s.file == nil {
		return nil
	}
	if err := s.file.Close(); err != nil {
		os.Remove(s.tmpPath)
		return fmt.Errorf("close %s: %w", s.tmpPath, err)
	}
	if err := os.Rename(s.tmpPath, s.dstPath); err != nil {
		os.Remove(s.tmpPath)
		return fmt.Errorf("rename %s to %s: %w", s.tmpPath, s.dstPath, err)
	}
	s.file = nil
	return nil
}

// abort discards a partial write. Safe to call after commit (the file handle is
// cleared), so callers can defer it unconditionally.
func (s *exportSink) abort() {
	if s.file == nil {
		return
	}
	s.file.Close()
	os.Remove(s.tmpPath)
	s.file = nil
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
