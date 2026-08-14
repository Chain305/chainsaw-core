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
	"net/url"
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
	auditExportCmd.Flags().String("out", "", "Write to file instead of stdout (use - for stdout); the global --output/-o is an alias")
	auditExportCmd.Flags().String("start", "", "Filter events on or after this date (RFC3339 or YYYY-MM-DD)")
	auditExportCmd.Flags().String("end", "", "Filter events on or before this date (RFC3339 or YYYY-MM-DD)")
	auditExportCmd.Flags().String("since", "", "Relative time window (e.g. 24h, 7d, 30m); overrides --start if set")
	auditExportCmd.Flags().String("action", "", "Filter by action (substring match)")
	auditExportCmd.Flags().String("actor", "", "Filter by actor (substring match)")
	auditExportCmd.Flags().Int("limit", 0, "Maximum number of events to export (default 0 = all, unlike 'audit view' which defaults to 50)")
	auditExportCmd.Flags().Bool("allow-truncated", false, "Write the export even when the server reports it is incomplete (default: refuse)")
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
	if err := client.Get(auditExportRequestPath(startTime, endTime), &resp); err != nil {
		return err
	}

	// C9: decide on completeness BEFORE opening the sink. A truncated
	// compliance export must not exist on disk at all unless the operator
	// explicitly asked for a partial one — writing it and then printing a
	// warning leaves a short file that outlives the terminal it was warned
	// in.
	allowTruncated, _ := cmd.Flags().GetBool("allow-truncated")
	if err := reportAuditExportCompleteness(cmd, resp, allowTruncated); err != nil {
		return err
	}

	actionFilter := mustString(cmd, "action")
	actorFilter := mustString(cmd, "actor")
	events := filterEvents(resp.Events, startTime, endTime, actionFilter, actorFilter)

	limit, _ := cmd.Flags().GetInt("limit")
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}

	outFile, err := resolveAuditExportPath(cmd)
	if err != nil {
		return err
	}
	sink, err := openExportSink(outFile)
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
	if outFile != "" && outFile != "-" {
		fmt.Fprintf(cmd.OutOrStderr(), "Exported %d audit event(s) to %s\n", len(events), outFile)
	}
	// C9: the export used to report a count and nothing else, which reads as
	// "this is the whole range". Print the window the SERVER says it queried,
	// on stderr so a `--out -` pipe stays clean.
	if note := auditExportWindowNote(resp.Window); note != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "note: %s\n", note)
	}
	return nil
}

// resolveAuditExportPath returns the file the export must land in, reconciling
// this command's own --out with the global --output.
//
// S9b — `audit export` predates the global --output/-o and named its own sink
// flag --out, then read ONLY that one. Both spellings are published: this
// command's help says `--out audit.csv`, and the recipe quoted in root.go's
// formatIsMachineReadable (the reason `audit export --format csv` is exempt
// from the --output validator) says `--output audit.csv`. The --output form
// therefore exited 0 having created no file, streaming 55 KB of CSV to stdout
// instead — a silent no-op, and on a compliance artifact.
//
// --out wins when both name the SAME destination or only it is set: it is this
// command's own, longest-standing spelling. Two DIFFERENT destinations are
// refused rather than silently resolved, because honouring one and dropping the
// other is the same class of silent loss this fixes. ExitUsage(4): the
// invocation was wrong, not the server.
func resolveAuditExportPath(cmd *cobra.Command) (string, error) {
	local := strings.TrimSpace(mustString(cmd, "out"))
	global := strings.TrimSpace(mustString(cmd, "output"))
	if local != "" && global != "" && local != global {
		return "", &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf(
			"--out %q and --output %q name different files; pass only one", local, global)}
	}
	if local != "" {
		return local, nil
	}
	return global, nil
}

// auditExportRequestPath builds the export request, passing the caller's
// window to the server instead of filtering a fixed server-side slab
// client-side. Before this the server always applied its own 90-day floor:
// `--start 2026-01-01` run in August returned mid-May onward, and the CLI
// filtered that already-clipped slab and reported the result as the range
// the operator asked for.
func auditExportRequestPath(start, end time.Time) string {
	q := url.Values{}
	q.Set("export", "true")
	if !start.IsZero() {
		q.Set("start", start.UTC().Format(time.RFC3339))
	}
	if !end.IsZero() {
		q.Set("end", end.UTC().Format(time.RFC3339))
	}
	return "/api/audit/logs?" + q.Encode()
}

// auditExportWindowNote renders the server-reported window. Empty when the
// server did not report one (an older build), because inventing a window is
// exactly the failure being fixed.
func auditExportWindowNote(win *auditExportWindowInfo) string {
	if win == nil {
		return ""
	}
	start := "the beginning of the log"
	if win.Start != nil {
		start = win.Start.UTC().Format(time.RFC3339)
	}
	end := "now"
	if win.End != nil {
		end = win.End.UTC().Format(time.RFC3339)
	}
	note := fmt.Sprintf("server queried %s → %s", start, end)
	if win.DefaultApplied {
		note += fmt.Sprintf(" (server default lookback of %d days — pass --start to widen)", win.DefaultDays)
	}
	return note
}

// reportAuditExportCompleteness is the C9 gate. The server now reports, per
// source, how many rows exist in the requested window versus how many it
// returned; this turns that into one of three outcomes:
//
//   - server says complete → nothing to say, write the file.
//   - server says truncated → REFUSE, unless --allow-truncated. A short
//     compliance artifact that claims to be whole is worse than no artifact:
//     the operator finds out at audit time, not export time. The refusal
//     names which source clipped and by how much, so the fix (a narrower
//     --start/--end) is obvious.
//   - server said nothing (older build) → warn loudly that completeness is
//     UNVERIFIED and continue. Refusing here would break every export against
//     a server that predates the field, and "we can't tell" is not the same
//     claim as "it's clipped".
//
// Note the deliberate absence of a len(events)==cap heuristic: an org with
// exactly cap rows is complete, and guessing would refuse it. The server is
// the only thing that can answer this, which is why it now does.
func reportAuditExportCompleteness(cmd *cobra.Command, resp auditLogResponse, allowTruncated bool) error {
	errOut := cmd.ErrOrStderr()
	if resp.Truncated == nil {
		fmt.Fprintln(errOut,
			"warning: this server does not report audit-export completeness, so this export "+
				"CANNOT be verified as covering the requested range. It may be silently short. "+
				"Upgrade the server, or reconcile the row count against another source before "+
				"relying on this file for compliance.")
		return nil
	}
	// A source that contributed rows but could not be counted is a third
	// state: not clipped as far as we know, but not verified either. Say so
	// rather than letting silence imply completeness. Sources that returned
	// nothing are not worth a warning — they contributed no rows to vouch
	// for.
	for _, src := range resp.Sources {
		if !src.TotalKnown && src.Returned > 0 {
			fmt.Fprintf(errOut,
				"warning: the server could not count the %q source, so the %d row(s) it "+
					"contributed cannot be verified as complete.\n", src.Source, src.Returned)
			// The note is where the server explains WHY it cannot count —
			// e.g. the in-memory ring cannot tell which of its evicted rows
			// were recovered from the durable audit table and which were
			// never persisted. Printing the warning without it leaves the
			// operator with no way to judge the risk. (The truncated branch
			// below prints notes for its own sources.)
			if src.Note != "" {
				fmt.Fprintf(errOut, "  %s\n", src.Note)
			}
		}
	}

	if !*resp.Truncated {
		return nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "the server clipped this export: it returned %d row(s) but the requested window holds at least %d",
		derefInt(resp.Count, len(resp.Events)), derefInt(resp.Total, 0))
	for _, src := range resp.Sources {
		if !src.Truncated {
			continue
		}
		fmt.Fprintf(&b, "\n  %s: returned %d of %d row(s) (server limit %d)",
			src.Source, src.Returned, src.Total, src.Limit)
		if src.Note != "" {
			fmt.Fprintf(&b, "\n    %s", src.Note)
		}
	}
	if note := auditExportWindowNote(resp.Window); note != "" {
		fmt.Fprintf(&b, "\n  %s", note)
	}

	if allowTruncated {
		fmt.Fprintf(errOut, "warning: %s\nwarning: writing a PARTIAL export anyway (--allow-truncated). "+
			"Do not present this file as a complete audit record.\n", b.String())
		return nil
	}
	return fmt.Errorf("refusing to write a truncated audit export — %s\n"+
		"Narrow the window with --start/--end so each source fits under its limit, "+
		"or pass --allow-truncated to write the partial export anyway", b.String())
}

func derefInt(p *int, fallback int) int {
	if p == nil {
		return fallback
	}
	return *p
}

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
