package cli

// Tests for `chainsaw audit export`. These are pure-CLI tests — no live
// server, no fixture HTTP, no DB. They drive the writers and the small
// helpers (window resolution, duration parsing) directly. The wire path
// (client.Get → /api/audit/logs) is the same path `audit view` already
// covers, so we don't re-test it here.

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func sampleEvents() []auditEvent {
	t1 := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 4, 2, 11, 30, 0, 0, time.UTC)
	return []auditEvent{
		{
			ID: "ae-1", Action: "policy.created", Actor: "alice@example.com",
			Resource: "policy:42", Decision: "block", Status: "success",
			Severity: "info", Timestamp: t1,
			Metadata: map[string]any{"policy_kind": "block"},
		},
		{
			ID: "ae-2", Action: "policy.deleted", Actor: "bob@example.com",
			Resource: "policy:43", Status: "success", Severity: "warn",
			Timestamp: t2, Client: "cli",
		},
	}
}

func TestWriteAuditCSV_HeadersAndRows(t *testing.T) {
	var buf bytes.Buffer
	if err := writeAuditCSV(&buf, sampleEvents()); err != nil {
		t.Fatalf("writeAuditCSV: %v", err)
	}

	r := csv.NewReader(&buf)
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv.ReadAll: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("want 3 rows (header + 2 events), got %d", len(rows))
	}
	// Header must match the canonical schema exactly — downstream pipelines
	// will key off these column names.
	for i, want := range auditCSVHeaders {
		if rows[0][i] != want {
			t.Errorf("header[%d]=%q, want %q", i, rows[0][i], want)
		}
	}
	// Spot-check row 1 (alice, policy.created) for field placement.
	if rows[1][0] != "ae-1" {
		t.Errorf("row1 id=%q, want ae-1", rows[1][0])
	}
	if rows[1][2] != "alice@example.com" {
		t.Errorf("row1 actor=%q", rows[1][2])
	}
	if rows[1][3] != "policy.created" {
		t.Errorf("row1 action=%q", rows[1][3])
	}
	// Metadata column must be valid JSON when present.
	var meta map[string]any
	if err := json.Unmarshal([]byte(rows[1][9]), &meta); err != nil {
		t.Errorf("row1 metadata not valid JSON (%q): %v", rows[1][9], err)
	}
	// Empty metadata renders as empty string, not "null".
	if rows[2][9] != "" {
		t.Errorf("row2 metadata should be empty, got %q", rows[2][9])
	}
}

func TestWriteAuditJSON_Envelope(t *testing.T) {
	var buf bytes.Buffer
	if err := writeAuditJSON(&buf, sampleEvents()); err != nil {
		t.Fatalf("writeAuditJSON: %v", err)
	}
	var env struct {
		Events []auditEvent `json:"events"`
		Count  int          `json:"count"`
	}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	if env.Count != 2 || len(env.Events) != 2 {
		t.Fatalf("want count=2 len=2, got count=%d len=%d", env.Count, len(env.Events))
	}
	if env.Events[0].ID != "ae-1" {
		t.Errorf("first event ID=%q, want ae-1", env.Events[0].ID)
	}
}

func TestWriteAuditNDJSON_OneEventPerLine(t *testing.T) {
	var buf bytes.Buffer
	if err := writeAuditNDJSON(&buf, sampleEvents()); err != nil {
		t.Fatalf("writeAuditNDJSON: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 NDJSON lines, got %d", len(lines))
	}
	for i, line := range lines {
		var e auditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Errorf("line %d not valid JSON: %v", i, err)
		}
	}
}

func TestParseSinceDuration(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"24h", 24 * time.Hour, false},
		{"30m", 30 * time.Minute, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"  12h  ", 12 * time.Hour, false},
		{"", 0, true},
		{"0h", 0, true},
		{"-1h", 0, true},
		{"abc", 0, true},
		{"0d", 0, true},
		{"-3d", 0, true},
	}
	for _, tc := range tests {
		got, err := parseSinceDuration(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseSinceDuration(%q): want error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseSinceDuration(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseSinceDuration(%q)=%v, want %v", tc.in, got, tc.want)
		}
	}
}

// newAuditExportTestCmd builds a fresh cobra command with the same flag
// definitions as auditExportCmd, but no parent and no RunE. Lets us drive
// the helpers (resolveExportWindow) without colliding with the global cobra
// state created in init().
func newAuditExportTestCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("format", "csv", "")
	cmd.Flags().String("out", "", "")
	cmd.Flags().String("start", "", "")
	cmd.Flags().String("end", "", "")
	cmd.Flags().String("since", "", "")
	cmd.Flags().String("action", "", "")
	cmd.Flags().String("actor", "", "")
	cmd.Flags().Int("limit", 0, "")
	return cmd
}

func TestResolveExportWindow_StartEnd(t *testing.T) {
	cmd := newAuditExportTestCmd()
	if err := cmd.ParseFlags([]string{"--start=2026-04-01", "--end=2026-04-30"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	start, end, err := resolveExportWindow(cmd)
	if err != nil {
		t.Fatalf("resolveExportWindow: %v", err)
	}
	if start.IsZero() {
		t.Errorf("start should be set")
	}
	// End-of-day extension: end should be after 23:59:00.
	if end.Hour() != 23 || end.Minute() != 59 {
		t.Errorf("end should be end-of-day, got %v", end)
	}
}

func TestResolveExportWindow_SinceWinsOverStart(t *testing.T) {
	cmd := newAuditExportTestCmd()
	if err := cmd.ParseFlags([]string{"--start=2020-01-01", "--since=24h"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	start, _, err := resolveExportWindow(cmd)
	if err != nil {
		t.Fatalf("resolveExportWindow: %v", err)
	}
	// --since=24h should land within the last 25 hours, not back in 2020.
	if time.Since(start) > 25*time.Hour {
		t.Errorf("--since should override --start, but start=%v is too old", start)
	}
}

func TestResolveExportWindow_BadStart(t *testing.T) {
	cmd := newAuditExportTestCmd()
	if err := cmd.ParseFlags([]string{"--start=not-a-date"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if _, _, err := resolveExportWindow(cmd); err == nil {
		t.Fatalf("expected error for bad --start")
	}
}

func TestResolveExportWindow_BadSince(t *testing.T) {
	cmd := newAuditExportTestCmd()
	if err := cmd.ParseFlags([]string{"--since=lots"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if _, _, err := resolveExportWindow(cmd); err == nil {
		t.Fatalf("expected error for bad --since")
	}
}

func TestOpenExportSink_StdoutAndFile(t *testing.T) {
	// stdout case — empty path and "-" both route to os.Stdout and are never
	// staged through a temp file.
	for _, p := range []string{"", "-"} {
		s, err := openExportSink(p)
		if err != nil {
			t.Fatalf("openExportSink(%q): %v", p, err)
		}
		if s.w != os.Stdout {
			t.Errorf("openExportSink(%q): want os.Stdout, got %T", p, s.w)
		}
		if s.file != nil {
			t.Errorf("openExportSink(%q): want no staged file, got %v", p, s.tmpPath)
		}
		if err := s.commit(); err != nil {
			t.Errorf("commit on stdout sink: %v", err)
		}
	}

	// file case — bytes land in place only after commit.
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.csv")
	s, err := openExportSink(path)
	if err != nil {
		t.Fatalf("openExportSink(file): %v", err)
	}
	if s.file == nil {
		t.Fatalf("file path should stage through a real file handle")
	}
	if _, err := s.w.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("file contents=%q, want hello", string(got))
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file %s should be gone after commit", path+".tmp")
	}
}

// TestWriteAuditCSV_NeutralisesFormulaInjection — `chainsaw audit export
// --format csv` writes a file the operator opens in a spreadsheet, and the
// rows carry values the CLI did not author: package coordinates from the
// upstream registry reach `resource`, and the metadata blob is whatever the
// emitting handler recorded. Excel evaluates a cell whose first character is
// `= + - @` TAB or CR, so those must arrive behind the literal-text prefix.
//
// Mirrors the server-side exporter's guard (internal/server/dashboard.go),
// which shares the same core/csvsafe rules — the two exports of one audit row
// must agree byte for byte.
func TestWriteAuditCSV_NeutralisesFormulaInjection(t *testing.T) {
	const dde = `=cmd|'/c calc'!A1`
	events := []auditEvent{{
		ID: "ae-hostile", Action: "package.install", Actor: "-1+" + dde,
		Resource: dde, Client: "@SUM(1+1)", Status: "success",
		Severity: "info", Timestamp: time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC),
	}}
	var buf bytes.Buffer
	if err := writeAuditCSV(&buf, events); err != nil {
		t.Fatalf("writeAuditCSV: %v", err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("csv.ReadAll: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want header + 1 row, got %d", len(rows))
	}
	for _, tc := range []struct {
		col  int
		name string
		want string
	}{
		{2, "actor", "'-1+" + dde},
		{4, "resource", "'" + dde},
		{5, "client", "'@SUM(1+1)"},
	} {
		if rows[1][tc.col] != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, rows[1][tc.col], tc.want)
		}
	}
}

// TestWriteAuditCSV_LeavesOrdinaryRowsUntouched — the guard must be invisible
// on real data. If this ever starts failing, the escape has widened past the
// dangerous prefixes and every downstream CSV consumer is now reading mangled
// values.
func TestWriteAuditCSV_LeavesOrdinaryRowsUntouched(t *testing.T) {
	var buf bytes.Buffer
	if err := writeAuditCSV(&buf, sampleEvents()); err != nil {
		t.Fatalf("writeAuditCSV: %v", err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatalf("csv.ReadAll: %v", err)
	}
	for _, row := range rows {
		for i, cell := range row {
			if strings.HasPrefix(cell, "'") {
				t.Errorf("ordinary cell %d = %q gained an escape prefix", i, cell)
			}
		}
	}
	if rows[1][2] != "alice@example.com" {
		t.Errorf("actor = %q, want it untouched", rows[1][2])
	}
}
