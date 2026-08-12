package cli

// C9 (CLI half) — `chainsaw audit export` must never hand an operator a
// silently short compliance artifact.
//
// The server now reports, per source, how many rows exist in the requested
// window versus how many it returned. These tests pin what the CLI does with
// that answer: refuse on a clipped export, warn loudly when it cannot be
// verified, and stay quiet only when the server says the result is whole.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func intPtr(v int) *int    { return &v }
func boolPtr(v bool) *bool { return &v }

// exportServerWithResponse serves a fixed export envelope and records the
// query string of the last request, so a test can assert on both halves of
// the contract (what the CLI sent, what it did with the reply).
func exportServerWithResponse(t *testing.T, resp auditLogResponse) *url.Values {
	t.Helper()
	seen := &url.Values{}
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		*seen = q
		_ = json.NewEncoder(w).Encode(resp)
	})
	prevURL := viper.GetString("server_url")
	prevTok := viper.GetString("token")
	viper.Set("server_url", srv.URL)
	viper.Set("token", "test-token")
	t.Cleanup(func() {
		viper.Set("server_url", prevURL)
		viper.Set("token", prevTok)
	})
	return seen
}

func truncatedResponse() auditLogResponse {
	start := time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC)
	return auditLogResponse{
		Events:    sampleEvents(),
		Count:     intPtr(2),
		Total:     intPtr(41821),
		Truncated: boolPtr(true),
		Sources: []auditExportSource{
			{Source: "events", Returned: 2, Total: 2, TotalKnown: true, Limit: 2000},
			{Source: "violations", Returned: 10000, Total: 41822, TotalKnown: true, Limit: 10000, Truncated: true},
		},
		Window: &auditExportWindowInfo{Start: &start, DefaultApplied: true, DefaultDays: 90},
	}
}

func completeResponse() auditLogResponse {
	return auditLogResponse{
		Events:    sampleEvents(),
		Count:     intPtr(2),
		Total:     intPtr(2),
		Truncated: boolPtr(false),
		Sources: []auditExportSource{
			{Source: "violations", Returned: 2, Total: 2, TotalKnown: true, Limit: 10000},
		},
	}
}

// TestAuditExport_RefusesTruncatedExport is the headline: a clipped export
// must fail, and must NOT leave a short file on disk pretending to be a
// compliance record.
func TestAuditExport_RefusesTruncatedExport(t *testing.T) {
	exportServerWithResponse(t, truncatedResponse())
	out := filepath.Join(t.TempDir(), "audit.csv")

	var stdout, stderr bytes.Buffer
	cmd := newAuditExportRunCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"--format=csv", "--out=" + out})
	err := cmd.Execute()

	if err == nil {
		t.Fatalf("a truncated export must fail, got nil error (stderr=%q)", stderr.String())
	}
	msg := err.Error()
	for _, want := range []string{"refusing", "violations", "41822", "--allow-truncated"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal should mention %q: %q", want, msg)
		}
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("no file may be written for a refused export, but %s exists", out)
	}
	if _, statErr := os.Stat(out + ".tmp"); !os.IsNotExist(statErr) {
		t.Errorf("no staged temp file may be left behind at %s.tmp", out)
	}
}

// TestAuditExport_AllowTruncatedWritesButWarnsLoudly: the escape hatch must
// still make the file's status unmistakable.
func TestAuditExport_AllowTruncatedWritesButWarnsLoudly(t *testing.T) {
	exportServerWithResponse(t, truncatedResponse())
	out := filepath.Join(t.TempDir(), "audit.csv")

	var stdout, stderr bytes.Buffer
	cmd := newAuditExportRunCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"--format=csv", "--out=" + out, "--allow-truncated"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--allow-truncated should still write: %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Fatalf("expected the partial export to be written: %v", statErr)
	}
	got := stderr.String()
	for _, want := range []string{"warning", "PARTIAL", "41822"} {
		if !strings.Contains(got, want) {
			t.Errorf("stderr should carry %q: %q", want, got)
		}
	}
	// The warning must never contaminate the cobra stdout stream, which is
	// where a `--out -` payload goes.
	if strings.Contains(stdout.String(), "warning") {
		t.Errorf("warnings must stay on stderr, got stdout=%q", stdout.String())
	}
}

// TestAuditExport_CompleteExportIsQuiet: the fix must not cry wolf. An org
// whose export the server certifies as whole gets no truncation noise —
// including the org that happens to sit exactly on a row cap, which is why
// the CLI keys off the server's flag rather than a len(events)==cap guess.
func TestAuditExport_CompleteExportIsQuiet(t *testing.T) {
	resp := completeResponse()
	// Sit exactly on the source's row limit: the old heuristic would have
	// called this truncated and refused a perfectly complete export.
	resp.Sources[0].Returned = 10000
	resp.Sources[0].Total = 10000
	exportServerWithResponse(t, resp)
	out := filepath.Join(t.TempDir(), "audit.csv")

	var stdout, stderr bytes.Buffer
	cmd := newAuditExportRunCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"--format=csv", "--out=" + out})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("a complete export must succeed: %v", err)
	}
	for _, banned := range []string{"warning", "truncat", "refus"} {
		if strings.Contains(strings.ToLower(stderr.String()), banned) {
			t.Errorf("a complete export must not warn about %q: %q", banned, stderr.String())
		}
	}
}

// TestAuditExport_UnreportedCompletenessWarnsButProceeds: an older server
// sends no truncated field. "We can't tell" is not "it's clipped" — refusing
// would break every export against such a server — but silence would imply a
// guarantee nobody made.
func TestAuditExport_UnreportedCompletenessWarnsButProceeds(t *testing.T) {
	exportServerWithResponse(t, auditLogResponse{Events: sampleEvents()})
	out := filepath.Join(t.TempDir(), "audit.csv")

	var stdout, stderr bytes.Buffer
	cmd := newAuditExportRunCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"--format=csv", "--out=" + out})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("an unreporting server must not break the export: %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Fatalf("expected the export to be written: %v", statErr)
	}
	got := stderr.String()
	if !strings.Contains(got, "CANNOT be verified") {
		t.Errorf("stderr should flag the export as unverifiable: %q", got)
	}
}

// TestAuditExport_UncountableSourceWarns: a source that contributed rows but
// could not be counted is neither verified nor clipped, and must be reported
// as such rather than passing silently.
func TestAuditExport_UncountableSourceWarns(t *testing.T) {
	resp := completeResponse()
	resp.Sources = []auditExportSource{
		{Source: "violations", Returned: 7, TotalKnown: false},
	}
	exportServerWithResponse(t, resp)
	out := filepath.Join(t.TempDir(), "audit.csv")

	var stdout, stderr bytes.Buffer
	cmd := newAuditExportRunCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"--format=csv", "--out=" + out})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stderr.String(), "could not count") {
		t.Errorf("an uncountable source must be surfaced: %q", stderr.String())
	}
}

// TestAuditExport_UncountableSourceNoteIsPrinted: the warning alone says only
// that a count failed. The server's note is where it explains why — e.g. that
// an evicted in-memory row may have been recovered from the durable audit
// table or may never have been persisted. Swallowing it leaves the operator
// with a warning they cannot act on.
func TestAuditExport_UncountableSourceNoteIsPrinted(t *testing.T) {
	resp := completeResponse()
	resp.Sources = []auditExportSource{
		{
			Source:     "buffer",
			Returned:   4,
			TotalKnown: false,
			Note:       "rows have been evicted; the recovered/lost split is not knowable",
		},
	}
	exportServerWithResponse(t, resp)
	out := filepath.Join(t.TempDir(), "audit.csv")

	var stdout, stderr bytes.Buffer
	cmd := newAuditExportRunCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"--format=csv", "--out=" + out})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stderr.String(), "not knowable") {
		t.Errorf("the server's explanation must reach the operator: %q", stderr.String())
	}
}

// TestAuditExport_SendsWindowAndPrintsTheServersOwn: the caller's window has
// to reach the server (it used to be filtered client-side out of an
// already-clipped slab), and the printed note must be the server's window,
// not a constant compiled into the CLI.
func TestAuditExport_SendsWindowAndPrintsTheServersOwn(t *testing.T) {
	seen := exportServerWithResponse(t, completeResponse())
	out := filepath.Join(t.TempDir(), "audit.csv")

	var stdout, stderr bytes.Buffer
	cmd := newAuditExportRunCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"--format=csv", "--out=" + out, "--start=2026-01-01", "--end=2026-04-30"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := seen.Get("export"); got != "true" {
		t.Errorf("export flag = %q", got)
	}
	// A bare date is parsed in the operator's local zone (existing --start
	// semantics) and sent as the equivalent UTC instant.
	wantStart := time.Date(2026, 1, 1, 0, 0, 0, 0, time.Local).UTC().Format(time.RFC3339)
	wantEnd := time.Date(2026, 4, 30, 0, 0, 0, 0, time.Local).
		Add(24*time.Hour - time.Second).UTC().Format(time.RFC3339)
	if got := seen.Get("start"); got != wantStart {
		t.Errorf("server should receive the caller's start %q, got %q", wantStart, got)
	}
	if got := seen.Get("end"); got != wantEnd {
		t.Errorf("server should receive the caller's end %q, got %q", wantEnd, got)
	}
	// completeResponse() carries no window, so there is nothing truthful to
	// print — and the CLI must not invent one.
	if strings.Contains(stderr.String(), "note:") {
		t.Errorf("no server window was reported; the CLI must not print one: %q", stderr.String())
	}
}

// TestAuditExport_PrintsTheServerReportedWindow is the positive control for
// the above.
func TestAuditExport_PrintsTheServerReportedWindow(t *testing.T) {
	resp := completeResponse()
	start := time.Date(2026, 5, 14, 0, 0, 0, 0, time.UTC)
	resp.Window = &auditExportWindowInfo{Start: &start, DefaultApplied: true, DefaultDays: 90}
	exportServerWithResponse(t, resp)
	out := filepath.Join(t.TempDir(), "audit.csv")

	var stdout, stderr bytes.Buffer
	cmd := newAuditExportRunCmd(&stdout, &stderr)
	cmd.SetArgs([]string{"--format=csv", "--out=" + out})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got := stderr.String()
	if !strings.Contains(got, "2026-05-14T00:00:00Z") {
		t.Errorf("stderr should carry the server's window start: %q", got)
	}
	if !strings.Contains(got, "--start") {
		t.Errorf("a default lookback should tell the operator how to widen it: %q", got)
	}
}
