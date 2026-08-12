package cli

// C6 — --end must only be stretched to end-of-day for a DATE, never for an
// explicit RFC3339 stamp.
// C9 — the CLI must stop claiming an export covers "the full range".
// C15 — a mid-write failure must not destroy the previous good export.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseDate_ReportsDateOnly(t *testing.T) {
	cases := []struct {
		in       string
		dateOnly bool
	}{
		{"2026-04-30", true},
		{"2026-04-30T00:00:00Z", false},
		{"2026-04-30T12:34:56+02:00", false},
	}
	for _, tc := range cases {
		_, dateOnly, err := parseDate(tc.in)
		if err != nil {
			t.Fatalf("parseDate(%q): %v", tc.in, err)
		}
		if dateOnly != tc.dateOnly {
			t.Errorf("parseDate(%q) dateOnly=%v, want %v", tc.in, dateOnly, tc.dateOnly)
		}
	}
	if _, _, err := parseDate("nonsense"); err == nil {
		t.Errorf("parseDate should reject an unrecognised format")
	}
}

// TestResolveExportWindow_RFC3339EndIsNotWidened: `--end 2026-04-30T00:00:00Z`
// used to include everything through 2026-04-30T23:59:59Z — an undisclosed
// extra day of records in a compliance handoff.
func TestResolveExportWindow_RFC3339EndIsNotWidened(t *testing.T) {
	cmd := newAuditExportTestCmd()
	if err := cmd.ParseFlags([]string{"--end=2026-04-30T00:00:00Z"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	_, end, err := resolveExportWindow(cmd)
	if err != nil {
		t.Fatalf("resolveExportWindow: %v", err)
	}
	want := time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC)
	if !end.Equal(want) {
		t.Errorf("end = %s, want %s (an explicit timestamp must be honoured verbatim)",
			end.Format(time.RFC3339), want.Format(time.RFC3339))
	}
}

// TestResolveExportWindow_DateOnlyEndStillCoversTheDay is the negative control:
// the end-of-day extension must survive for a bare date.
func TestResolveExportWindow_DateOnlyEndStillCoversTheDay(t *testing.T) {
	cmd := newAuditExportTestCmd()
	if err := cmd.ParseFlags([]string{"--end=2026-04-30"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	_, end, err := resolveExportWindow(cmd)
	if err != nil {
		t.Fatalf("resolveExportWindow: %v", err)
	}
	// Local midnight + 24h - 1s.
	want := time.Date(2026, 4, 30, 0, 0, 0, 0, time.Local).Add(24*time.Hour - time.Second)
	if !end.Equal(want) {
		t.Errorf("end = %s, want %s", end, want)
	}
}

// TestAuditCopy_DoesNotClaimFullRange pins C9's CLI half: `audit view` used to
// send operators to `audit export` "for the full range", a promise the server's
// row/window ceilings cannot keep.
//
// The follow-up wave replaced that claim with hardcoded ceiling numbers, which
// were themselves wrong (the events log clamps to its own capacity, well under
// the 10000 the CLI quoted). The numbers now come from the server per-response,
// so the hint must not carry a hardcoded ceiling at all — it must describe the
// behaviour the operator can rely on instead.
func TestAuditCopy_DoesNotClaimFullRange(t *testing.T) {
	if strings.Contains(auditViewExportHint, "full range") {
		t.Errorf("audit view still promises the full range: %q", auditViewExportHint)
	}
	for _, banned := range []string{"10000", "90 days"} {
		if strings.Contains(auditViewExportHint, banned) {
			t.Errorf("the view hint hardcodes a server ceiling (%s) the CLI cannot know: %q",
				banned, auditViewExportHint)
		}
	}
	// It must still tell the operator the export is bounded and self-checking.
	if !strings.Contains(auditViewExportHint, "clipped") {
		t.Errorf("the view hint should say the export refuses a clipped result: %q", auditViewExportHint)
	}
}

// TestAuditExportWindowNote_OnlyReportsWhatTheServerSaid: with no window in
// the response there is nothing truthful to print, and inventing one is the
// exact failure C9 is about.
func TestAuditExportWindowNote_OnlyReportsWhatTheServerSaid(t *testing.T) {
	if got := auditExportWindowNote(nil); got != "" {
		t.Errorf("no server window should print nothing, got %q", got)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := auditExportWindowNote(&auditExportWindowInfo{Start: &start})
	if !strings.Contains(got, "2026-01-01T00:00:00Z") {
		t.Errorf("note should carry the server's start: %q", got)
	}
	if strings.Contains(got, "default") {
		t.Errorf("no default was applied; note must not say one was: %q", got)
	}
	got = auditExportWindowNote(&auditExportWindowInfo{Start: &start, DefaultApplied: true, DefaultDays: 90})
	if !strings.Contains(got, "90 days") {
		t.Errorf("a substituted default window must be disclosed: %q", got)
	}
}

// TestAuditExportRequestPath_SendsTheCallersWindow: the window has to reach
// the server. While it did not, `--start 2026-01-01` run in August was
// filtered client-side out of a slab the server had already clipped to 90
// days, and the result was reported as the range the operator asked for.
func TestAuditExportRequestPath_SendsTheCallersWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC)
	got := auditExportRequestPath(start, end)
	for _, want := range []string{"export=true", "start=2026-01-01T00%3A00%3A00Z", "end=2026-04-30T23%3A59%3A59Z"} {
		if !strings.Contains(got, want) {
			t.Errorf("request path %q missing %q", got, want)
		}
	}
	// An unset window must not send empty parameters — the server treats a
	// missing start as "apply the default lookback" and an empty one as a
	// parse error.
	if got := auditExportRequestPath(time.Time{}, time.Time{}); got != "/api/audit/logs?export=true" {
		t.Errorf("unset window path = %q", got)
	}
}

// TestExportSink_AbortLeavesPreviousExportIntact pins C15: os.Create truncated
// the destination up front, so an error part-way through destroyed the last
// good export and replaced it with a partial file.
func TestExportSink_AbortLeavesPreviousExportIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.csv")
	const previous = "id,timestamp\nprev-1,2026-01-01T00:00:00Z\n"
	if err := os.WriteFile(path, []byte(previous), 0o644); err != nil {
		t.Fatalf("seed previous export: %v", err)
	}

	sink, err := openExportSink(path)
	if err != nil {
		t.Fatalf("openExportSink: %v", err)
	}
	if _, err := sink.w.Write([]byte("id,timestamp\npartial")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Simulate a mid-stream writer failure: abort instead of commit.
	sink.abort()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("previous export is gone: %v", err)
	}
	if string(got) != previous {
		t.Errorf("previous export was clobbered by a failed run:\ngot  %q\nwant %q", string(got), previous)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("partial temp file left behind at %s", path+".tmp")
	}
}
