package intelligence

import (
	"testing"
	"time"
)

// TestPreviousRelease: the cross-version diff baseline is the release
// published immediately before, not the last row collected. testify v1.12.1
// was diffed against 1.7.2 on the public page (2026-10-02).
func TestPreviousRelease(t *testing.T) {
	d := func(days int) time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, days) }
	tl := []VersionRelease{
		{Version: "1.7.2", PublishedAt: d(0)},
		{Version: "1.12.0", PublishedAt: d(1000)},
		{Version: "1.12.1", PublishedAt: d(1010)},
		{Version: "2.0.0-rc.1", PublishedAt: d(1020)},
	}
	at := d(1010)
	if got := previousRelease(tl, "1.12.1", &at); got != "1.12.0" {
		t.Fatalf("previous of 1.12.1 = %q, want 1.12.0", got)
	}
	if got := previousRelease(tl, "1.12.1", nil); got != "1.12.0" {
		t.Fatalf("undated release must take its own timeline entry, got %q", got)
	}
	if got := previousRelease(tl, "1.7.2", nil); got != "" {
		t.Fatalf("first release has no previous, got %q", got)
	}
	undated := []VersionRelease{{Version: "1.0"}, {Version: "1.1"}}
	if got := previousRelease(undated, "1.1", nil); got != "" {
		t.Fatalf("undated timeline must fall back (\"\"), got %q", got)
	}
}
