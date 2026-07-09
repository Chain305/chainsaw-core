package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestDoctorOffline_FailOpenShowsNoCoverageMarker guards the fail-open honesty
// fix: under CHAINSAW_OFFLINE_FAIL_MODE=open, remote-only signals are inert
// (allow-by-default), so they must render as "○ no coverage" rather than the
// misleading "⚠ degraded" — an operator scanning the STATUS column must see
// that those signals provide no protection, not that they are partially working.
func TestDoctorOffline_FailOpenShowsNoCoverageMarker(t *testing.T) {
	t.Setenv("CHAINSAW_OFFLINE_FAIL_MODE", "open")

	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runDoctorOffline(cmd, nil); err != nil {
		t.Fatalf("runDoctorOffline: %v", err)
	}

	text := out.String()
	if !strings.Contains(text, "○") {
		t.Fatalf("fail-open remote-only signals must render ○ (no coverage); got:\n%s", text)
	}
	if !strings.Contains(text, "fail-open: allows installs") {
		t.Fatalf("expected the fail-open detail on a remote-only row; got:\n%s", text)
	}
	// A remote-only signal under fail-open must NOT be marked ⚠ (degraded) —
	// the whole point of the fix is to stop understating "no coverage".
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "remote-only") && strings.Contains(line, "⚠") {
			t.Fatalf("remote-only signal still marked ⚠ under fail-open: %q", line)
		}
	}
	// The legend must explain the ○ marker.
	if !strings.Contains(text, "○ no coverage") {
		t.Fatalf("legend missing the ○ explanation; got:\n%s", text)
	}
}
