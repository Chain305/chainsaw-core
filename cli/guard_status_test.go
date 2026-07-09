package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestGuardStatusEmptyState runs `guard status` against a fresh config dir
// (no guard_state.json) and asserts it succeeds and prints the expected
// sections plus a conversion CTA.
func TestGuardStatusEmptyState(t *testing.T) {
	// CHAINSAW_CONFIG_HOME is honored on every OS; XDG_CONFIG_HOME is Linux-only
	// (platform.ConfigHome), so use the former to keep this hermetic on macOS too.
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())

	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	if err := runGuardStatus(cmd, nil); err != nil {
		t.Fatalf("runGuardStatus returned error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Install guard",
		"Installs checked",
		"First run",
		"never", // FirstRunUnix == 0 on empty state
		"Privacy",
		"Telemetry",
		"Device id",
		"chain305.com", // a CTA link is always present
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

func TestOnOff(t *testing.T) {
	if onOff(true) != "on" {
		t.Errorf("onOff(true) = %q, want on", onOff(true))
	}
	if onOff(false) != "off" {
		t.Errorf("onOff(false) = %q, want off", onOff(false))
	}
}
