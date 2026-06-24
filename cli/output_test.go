package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Note: the TTY-based disable branch (stdout not a terminal) is not covered
// here because it requires a real PTY to exercise reliably. All tests below
// force stdoutIsTerminal to true so the user-opt-out signals are isolated.

func newTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "test"}
	c.Flags().Bool("no-color", false, "")
	return c
}

func withStdoutTTY(t *testing.T, isTTY bool) {
	t.Helper()
	prev := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return isTTY }
	t.Cleanup(func() { stdoutIsTerminal = prev })
}

func resetViperColor(t *testing.T) {
	t.Helper()
	prev := viper.GetBool("no_color")
	viper.Set("no_color", false)
	t.Cleanup(func() { viper.Set("no_color", prev) })
}

func TestNoColor_EnvVarDisables(t *testing.T) {
	withStdoutTTY(t, true)
	resetViperColor(t)
	t.Setenv("NO_COLOR", "1")

	cmd := newTestCmd()
	if !noColor(cmd) {
		t.Fatalf("noColor() = false with NO_COLOR=1, want true")
	}
	if IsColorEnabled(cmd) {
		t.Fatalf("IsColorEnabled() = true with NO_COLOR=1, want false")
	}
}

func TestNoColor_FlagDisables(t *testing.T) {
	withStdoutTTY(t, true)
	resetViperColor(t)
	t.Setenv("NO_COLOR", "")

	cmd := newTestCmd()
	if err := cmd.Flags().Set("no-color", "true"); err != nil {
		t.Fatalf("set --no-color: %v", err)
	}
	if !noColor(cmd) {
		t.Fatalf("noColor() = false with --no-color, want true")
	}
	if IsColorEnabled(cmd) {
		t.Fatalf("IsColorEnabled() = true with --no-color, want false")
	}
}

func TestNoColor_ViperDisables(t *testing.T) {
	withStdoutTTY(t, true)
	resetViperColor(t)
	t.Setenv("NO_COLOR", "")

	viper.Set("no_color", true)
	cmd := newTestCmd()
	if !noColor(cmd) {
		t.Fatalf("noColor() = false with viper no_color=true, want true")
	}
	if IsColorEnabled(cmd) {
		t.Fatalf("IsColorEnabled() = true with viper no_color=true, want false")
	}
}

func TestIsColorEnabled_AllowsWhenTTYAndNoOptOut(t *testing.T) {
	withStdoutTTY(t, true)
	resetViperColor(t)
	t.Setenv("NO_COLOR", "")

	cmd := newTestCmd()
	if !IsColorEnabled(cmd) {
		t.Fatalf("IsColorEnabled() = false on TTY with no opt-out, want true")
	}
}
