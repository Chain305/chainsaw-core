package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestGuardInitSnippet(t *testing.T) {
	cases := []struct {
		shell string
		want  string
	}{
		{"zsh", `npm() { command chainsaw npm "$@"; }`},
		{"bash", `pip() { command chainsaw pip "$@"; }`},
		{"fish", `function npm; command chainsaw npm $argv; end`},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		c := &cobra.Command{}
		c.SetOut(&buf)
		if err := runGuardInit(c, []string{tc.shell}); err != nil {
			t.Fatalf("%s: %v", tc.shell, err)
		}
		got := buf.String()
		if !strings.Contains(got, tc.want) {
			t.Errorf("%s snippet missing %q:\n%s", tc.shell, tc.want, got)
		}
		// Recursion-safety: must route via `command chainsaw` so the function
		// can't re-enter itself, and chainsaw resolves the real tool via PATH.
		if !strings.Contains(got, "command chainsaw") {
			t.Errorf("%s snippet must use `command chainsaw`", tc.shell)
		}
	}

	// Unsupported shell is a clear error, not silent output.
	c := &cobra.Command{}
	c.SetOut(&bytes.Buffer{})
	if err := runGuardInit(c, []string{"powershell"}); err == nil {
		t.Error("unsupported shell should error")
	}
}

func TestDetectShell(t *testing.T) {
	cases := map[string]string{
		"/usr/bin/fish": "fish",
		"/bin/zsh":      "zsh",
		"/bin/bash":     "bash",
		"/weird/xonsh":  "bash", // unknown → bash-compatible default
		"":              "bash",
	}
	for shellEnv, want := range cases {
		t.Setenv("SHELL", shellEnv)
		if got := detectShell(); got != want {
			t.Errorf("detectShell(SHELL=%q) = %q, want %q", shellEnv, got, want)
		}
	}
}
