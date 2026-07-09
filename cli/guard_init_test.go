package cli

import (
	"bytes"
	"os"
	"path/filepath"
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

func TestInstallGuardInit_AppendsAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rc := filepath.Join(home, ".zshrc")

	run := func() string {
		var buf bytes.Buffer
		c := &cobra.Command{}
		c.SetOut(&buf)
		if err := installGuardInit(c, "zsh"); err != nil {
			t.Fatalf("installGuardInit: %v", err)
		}
		return buf.String()
	}

	out := run()
	if !strings.Contains(out, "added the install guard to") || !strings.Contains(out, rc) {
		t.Fatalf("first install should confirm the rc path, got: %q", out)
	}
	data, err := os.ReadFile(rc)
	if err != nil {
		t.Fatalf("read rc: %v", err)
	}
	want := `eval "$(chainsaw guard init zsh)"`
	if !strings.Contains(string(data), want) {
		t.Fatalf("rc missing activation line %q:\n%s", want, data)
	}

	// Second run must be a no-op: detect the existing line, change nothing.
	out2 := run()
	if !strings.Contains(out2, "already active") {
		t.Fatalf("second install should report already active, got: %q", out2)
	}
	data2, err := os.ReadFile(rc)
	if err != nil {
		t.Fatalf("re-read rc: %v", err)
	}
	if got := strings.Count(string(data2), want); got != 1 {
		t.Fatalf("activation line should appear exactly once, got %d:\n%s", got, data2)
	}
}

func TestInstallGuardInit_DryRunWritesNothing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rc := filepath.Join(home, ".zshrc")

	c := &cobra.Command{}
	c.Flags().Bool("install", true, "")
	c.Flags().Bool("dry-run", true, "")
	var buf bytes.Buffer
	c.SetOut(&buf)
	if err := installGuardInit(c, "zsh"); err != nil {
		t.Fatalf("installGuardInit dry-run: %v", err)
	}

	if _, err := os.Stat(rc); !os.IsNotExist(err) {
		t.Fatalf("--dry-run must not create the rc file; stat err = %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "would append") || !strings.Contains(out, "eval \"$(chainsaw guard init zsh)\"") {
		t.Fatalf("dry-run should preview the target + line, got: %q", out)
	}
}

func TestInstallGuardInit_FishUsesConfigPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	var buf bytes.Buffer
	c := &cobra.Command{}
	c.SetOut(&buf)
	if err := installGuardInit(c, "fish"); err != nil {
		t.Fatalf("installGuardInit fish: %v", err)
	}
	rc := filepath.Join(home, ".config", "fish", "config.fish")
	data, err := os.ReadFile(rc)
	if err != nil {
		t.Fatalf("read fish config (should be created): %v", err)
	}
	if !strings.Contains(string(data), "chainsaw guard init fish | source") {
		t.Fatalf("fish config missing source line:\n%s", data)
	}
}

func TestRunGuardInit_InstallFlagRoutesToInstall(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	c := &cobra.Command{}
	c.Flags().Bool("install", false, "")
	if err := c.Flags().Set("install", "true"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	var buf bytes.Buffer
	c.SetOut(&buf)
	if err := runGuardInit(c, []string{"bash"}); err != nil {
		t.Fatalf("runGuardInit --install: %v", err)
	}
	// Must have written the rc, not printed the shell functions.
	if strings.Contains(buf.String(), "command chainsaw npm") {
		t.Fatalf("--install must not print functions, got: %q", buf.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".bashrc")); err != nil {
		t.Fatalf("expected .bashrc written: %v", err)
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
