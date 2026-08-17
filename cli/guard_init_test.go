package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runInit drives `guard init <shell>` (no --install) and returns stdout/stderr.
func runInit(t *testing.T, shell string) (string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	c := &cobra.Command{}
	c.SetOut(&out)
	c.SetErr(&errb)
	var args []string
	if shell != "" {
		args = []string{shell}
	}
	if err := runGuardInit(c, args); err != nil {
		t.Fatalf("runGuardInit(%q): %v", shell, err)
	}
	return out.String(), errb.String()
}

// TestGuardInitSnippet locks the emitted syntax for every supported shell. The
// expectation is built from guardedTools so adding a wrapped manager doesn't
// break the test — only a change to a shell's *syntax* does, which is the point.
func TestGuardInitSnippet(t *testing.T) {
	cases := []struct {
		name    string
		shells  []string // aliases that must all emit the same thing
		header  string
		lineFmt string // fn, tool
	}{
		{
			name:    "posix",
			shells:  []string{"bash", "zsh", "sh", ""},
			header:  "# chainsaw install guard — https://chain305.com",
			lineFmt: `%s() { command chainsaw %s "$@"; }`,
		},
		{
			name:    "fish",
			shells:  []string{"fish"},
			header:  "# chainsaw install guard — https://chain305.com",
			lineFmt: `function %s; command chainsaw %s $argv; end`,
		},
		{
			name:    "powershell",
			shells:  []string{"powershell", "pwsh"},
			header:  "# chainsaw install guard — https://chain305.com",
			lineFmt: `function %s { chainsaw %s @args }`,
		},
		{
			name:    "cmd",
			shells:  []string{"cmd"},
			header:  ":: chainsaw install guard — https://chain305.com",
			lineFmt: `doskey %s=chainsaw %s $*`,
		},
	}

	for _, tc := range cases {
		for _, shell := range tc.shells {
			t.Run(tc.name+"/"+shell, func(t *testing.T) {
				var want strings.Builder
				want.WriteString(tc.header + "\n")
				for _, g := range guardedTools {
					fmt.Fprintf(&want, tc.lineFmt+"\n", g.fn, g.tool)
				}
				got, _ := runInit(t, shell)
				if got != want.String() {
					t.Errorf("%s snippet mismatch:\ngot:\n%s\nwant:\n%s", shell, got, want.String())
				}
				// Every shell must route through `chainsaw <tool>` so the guard
				// runs before the real manager does.
				for _, g := range guardedTools {
					if !strings.Contains(got, "chainsaw "+g.tool) {
						t.Errorf("%s snippet does not route %s through chainsaw:\n%s", shell, g.fn, got)
					}
				}
			})
		}
	}
}

// TestGuardInitSnippet_WindowsShellsAreNotPOSIX is the regression guard for the
// original defect: Windows users got byte-identical bash functions, which no
// Windows shell can load.
func TestGuardInitSnippet_WindowsShellsAreNotPOSIX(t *testing.T) {
	bash, _ := runInit(t, "bash")
	for _, shell := range []string{"powershell", "pwsh", "cmd"} {
		got, _ := runInit(t, shell)
		if got == bash {
			t.Errorf("%s emitted the bash snippet verbatim — Windows shells cannot load it", shell)
		}
		if strings.Contains(got, `"$@"`) {
			t.Errorf("%s snippet contains POSIX argument expansion:\n%s", shell, got)
		}
	}
}

// TestGuardInit_CmdTerminalHintDoesNotPromiseInstall: the generic hint tells the
// user to run --install, which cannot work for cmd. Pointing them at it would
// re-create the false-success bug in the help text.
func TestGuardInit_CmdTerminalHintDoesNotPromiseInstall(t *testing.T) {
	prev := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdoutIsTerminal = prev })

	_, stderrCmd := runInit(t, "cmd")
	if strings.Contains(stderrCmd, "guard init --install\n") {
		t.Errorf("cmd hint must not offer the bare --install: %q", stderrCmd)
	}
	if !strings.Contains(stderrCmd, "console session only") || !strings.Contains(stderrCmd, "powershell") {
		t.Errorf("cmd hint should explain session-locality and point at PowerShell, got: %q", stderrCmd)
	}

	_, stderrPS := runInit(t, "powershell")
	if !strings.Contains(stderrPS, "chainsaw guard init --install") {
		t.Errorf("powershell hint should offer --install, got: %q", stderrPS)
	}
}

func TestGuardInit_UnsupportedShell(t *testing.T) {
	for _, shell := range []string{"tcsh", "nushell", "elvish"} {
		c := &cobra.Command{}
		c.SetOut(&bytes.Buffer{})
		err := runGuardInit(c, []string{shell})
		if err == nil {
			t.Fatalf("unsupported shell %q should error", shell)
		}
		// The error must list the shells we now support, or a Windows user is
		// told to use bash/zsh/fish and gives up.
		for _, want := range []string{"powershell", "pwsh", "cmd", "bash", "zsh", "fish"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q should list supported shell %q", err, want)
			}
		}
	}
}

func TestDetectShellFor(t *testing.T) {
	cases := []struct {
		goos, shellEnv, want string
	}{
		// POSIX behaviour must be unchanged.
		{"linux", "/usr/bin/fish", "fish"},
		{"darwin", "/bin/zsh", "zsh"},
		{"linux", "/bin/bash", "bash"},
		{"linux", "/bin/sh", "sh"},
		{"linux", "/weird/xonsh", "bash"}, // unknown → bash-compatible default
		{"darwin", "", "bash"},
		{"linux", "", "bash"},
		// Windows with $SHELL unset is THE bug: it used to fall through to
		// bash and emit POSIX functions no Windows shell can load.
		{"windows", "", "powershell"},
		{"windows", "/weird/xonsh", "powershell"},
		// Windows-style paths resolve even though the test runs on POSIX.
		{"windows", `C:\Program Files\PowerShell\7\pwsh.exe`, "pwsh"},
		{"windows", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "powershell"},
		{"windows", `C:\Program Files\Git\bin\bash.exe`, "bash"},
		// pwsh is cross-platform, so honour it off Windows too.
		{"linux", "/usr/bin/pwsh", "pwsh"},
	}
	for _, tc := range cases {
		if got := detectShellFor(tc.goos, tc.shellEnv); got != tc.want {
			t.Errorf("detectShellFor(%q, %q) = %q, want %q", tc.goos, tc.shellEnv, got, tc.want)
		}
	}
}

// TestDetectShell exercises the runtime.GOOS-bound wrapper on whatever platform
// CI runs, so the seam between it and detectShellFor stays wired.
func TestDetectShell(t *testing.T) {
	for _, shellEnv := range []string{"/usr/bin/fish", "/bin/zsh", "/bin/bash", ""} {
		t.Setenv("SHELL", shellEnv)
		want := detectShellFor(runtime.GOOS, shellEnv)
		if got := detectShell(); got != want {
			t.Errorf("detectShell(SHELL=%q) = %q, want %q", shellEnv, got, want)
		}
	}
}

func TestShellRCPathFor(t *testing.T) {
	home := filepath.Join("home", "u")
	cases := []struct {
		goos, shell string
		want        string
		wantErr     bool
	}{
		{goos: "linux", shell: "zsh", want: filepath.Join(home, ".zshrc")},
		{goos: "linux", shell: "bash", want: filepath.Join(home, ".bashrc")},
		{goos: "linux", shell: "sh", want: filepath.Join(home, ".profile")},
		{goos: "linux", shell: "", want: filepath.Join(home, ".profile")},
		{goos: "linux", shell: "fish", want: filepath.Join(home, ".config", "fish", "config.fish")},
		// The defect: --install on Windows resolved to ~/.bashrc, wrote it, and
		// printed success. It must land on a PowerShell profile instead.
		{goos: "windows", shell: "powershell", want: filepath.Join(home, "Documents", "WindowsPowerShell", "profile.ps1")},
		{goos: "windows", shell: "pwsh", want: filepath.Join(home, "Documents", "PowerShell", "profile.ps1")},
		{goos: "linux", shell: "pwsh", want: filepath.Join(home, ".config", "powershell", "profile.ps1")},
		// Windows PowerShell 5.1 doesn't exist off Windows.
		{goos: "linux", shell: "powershell", wantErr: true},
		// cmd.exe has no startup file at all.
		{goos: "windows", shell: "cmd", wantErr: true},
		{goos: "linux", shell: "tcsh", wantErr: true},
	}
	for _, tc := range cases {
		got, err := shellRCPathFor(tc.goos, tc.shell, home)
		if tc.wantErr {
			if err == nil {
				t.Errorf("shellRCPathFor(%q, %q) = %q, want error", tc.goos, tc.shell, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("shellRCPathFor(%q, %q): %v", tc.goos, tc.shell, err)
			continue
		}
		if got != tc.want {
			t.Errorf("shellRCPathFor(%q, %q) = %q, want %q", tc.goos, tc.shell, got, tc.want)
		}
	}

	// Under no circumstance may a Windows target resolve to a POSIX dotfile —
	// that is the exact false-success path being fixed.
	for _, shell := range []string{"powershell", "pwsh"} {
		got, err := shellRCPathFor("windows", shell, home)
		if err != nil {
			t.Fatalf("shellRCPathFor(windows, %s): %v", shell, err)
		}
		if strings.Contains(got, ".bashrc") || strings.Contains(got, ".profile") && !strings.HasSuffix(got, ".ps1") {
			t.Errorf("windows %s resolved to a POSIX rc file: %q", shell, got)
		}
	}
}

func TestShellSourceLine(t *testing.T) {
	cases := map[string]string{
		"bash":       `eval "$(chainsaw guard init bash)"`,
		"zsh":        `eval "$(chainsaw guard init zsh)"`,
		"fish":       "chainsaw guard init fish | source",
		"powershell": "chainsaw guard init powershell | Invoke-Expression",
		"pwsh":       "chainsaw guard init pwsh | Invoke-Expression",
	}
	for shell, want := range cases {
		if got := shellSourceLine(shell); got != want {
			t.Errorf("shellSourceLine(%q) = %q, want %q", shell, got, want)
		}
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

// TestInstallGuardInit_CmdRefusesLoudly is the core anti-false-success test: a
// cmd wiring cannot be persisted, so --install must fail with instructions
// rather than write a file and claim victory.
func TestInstallGuardInit_CmdRefusesLoudly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	var buf bytes.Buffer
	c := &cobra.Command{}
	c.SetOut(&buf)
	err := installGuardInit(c, "cmd")
	if err == nil {
		t.Fatal("--install cmd must return an error, not report success")
	}
	if !errors.Is(err, errCmdNotPersistable) {
		t.Errorf("unexpected error: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"no startup file", "console session", "guard init --install powershell"} {
		if !strings.Contains(msg, want) {
			t.Errorf("cmd refusal should mention %q, got:\n%s", want, msg)
		}
	}
	if strings.Contains(buf.String(), "added the install guard") {
		t.Errorf("--install cmd must not print success: %q", buf.String())
	}
	// Nothing may be written anywhere under HOME.
	entries, _ := os.ReadDir(home)
	if len(entries) != 0 {
		t.Errorf("--install cmd wrote %d entries into HOME, expected none", len(entries))
	}
}

// TestInstallGuardInit_PowerShellUsesQueriedProfile proves --install honours the
// path PowerShell itself reports, so OneDrive's redirected Documents folder
// can't turn the install into another silent no-op.
func TestInstallGuardInit_PowerShellUsesQueriedProfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	profile := filepath.Join(home, "OneDrive", "Documents", "PowerShell", "profile.ps1")

	prev := powerShellProfilePath
	powerShellProfilePath = func(shell string) (string, error) {
		if shell != "pwsh" {
			t.Errorf("resolver called with %q, want pwsh", shell)
		}
		return profile, nil
	}
	t.Cleanup(func() { powerShellProfilePath = prev })

	var buf bytes.Buffer
	c := &cobra.Command{}
	c.SetOut(&buf)
	if err := installGuardInit(c, "pwsh"); err != nil {
		t.Fatalf("installGuardInit pwsh: %v", err)
	}
	data, err := os.ReadFile(profile)
	if err != nil {
		t.Fatalf("read $PROFILE (should be created): %v", err)
	}
	if !strings.Contains(string(data), "chainsaw guard init pwsh | Invoke-Expression") {
		t.Fatalf("$PROFILE missing activation line:\n%s", data)
	}
	if !strings.Contains(buf.String(), profile) {
		t.Errorf("output should name the profile it wrote, got: %q", buf.String())
	}
	// A .bashrc must NOT have been created — the original bug.
	if _, err := os.Stat(filepath.Join(home, ".bashrc")); !os.IsNotExist(err) {
		t.Errorf("--install pwsh must not touch ~/.bashrc; stat err = %v", err)
	}
}

// TestInstallGuardInit_PowerShellFallsBackWhenQueryFails: on a box with no
// PowerShell on PATH we still resolve a conventional profile path for this GOOS
// rather than erroring or silently using a POSIX dotfile.
func TestInstallGuardInit_PowerShellFallsBackWhenQueryFails(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	prev := powerShellProfilePath
	powerShellProfilePath = func(string) (string, error) { return "", errors.New("pwsh not found") }
	t.Cleanup(func() { powerShellProfilePath = prev })

	got, err := shellRCPath("pwsh")
	if err != nil {
		t.Fatalf("shellRCPath pwsh fallback: %v", err)
	}
	want, err := shellRCPathFor(runtime.GOOS, "pwsh", home)
	if err != nil {
		t.Fatalf("shellRCPathFor: %v", err)
	}
	if got != want {
		t.Fatalf("fallback = %q, want %q", got, want)
	}
	if !strings.HasSuffix(got, ".ps1") {
		t.Fatalf("PowerShell fallback must be a .ps1 profile, got %q", got)
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

// TestRunGuardInit_InstallCmdPropagatesError: the refusal has to survive the
// cobra layer so the process exits non-zero.
func TestRunGuardInit_InstallCmdPropagatesError(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	c := &cobra.Command{}
	c.Flags().Bool("install", false, "")
	if err := c.Flags().Set("install", "true"); err != nil {
		t.Fatalf("set flag: %v", err)
	}
	c.SetOut(&bytes.Buffer{})
	if err := runGuardInit(c, []string{"cmd"}); err == nil {
		t.Fatal("runGuardInit --install cmd should error")
	}
}
