package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectGuardShim(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	active := write(".zshrc", "export PATH=$PATH:/x\neval \"$(chainsaw guard init zsh)\"\n")
	commented := write(".bashrc", "# eval \"$(chainsaw guard init bash)\"\n")
	clean := write(".profile", "export EDITOR=vim\n")
	missing := filepath.Join(dir, ".does-not-exist")

	t.Run("active invocation detected", func(t *testing.T) {
		ok, src := detectGuardShim([]string{clean, active})
		if !ok || src != active {
			t.Fatalf("want detected at %s, got ok=%v src=%s", active, ok, src)
		}
	})
	t.Run("commented-out is not active", func(t *testing.T) {
		if ok, _ := detectGuardShim([]string{commented}); ok {
			t.Fatal("commented-out invocation must not count as active")
		}
	})
	t.Run("clean and missing files", func(t *testing.T) {
		if ok, _ := detectGuardShim([]string{clean, missing}); ok {
			t.Fatal("no marker present, should not detect")
		}
	})
}

// TestShellRCCandidatesFor covers the platform split. The Windows list used to
// be POSIX-only, so `chainsaw doctor` could never see an installed shim on
// Windows and reported every manager unprotected.
func TestShellRCCandidatesFor(t *testing.T) {
	home := filepath.Join("home", "u")

	t.Run("posix keeps the dotfiles and adds cross-platform pwsh", func(t *testing.T) {
		got := shellRCCandidatesFor("linux", home)
		for _, want := range []string{
			filepath.Join(home, ".zshrc"),
			filepath.Join(home, ".bashrc"),
			filepath.Join(home, ".profile"),
			filepath.Join(home, ".config", "fish", "config.fish"),
			filepath.Join(home, ".config", "powershell", "profile.ps1"),
		} {
			if !containsPath(got, want) {
				t.Errorf("linux candidates missing %q:\n%v", want, got)
			}
		}
	})

	t.Run("windows adds every PowerShell profile", func(t *testing.T) {
		got := shellRCCandidatesFor("windows", home)
		for _, want := range []string{
			// PowerShell 7+ and Windows PowerShell 5.1, all-hosts and console-host.
			filepath.Join(home, "Documents", "PowerShell", "profile.ps1"),
			filepath.Join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
			filepath.Join(home, "Documents", "WindowsPowerShell", "profile.ps1"),
			filepath.Join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
			// OneDrive Known Folder Move relocates Documents on most modern installs.
			filepath.Join(home, "OneDrive", "Documents", "PowerShell", "profile.ps1"),
			filepath.Join(home, "OneDrive", "Documents", "WindowsPowerShell", "profile.ps1"),
			// Git Bash / WSL users on Windows still have POSIX dotfiles.
			filepath.Join(home, ".bashrc"),
		} {
			if !containsPath(got, want) {
				t.Errorf("windows candidates missing %q:\n%v", want, got)
			}
		}
	})

	t.Run("detects a shim in a PowerShell profile", func(t *testing.T) {
		dir := t.TempDir()
		profile := filepath.Join(dir, "profile.ps1")
		if err := os.WriteFile(profile, []byte("# chainsaw install guard\nchainsaw guard init pwsh | Invoke-Expression\n"), 0o644); err != nil {
			t.Fatalf("write profile: %v", err)
		}
		ok, src := detectGuardShim([]string{profile})
		if !ok || src != profile {
			t.Fatalf("want detected at %s, got ok=%v src=%s", profile, ok, src)
		}
	})
}

func containsPath(list []string, want string) bool {
	for _, p := range list {
		if p == want {
			return true
		}
	}
	return false
}

func TestGuardedManagerSet(t *testing.T) {
	set := guardedManagerSet()
	// cargo and gem are now shell-shimmed too (guardedTools), so the shim
	// coverage matches what the installer advertises (npm/pip/go/cargo/gem).
	for _, name := range []string{"npm", "pip", "go", "cargo", "gem"} {
		if !set[name] {
			t.Errorf("expected %q in guarded set", name)
		}
	}
	if set["maven"] {
		t.Error("maven is not shell-shimmed; must not be in guarded set")
	}
}

// TestDoctor_ShimStateShownForGuardedManagers drives doctor with a shell rc that
// sources the guard, and asserts guarded managers report "shim" (not "no") while
// non-guarded ones still report "no", plus the explanatory footnote.
func TestDoctor_ShimStateShownForGuardedManagers(t *testing.T) {
	withHookEnv(t) // isolates config files ⇒ nothing is config-wired

	dir := t.TempDir()
	rc := filepath.Join(dir, ".zshrc")
	if err := os.WriteFile(rc, []byte("eval \"$(chainsaw guard init zsh)\"\n"), 0o644); err != nil {
		t.Fatalf("write rc: %v", err)
	}
	prev := shellRCCandidates
	shellRCCandidates = func() []string { return []string{rc} }
	defer func() { shellRCCandidates = prev }()

	cmd := newDoctorCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	_ = cmd.Flags().Set("no-color", "true")
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}

	text := out.String()
	// npm is guarded and not config-wired here ⇒ its row must carry "shim".
	if !rowHasState(t, text, "npm", "shim") {
		t.Fatalf("expected npm row to show shim state:\n%s", text)
	}
	// cargo is now guarded too (guardedTools includes cargo/gem) ⇒ shim.
	if !rowHasState(t, text, "cargo", "shim") {
		t.Fatalf("expected cargo row to show shim state:\n%s", text)
	}
	// maven is not shell-shimmed ⇒ stays "no".
	if !rowHasState(t, text, "maven", "no") {
		t.Fatalf("expected maven row to show no state:\n%s", text)
	}
	if !strings.Contains(text, "shim = routed through the shell guard") {
		t.Fatalf("expected shim explanation footnote:\n%s", text)
	}
	if !strings.Contains(text, rc) {
		t.Fatalf("footnote should name the rc file %s:\n%s", rc, text)
	}
}

// rowHasState checks the table line beginning with manager has the given WIRED
// token. Tolerant of column spacing.
func rowHasState(t *testing.T, table, manager, state string) bool {
	t.Helper()
	for _, line := range strings.Split(table, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == manager {
			// fields: MANAGER INSTALLED WIRED CONFIG...
			return fields[2] == state
		}
	}
	return false
}
