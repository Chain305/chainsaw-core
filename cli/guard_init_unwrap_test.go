package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestGuardInitSkipRemovesLiveWrapper runs the emitted snippet in real shells.
// A shell that already has the npm wrapper (rc sourced before the skip list
// changed) and evaluates the skip line must lose it; a user's own function
// of the same name (nvm's lazy `npm`, here `yarn`) must survive.
func TestGuardInitSkipRemovesLiveWrapper(t *testing.T) {
	t.Setenv(guardSkipEnv, "")
	for _, sh := range []string{"bash", "zsh", "dash", "pwsh"} {
		t.Run(sh, func(t *testing.T) {
			bin, err := exec.LookPath(sh)
			if err != nil {
				t.Skipf("%s not installed", sh)
			}
			dialect := sh
			if sh == "dash" {
				dialect = "sh"
			}
			full, _, _ := runGuardInitForTest(t, dialect)
			skip, _, _ := runGuardInitForTest(t, dialect, "--skip", "npm,yarn")

			var script string
			var args []string
			if sh == "pwsh" {
				script = full + "\nfunction yarn { 'mine' }\n" + skip +
					"\nif (Get-Item Function:npm -ErrorAction SilentlyContinue) { 'NPM_STILL' }\nyarn\n"
				args = []string{"-NoProfile", "-NonInteractive", "-Command", script}
			} else {
				script = full + "\nyarn() { echo mine; }\n" + skip +
					"\nif typeset -f npm >/dev/null 2>&1; then echo NPM_STILL; fi\nyarn\n"
				args = []string{"-c", script}
			}
			var out, errb bytes.Buffer
			c := exec.Command(bin, args...)
			c.Stdout, c.Stderr = &out, &errb
			if err := c.Run(); err != nil || errb.Len() > 0 {
				t.Fatalf("%s: err=%v stderr=%q", sh, err, errb.String())
			}
			if strings.Contains(out.String(), "NPM_STILL") {
				t.Errorf("%s: skipped npm wrapper still defined", sh)
			}
			if !strings.Contains(out.String(), "mine") {
				t.Errorf("%s: user's own yarn function was removed: %q", sh, out.String())
			}
		})
	}
}

// TestInstallSkipRewritesOwnLine: changing the skip list of the line
// --install wrote edits it in place; a hand-edited line still refuses.
func TestInstallSkipRewritesOwnLine(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(guardSkipEnv, "")
	rc := filepath.Join(home, ".zshrc")
	install := func(skip ...string) (string, error) {
		c := &cobra.Command{}
		c.Flags().Bool("dry-run", false, "")
		var buf bytes.Buffer
		c.SetOut(&buf)
		err := installGuardInit(c, "zsh", skip, true)
		return buf.String(), err
	}

	_ = os.WriteFile(rc, []byte("export X=1\n\n# chainsaw install guard — https://chain305.com\n"+
		`eval "$(CHAINSAW_GUARD_SKIP=npm chainsaw guard init zsh)"`+"\nalias l=ls\n"), 0o644)
	out, err := install("npm", "yarn")
	if err != nil || !strings.Contains(out, "updated") {
		t.Fatalf("own line must be rewritten: out=%q err=%v", out, err)
	}
	got, _ := os.ReadFile(rc)
	want := "export X=1\n\n# chainsaw install guard — https://chain305.com\n" +
		`eval "$(CHAINSAW_GUARD_SKIP=npm,yarn chainsaw guard init zsh)"` + "\nalias l=ls\n"
	if string(got) != want {
		t.Fatalf("rc after rewrite:\n%s\nwant:\n%s", got, want)
	}

	hand := "eval \"$(chainsaw guard init zsh 2>/dev/null)\"\n"
	_ = os.WriteFile(rc, []byte(hand), 0o644)
	if _, err := install("npm"); err == nil || !strings.Contains(err.Error(), "replace this line") {
		t.Fatalf("hand-edited line must refuse, got %v", err)
	}
	if got, _ := os.ReadFile(rc); string(got) != hand {
		t.Fatal("refusal modified the rc")
	}
}

// TestNoteGivesRunnableCommand: the uninstall-hook note must hand the user a
// command (which edits the rc) rather than an rc line they then run in the
// shell, which changed nothing.
func TestNoteGivesRunnableCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv(guardSkipEnv, "")
	rc := filepath.Join(home, ".zshrc")
	_ = os.WriteFile(rc, []byte(`eval "$(CHAINSAW_GUARD_SKIP=npm chainsaw guard init zsh)"`+"\n"), 0o644)
	prev := shellRCCandidates
	shellRCCandidates = func() []string { return []string{rc} }
	defer func() { shellRCCandidates = prev }()

	var b bytes.Buffer
	noteShellGuardStillRoutes(&b, "yarn")
	got := b.String()
	if !strings.Contains(got, "chainsaw guard init zsh --install --skip npm,yarn") || !strings.Contains(got, "unset -f yarn") {
		t.Fatalf("want a runnable --install command keeping npm, got %q", got)
	}
	if strings.Contains(got, "eval ") {
		t.Fatalf("must not offer the raw rc line, got %q", got)
	}
}
