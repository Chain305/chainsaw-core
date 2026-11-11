package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func runGuardUninstallForTest(t *testing.T, dry bool) string {
	t.Helper()
	c := &cobra.Command{}
	c.Flags().Bool("dry-run", false, "")
	if dry {
		_ = c.Flags().Set("dry-run", "true")
	}
	var out bytes.Buffer
	c.SetOut(&out)
	if err := runGuardUninstall(c, nil); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestGuardUninstall(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	dir := t.TempDir()
	zshrc := filepath.Join(dir, ".zshrc")
	bashrc := filepath.Join(dir, ".bashrc")
	untouched := filepath.Join(dir, ".profile")
	prev := shellRCCandidates
	shellRCCandidates = func() []string { return []string{zshrc, bashrc, untouched, filepath.Join(dir, "missing")} }
	defer func() { shellRCCandidates = prev }()

	// What --install writes, between the user's own lines, plus a
	// commented-out line that must survive.
	zsh := "export A=1\n\n" + guardInstallComment + "\n" +
		`eval "$(CHAINSAW_GUARD_SKIP=npm chainsaw guard init zsh)"` + "\n" +
		`# eval "$(chainsaw guard init zsh)"` + "\nalias l=ls\n"
	bash := "[ -x /usr/local/bin/chainsaw ] && eval \"$(chainsaw guard init bash)\"\nexport B=2\n"
	other := "export C=3\n"
	for p, s := range map[string]string{zshrc: zsh, bashrc: bash, untouched: other} {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	out := runGuardUninstallForTest(t, true)
	if !strings.Contains(out, "would remove") {
		t.Fatalf("dry run output: %q", out)
	}
	if b, _ := os.ReadFile(zshrc); string(b) != zsh {
		t.Fatal("dry run modified a file")
	}

	out = runGuardUninstallForTest(t, false)
	if b, _ := os.ReadFile(zshrc); string(b) != "export A=1\n"+`# eval "$(chainsaw guard init zsh)"`+"\nalias l=ls\n" {
		t.Fatalf("zshrc after uninstall:\n%q", b)
	}
	if b, _ := os.ReadFile(bashrc); string(b) != "export B=2\n" {
		t.Fatalf("a hand-written guard line must go too:\n%q", b)
	}
	if b, _ := os.ReadFile(zshrc + ".chainsaw-uninstall.bak"); string(b) != zsh {
		t.Fatal("backup must hold the original")
	}
	if _, err := os.Stat(untouched + ".chainsaw-uninstall.bak"); err == nil {
		t.Fatal("a file without a guard line must not be backed up")
	}
	if !strings.Contains(out, "unset -f npm pip pip3") || !strings.Contains(out, "uninstall-hook --all") {
		t.Fatalf("want session cleanup and the uninstall-hook pointer: %q", out)
	}

	if out := runGuardUninstallForTest(t, false); !strings.Contains(out, "nothing to do") {
		t.Fatalf("second run must be a no-op: %q", out)
	}
}

// TestGuardUninstallThenDoctorSeesNoShim: after uninstall the shim detector
// (doctor, uninstall-hook) must find nothing.
func TestGuardUninstallThenDoctorSeesNoShim(t *testing.T) {
	rc := filepath.Join(t.TempDir(), ".zshrc")
	_ = os.WriteFile(rc, []byte(guardInstallComment+"\n"+`eval "$(chainsaw guard init zsh)"`+"\n"), 0o644)
	prev := shellRCCandidates
	shellRCCandidates = func() []string { return []string{rc} }
	defer func() { shellRCCandidates = prev }()
	runGuardUninstallForTest(t, false)
	if found, _, _ := detectGuardShim([]string{rc}); found {
		t.Fatal("guard still detected after uninstall")
	}
}
