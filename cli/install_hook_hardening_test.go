package cli

// CLI-level coverage for the hook hardening wave: H7 (a repo-local config
// holding a live client secret must not be committable), H9's opt-in
// `uninstall-hook --repair`, and H3's `uninstall-hook docker --mirror`
// escape hatch.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// newGitRepo makes cwd a throwaway git repository for the duration of the
// test. Only the .git marker matters — guardProjectSecret walks up looking
// for it, it never shells out.
func newGitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	return dir
}

// withHookServer points the config chain at a server URL so the renderers
// emit a real (credential-bearing) block rather than the commented-out
// placeholder they fall back to when no server is configured.
func withHookServer(t *testing.T) {
	t.Helper()
	prev := viper.GetString("server_url")
	viper.Set("server_url", "https://chain305.com")
	t.Cleanup(func() { viper.Set("server_url", prev) })
}

func TestInstallHook_ProjectScopeWithSecretIsGitignored(t *testing.T) {
	dir := newGitRepo(t)
	withHookServer(t)
	cmd := newInstallHookCmd()
	cmd.SetArgs([]string{"npm", "--scope", "project", "--credentials", "cli-abc:s3cr3t-value"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}

	npmrc := filepath.Join(dir, ".npmrc")
	data, err := os.ReadFile(npmrc)
	if err != nil {
		t.Fatalf("read project .npmrc: %v", err)
	}
	if !strings.Contains(string(data), "s3cr3t-value") {
		t.Fatalf("expected the secret to be embedded; got:\n%s", data)
	}

	gitignore, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatalf("install-hook wrote a repo-local secret without a .gitignore guard: %v", err)
	}
	if !strings.Contains(string(gitignore), ".npmrc") {
		t.Fatalf(".gitignore does not cover the secret-bearing config:\n%s", gitignore)
	}
	if !strings.Contains(errb.String(), ".gitignore") {
		t.Errorf("the .gitignore edit was silent; stderr = %q", errb.String())
	}
}

func TestInstallHook_ProjectScopeGitignoreIsIdempotent(t *testing.T) {
	dir := newGitRepo(t)
	withHookServer(t)
	for i := 0; i < 2; i++ {
		cmd := newInstallHookCmd()
		cmd.SetArgs([]string{"npm", "--scope", "project", "--credentials", "cli-abc:s3cr3t-value"})
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("execute %d: %v", i+1, err)
		}
	}
	gitignore, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(gitignore), ".npmrc"); n != 1 {
		t.Fatalf(".gitignore accumulated %d entries across two runs:\n%s", n, gitignore)
	}
}

func TestInstallHook_ProjectScopeWithoutSecretLeavesGitignoreAlone(t *testing.T) {
	dir := newGitRepo(t)
	cmd := newInstallHookCmd()
	cmd.SetArgs([]string{"npm", "--scope", "project", "--no-credentials"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".gitignore")); err == nil {
		t.Error("created a .gitignore for a config that carries no secret")
	}
}

func TestInstallHook_ProjectScopeRespectsAnExistingGitignoreEntry(t *testing.T) {
	dir := newGitRepo(t)
	withHookServer(t)
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("node_modules/\n.npmrc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := newInstallHookCmd()
	cmd.SetArgs([]string{"npm", "--scope", "project", "--credentials", "cli-abc:s3cr3t-value"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "node_modules/\n.npmrc\n" {
		t.Fatalf(".gitignore was rewritten despite already covering the file:\n%s", got)
	}
}

// TestUninstallHook_RepairRefusesWithoutConfirmation pins that the one
// destructive path never runs unattended. --repair deletes lines from a file
// chainsaw does not own; in CI there is nobody to confirm.
func TestUninstallHook_RepairRefusesWithoutConfirmation(t *testing.T) {
	dir := t.TempDir()
	npmrc := filepath.Join(dir, "npmrc")
	t.Setenv("NPM_CONFIG_USERCONFIG", npmrc)
	corrupt := "save-exact=true\n# >>> chainsaw-managed >>>\nregistry=https://old/\n"
	if err := os.WriteFile(npmrc, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newUninstallHookCmd()
	cmd.SetArgs([]string{"npm", "--repair"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("--repair deleted lines with no interactive confirmation")
	}
	if !strings.Contains(err.Error(), "terminal") {
		t.Errorf("refusal does not explain what is needed: %v", err)
	}
	// The preview must still be printed so an operator can see the damage.
	if !strings.Contains(out.String(), "chainsaw-managed") {
		t.Errorf("no preview was shown before refusing:\n%s", out.String())
	}
	data, err := os.ReadFile(npmrc)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != corrupt {
		t.Fatalf("the file was modified despite the refusal:\n%s", data)
	}
}

func TestUninstallHook_RepairOnAHealthyConfigIsANoOp(t *testing.T) {
	dir := t.TempDir()
	npmrc := filepath.Join(dir, "npmrc")
	t.Setenv("NPM_CONFIG_USERCONFIG", npmrc)
	if err := os.WriteFile(npmrc, []byte("save-exact=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newUninstallHookCmd()
	cmd.SetArgs([]string{"npm", "--repair"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("--repair on a healthy config should exit 0: %v", err)
	}
}

func TestUninstallHook_RepairRejectsAll(t *testing.T) {
	cmd := newUninstallHookCmd()
	cmd.SetArgs([]string{"--all", "--repair"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("--repair --all was accepted; repair must target one manager")
	}
}

func TestUninstallHook_MirrorFlagIsDockerOnly(t *testing.T) {
	cmd := newUninstallHookCmd()
	cmd.SetArgs([]string{"npm", "--mirror", "https://chain305.com"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("--mirror was accepted for a non-docker manager")
	}
	if !strings.Contains(err.Error(), "docker") {
		t.Errorf("error does not name the supported command: %v", err)
	}
}

func TestUninstallHook_DockerMirrorEscapeHatch(t *testing.T) {
	dir := newGitRepo(t)
	daemon := filepath.Join(dir, "daemon.json")
	if err := os.WriteFile(daemon, []byte(`{"registry-mirrors":["https://chain305.com"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := newUninstallHookCmd()
	cmd.SetArgs([]string{"docker", "--scope", "project", "--mirror", "https://chain305.com"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}
	data, err := os.ReadFile(daemon)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "chain305.com") {
		t.Fatalf("--mirror did not remove the entry:\n%s", data)
	}
	if !strings.Contains(out.String(), "removed registry mirror") {
		t.Errorf("no confirmation printed: %q", out.String())
	}
}

// TestUninstallHook_DefaultScopeIsUserForScripts pins that widening the
// --scope default (H7) did not change behaviour for non-interactive callers.
func TestUninstallHook_DefaultScopeIsUserForScripts(t *testing.T) {
	dir := t.TempDir()
	npmrc := filepath.Join(dir, "npmrc")
	t.Setenv("NPM_CONFIG_USERCONFIG", npmrc)
	block := "# >>> chainsaw-managed >>>\nregistry=https://chain305.com/x/\n# <<< chainsaw-managed <<<\n"
	if err := os.WriteFile(npmrc, []byte(block), 0o600); err != nil {
		t.Fatal(err)
	}
	// A stray project-scope file must be left alone.
	proj := newGitRepo(t)
	if err := os.WriteFile(filepath.Join(proj, ".npmrc"), []byte(block), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := newUninstallHookCmd()
	cmd.SetArgs([]string{"npm"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	userData, err := os.ReadFile(npmrc)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(userData), "chainsaw-managed") {
		t.Errorf("user-scope block survived the default uninstall:\n%s", userData)
	}
	projData, err := os.ReadFile(filepath.Join(proj, ".npmrc"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(projData), "chainsaw-managed") {
		t.Errorf("the default scope reached the project file: %s", projData)
	}
}
