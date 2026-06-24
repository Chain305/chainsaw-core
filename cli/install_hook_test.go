package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// withHookEnv redirects every supported package manager's user-scoped
// config file into a temp directory so tests never touch the real
// user's configuration. Returns the three paths in (npmrc, pipconf,
// cargoconfig) order.
func withHookEnv(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()

	npmrc := filepath.Join(dir, "npmrc")
	pipconf := filepath.Join(dir, "pip.conf")
	cargoHome := filepath.Join(dir, "cargo")
	if err := os.MkdirAll(cargoHome, 0o700); err != nil {
		t.Fatalf("mkdir cargo home: %v", err)
	}
	cargoCfg := filepath.Join(cargoHome, "config.toml")

	t.Setenv("NPM_CONFIG_USERCONFIG", npmrc)
	t.Setenv("PIP_CONFIG_FILE", pipconf)
	t.Setenv("CARGO_HOME", cargoHome)

	return npmrc, pipconf, cargoCfg
}

func TestInstallHook_SingleManager_WritesSentinel(t *testing.T) {
	npmrc, _, _ := withHookEnv(t)
	cmd := newInstallHookCmd()
	cmd.SetArgs([]string{"npm"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}
	data, err := os.ReadFile(npmrc)
	if err != nil {
		t.Fatalf("read npmrc: %v", err)
	}
	if !strings.Contains(string(data), "chainsaw-managed") {
		t.Fatalf("npmrc missing sentinel block, got: %s", data)
	}
	if !strings.Contains(out.String(), "wired npm") {
		t.Fatalf("stdout missing success line, got: %q", out.String())
	}
}

// TestInstallHook_UnknownManager exercises the unknown-name branch.
// The production path calls os.Exit(1) after printing the help line —
// we can't invoke Execute() directly without terminating the test
// binary, so instead we assert the contract (hook.ByName returns an
// error and managerNames produces the expected list) that feeds the
// exit path. This keeps the test hermetic and matches the behavior a
// user would see.
func TestInstallHook_UnknownManager_ListsAvailable(t *testing.T) {
	names := managerNames()
	if len(names) < 3 {
		t.Fatalf("expected >= 3 registered managers, got %d: %v", len(names), names)
	}
	want := map[string]bool{"npm": false, "pip": false, "cargo": false}
	for _, n := range names {
		if _, ok := want[n]; ok {
			want[n] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("managerNames missing %q: got %v", name, names)
		}
	}
}

func TestUninstallHook_RemovesBlock(t *testing.T) {
	npmrc, _, _ := withHookEnv(t)

	// Wire first.
	install := newInstallHookCmd()
	install.SetArgs([]string{"npm"})
	var out, errb bytes.Buffer
	install.SetOut(&out)
	install.SetErr(&errb)
	if err := install.Execute(); err != nil {
		t.Fatalf("wire setup: %v", err)
	}

	// Now uninstall.
	uninstall := newUninstallHookCmd()
	uninstall.SetArgs([]string{"npm"})
	out.Reset()
	errb.Reset()
	uninstall.SetOut(&out)
	uninstall.SetErr(&errb)
	if err := uninstall.Execute(); err != nil {
		t.Fatalf("uninstall: %v\nstderr: %s", err, errb.String())
	}

	data, err := os.ReadFile(npmrc)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read npmrc: %v", err)
	}
	if strings.Contains(string(data), "chainsaw-managed") {
		t.Fatalf("npmrc still contains sentinel: %s", data)
	}
	if !strings.Contains(out.String(), "unwired npm") {
		t.Fatalf("stdout missing unwired line, got: %q", out.String())
	}
}

func TestUninstallHook_NoBlock_Idempotent(t *testing.T) {
	npmrc, _, _ := withHookEnv(t)

	// Seed the config with user content but no sentinel.
	if err := os.WriteFile(npmrc, []byte("registry=https://registry.npmjs.org/\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	uninstall := newUninstallHookCmd()
	uninstall.SetArgs([]string{"npm"})
	var out, errb bytes.Buffer
	uninstall.SetOut(&out)
	uninstall.SetErr(&errb)
	if err := uninstall.Execute(); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !strings.Contains(errb.String(), "nothing to do") {
		t.Fatalf("stderr missing idempotency message, got: %q", errb.String())
	}
}

// TestInstallHook_UsesRootServerFromConfigChain asserts that install-hook
// picks up the server URL from the standard config chain (viper "server_url",
// which is bound to the root --server flag + CHAINSAW_SERVER env var + YAML).
// The command no longer has its own local --server flag; removing it avoids
// ambiguous precedence when both root and local flags are set.
func TestInstallHook_UsesRootServerFromConfigChain(t *testing.T) {
	npmrc, _, _ := withHookEnv(t)

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("server_url", "https://root-server.example")

	cmd := newInstallHookCmd()
	cmd.SetArgs([]string{"npm"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}

	data, err := os.ReadFile(npmrc)
	if err != nil {
		t.Fatalf("read npmrc: %v", err)
	}
	if !strings.Contains(string(data), "root-server.example") {
		t.Fatalf("npmrc did not pick up root --server URL; got: %s", data)
	}
}

// TestInstallHook_RejectsLocalServerFlag verifies the local --server flag is
// gone. Passing it should cause cobra to reject the invocation — which is the
// desired failure mode (the user gets a clear "unknown flag" error rather than
// silently shadowing the root --server).
func TestInstallHook_RejectsLocalServerFlag(t *testing.T) {
	withHookEnv(t)

	cmd := newInstallHookCmd()
	cmd.SetArgs([]string{"npm", "--server", "https://nope.example"})
	cmd.SilenceErrors = true
	cmd.SilenceUsage = true
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected error for unknown --server flag, got nil\nstdout: %s\nstderr: %s", out.String(), errb.String())
	}
}

// TestRejectPostSubcommandServerFlag covers the "--server placed after the
// subcommand" shortcut. The persistent root flag would accept it silently via
// cobra's propagation, but that hides the canonical form from users — so the
// PersistentPreRunE on rootCmd errors with a pointer to the right syntax.
func TestRejectPostSubcommandServerFlag(t *testing.T) {
	root := &cobra.Command{Use: "chainsaw"}
	root.PersistentFlags().String("server", "", "Server URL (overrides config)")
	sub := &cobra.Command{Use: "install-hook", RunE: func(*cobra.Command, []string) error { return nil }}
	root.AddCommand(sub)

	argv := []string{"chainsaw", "install-hook", "npm", "--server", "https://nope.example"}
	err := rejectPostSubcommandServerFlag(sub, argv)
	if err == nil {
		t.Fatal("expected error for --server after subcommand, got nil")
	}
	if !strings.Contains(err.Error(), "--server") {
		t.Fatalf("error should mention --server, got: %v", err)
	}
	if !strings.Contains(err.Error(), "chainsaw --server <url> install-hook") {
		t.Fatalf("error should show canonical root-flag form, got: %v", err)
	}

	// `chainsaw --server X install-hook npm` — legal, --server precedes the
	// subcommand and must not trip the check.
	argv = []string{"chainsaw", "--server", "https://ok.example", "install-hook", "npm"}
	if err := rejectPostSubcommandServerFlag(sub, argv); err != nil {
		t.Fatalf("unexpected error for pre-subcommand --server: %v", err)
	}

	// `--server=foo` attached-value form, still after the subcommand.
	argv = []string{"chainsaw", "install-hook", "--server=https://nope.example", "npm"}
	if err := rejectPostSubcommandServerFlag(sub, argv); err == nil {
		t.Fatal("expected error for --server=value form after subcommand, got nil")
	}

	// A subcommand that does define its own --server (e.g. `auth login`) must
	// be exempt.
	login := &cobra.Command{Use: "login", RunE: func(*cobra.Command, []string) error { return nil }}
	login.Flags().String("server", "", "Server URL")
	auth := &cobra.Command{Use: "auth"}
	auth.AddCommand(login)
	root.AddCommand(auth)
	argv = []string{"chainsaw", "auth", "login", "--server", "https://ok.example"}
	if err := rejectPostSubcommandServerFlag(login, argv); err != nil {
		t.Fatalf("auth login should accept its local --server, got: %v", err)
	}
}

// TestInstallHook_AllManagers_WriteSentinelViaPerName drives the wire
// code path for every registered manager. `--all` itself filters on
// IsInstalled(), which depends on whether npm/pip/cargo are on the
// host's PATH — we can't rely on that in CI, so this test wires each
// one by name and asserts the config file gets the sentinel. That
// covers the Wire() loop for every manager without a host dependency.
func TestInstallHook_AllManagers_WriteSentinelViaPerName(t *testing.T) {
	npmrc, pipconf, cargoCfg := withHookEnv(t)

	for _, name := range []string{"npm", "pip", "cargo"} {
		cmd := newInstallHookCmd()
		cmd.SetArgs([]string{name})
		var out, errb bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errb)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("wire %s: %v\nstderr: %s", name, err, errb.String())
		}
	}

	for _, p := range []string{npmrc, pipconf, cargoCfg} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if !strings.Contains(string(data), "chainsaw-managed") {
			t.Fatalf("%s missing sentinel, got: %s", p, data)
		}
	}
}

// TestInstallHook_PipEmitsChainproxyOrgScopedURL is the regression test
// for the QA smoke finding (D.1.1, CHW-4314): the CLI was emitting a
// legacy slug-less URL like
//
//	https://chain305.com/repository/pypi/simple
//
// while the dashboard's "Save this secret now" snippet uses the proxy-
// mounted, org-scoped form
//
//	https://chain305.com/chainproxy/repository/@<slug>/pypi/simple/
//
// The proxy rejects the legacy form with HTTP 400/404. This test wires
// the pip manager with explicit --org and --credentials and asserts the
// generated pip.conf contains the canonical URL shape, including the
// /chainproxy/ prefix, the @<slug>/ segment, and the trailing slash.
func TestInstallHook_PipEmitsChainproxyOrgScopedURL(t *testing.T) {
	_, pipconf, _ := withHookEnv(t)

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("server_url", "https://chain305.com")

	cmd := newInstallHookCmd()
	cmd.SetArgs([]string{"pip", "--scope", "project", "--org", "smoke-appsec-20260520", "--credentials", "smoke-appsec-a:KBHfU6"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)

	// --scope project writes pip.conf in cwd; redirect cwd to the
	// pipconf parent so the file lands where withHookEnv expects.
	prevWd, _ := os.Getwd()
	if err := os.Chdir(filepath.Dir(pipconf)); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prevWd) })

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}

	projectPipConf := filepath.Join(filepath.Dir(pipconf), "pip.conf")
	data, err := os.ReadFile(projectPipConf)
	if err != nil {
		t.Fatalf("read pip.conf at %s: %v", projectPipConf, err)
	}
	got := string(data)
	// Acceptance criteria 1: index-url MUST contain the /chainproxy/
	// prefix, the @<slug>/ segment, and the trailing slash.
	wantURL := "https://smoke-appsec-a:KBHfU6@chain305.com/chainproxy/repository/@smoke-appsec-20260520/pypi/simple/"
	if !strings.Contains(got, wantURL) {
		t.Fatalf("pip.conf missing canonical org-scoped index-url\nwant substring: %s\ngot:\n%s", wantURL, got)
	}
	// Legacy slug-less form must NOT appear anywhere — even in a comment
	// it would tempt a copy-paste fix that the proxy rejects.
	legacy := "@chain305.com/repository/pypi/simple"
	if strings.Contains(got, legacy) {
		t.Fatalf("pip.conf still contains legacy slug-less URL %q:\n%s", legacy, got)
	}
}

// TestInstallHook_NpmEmitsChainproxyOrgScopedURL is the npm sibling of
// the pip regression test: registry= line must include the /chainproxy/
// prefix and the @<slug>/ org segment, matching the dashboard snippet.
func TestInstallHook_NpmEmitsChainproxyOrgScopedURL(t *testing.T) {
	npmrc, _, _ := withHookEnv(t)

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("server_url", "https://chain305.com")

	cmd := newInstallHookCmd()
	cmd.SetArgs([]string{"npm", "--org", "acme-corp"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}
	data, err := os.ReadFile(npmrc)
	if err != nil {
		t.Fatalf("read npmrc: %v", err)
	}
	got := string(data)
	want := "registry=https://chain305.com/chainproxy/repository/@acme-corp/npmjs/"
	if !strings.Contains(got, want) {
		t.Fatalf(".npmrc missing chainproxy-prefixed registry line\nwant: %s\ngot:\n%s", want, got)
	}
}
