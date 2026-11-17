package cli

// Round-2 adversarial review of install-hook and doctor --strict
// (R2-S5, R2-S7, R2-S8, R2-S9, R2-S11, R2-S12).

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// R2-S5: any org can create a repository on a shared server, so with no org
// slug configured no wired config can be shown to route to THIS org.
func TestEvaluateManager_UnknownOrgIsDrift(t *testing.T) {
	clearWatchedEnv(t)
	m := fakeHookManager{name: "cargo", configPath: t.TempDir()}
	if st := evaluateManager(m, map[string]string{}, map[string]string{}); st.Status != "compliant" {
		t.Fatalf("baseline with an org: %+v", st)
	}
	viper.Set("org_slug", "")
	st := evaluateManager(m, map[string]string{}, map[string]string{})
	if st.Status != "drifted" || !strings.Contains(st.Reason, "org slug") {
		t.Fatalf("no org slug: %+v, want drifted", st)
	}
}

// installHookSandbox isolates HOME, the chainsaw config dir and uv's paths.
func installHookSandbox(t *testing.T) (home string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CHAINSAW_CONFIG_HOME", filepath.Join(home, "chainsaw-cfg"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg"))
	t.Setenv("XDG_CONFIG_DIRS", filepath.Join(home, "xdg-dirs"))
	t.Setenv("UV_CONFIG_FILE", "")
	t.Setenv("CHAINSAW_ORG_SLUG", "")
	os.Unsetenv("CHAINSAW_ORG_SLUG")
	withHookServer(t)
	prev := viper.GetString("org_slug")
	viper.Set("org_slug", "")
	t.Cleanup(func() { viper.Set("org_slug", prev) })
	t.Chdir(t.TempDir())
	return home
}

func execInstallHook(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newInstallHookCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.SetArgs(args)
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

// R2-S5: an explicit --org is recorded once something is wired with it, so a
// later doctor --strict checks against that org; a recorded org is never
// overwritten.
func TestInstallHook_RecordsExplicitOrg(t *testing.T) {
	home := installHookSandbox(t)
	if _, stderr, err := execInstallHook(t, "npm", "--scope", "user", "--org", "acme-corp", "--credentials", "cli-abc:s3cr3t-value"); err != nil {
		t.Fatalf("install-hook: %v\n%s", err, stderr)
	}
	cfg, err := os.ReadFile(filepath.Join(home, "chainsaw-cfg", "config.yaml"))
	if err != nil || !strings.Contains(string(cfg), "org_slug: acme-corp") {
		t.Fatalf("org not recorded: %v\n%s", err, cfg)
	}
	if strings.Contains(string(cfg), "server_url") {
		t.Fatalf("recording the org also persisted the run's server:\n%s", cfg)
	}
	_, stderr, err := execInstallHook(t, "npm", "--scope", "user", "--org", "other-org", "--credentials", "cli-abc:s3cr3t-value")
	if err != nil {
		t.Fatal(err)
	}
	if viper.GetString("org_slug") != "acme-corp" || !strings.Contains(stderr, `records org "acme-corp"`) {
		t.Fatalf("recorded org overwritten or the mismatch was silent: %q\n%s", viper.GetString("org_slug"), stderr)
	}
}

// R2-S12: --json returned before the exit-code logic, so refusals and
// failures exited 0. R2-S11: the refusal quoted the user's credential.
func TestInstallHook_JSONKeepsExitCodeAndRedacts(t *testing.T) {
	home := installHookSandbox(t)
	uvToml := filepath.Join(home, "xdg", "uv", "uv.toml")
	if err := os.MkdirAll(filepath.Dir(uvToml), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(uvToml, []byte("index-url = \"https://me:topsecret@mirror.corp/simple\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err := execInstallHook(t, "uv", "--scope", "user", "--org", "acme-corp", "--no-credentials", "--json")
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitHookRefused || coded.Err != nil {
		t.Fatalf("--json refusal: err=%v, want a silent ExitCodeError{%d}", err, ExitHookRefused)
	}
	if !strings.Contains(stdout, "mirror.corp") || strings.Contains(stdout+stderr, "topsecret") {
		t.Fatalf("reason missing or credential printed:\nstdout=%s\nstderr=%s", stdout, stderr)
	}
	// Text mode: same code, and the returned error is redacted too.
	_, stderr, err = execInstallHook(t, "uv", "--scope", "user", "--org", "acme-corp", "--no-credentials")
	if !errors.As(err, &coded) || coded.Code != ExitHookRefused || strings.Contains(err.Error()+stderr, "topsecret") {
		t.Fatalf("text refusal: err=%v stderr=%s", err, stderr)
	}
	// A real failure (a file uv cannot parse) is non-zero under --json too.
	if err := os.WriteFile(uvToml, []byte("index-url = \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err = execInstallHook(t, "uv", "--scope", "user", "--org", "acme-corp", "--no-credentials", "--json")
	if !errors.As(err, &coded) || coded.Code == 0 || coded.Code == ExitHookRefused {
		t.Fatalf("--json failure: err=%v, want a non-zero, non-refusal code", err)
	}
}

// R2-S7: uv's index env vars must be this org's Chainsaw PyPI repository,
// not any URL that mentions "chainsaw".
func TestEvaluateManager_UVIndexEnvMustBeThisOrg(t *testing.T) {
	for _, tc := range []struct {
		key, val string
		drift    bool
	}{
		{"UV_DEFAULT_INDEX", "http://chainsaw.attacker.test/simple", true},
		{"UV_INDEX_URL", "https://localhost.evil.example/simple", true},
		{"UV_INDEX", "corp=" + rewriteTestServer + "/repository/@other/pypi/simple/", true},
		{"UV_DEFAULT_INDEX", rewriteTestServer + "/repository/@acme/pypi/simple/", false},
		{"UV_INDEX", "corp=" + rewriteTestServer + "/repository/@acme/pypi/simple/", false},
	} {
		t.Run(tc.key+"="+tc.val, func(t *testing.T) {
			clearWatchedEnv(t)
			t.Chdir(t.TempDir())
			viper.Set("server_url", rewriteTestServer)
			t.Cleanup(func() { viper.Set("server_url", "") })
			t.Setenv(tc.key, tc.val)
			st := evaluateManager(fakeHookManager{name: "uv", configPath: t.TempDir()}, map[string]string{}, map[string]string{})
			if (st.Status == "drifted") != tc.drift {
				t.Fatalf("%s=%s: %+v, want drift=%v", tc.key, tc.val, st, tc.drift)
			}
		})
	}
}

// R2-S9: www.rubygems.org serves the same gems and is not covered by the
// rubygems.org mirror.
func TestLockfileScan_WWWRubygems(t *testing.T) {
	clearWatchedEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte("GEM\n  remote: https://www.rubygems.org/\n  specs:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if hits := scanLockfilesForPublicSources(); len(hits) != 1 || !strings.Contains(hits[0], "www.rubygems.org") {
		t.Fatalf("hits = %v", hits)
	}
}

// R2-S8: a project pinning a package to a non-Chainsaw explicit index is
// reported as a note (not drift).
func TestProjectPinnedIndexNotes(t *testing.T) {
	clearWatchedEnv(t)
	dir := t.TempDir()
	t.Chdir(dir)
	viper.Set("server_url", rewriteTestServer)
	t.Cleanup(func() { viper.Set("server_url", "") })
	py := "[project]\nname = \"x\"\n\n[[tool.uv.index]]\nname = \"evil\"\nurl = \"https://u:pw@evil.example/simple\"\nexplicit = true\n\n[tool.uv.sources]\nrequests = { index = \"evil\" }\n"
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte(py), 0o644); err != nil {
		t.Fatal(err)
	}
	notes := projectPinnedIndexNotes()
	if len(notes) != 1 || !strings.Contains(notes[0], `"requests"`) || strings.Contains(notes[0], ":pw@") {
		t.Fatalf("notes = %v", notes)
	}
	if reason := projectIndexOverride("uv"); reason != "" {
		t.Fatalf("an explicit pinned index must be a note, not drift: %q", reason)
	}
}
