package cli

// auth_logout_test.go covers Y8: `auth logout` deletes the credstore entry and
// the YAML, then unconditionally reports success — while cfgToken (root.go)
// gives CHAINSAW_TOKEN and --token higher precedence than either. The user is
// told they logged out and `auth status` immediately after still says
// Authenticated. The fix keeps rc=0 and keeps the deletion unconditional, but
// warns and names the source that is keeping the session alive.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// runAuthLogout drives the real logout RunE with an isolated config home, a
// file-backed credstore, and a SEEDED credential — the state the Y8 warning is
// about. tokenFlag != "" registers and sets --token the way the root persistent
// flag reaches the subcommand at execute time.
//
// Z4 note: the seed is load-bearing now. Logout used to report "Logged out"
// whether or not anything was stored, so these tests passed without one; they
// were asserting the message, not the logout. The bare-install case has its own
// helper below.
func runAuthLogout(t *testing.T, asJSON bool, tokenFlag string) (stdout, stderr string, err error) {
	t.Helper()
	withIsolatedConfigHome(t)
	store := withFileCredStore(t)
	viper.Set("server_url", "https://example.test")
	if serr := store.Set(credService, "https://example.test", "stored-token"); serr != nil {
		t.Fatalf("seed credential: %v", serr)
	}

	// Run the production RunE on a FRESH command rather than the package-level
	// authLogoutCmd: registering --output/--token on the singleton would leak
	// into the real command tree and trip the global flag-contract tests.
	cmd := &cobra.Command{Use: "logout", RunE: authLogoutCmd.RunE, SilenceUsage: true}
	flags := cmd.Flags()
	flags.Bool("json", false, "")
	flags.String("token", "", "")
	flags.String("output", "", "")
	if asJSON {
		_ = flags.Set("json", "true")
	}
	_ = flags.Set("token", tokenFlag)

	// PrintJSONTo writes through outWriter, which honors --output and otherwise
	// goes to the real os.Stdout (not cobra's SetOut). Route the JSON body to a
	// temp file so the test can read it deterministically.
	jsonPath := filepath.Join(t.TempDir(), "logout.json")
	if asJSON {
		_ = flags.Set("output", jsonPath)
	}

	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)

	err = cmd.RunE(cmd, nil)
	stdout = out.String()
	if asJSON {
		if data, rerr := os.ReadFile(jsonPath); rerr == nil {
			stdout = string(data)
		}
	}
	return stdout, errb.String(), err
}

// TestAuthLogout_WarnsWhenEnvTokenKeepsSessionAlive is the Y8 regression: with
// CHAINSAW_TOKEN exported, "Logged out" alone is a lie.
func TestAuthLogout_WarnsWhenEnvTokenKeepsSessionAlive(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "still-live-token")

	stdout, stderr, err := runAuthLogout(t, false, "")
	if err != nil {
		t.Fatalf("logout must still succeed (rc=0), got: %v", err)
	}
	if !strings.Contains(stdout, "Logged out") {
		t.Fatalf("stored credentials are really gone, so the success line must stay; stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "CHAINSAW_TOKEN") {
		t.Fatalf("logout claimed success while CHAINSAW_TOKEN keeps the session authenticated, and never named the variable\nstderr: %q", stderr)
	}
	if !strings.Contains(stderr, "unset CHAINSAW_TOKEN") {
		t.Fatalf("the warning should say how to finish signing out; stderr = %q", stderr)
	}
	// Purity: the warning belongs on stderr, not in the parseable stdout.
	if strings.Contains(stdout, "CHAINSAW_TOKEN") {
		t.Fatalf("warning leaked onto stdout: %q", stdout)
	}
}

// TestAuthLogout_WarnsWhenTokenFlagKeepsSessionAlive covers the other override
// tier: --token outranks everything logout just cleared.
func TestAuthLogout_WarnsWhenTokenFlagKeepsSessionAlive(t *testing.T) {
	stdout, stderr, err := runAuthLogout(t, false, "flag-token")
	if err != nil {
		t.Fatalf("logout must still succeed (rc=0), got: %v", err)
	}
	if !strings.Contains(stdout, "Logged out") {
		t.Fatalf("stdout = %q, want the success line", stdout)
	}
	if !strings.Contains(stderr, "--token") {
		t.Fatalf("logout with --token set must name the flag that keeps the session alive; stderr = %q", stderr)
	}
}

// TestAuthLogout_QuietWhenNothingOverrides pins the normal case: no warning,
// rc=0, X8 stdout unchanged.
func TestAuthLogout_QuietWhenNothingOverrides(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "")

	stdout, stderr, err := runAuthLogout(t, false, "")
	if err != nil {
		t.Fatalf("logout err = %v, want nil", err)
	}
	if !strings.Contains(stdout, "Logged out") {
		t.Fatalf("stdout = %q, want the success line", stdout)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Fatalf("clean logout must not warn; stderr = %q", stderr)
	}
}

// TestAuthLogout_JSONReportsEnvTokenActive pins the X8 JSON contract plus the
// Y8 addition: logged_out/server unchanged, env_token_active tells a script the
// session is still live.
func TestAuthLogout_JSONReportsEnvTokenActive(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "still-live-token")

	stdout, _, err := runAuthLogout(t, true, "")
	if err != nil {
		t.Fatalf("logout err = %v, want nil", err)
	}
	var body struct {
		LoggedOut      bool   `json:"logged_out"`
		Server         string `json:"server"`
		EnvTokenActive bool   `json:"env_token_active"`
	}
	if uerr := json.Unmarshal([]byte(stdout), &body); uerr != nil {
		t.Fatalf("stdout is not JSON (%v): %q", uerr, stdout)
	}
	if !body.LoggedOut {
		t.Fatalf("logged_out = false, want true (X8 contract)")
	}
	if body.Server != "https://example.test" {
		t.Fatalf("server = %q, want the configured server (X8 contract)", body.Server)
	}
	if !body.EnvTokenActive {
		t.Fatalf("env_token_active = false while CHAINSAW_TOKEN is set; a script cannot tell the session is still authenticated")
	}
	if strings.Contains(stdout, "Warning") {
		t.Fatalf("human warning leaked into the JSON body: %q", stdout)
	}
}

// TestAuthLogout_JSONEnvTokenInactiveWhenClean is the negative half.
func TestAuthLogout_JSONEnvTokenInactiveWhenClean(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "")

	stdout, _, err := runAuthLogout(t, true, "")
	if err != nil {
		t.Fatalf("logout err = %v, want nil", err)
	}
	var body map[string]any
	if uerr := json.Unmarshal([]byte(stdout), &body); uerr != nil {
		t.Fatalf("stdout is not JSON (%v): %q", uerr, stdout)
	}
	if body["env_token_active"] != false {
		t.Fatalf("env_token_active = %v, want false", body["env_token_active"])
	}
}

// ── Z4: logout must not claim a logout that never happened ────────────────────
//
// `auth logout` printed "Logged out" unconditionally. On a machine that had
// never logged in that is a plain falsehood — and it was not a cosmetic one:
// saveConfig("","","") routes to clearConfig (root.go), which REMOVES
// config.yaml. So someone running `chainsaw auth logout` to check their state
// silently lost server_url and org_id to a command that told them it had just
// signed them out.
//
// The fix keeps the clear idempotent and keeps rc=0 — running logout twice must
// stay safe, and "you are signed out" is a true statement about the end state
// either way. What changes is that the command now reports which of the two
// happened, and stops taking unrelated configuration with it when the answer is
// "nothing".

// runAuthLogoutBare drives logout on a machine with a configured server and
// org but NO stored credential: the fresh-install / already-logged-out state.
// Returns the config dir so callers can inspect what survived.
func runAuthLogoutBare(t *testing.T, asJSON bool, tokenFlag string) (dir, stdout, stderr string, err error) {
	t.Helper()
	dir = withIsolatedConfigHome(t)
	withFileCredStore(t)
	viper.Set("server_url", "https://example.test")
	viper.Set("org_id", "org-42")
	if werr := writeConfigYAML(); werr != nil {
		t.Fatalf("seed config.yaml: %v", werr)
	}

	cmd := &cobra.Command{Use: "logout", RunE: authLogoutCmd.RunE, SilenceUsage: true}
	flags := cmd.Flags()
	flags.Bool("json", false, "")
	flags.String("token", "", "")
	flags.String("output", "", "")
	if asJSON {
		_ = flags.Set("json", "true")
	}
	_ = flags.Set("token", tokenFlag)

	jsonPath := filepath.Join(t.TempDir(), "logout.json")
	if asJSON {
		_ = flags.Set("output", jsonPath)
	}

	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)

	err = cmd.RunE(cmd, nil)
	stdout = out.String()
	if asJSON {
		if data, rerr := os.ReadFile(jsonPath); rerr == nil {
			stdout = string(data)
		}
	}
	return dir, stdout, errb.String(), err
}

// TestAuthLogout_BareInstallSaysNothingToDo is the headline Z4 regression.
func TestAuthLogout_BareInstallSaysNothingToDo(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "")

	_, stdout, stderr, err := runAuthLogoutBare(t, false, "")
	if err != nil {
		t.Fatalf("logout on a bare install must stay rc=0, got: %v", err)
	}
	if strings.Contains(stdout, "Logged out") {
		t.Fatalf("logout claimed a sign-out that never happened; stdout = %q", stdout)
	}
	if !strings.Contains(stdout, "Not logged in — nothing to do.") {
		t.Fatalf("stdout = %q, want the honest nothing-to-do line", stdout)
	}
	if strings.TrimSpace(stderr) != "" {
		t.Fatalf("nothing was overriding anything; stderr should be quiet, got %q", stderr)
	}
}

// TestAuthLogout_BareInstallPreservesServerConfig is the destructive half:
// clearConfig removed the whole YAML, so the "reassuring" no-op deleted the
// user's server_url and org_id.
func TestAuthLogout_BareInstallPreservesServerConfig(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "")

	dir, _, _, err := runAuthLogoutBare(t, false, "")
	if err != nil {
		t.Fatalf("logout err = %v, want nil", err)
	}

	cfgPath := filepath.Join(dir, "config.yaml")
	data, rerr := os.ReadFile(cfgPath)
	if rerr != nil {
		t.Fatalf("config.yaml was deleted by a logout that had nothing to log out of: %v", rerr)
	}
	body := string(data)
	if !strings.Contains(body, "https://example.test") {
		t.Errorf("server_url did not survive:\n%s", body)
	}
	if !strings.Contains(body, "org-42") {
		t.Errorf("org_id did not survive:\n%s", body)
	}
	// And the in-process view must agree with the file.
	if got := cfgServerURL(); got != "https://example.test" {
		t.Errorf("cfgServerURL() = %q after a no-op logout, want the configured server", got)
	}
	if got := cfgOrgID(); got != "org-42" {
		t.Errorf("cfgOrgID() = %q after a no-op logout, want org-42", got)
	}
}

// TestAuthLogout_BareInstallJSONReportsLoggedOutFalse: a script must be able to
// tell "I removed a session" from "there was nothing to remove".
func TestAuthLogout_BareInstallJSONReportsLoggedOutFalse(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "")

	_, stdout, _, err := runAuthLogoutBare(t, true, "")
	if err != nil {
		t.Fatalf("logout err = %v, want nil", err)
	}
	var body struct {
		LoggedOut bool   `json:"logged_out"`
		Server    string `json:"server"`
	}
	if uerr := json.Unmarshal([]byte(stdout), &body); uerr != nil {
		t.Fatalf("stdout is not JSON (%v): %q", uerr, stdout)
	}
	if body.LoggedOut {
		t.Fatalf("logged_out = true while nothing was stored: %q", stdout)
	}
	if body.Server != "https://example.test" {
		t.Errorf("server = %q, want the configured server", body.Server)
	}
}

// TestAuthLogout_BareInstallWithEnvTokenStillWarns: "Not logged in" must not
// become the NEW lie. CHAINSAW_TOKEN authenticates every command in this shell,
// and logout cannot remove it — say so, without claiming a removal.
func TestAuthLogout_BareInstallWithEnvTokenStillWarns(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "still-live-token")

	_, stdout, stderr, err := runAuthLogoutBare(t, false, "")
	if err != nil {
		t.Fatalf("logout err = %v, want nil", err)
	}
	if !strings.Contains(stdout, "Not logged in — nothing to do.") {
		t.Fatalf("stdout = %q, want the nothing-to-do line", stdout)
	}
	if !strings.Contains(stderr, "CHAINSAW_TOKEN") {
		t.Fatalf("the env token keeps the session live and was not named; stderr = %q", stderr)
	}
	if strings.Contains(stderr, "Saved credentials were removed") {
		t.Fatalf("the warning claims a removal that did not happen; stderr = %q", stderr)
	}
}

// TestAuthLogout_TokenFlagAloneIsNotAStoredCredential pins the precedence rule
// inside storedCredentialExists: viper.GetString("token") also returns the
// --token flag, so counting it would make `chainsaw --token X auth logout`
// report a logout AND delete config.yaml on a machine that never logged in.
func TestAuthLogout_TokenFlagAloneIsNotAStoredCredential(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "")

	dir, stdout, _, err := runAuthLogoutBare(t, false, "flag-token")
	if err != nil {
		t.Fatalf("logout err = %v, want nil", err)
	}
	if strings.Contains(stdout, "Logged out") {
		t.Fatalf("a --token flag was mistaken for a stored credential: %q", stdout)
	}
	if _, rerr := os.ReadFile(filepath.Join(dir, "config.yaml")); rerr != nil {
		t.Fatalf("config.yaml was deleted on the strength of a --token flag: %v", rerr)
	}
}

// TestAuthLogout_IsIdempotent: the second logout is the bare case, and it must
// stay rc=0 and stop reporting a removal.
func TestAuthLogout_IsIdempotent(t *testing.T) {
	t.Setenv("CHAINSAW_TOKEN", "")

	stdout, _, err := runAuthLogout(t, false, "")
	if err != nil {
		t.Fatalf("first logout: %v", err)
	}
	if !strings.Contains(stdout, "Logged out") {
		t.Fatalf("first logout should report the removal; got %q", stdout)
	}

	cmd := &cobra.Command{Use: "logout", RunE: authLogoutCmd.RunE, SilenceUsage: true}
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("token", "", "")
	cmd.Flags().String("output", "", "")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	if rerr := cmd.RunE(cmd, nil); rerr != nil {
		t.Fatalf("second logout must stay rc=0: %v", rerr)
	}
	if strings.Contains(out.String(), "Logged out") {
		t.Fatalf("the second logout still claims to have removed something: %q", out.String())
	}
	if !strings.Contains(out.String(), "Not logged in") {
		t.Fatalf("second logout = %q, want the nothing-to-do line", out.String())
	}
}

// TestStoredCredentialExists_CountsTheLegacyYAMLTier: pre-keychain installs
// keep the token in config.yaml. Logging those out is a real removal and must
// still clear the file.
func TestStoredCredentialExists_CountsTheLegacyYAMLTier(t *testing.T) {
	dir := withIsolatedConfigHome(t)
	withFileCredStore(t)

	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	yaml := "server_url: https://example.test\norg_id: org-1\ntoken: legacy-token\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	viper.SetConfigFile(cfgPath)
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("read config: %v", err)
	}

	if !storedCredentialExists(cfgServerURL()) {
		t.Fatal("a plaintext YAML token is a stored credential; logout must report removing it")
	}
}
