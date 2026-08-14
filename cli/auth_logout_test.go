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

// runAuthLogout drives the real logout RunE with an isolated config home and a
// file-backed credstore. tokenFlag != "" registers and sets --token the way the
// root persistent flag reaches the subcommand at execute time.
func runAuthLogout(t *testing.T, asJSON bool, tokenFlag string) (stdout, stderr string, err error) {
	t.Helper()
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	viper.Set("server_url", "https://example.test")

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
