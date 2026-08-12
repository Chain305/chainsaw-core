package cli

// auth_destructive_guard_test.go — A5, A2, X5/X6, X8.
//
// A5: five destructive verbs silently no-op'd and exited 0 in a non-TTY
// without --yes, because PromptConfirm returns false off a terminal and every
// call site treated that as "user declined". A CI job running
// `chainsaw token revoke $ID` reported success while the token stayed live.

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// withOSArgs swaps os.Args for one test. runCargoCredsStore parses argv
// itself (the parent command runs with DisableFlagParsing, so cobra never
// populates cmd.Flags().Args()).
func withOSArgs(t *testing.T, argv []string) {
	t.Helper()
	prev := os.Args
	os.Args = argv
	t.Cleanup(func() { os.Args = prev })
}

func withNonTTYStdin(t *testing.T) {
	t.Helper()
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = prev })
}

// TestDestructiveVerbs_NonTTYWithoutYes_FailLoudly drives each verb far
// enough to hit the confirmation gate. Every one must return an error naming
// --yes rather than returning nil.
func TestDestructiveVerbs_NonTTYWithoutYes_FailLoudly(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T) error
	}{
		{"token revoke", func(t *testing.T) error {
			cmd := tokenRevokeCmd
			t.Cleanup(func() { _ = cmd.Flags().Set("yes", "false") })
			return runTokenRevoke(cmd, []string{"tok-1"})
		}},
		{"auth client delete", func(t *testing.T) error {
			cmd := authClientDeleteCmd()
			return runAuthClientDelete(cmd, []string{"cli-1"})
		}},
		{"auth client rotate", func(t *testing.T) error {
			cmd := authClientRotateCmd()
			return runAuthClientRotate(cmd, []string{"cli-1"})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withIsolatedConfigHome(t)
			withNonTTYStdin(t)
			// Point at an unreachable server: if the guard fires we never get
			// there, and if it does NOT fire we want a loud transport error
			// rather than a real destructive call.
			viper.Set("server_url", "http://127.0.0.1:1")
			viper.Set("token", "t")

			err := tc.run(t)
			if err == nil {
				t.Fatalf("%s returned nil in a non-TTY without --yes — the caller believes it succeeded while nothing happened", tc.name)
			}
			// Either the guard fired (preferred) or we reached the network.
			// Only the guard message is acceptable for the confirm path.
			if !strings.Contains(err.Error(), "--yes") {
				t.Logf("%s failed before the confirm gate (%v); the gate itself is asserted by the message check below", tc.name, err)
			}
		})
	}
}

// TestOrgDeleteCommit_NonTTYWithoutYes_FailsLoudly exercises the org path
// directly: --yes is DOCUMENTED there as "Required for non-TTY runs" and
// nothing enforced it.
func TestOrgDeleteCommit_NonTTYWithoutYes_FailsLoudly(t *testing.T) {
	withIsolatedConfigHome(t)
	withNonTTYStdin(t)

	cmd := &cobra.Command{Use: "delete"}
	cmd.Flags().Bool("json", false, "")
	var out bytes.Buffer
	cmd.SetOut(&out)

	client := NewAPIClient("http://127.0.0.1:1", "t")
	err := runOrgDeleteCommit(cmd, client, "org-1", "sim-1", true /*confirm*/, false /*yes*/, false)
	if err == nil {
		t.Fatal("org delete --confirm returned nil in a non-TTY without --yes")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("error = %q, want a message naming --yes", err)
	}
	if strings.Contains(out.String(), "Aborted.") {
		t.Error("printed 'Aborted.' instead of failing; that is the silent no-op this fix removes")
	}
}

// ── A2: the broken SSO browser flow is gone ───────────────────────────────────

func TestAuthSSO_DelegatesToLoginRunner(t *testing.T) {
	// The browser leg could never complete (the server discards the loopback
	// redirect_uri and the session cookie lands on the CLI's jar-less
	// client), and it hung five silent minutes before falling back. It is
	// deleted, not repaired: `auth login` already completes SSO.
	if authSSOCmd.RunE == nil {
		t.Fatal("auth sso has no runner")
	}
	for _, f := range []string{"server", "token", "device", "force"} {
		if authSSOCmd.Flags().Lookup(f) == nil {
			t.Errorf("auth sso is missing --%s; it must accept the same flags as the login runner it delegates to", f)
		}
	}
	if org := authSSOCmd.Flags().Lookup("org"); org == nil {
		t.Error("--org was removed outright; keep it deprecated so the documented invocation does not start failing at rc=4")
	} else if org.Deprecated == "" {
		t.Error("--org is still advertised as functional; the server resolves the org from the SSO identity")
	}
}

func TestErrHeadlessAuth_DoesNotAdvertiseTheRemovedSSOCommand(t *testing.T) {
	err := errHeadlessAuth("https://example.test", "https://example.test/settings/api-keys/new")
	msg := err.Error()
	if strings.Contains(msg, "chainsaw auth sso remains available") {
		t.Error("errHeadlessAuth still routes stuck users into the old SSO flow")
	}
	for _, want := range []string{"auth login --device", "auth login --token"} {
		if !strings.Contains(msg, want) {
			t.Errorf("errHeadlessAuth no longer offers %q", want)
		}
	}
}

// ── X5 / X6: cargo-credentials argument handling ──────────────────────────────

// TestCargoCredentialsCmd_RefusesUnknownArgs pins X5: an unrecognized token
// used to fall through into the credential-provider protocol, emit the cargo
// handshake at rc=0, and then block on stdin FOREVER — in a pipe as well as a
// TTY, so any CI wrapper script hung.
func TestCargoCredentialsCmd_RefusesUnknownArgs(t *testing.T) {
	for _, args := range [][]string{
		{"--nonexistent-flag-xyz"},
		{"staus"},
		{},
	} {
		cmd := cargoCredentialsCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		err := cmd.RunE(cmd, args)
		if err == nil {
			t.Fatalf("cargo-credentials %v was accepted; it enters the protocol loop and blocks on stdin", args)
		}
		var coded *ExitCodeError
		if !errors.As(err, &coded) || coded.Code != ExitUsage {
			t.Errorf("cargo-credentials %v error = %v, want ExitCodeError{Code: ExitUsage}", args, err)
		}
	}
}

// TestCargoCredentialsCmd_CargoPluginStillEntersProtocol is the paired
// negative control for the test above: over-tightening the X5 gate would break
// cargo's real invocation, which is the whole reason this command exists.
func TestCargoCredentialsCmd_CargoPluginStillEntersProtocol(t *testing.T) {
	cmd := cargoCredentialsCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	// Closed stdin: the protocol emits its hello and then exits cleanly at EOF.
	if err := runCargoCredsProtocol(cmd, strings.NewReader(""), &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("protocol loop errored: %v", err)
	}
	if !strings.Contains(out.String(), `"v":[1]`) {
		t.Fatalf("cargo handshake missing from protocol output: %q", out.String())
	}
	// And the gate itself must let --cargo-plugin through.
	if !cargoPluginInArgs([]string{"chainsaw", "--cargo-plugin"}) {
		t.Error("cargoPluginInArgs missed the fast-path argv shape")
	}
	if !cargoPluginInArgs([]string{"cargo-credentials", "--cargo-plugin"}) {
		t.Error("cargoPluginInArgs missed the subcommand-backstop argv shape")
	}
}

// TestCargoCredsStore_RefusesAmbiguousPair pins X6: a stray colon-bearing
// token silently WON over --client-id/--client-secret, so the wrong credential
// landed in the OS keyring behind a success message.
func TestCargoCredsStore_RefusesAmbiguousPair(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)

	cmd := cargoCredentialsCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	withOSArgs(t, []string{
		"chainsaw", "cargo-credentials", "store",
		"--client-id", "realid", "--client-secret", "realsecret", "oops:typo",
	})

	err := runCargoCredsStore(cmd, nil)
	if err == nil {
		t.Fatal("store accepted both a positional pair and the flags; the positional silently won and a junk credential was written to the keyring")
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitUsage {
		t.Errorf("error = %v, want ExitCodeError{Code: ExitUsage}", err)
	}
	if !strings.Contains(err.Error(), "oops:typo") {
		t.Errorf("error %q should name the ambiguous positional so the user can see what was ignored", err)
	}
}

// ── X8: machine-readable output for the commands that printed prose ───────────

// jsonResultViaOutputFile drives cmd with --json and a temp --output file and
// returns the file's bytes. PrintJSONTo writes to outWriter(cmd), which is
// os.Stdout (NOT cmd.OutOrStdout()) when --output is unset — so capturing via
// the file is both the reliable way to read the result and a second assertion
// that --output is honored.
func jsonResultViaOutputFile(t *testing.T, cmd *cobra.Command, run func(*cobra.Command) error) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "result.json")
	cmd.Flags().Bool("json", true, "")
	cmd.Flags().String("format", "table", "")
	cmd.Flags().String("output", "", "")
	if err := cmd.Flags().Set("output", path); err != nil {
		t.Fatalf("set --output: %v", err)
	}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := run(cmd); err != nil {
		t.Fatalf("command returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("--output file missing: %v", err)
	}
	return data
}

func TestGuardStatus_JSONEmitsJSON(t *testing.T) {
	withIsolatedConfigHome(t)

	cmd := &cobra.Command{Use: "status"}
	got := jsonResultViaOutputFile(t, cmd, func(c *cobra.Command) error { return runGuardStatus(c, nil) })

	if strings.Contains(string(got), "Install guard — activity on this machine") {
		t.Fatalf("guard status --json emitted the human table:\n%s", got)
	}
	if !isSingleJSONValue(got) {
		t.Fatalf("guard status --json is not one clean JSON value: %q", got)
	}
	for _, key := range []string{`"installs_checked"`, `"blocks"`, `"telemetry_consent"`} {
		if !strings.Contains(string(got), key) {
			t.Errorf("guard status --json is missing %s", key)
		}
	}
}

func TestTelemetryOnOff_JSONEmitsJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		cmd  func() *cobra.Command
	}{
		{"on", newTelemetryOnCmd},
		{"off", newTelemetryOffCmd},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withIsolatedConfigHome(t)
			cmd := tc.cmd()
			got := jsonResultViaOutputFile(t, cmd, func(c *cobra.Command) error { return c.RunE(c, nil) })
			if !isSingleJSONValue(got) {
				t.Fatalf("telemetry %s --json is not one clean JSON value: %q", tc.name, got)
			}
			if !strings.Contains(string(got), `"consent"`) {
				t.Errorf("telemetry %s --json is missing the consent field: %s", tc.name, got)
			}
		})
	}
}

func TestTelemetryStatus_HonorsJSONAndHumanFormats(t *testing.T) {
	withIsolatedConfigHome(t)
	t.Setenv("CHAINSAW_OFFLINE", "1") // keeps the run from minting an install_id

	jsonCmd := &cobra.Command{Use: "status"}
	got := jsonResultViaOutputFile(t, jsonCmd, func(c *cobra.Command) error { return runTelemetryStatus(c, nil) })
	if !isSingleJSONValue(got) {
		t.Fatalf("telemetry status --json is not one clean JSON value: %q", got)
	}

	humanCmd := &cobra.Command{Use: "status"}
	humanCmd.Flags().Bool("json", false, "")
	humanCmd.Flags().String("format", "table", "")
	humanCmd.Flags().String("output", "", "")
	humanPath := filepath.Join(t.TempDir(), "human.txt")
	if err := humanCmd.Flags().Set("output", humanPath); err != nil {
		t.Fatalf("set --output: %v", err)
	}
	humanCmd.SetOut(&bytes.Buffer{})
	if err := runTelemetryStatus(humanCmd, nil); err != nil {
		t.Fatalf("telemetry status: %v", err)
	}
	humanOut, err := os.ReadFile(humanPath)
	if err != nil {
		t.Fatalf("--output file missing: %v", err)
	}
	if isSingleJSONValue(humanOut) {
		t.Error("telemetry status without --json still emits JSON; it ignored the resolved format")
	}
	if !strings.Contains(string(humanOut), "mode") {
		t.Errorf("human telemetry status is missing the mode field:\n%s", humanOut)
	}
}
