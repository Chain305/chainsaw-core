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
		// N1: `token rotate` was the one destructive verb with no gate at
		// all — no --yes flag, no guard — while its own Long text said it
		// "invalidates the old secret immediately". A stray rotate in CI
		// broke every consumer of that PAT with no prompt and no undo.
		{"token rotate", func(t *testing.T) error {
			cmd := tokenRotateCmd
			t.Cleanup(func() { _ = cmd.Flags().Set("yes", "false") })
			return runTokenRotate(cmd, []string{"ak-1"})
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

// TestTokenRotate_NonTTYWithoutYes_FailsLoudly is the strict version of the
// table entry above (that loop only t.Logf's when the message is not the
// guard's, because two of its cases can fail at the transport first).
// token rotate's guard fires before any client work, so it can be asserted
// exactly — and it must be, because this is the gate N1 found missing.
func TestTokenRotate_NonTTYWithoutYes_FailsLoudly(t *testing.T) {
	withIsolatedConfigHome(t)
	withNonTTYStdin(t)
	viper.Set("server_url", "http://127.0.0.1:1")
	viper.Set("token", "t")

	cmd := tokenRotateCmd
	t.Cleanup(func() { _ = cmd.Flags().Set("yes", "false") })
	var out bytes.Buffer
	cmd.SetOut(&out)

	err := runTokenRotate(cmd, []string{"ak-live"})
	if err == nil {
		t.Fatal("token rotate returned nil in a non-TTY without --yes; the caller believes the secret was replaced")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Errorf("error = %q, want a message naming --yes", err)
	}
	if !strings.Contains(err.Error(), "ak-live") {
		t.Errorf("error = %q, want it to name the token being rotated", err)
	}
	if strings.Contains(out.String(), "Aborted.") {
		t.Error("printed 'Aborted.' instead of failing; that is the silent no-op this guard removes")
	}
}

// ── N1: the set-completeness assertion ────────────────────────────────────────
//
// The table above is hand-written, and that is exactly how `token rotate` sat
// ungated next to ten guarded siblings for as long as it did: nothing asserted
// the SET was complete, only that the two listed entries behaved. The two maps
// below close that.
//
// MEMBERSHIP RULE (deliberate, and the reason this is a curated list rather
// than a pure heuristic):
//
//	A command requires a --yes gate when running it DESTROYS OR REPLACES
//	durable state that the CLI offers no verb to restore FROM THE ARGUMENTS
//	THE OPERATOR STILL HAS — a credential secret, a policy, an exception, a
//	tenant, an enforcement posture, or a row whose restoring verb needs a
//	field only that row was holding.
//
// Z3 sharpened the second half. It used to read "no verb to restore", full
// stop, and on that reading `team remove` and `coverage expected remove` were
// filed exempt because `team add` / `coverage expected add` exist. That
// misses which ARGUMENTS those verbs need. `team remove <pattern>` takes the
// pattern and destroys the team name; `coverage expected remove <id>` takes an
// opaque id and destroys the client pattern. In both cases the restoring verb
// requires the half the deletion just consumed, and nothing in the operator's
// scrollback holds it. A restoring verb you cannot supply arguments to is not
// a restore path, so both moved into requiresYesGate — and their prompts now
// name the destroyed field, which makes the confirmation itself the record.
//
// A pure heuristic cannot decide that (it cannot tell `admission soak clear`,
// which computes a gate verdict and mutates nothing, from `policy delete`), and
// a pure allowlist cannot notice the ELEVENTH command. So both run:
//
//  1. every command in requiresYesGate must exist and declare --yes; and
//  2. every runnable command in the live tree whose verb sounds destructive
//     must appear in requiresYesGate or in destructiveVerbExempt, with a
//     written reason. A new `foo delete` fails this test on the day it is
//     added, and the author must classify it rather than default into
//     silence.
var requiresYesGate = map[string]string{
	"chainsaw token revoke":             "revokes a live PAT; no un-revoke verb",
	"chainsaw token rotate":             "replaces a live PAT secret in place; no un-rotate verb (N1)",
	"chainsaw auth client rotate":       "deletes + recreates a registry credential; the old secret is gone",
	"chainsaw auth client delete":       "removes a registry credential; clients using it start failing",
	"chainsaw policy delete":            "removes an enforcement policy; packages it blocked stop being blocked",
	"chainsaw policy flip-to-block":     "flips monitor → block org-wide; can wedge every install in CI",
	"chainsaw exception delete":         "removes an exception; installs it allowed start being blocked",
	"chainsaw finding suppress":         "permanently exempts a package@version from enforcement",
	"chainsaw org delete":               "hard-deletes a tenant and every artifact it owns",
	"chainsaw undo":                     "reverses a prior action; the reversal is itself a mutation",
	"chainsaw team remove":              "deletes the routing row; `team add` needs the team name this row was the only record of (Z3)",
	"chainsaw coverage expected remove": "deletes a declared source by id; `coverage expected add` needs the client pattern the id hid (Z3)",
	"chainsaw repo disable":             "takes a repository out of service org-wide; every client resolving through it starts failing",
}

// destructiveVerbExempt lists commands whose verb matches the vocabulary but
// which do NOT meet the membership rule. One line of justification each —
// if you cannot write the justification, the command belongs in
// requiresYesGate instead.
var destructiveVerbExempt = map[string]string{
	"chainsaw admission soak clear": "read-only: evaluates the soak gate and prints a kubectl patch; never applies it",
	"chainsaw telemetry reset":      "resets local telemetry consent; `telemetry on/off` restores it, no server state — and the operator supplies no argument that the reset destroys",
	"chainsaw uninstall-hook":       "removes the local package-manager hook; `install-hook` restores it, and refusing to let someone turn the guard off is worse than the fat-finger risk",
	"chainsaw policy disable":       "stops one rule from firing; `policy enable` restores it, nothing stops working, and the operator supplies no argument the disable destroys",
}

// destructiveVerbVocabulary is the trigger set for rule (2). Matched against
// cmd.Name() — the verb, not the whole path — so it stays readable.
//
// "disable" joined the set with `repo disable`. It is the one verb here that
// destroys nothing, and it earns its place anyway: taking a repository out of
// service stops every client resolving through it, which is an outage whether
// or not a row was deleted. Its presence forces every future `foo disable` to
// be classified — `policy disable` is exempt above precisely because someone
// had to write down why.
var destructiveVerbVocabulary = []string{
	"delete", "revoke", "rotate", "remove", "rm", "purge", "destroy",
	"suppress", "undo", "reset", "clear", "uninstall", "wipe", "prune",
	"drop", "flip-to-block", "disable",
}

// walkRunnableCommands returns every runnable command in the tree rooted at
// root, hidden ones included — a hidden destructive verb is still reachable
// from a script.
func walkRunnableCommands(root *cobra.Command) []*cobra.Command {
	var out []*cobra.Command
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Runnable() {
			out = append(out, c)
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	return out
}

func hasYesFlag(c *cobra.Command) bool {
	return c.Flags().Lookup("yes") != nil || c.InheritedFlags().Lookup("yes") != nil
}

// TestDestructiveCommands_AllDeclareYesFlag is rule (1): every command the
// membership rule covers must actually offer the gate. This is the assertion
// that would have failed on `token rotate` before N1.
func TestDestructiveCommands_AllDeclareYesFlag(t *testing.T) {
	byPath := map[string]*cobra.Command{}
	for _, c := range walkRunnableCommands(rootCmd) {
		byPath[c.CommandPath()] = c
	}
	for path, why := range requiresYesGate {
		cmd, ok := byPath[path]
		if !ok {
			t.Errorf("%q is listed as requiring a --yes gate but no such runnable command exists; "+
				"if it was renamed or removed, update requiresYesGate in this file", path)
			continue
		}
		if !hasYesFlag(cmd) {
			t.Errorf("%q declares no --yes flag, so it cannot be confirmed and cannot be scripted safely.\n"+
				"  why it needs one: %s\n"+
				"  fix: add `cmd.Flags().Bool(\"yes\", false, \"Skip confirmation prompt\")` and the "+
				"non-TTY guard from runTokenRevoke", path, why)
		}
	}
}

// TestDestructiveCommands_SetIsComplete is rule (2): no command with a
// destructive-sounding verb may sit outside BOTH lists. This is the structural
// guard the hand-written table lacked — the eleventh hole cannot open silently.
func TestDestructiveCommands_SetIsComplete(t *testing.T) {
	matches := 0
	for _, c := range walkRunnableCommands(rootCmd) {
		name := c.Name()
		matched := false
		for _, verb := range destructiveVerbVocabulary {
			if name == verb || strings.HasPrefix(name, verb+"-") || strings.HasSuffix(name, "-"+verb) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		matches++
		path := c.CommandPath()
		_, gated := requiresYesGate[path]
		_, exempt := destructiveVerbExempt[path]
		switch {
		case gated && exempt:
			t.Errorf("%q is in BOTH requiresYesGate and destructiveVerbExempt; pick one", path)
		case !gated && !exempt:
			t.Errorf("%q has a destructive verb (%q) but is classified in neither list.\n"+
				"  Decide, in this file, which it is:\n"+
				"    - it destroys or replaces durable state with no restoring verb → add it to\n"+
				"      requiresYesGate AND give it the --yes + non-TTY guard from runTokenRevoke;\n"+
				"    - it is reversible / read-only → add it to destructiveVerbExempt with the reason.\n"+
				"  Defaulting to silence is how `token rotate` shipped ungated.", path, name)
		}
	}
	// Anti-vacuity: if a refactor ever made the walk or the verb match come
	// up empty, this test would "pass" while checking nothing — the exact
	// failure mode it exists to prevent. The tree carried 15 verb matches
	// when this was written; anything below the size of the two lists means
	// the matcher, not the tree, changed.
	if want := len(requiresYesGate) + len(destructiveVerbExempt); matches < want {
		t.Fatalf("verb scan matched only %d commands but the two lists name %d; "+
			"the walk or the vocabulary match is broken, so this test is not actually checking anything",
			matches, want)
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
