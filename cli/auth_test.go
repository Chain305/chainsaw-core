package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestAuthClient_RejectsWhenNoServerConfigured pins the D1b fix: the
// `auth client` command used to silently drop secrets when no server
// was configured (the credstore write happened behind a non-empty
// server URL gate). The new behaviour is a clean, actionable early exit
// before any subcommand work runs — surfaced via the parent's RunE so
// every subcommand inherits the same fast-fail.
func TestAuthClient_RejectsWhenNoServerConfigured(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)

	// No server in viper at all — simulates a user who has never logged in.
	cmd := authClientCmd()
	// SetArgs([]) so cobra doesn't try to interpret the test runner's
	// args (-test.run=...) as a subcommand.
	cmd.SetArgs([]string{})

	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetIn(strings.NewReader("")) // belt-and-braces: no prompt input

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error when no server is configured, got nil\nstdout: %s\nstderr: %s", out.String(), errb.String())
	}
	if !strings.Contains(err.Error(), "no server configured") {
		t.Fatalf("error should mention missing server, got: %v", err)
	}
	// Make sure the hint points the user at a concrete next step.
	if !strings.Contains(err.Error(), "chainsaw auth login") && !strings.Contains(err.Error(), "CHAINSAW_SERVER") {
		t.Fatalf("error should suggest how to fix, got: %v", err)
	}
}
