package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

// TestCfgToken_VerboseLogsKeychainOverride confirms the defensive log fires
// when CHAINSAW_VERBOSE is set, --token is provided, AND a keychain entry
// exists for the same server. Operators chasing "why did this work / not
// work" rely on this line during support investigations.
func TestCfgToken_VerboseLogsKeychainOverride(t *testing.T) {
	withIsolatedConfigHome(t)
	store := withFileCredStore(t)
	rebindRootFlagsAfterReset(t)

	const server = "https://chain305.com/chainproxy"
	if err := store.Set(credService, server, "keychain-token"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	t.Setenv("CHAINSAW_VERBOSE", "1")

	// Capture stderr around the cfgToken() call.
	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = origStderr })

	// Simulate the resolved state of a `chainsaw --server X --token Z` run.
	// (We've already covered the end-to-end Execute() flow in
	// TestCfgToken_FlagWinsOverKeychain; here we want a focused check on the
	// log-emission branch of cfgToken itself.)
	if err := rootCmd.PersistentFlags().Set("server", server); err != nil {
		t.Fatalf("set server: %v", err)
	}
	if err := rootCmd.PersistentFlags().Set("token", "flag-token"); err != nil {
		t.Fatalf("set token: %v", err)
	}

	got := cfgToken()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if got != "flag-token" {
		t.Fatalf("cfgToken() = %q, want flag-token", got)
	}
	stderr := buf.String()
	if !strings.Contains(stderr, "ignoring keychain credential") {
		t.Fatalf("expected verbose log mentioning the keychain override, got: %q", stderr)
	}
	if !strings.Contains(stderr, server) {
		t.Fatalf("verbose log should include the server URL for support context, got: %q", stderr)
	}
}

// TestCfgToken_VerboseSilentWithoutKeychain confirms we don't emit the
// defensive log when --token is set but there's no competing keychain entry.
// A noisy "(no keychain entry)" line would just be noise.
func TestCfgToken_VerboseSilentWithoutKeychain(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	rebindRootFlagsAfterReset(t)

	const server = "https://chain305.com/chainproxy"
	t.Setenv("CHAINSAW_VERBOSE", "1")

	origStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = origStderr })

	if err := rootCmd.PersistentFlags().Set("server", server); err != nil {
		t.Fatalf("set server: %v", err)
	}
	if err := rootCmd.PersistentFlags().Set("token", "flag-token"); err != nil {
		t.Fatalf("set token: %v", err)
	}

	got := cfgToken()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	if got != "flag-token" {
		t.Fatalf("cfgToken() = %q, want flag-token", got)
	}
	if strings.Contains(buf.String(), "ignoring keychain") {
		t.Fatalf("should not log keychain-override when keychain is empty, got: %q", buf.String())
	}
}
