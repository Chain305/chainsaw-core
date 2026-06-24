package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRunGuardUpdate_NoTokenGate verifies the free-account gate (D-NUDGE):
// with no token resolvable (flag/env/config/keyring all empty), `guard update`
// must return a non-nil error WITHOUT fetching, and must not write the cache
// file. The embedded offline floor is untouched and not exercised here.
func TestRunGuardUpdate_NoTokenGate(t *testing.T) {
	// Isolated config + empty file cred store ⇒ cfgToken() resolves to "".
	withIsolatedConfigHome(t)
	withFileCredStore(t)

	dst := filepath.Join(t.TempDir(), "known_malicious.json")
	t.Setenv(guardDBEnv, dst)

	err := runGuardUpdate(guardUpdateCmd, nil)
	if err == nil {
		t.Fatal("expected a non-nil error when no token is present, got nil")
	}
	if !strings.Contains(err.Error(), "free account") {
		t.Fatalf("error should mention the free-account gate, got: %v", err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatalf("cache file must not be written when gated; stat err = %v", statErr)
	}
}
