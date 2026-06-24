package cli

// auth_browser_test.go covers the pure-function helpers in
// auth_browser.go: URL composition, hostname trimming, headless
// detection. The runBrowserAuth listener dance is exercised at the
// integration level (and is hard to unit-test without spinning up a
// real HTTP client).

import (
	"os"
	"testing"
)

// TestNewAuthNonce guards entropy/format so the server's isHexString
// check on /api/auth/cli/session accepts what we produce.
func TestNewAuthNonce(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		n, err := newAuthNonce()
		if err != nil {
			t.Fatalf("newAuthNonce: %v", err)
		}
		if len(n) != 32 {
			t.Errorf("nonce length: got %d, want 32 (%q)", len(n), n)
		}
		if seen[n] {
			t.Errorf("duplicate nonce: %q", n)
		}
		seen[n] = true
		for _, r := range n {
			if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
				t.Errorf("non-hex char %q in nonce %q", r, n)
				break
			}
		}
	}
}

// TestCliHostnameBounded guards the api_keys.name cap: the server uses
// the CLI-provided hostname as a key label and trims it server-side,
// but we also trim client-side so the telemetry + logs stay readable.
func TestCliHostnameBounded(t *testing.T) {
	h := cliHostname()
	if len(h) > 60 {
		t.Errorf("hostname should be capped at 60 chars, got %d: %q", len(h), h)
	}
}

// TestBrowserLikelyAvailableHeadless makes sure the CI env var is
// respected — if $CI is set, we never try to open a browser. This is
// the guard against a CI-runner machine having an `open`-like binary
// that would silently open a hidden browser instance.
func TestBrowserLikelyAvailableHeadless(t *testing.T) {
	// Save + restore $CI so we don't leak into other tests.
	prev, hadCI := os.LookupEnv("CI")
	defer func() {
		if hadCI {
			_ = os.Setenv("CI", prev)
		} else {
			_ = os.Unsetenv("CI")
		}
	}()

	// Force TTY=true via the test seam. Without this, the test would
	// say "not available" for reasons other than CI.
	prevStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	defer func() { stdinIsTerminal = prevStdin }()

	_ = os.Setenv("CI", "1")
	if browserLikelyAvailable() {
		t.Error("browserLikelyAvailable() should return false when $CI is set")
	}
	_ = os.Unsetenv("CI")
}
