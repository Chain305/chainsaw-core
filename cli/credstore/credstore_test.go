package credstore

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// The real OS keyring backend requires a live daemon / session (macOS
// Keychain, Windows Credential Manager, libsecret on Linux) and is not
// exercised from unit tests. File-backend coverage below is the contract.

func TestFileStore_SetGetDeleteRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	s := ForceFileBackend(path)

	const svc, acct, secret = "chainsaw", "https://example.com", "tok-abc"
	if err := s.Set(svc, acct, secret); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get(svc, acct)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != secret {
		t.Fatalf("Get = %q, want %q", got, secret)
	}
	if err := s.Delete(svc, acct); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(svc, acct); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete err = %v, want ErrNotFound", err)
	}
}

func TestFileStore_GetMissingReturnsErrNotFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	s := ForceFileBackend(path)

	_, err := s.Get("chainsaw", "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get err = %v, want ErrNotFound", err)
	}
}

func TestFileStore_DeleteMissingReturnsErrNotFound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	s := ForceFileBackend(path)

	err := s.Delete("chainsaw", "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete err = %v, want ErrNotFound", err)
	}
}

func TestFileStore_MultipleAccounts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	s := ForceFileBackend(path)

	accounts := map[string]string{
		"https://prod.example.com":    "tok-prod",
		"https://staging.example.com": "tok-staging",
	}
	for acct, tok := range accounts {
		if err := s.Set("chainsaw", acct, tok); err != nil {
			t.Fatalf("Set(%s): %v", acct, err)
		}
	}
	for acct, want := range accounts {
		got, err := s.Get("chainsaw", acct)
		if err != nil {
			t.Fatalf("Get(%s): %v", acct, err)
		}
		if got != want {
			t.Fatalf("Get(%s) = %q, want %q", acct, got, want)
		}
	}
}

// --- probeKeyring (Y9) -----------------------------------------------------

// withProbeStub swaps the keyring round-trip and the probe timeout for the
// duration of a test.
func withProbeStub(t *testing.T, fn func() error, timeout time.Duration) {
	t.Helper()
	prevFn, prevTO := keyringRoundTrip, probeKeyringTimeout
	keyringRoundTrip, probeKeyringTimeout = fn, timeout
	t.Cleanup(func() { keyringRoundTrip, probeKeyringTimeout = prevFn, prevTO })
}

// TestProbeKeyring_BlockedBackendFallsThrough is the Y9 regression. go-keyring
// has no context API and its darwin backend execs `/usr/bin/security -i` then
// Wait()s forever, so an unusable login keychain ($HOME with no
// Library/Keychains) makes the probe BLOCK instead of erroring. Before the fix
// probeKeyring never returned and every authenticated command hung; now the
// timeout expires and we report the keyring as unusable so Default() falls
// through to the file store.
func TestProbeKeyring_BlockedBackendFallsThrough(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	withProbeStub(t, func() error { <-release; return nil }, 100*time.Millisecond)

	result := make(chan bool, 1)
	start := time.Now()
	go func() { result <- probeKeyring() }()

	select {
	case usable := <-result:
		if usable {
			t.Fatal("probeKeyring() = true for a backend that never answered; want false so Default() uses the file store")
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("probeKeyring took %s to give up; want ~%s", elapsed, probeKeyringTimeout)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probeKeyring blocked on an unusable keyring backend (Y9): every authenticated command would hang here")
	}
}

// TestProbeKeyring_HealthyBackendSelectsKeyring pins the must-not-regress side:
// a keyring that answers promptly is still reported usable.
func TestProbeKeyring_HealthyBackendSelectsKeyring(t *testing.T) {
	withProbeStub(t, func() error { return nil }, 2*time.Second)
	if !probeKeyring() {
		t.Fatal("probeKeyring() = false for a healthy backend; want true")
	}
}

// TestProbeKeyring_ErroringBackendFallsThrough covers the Linux/headless path:
// no secret service → immediate error → file store, without waiting out the
// timeout.
func TestProbeKeyring_ErroringBackendFallsThrough(t *testing.T) {
	withProbeStub(t, func() error { return errors.New("no secret service") }, 10*time.Second)
	start := time.Now()
	if probeKeyring() {
		t.Fatal("probeKeyring() = true for an erroring backend; want false")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("erroring backend waited %s; it must fail fast, not sit on the timeout", elapsed)
	}
}
