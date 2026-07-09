package credstore

import (
	"errors"
	"path/filepath"
	"testing"
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
