// Package credstore abstracts secret storage. Backends: the OS keyring (macOS
// Keychain, Windows Credential Manager, libsecret/KWallet on Linux) and a
// file fallback for headless Linux / CI environments where no secret service
// is reachable. Non-secret config stays in YAML; this package only handles
// values that should not live in plaintext next to the rest of the settings.
package credstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	keyring "github.com/zalando/go-keyring"

	"github.com/chain305/chainsaw-core/cli/platform"
	"github.com/chain305/chainsaw-core/cli/secureio"
)

// Store is the credential storage interface. Backends: OS keyring (primary)
// and file (fallback). Account scopes credentials to a specific server URL
// so multiple profiles coexist under one service name.
type Store interface {
	Get(service, account string) (string, error)
	Set(service, account, secret string) error
	Delete(service, account string) error
}

// ErrNotFound is returned when no credential exists for the given key.
var ErrNotFound = errors.New("credential not found")

var (
	defaultOnce  sync.Once
	defaultStore Store
)

// Default returns the best available store for the current environment. It
// prefers the OS keyring but falls back to a file store when the keyring is
// unavailable (common in headless Linux / CI). The probe is cached because
// D-Bus calls on Linux are not cheap.
func Default() Store {
	defaultOnce.Do(func() {
		if probeKeyring() {
			defaultStore = keyringStore{}
			return
		}
		defaultStore = newFileStore(defaultFilePath())
	})
	return defaultStore
}

// ForceFileBackend returns a file-backed store pinned to path. Tests use this
// to avoid touching the real OS keyring.
func ForceFileBackend(path string) Store {
	return newFileStore(path)
}

func defaultFilePath() string {
	return filepath.Join(platform.ConfigHome(), "credentials.json")
}

// probeKeyring does a round-trip Set/Delete to decide if the OS keyring is
// usable. Any error (no D-Bus session, locked keychain, unsupported platform)
// falls us through to the file store.
func probeKeyring() bool {
	const probeSvc, probeAcct = "chainsaw-probe", "probe"
	if err := keyring.Set(probeSvc, probeAcct, "1"); err != nil {
		return false
	}
	if err := keyring.Delete(probeSvc, probeAcct); err != nil {
		return false
	}
	return true
}

// --- keyring backend ------------------------------------------------------

type keyringStore struct{}

func (keyringStore) Get(service, account string) (string, error) {
	v, err := keyring.Get(service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("keyring get: %w", err)
	}
	return v, nil
}

func (keyringStore) Set(service, account, secret string) error {
	if err := keyring.Set(service, account, secret); err != nil {
		return fmt.Errorf("keyring set: %w", err)
	}
	return nil
}

func (keyringStore) Delete(service, account string) error {
	if err := keyring.Delete(service, account); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("keyring delete: %w", err)
	}
	return nil
}

// --- file backend ---------------------------------------------------------

type fileStore struct {
	path string
	mu   sync.Mutex
}

func newFileStore(path string) *fileStore {
	return &fileStore{path: path}
}

func fileKey(service, account string) string {
	return service + "::" + account
}

func (f *fileStore) load() (map[string]string, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read creds: %w", err)
	}
	if len(data) == 0 {
		return map[string]string{}, nil
	}
	out := map[string]string{}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse creds: %w", err)
	}
	return out, nil
}

func (f *fileStore) save(m map[string]string) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("encode creds: %w", err)
	}
	return secureio.WriteFile(f.path, data)
}

func (f *fileStore) Get(service, account string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return "", err
	}
	v, ok := m[fileKey(service, account)]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (f *fileStore) Set(service, account, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return err
	}
	m[fileKey(service, account)] = secret
	return f.save(m)
}

func (f *fileStore) Delete(service, account string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return err
	}
	key := fileKey(service, account)
	if _, ok := m[key]; !ok {
		return ErrNotFound
	}
	delete(m, key)
	return f.save(m)
}
