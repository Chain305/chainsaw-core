package telemetry

// install_id is the cross-channel identity anchor. A UUIDv7 is generated
// on first run and persisted under the XDG config directory. The ID is
// emitted as the PostHog distinct_id (prefixed "install:") until a
// user-authenticated request arrives — at that point the server issues an
// Alias(install:<id> → user:<user_id>) so the pre-auth events merge into
// the authenticated person.
//
// We intentionally do NOT hash or derive from hardware identifiers: the
// file is the record, and users can blow it away with
// `chainsaw telemetry reset` (or their own `rm`) if they want to be
// counted as a fresh install.

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/google/uuid"
)

const (
	installFilename = "install_id"

	// installIDDisabled is written instead of a real ID when the first run
	// happens with CHAINSAW_TELEMETRY_DISABLED=1. Subsequent runs read
	// this sentinel and remain silent even if the user later unsets the
	// env var — the decision is sticky until they run
	// `chainsaw telemetry reset`.
	installIDDisabled = "disabled"
)

// Install is the persistent install record. ID is the PostHog distinct_id
// material (prefixed "install:" at emit time). Disabled is true when the
// user opted out before the first run was recorded.
type Install struct {
	ID       string
	Disabled bool
}

// LoadInstall resolves the install_id for this binary, creating and
// persisting one on first call. dir is the config directory (typically
// from ConfigDir()). A non-nil error indicates a filesystem problem
// (permissions, disk full); callers may treat that as telemetry-off
// rather than hard-failing the process.
func LoadInstall(dir string) (Install, error) {
	path := filepath.Join(dir, installFilename)
	raw, err := os.ReadFile(path)
	if err == nil {
		val := strings.TrimSpace(string(raw))
		if val == installIDDisabled {
			return Install{Disabled: true}, nil
		}
		if val != "" {
			return Install{ID: val}, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Install{}, err
	}

	// First run — either the file is missing or it was empty. Respect
	// CHAINSAW_TELEMETRY_DISABLED at first run so opted-out users never
	// have an ID written.
	if os.Getenv("CHAINSAW_TELEMETRY_DISABLED") == "1" {
		if err := writeInstallFile(dir, path, installIDDisabled); err != nil {
			return Install{Disabled: true}, err
		}
		return Install{Disabled: true}, nil
	}

	id, err := uuid.NewV7()
	if err != nil {
		return Install{}, err
	}
	value := id.String()
	if err := writeInstallFile(dir, path, value); err != nil {
		return Install{}, err
	}
	return Install{ID: value}, nil
}

// ResetInstall erases the install record so the next run starts fresh.
// Equivalent to `rm ~/.config/chainsaw/install_id` but routed through Go
// for Windows portability.
func ResetInstall(dir string) error {
	path := filepath.Join(dir, installFilename)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ConfigDir returns the XDG-compliant config directory for chainsaw,
// creating it if missing. Honors XDG_CONFIG_HOME on Unix and APPDATA on
// Windows; falls back to $HOME/.config/chainsaw.
func ConfigDir() (string, error) {
	var base string
	switch runtime.GOOS {
	case "windows":
		base = strings.TrimSpace(os.Getenv("APPDATA"))
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, "AppData", "Roaming")
		}
	default:
		base = strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			base = filepath.Join(home, ".config")
		}
	}
	dir := filepath.Join(base, "chainsaw")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

var (
	processInstallOnce sync.Once
	processInstall     Install
	processInstallErr  error
)

// ProcessInstall returns the install record for the current process,
// loading and persisting one on first call. Subsequent calls are a
// map-lookup cost. Errors are sticky — a transient filesystem issue on
// startup downgrades telemetry for the rest of the process.
func ProcessInstall() (Install, error) {
	processInstallOnce.Do(func() {
		dir, err := ConfigDir()
		if err != nil {
			processInstallErr = err
			return
		}
		processInstall, processInstallErr = LoadInstall(dir)
	})
	return processInstall, processInstallErr
}

// DistinctID returns the PostHog distinct_id for the current install.
// Empty string when telemetry is disabled (either the sentinel file or
// a load failure) — callers should treat that as "do not send".
func DistinctID(install Install) string {
	if install.Disabled || install.ID == "" {
		return ""
	}
	return "install:" + install.ID
}

func writeInstallFile(dir, path, value string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(value+"\n"), 0o600)
}
