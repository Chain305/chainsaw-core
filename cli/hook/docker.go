package hook

// dockerManager writes /etc/docker/daemon.json (or the platform
// equivalent). Docker's daemon.json is strict JSON — no comments —
// so this manager emits a whole-file standalone JSON document when the
// target doesn't exist yet, and refuses to touch an existing file
// without --force. The sentinel-block pattern used by INI / TOML
// managers doesn't apply.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type dockerManager struct{}

func (dockerManager) Name() string { return "docker" }

func (dockerManager) IsInstalled() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

func (m dockerManager) ConfigPath() (string, error) {
	return m.ConfigPathForScope(ScopeUser)
}

// ConfigPathForScope: ScopeSystem is the only scope Docker daemon
// configuration can live in — daemon.json is per-host, not per-user.
// User scope falls back to a writable location for testing but the CLI
// should warn that user-scope Docker wiring has no effect until the
// daemon reloads from the system file.
func (dockerManager) ConfigPathForScope(scope Scope) (string, error) {
	switch scope {
	case ScopeProject:
		cwd, err := os.Getwd()
		if err != nil || cwd == "" {
			return "", fmt.Errorf("resolve working dir: %w", err)
		}
		return filepath.Join(cwd, "daemon.json"), nil
	case ScopeSystem:
		switch runtime.GOOS {
		case "windows":
			pd := os.Getenv("ProgramData")
			if pd == "" {
				return "", fmt.Errorf("ProgramData not set")
			}
			return filepath.Join(pd, "docker", "config", "daemon.json"), nil
		default:
			return "/etc/docker/daemon.json", nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".docker", "daemon.json"), nil
}

func (m dockerManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return fmt.Errorf("docker hook requires --server")
	}
	base, err := validateServerURL(server)
	if err != nil {
		return err
	}

	// daemon.json is strict JSON — merge mirror entries into whatever's
	// already there, don't overwrite the file.
	existing := map[string]any{}
	data, readErr := readOrEmpty(path)
	if readErr != nil {
		return fmt.Errorf("read %s: %w", path, readErr)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &existing); err != nil {
			return fmt.Errorf("parse existing daemon.json: %w", err)
		}
		if _, err := backup(path); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
	}
	mirrors, _ := existing["registry-mirrors"].([]any)
	chainsawMirror := base
	found := false
	for _, m := range mirrors {
		if s, ok := m.(string); ok && s == chainsawMirror {
			found = true
			break
		}
	}
	if !found {
		mirrors = append([]any{chainsawMirror}, mirrors...)
	}
	existing["registry-mirrors"] = mirrors

	out, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal daemon.json: %w", err)
	}
	return writeAtomic(path, append(out, '\n'))
}

func (m dockerManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return ErrNotWired
	}
	existing := map[string]any{}
	if err := json.Unmarshal(data, &existing); err != nil {
		return fmt.Errorf("parse daemon.json: %w", err)
	}
	mirrors, _ := existing["registry-mirrors"].([]any)
	filtered := mirrors[:0]
	removed := false
	for _, entry := range mirrors {
		s, ok := entry.(string)
		if !ok {
			filtered = append(filtered, entry)
			continue
		}
		if strings.Contains(s, "your-chainsaw-server") || strings.Contains(s, "chainsaw") {
			removed = true
			continue
		}
		filtered = append(filtered, entry)
	}
	if !removed {
		return ErrNotWired
	}
	if len(filtered) == 0 {
		delete(existing, "registry-mirrors")
	} else {
		existing["registry-mirrors"] = filtered
	}
	if _, err := backup(path); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	out, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal daemon.json: %w", err)
	}
	return writeAtomic(path, append(out, '\n'))
}

func (m dockerManager) Status() (Status, error) {
	path, err := m.ConfigPath()
	if err != nil {
		return Status{}, err
	}
	data, readErr := readOrEmpty(path)
	if readErr != nil {
		return Status{ConfigPath: path, Installed: m.IsInstalled()}, readErr
	}
	wired := false
	if len(data) > 0 {
		existing := map[string]any{}
		if err := json.Unmarshal(data, &existing); err == nil {
			if mirrors, ok := existing["registry-mirrors"].([]any); ok {
				for _, entry := range mirrors {
					if s, ok := entry.(string); ok {
						if strings.Contains(s, "chainsaw") {
							wired = true
							break
						}
					}
				}
			}
		}
	}
	return Status{ConfigPath: path, Wired: wired, Installed: m.IsInstalled()}, nil
}
