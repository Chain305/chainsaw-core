package hook

// dockerManager writes /etc/docker/daemon.json (or the platform
// equivalent). Docker's daemon.json is strict JSON — no comments —
// so this manager emits a whole-file standalone JSON document when the
// target doesn't exist yet, and refuses to touch an existing file
// without --force. The sentinel-block pattern used by INI / TOML
// managers doesn't apply.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/chain305/chainsaw-core/cli/secureio"
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
	// Docker is the one manager that does NOT take the server's base path.
	// Every other renderer builds `<server>/repository/@<org>/<eco>/`, so it
	// needs whatever prefix the deployment is mounted behind — but dockerd
	// validates registry-mirrors entries and refuses to start on a URL that
	// carries a path, query or fragment. Reduce to scheme://host; the docker
	// registry is served from the host root under /v2/ regardless.
	mirrorBase, err := dockerMirrorBase(base)
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
	chainsawMirror := mirrorBase
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
	if err := writeConfigFile(path, append(out, '\n'), opts); err != nil {
		return err
	}
	// Record exactly what we inserted so Unwire/Status can match on equality
	// (H3). The record lives OUT OF BAND: dockerd validates daemon.json keys
	// and refuses to start on an unknown directive, so a "chainsaw-managed-
	// mirror" key inside the file would turn an unremovable mirror into a
	// dead Docker daemon.
	return recordDockerMirror(path, chainsawMirror)
}

// dockerMirrorBase reduces an already-validated server URL to the
// scheme://host form dockerd accepts as a registry mirror.
//
// dockerd rejects a mirror with a path ("invalid mirror: path, query, or
// fragment at end of the URI"), so an operator whose proxy is mounted at
// https://chain305.com/chainproxy still gets https://chain305.com here.
// Docker's own reference grammar can't express the org-scoped `@slug` URL
// either — the server exposes a docker-compatible `chainproxy/<repo>/<image>`
// image-name shape instead (stripChainproxyDockerPrefix, server-side), which
// travels in the image reference rather than in the mirror URL.
func dockerMirrorBase(serverURL string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid server URL: could not derive host for the docker registry mirror")
	}
	return u.Scheme + "://" + u.Host, nil
}

// dockerSidecarPath is the out-of-band record of the mirrors chainsaw added
// to a given daemon.json. dockerd never reads it.
func dockerSidecarPath(daemonPath string) string { return daemonPath + ".chainsaw" }

type dockerSidecar struct {
	Mirrors []string `json:"mirrors"`
}

func readDockerSidecar(daemonPath string) dockerSidecar {
	var rec dockerSidecar
	data, err := readOrEmpty(dockerSidecarPath(daemonPath))
	if err != nil || len(data) == 0 {
		return rec
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		return dockerSidecar{}
	}
	return rec
}

func recordDockerMirror(daemonPath, mirror string) error {
	rec := readDockerSidecar(daemonPath)
	for _, m := range rec.Mirrors {
		if m == mirror {
			return nil
		}
	}
	rec.Mirrors = append(rec.Mirrors, mirror)
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal chainsaw mirror record: %w", err)
	}
	if err := secureio.WriteFile(dockerSidecarPath(daemonPath), append(out, '\n')); err != nil {
		return fmt.Errorf("write chainsaw mirror record: %w", err)
	}
	return nil
}

// dockerMirrorMatcher returns a predicate that reports whether a mirror entry
// was inserted by chainsaw, plus whether the answer is authoritative.
//
// H3: the old test was `strings.Contains(s, "chainsaw")`. The production host
// is chain305.com, which contains no "chainsaw" — so the mirror could never
// be removed and Status permanently reported not-wired. Conversely an
// unrelated user mirror like https://mirror.internal/chainsaw-cache DID match
// and was deleted.
//
// With a sidecar we match on exact equality. Without one (an install from
// before this fix) we fall back to the one unambiguous marker: the visible
// placeholder host chainsaw writes when no server is configured. Anything
// else is genuinely undecidable from the file alone, which is what
// UnwireDockerMirror is for.
func dockerMirrorMatcher(daemonPath string) (match func(string) bool, authoritative bool) {
	rec := readDockerSidecar(daemonPath)
	if len(rec.Mirrors) > 0 {
		set := make(map[string]bool, len(rec.Mirrors))
		for _, m := range rec.Mirrors {
			set[m] = true
		}
		return func(s string) bool { return set[s] }, true
	}
	return func(s string) bool { return strings.Contains(s, "your-chainsaw-server") }, false
}

// UnwireDockerMirror removes one exact registry-mirror entry from the docker
// daemon config. It is the escape hatch for hosts wired before the sidecar
// existed, where the mirror URL cannot be recovered from the file:
//
//	chainsaw uninstall-hook docker --mirror https://chain305.com
func UnwireDockerMirror(scope Scope, mirror string) error {
	mirror = strings.TrimSpace(mirror)
	if mirror == "" {
		return fmt.Errorf("mirror URL is required")
	}
	path, err := dockerManager{}.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	return removeDockerMirrors(path, func(s string) bool { return s == mirror })
}

func (m dockerManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	match, _ := dockerMirrorMatcher(path)
	return removeDockerMirrors(path, match)
}

// removeDockerMirrors drops every registry-mirror entry satisfying match,
// backs the file up, and clears the sidecar record on success.
func removeDockerMirrors(path string, match func(string) bool) error {
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
	filtered := make([]any, 0, len(mirrors))
	removed := false
	for _, entry := range mirrors {
		s, ok := entry.(string)
		if ok && match(s) {
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
	if err := writeAtomic(path, append(out, '\n')); err != nil {
		return err
	}
	if err := os.Remove(dockerSidecarPath(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove chainsaw mirror record: %w", err)
	}
	return nil
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
	match, _ := dockerMirrorMatcher(path)
	wired := false
	if len(data) > 0 {
		existing := map[string]any{}
		if err := json.Unmarshal(data, &existing); err == nil {
			if mirrors, ok := existing["registry-mirrors"].([]any); ok {
				for _, entry := range mirrors {
					if s, ok := entry.(string); ok && match(s) {
						wired = true
						break
					}
				}
			}
		}
	}
	return Status{ConfigPath: path, Wired: wired, Installed: m.IsInstalled()}, nil
}
