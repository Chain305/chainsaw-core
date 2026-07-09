package hook

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// pipManager edits the per-user pip configuration file. Location follows pip
// documentation:
//
//	https://pip.pypa.io/en/stable/topics/configuration/
type pipManager struct{}

func (pipManager) Name() string { return "pip" }

func (pipManager) IsInstalled() bool {
	if _, err := exec.LookPath("pip3"); err == nil {
		return true
	}
	if _, err := exec.LookPath("pip"); err == nil {
		return true
	}
	return false
}

func (m pipManager) ConfigPath() (string, error) {
	return m.ConfigPathForScope(ScopeUser)
}

// ConfigPathForScope picks the target pip config file. For ScopeProject we
// prefer $VIRTUAL_ENV/pip.conf when a venv is active (pip reads it
// automatically) and fall back to ./pip.conf in the current directory so a
// bare `pip install` picks it up. Windows uses pip.ini.
func (pipManager) ConfigPathForScope(scope Scope) (string, error) {
	if scope == ScopeProject {
		name := "pip.conf"
		if runtime.GOOS == "windows" {
			name = "pip.ini"
		}
		if venv := strings.TrimSpace(os.Getenv("VIRTUAL_ENV")); venv != "" {
			return filepath.Join(venv, name), nil
		}
		cwd, err := os.Getwd()
		if err != nil || cwd == "" {
			return "", fmt.Errorf("resolve working dir: %w", err)
		}
		return filepath.Join(cwd, name), nil
	}
	if scope == ScopeSystem {
		switch runtime.GOOS {
		case "windows":
			pd := os.Getenv("ProgramData")
			if pd == "" {
				return "", fmt.Errorf("ProgramData not set")
			}
			return filepath.Join(pd, "pip", "pip.ini"), nil
		case "darwin":
			return "/Library/Application Support/pip/pip.conf", nil
		default:
			return "/etc/pip.conf", nil
		}
	}
	if p := os.Getenv("PIP_CONFIG_FILE"); p != "" {
		return p, nil
	}
	switch runtime.GOOS {
	case "linux":
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return filepath.Join(xdg, "pip", "pip.conf"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		return filepath.Join(home, ".config", "pip", "pip.conf"), nil
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		return filepath.Join(home, "Library", "Application Support", "pip", "pip.conf"), nil
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", fmt.Errorf("APPDATA not set")
		}
		return filepath.Join(appdata, "pip", "pip.ini"), nil
	default:
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		return filepath.Join(home, ".config", "pip", "pip.conf"), nil
	}
}

func (m pipManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	body, err := pipBlockBody(opts)
	if err != nil {
		return err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > 0 {
		if _, err := backup(path); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		// BUG-A7-b: if the existing file already has a non-sentinel
		// [global] section, emit our keys without our own [global]
		// header so they merge into the existing section instead of
		// producing a duplicate [global] that pip's configparser only
		// half-tolerates (last-wins per key, but visibly messy and a
		// footgun for stricter INI readers).
		if hasForeignGlobalSection(data) {
			body = stripLeadingGlobalHeader(body)
		}
	}
	block := buildBlock(body)
	return writeAtomic(path, replaceOrAppend(data, block))
}

// hasForeignGlobalSection reports whether the input contains a
// `[global]` INI section header that lives OUTSIDE the chainsaw-managed
// sentinel block. Used by pip's Wire path so the second-[global] bug
// (BUG-A7-b) is fixed only when there's a real user-owned section to
// merge into.
func hasForeignGlobalSection(data []byte) bool {
	inSentinel := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, sentinelStart) {
			inSentinel = true
			continue
		}
		if strings.HasPrefix(trimmed, sentinelEnd) {
			inSentinel = false
			continue
		}
		if inSentinel {
			continue
		}
		if trimmed == "[global]" {
			return true
		}
	}
	return false
}

// stripLeadingGlobalHeader removes a single `[global]` header line (and
// the optional blank/comment lines immediately preceding it) from the
// start of a pip block body. Leaves the rest untouched so all the
// chainsaw key/value pairs and trailing comments remain intact.
func stripLeadingGlobalHeader(body string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == "[global]" {
			return strings.Join(append(lines[:i], lines[i+1:]...), "\n")
		}
	}
	return body
}

func (m pipManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 || !hasSentinel(data) {
		return ErrNotWired
	}
	if _, err := backup(path); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	newData, removed := removeSentinel(data)
	if !removed {
		return ErrNotWired
	}
	return writeAtomic(path, newData)
}

func (m pipManager) Status() (Status, error) {
	path, err := m.ConfigPath()
	if err != nil {
		return Status{}, err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return Status{ConfigPath: path, Installed: m.IsInstalled()}, err
	}
	return Status{
		ConfigPath: path,
		Wired:      hasSentinel(data),
		Installed:  m.IsInstalled(),
	}, nil
}

// pipBlockBody renders the scaffolded body for pip.conf/pip.ini.
//
// The chainsaw proxy exposes pip traffic as a PEP 503 "simple" index at
// /repository/<repo-name>/simple — the default seed.yaml registers pypi.org
// under the name "pypi" (see configs/seed.yaml:366, client guide uses
// /repository/pypi/simple). pip authenticates via standard basic auth; the
// cleanest user-facing form is URL-embedded credentials, so we emit an
// index-url that expects ${CHAINSAW_TOKEN} to hold a pre-encoded
// "client_id:client_secret" pair. Because exposing a password in an INI
// file — even via env-var substitution, which pip does not perform — is
// brittle, we also emit the unauthenticated form as the default so
// anonymous-access repos work out of the box and we document the auth
// variant in a comment the user can uncomment.
//
// INI-style comments: both "#" and ";" are accepted; we stay with "#" so the
// sentinel markers match.
//
// A non-empty ServerURL is passed through validateServerURL. If it fails
// validation the caller gets an error rather than silent placeholder
// fallback: a user who explicitly provided --server should hear about a bad
// URL, not find out months later that their proxy was never wired up.
func pipBlockBody(opts WireOpts) (string, error) {
	const defaults = "# Defensive baseline (hash-pinning is not yet injected by chainsaw):\nrequire-hashes = false"
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return `[global]
# Uncomment and re-run ` + "`chainsaw --server <url> install-hook pip`" + ` to
# populate real proxy URLs. The chainsaw proxy mounts pip at
# /repository/<repo-name>/simple (default repo name: "pypi").
# index-url = https://<chainsaw-server>/repository/pypi/simple
# trusted-host = <chainsaw-server>
` + defaults, nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	host, ok := pipServerHost(base)
	if !ok {
		return "", fmt.Errorf("invalid server URL: could not derive host")
	}
	scheme, rest := splitScheme(base)
	// When the caller passes client_id:client_secret, embed them in the
	// index-url as percent-encoded userinfo so pip authenticates without
	// the user having to export PIP_INDEX_URL. File mode is 0600 (see
	// writeAtomic) so the secret stays local-only.
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		user, pass, ok := splitCreds(creds)
		if !ok {
			return "", fmt.Errorf("credentials: expected \"client_id:client_secret\"")
		}
		// BUG-A6: index-url path must be /repository/@<org>/pypi/simple/.
		// Trailing slash matters — pip treats the suffix as a directory.
		return fmt.Sprintf(`# chainsaw: credentials embedded in index-url below; tighten this
# file's permissions (chmod 600) if your home directory is shared.
[global]
index-url = %s%s:%s@%s/%s/simple/
trusted-host = %s
%s`, scheme, url.PathEscape(user), url.PathEscape(pass), rest, OrgScopedRepoPath(opts.OrgSlug, "pypi"), host, defaults), nil
	}
	// pip does not expand env vars in pip.conf, so without embedded creds
	// we only emit the unauthenticated index-url. Users whose proxy
	// requires auth should either re-run install-hook with credentials or
	// set PIP_INDEX_URL with embedded creds in their shell.
	pypiPath := OrgScopedRepoPath(opts.OrgSlug, "pypi")
	return fmt.Sprintf(`[global]
index-url = %s/%s/simple/
trusted-host = %s
# For proxies that require basic auth, unset index-url above and instead
# export PIP_INDEX_URL with embedded credentials:
#   export PIP_INDEX_URL=%s${CHAINSAW_TOKEN}@%s/%s/simple/
# where CHAINSAW_TOKEN holds your "client_id:client_secret" pair.
%s`, base, pypiPath, host, scheme, rest, pypiPath, defaults), nil
}

// splitCreds parses a "client_id:client_secret" pair. Returns the two halves
// and true when both are non-empty after trimming. Used by Wire paths that
// want to emit authenticated config.
func splitCreds(raw string) (string, string, bool) {
	parts := strings.SplitN(raw, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	id := strings.TrimSpace(parts[0])
	secret := strings.TrimSpace(parts[1])
	if id == "" || secret == "" {
		return "", "", false
	}
	return id, secret, true
}

// splitScheme returns ("https://", "proxy.example.com") for
// "https://proxy.example.com". For inputs without a scheme it returns
// ("", input). Used to splice a userinfo placeholder between the scheme and
// the host without going through url.Parse / url.String, which would
// percent-encode the "${CHAINSAW_TOKEN}" we want to keep literal.
func splitScheme(raw string) (string, string) {
	idx := strings.Index(raw, "://")
	if idx < 0 {
		return "", raw
	}
	return raw[:idx+3], raw[idx+3:]
}

// pipServerHost returns the bare hostname of a server URL for pip's
// trusted-host directive, which takes a host (and optional :port) without a
// scheme. Returns ("", false) for URLs we can't parse.
func pipServerHost(server string) (string, bool) {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return "", false
	}
	return u.Host, true
}
