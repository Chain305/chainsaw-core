package hook

import (
	"bytes"
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
	if err := checkSentinelIntegrity("pip", path, data, hashMarker); err != nil {
		return err
	}
	if len(data) > 0 {
		if err := backupAndNotify(path, opts); err != nil {
			return err
		}
	}
	// Work against the file WITHOUT any block we placed earlier, so a block
	// sitting under the wrong section is relocated rather than duplicated
	// (H8's repair path for existing installs).
	stripped, _ := removeSentinel(data)
	globalIdx := pipGlobalHeaderIndex(stripped)
	if globalIdx >= 0 {
		// BUG-A7-b: the file already has a user-owned [global] section, so
		// emit our keys without our own [global] header — they merge into
		// the existing section instead of producing a duplicate [global]
		// that pip's configparser only half-tolerates (last-wins per key,
		// but visibly messy and a footgun for stricter INI readers).
		body = stripLeadingGlobalHeader(body)
	}
	block := buildBlock(body)
	return writeConfigFile(path, pipSpliceBlock(stripped, block, globalIdx), opts)
}

// pipGlobalHeaderIndex returns the line index of the first `[global]` INI
// section header in data, or -1. Callers pass data with the chainsaw block
// already removed, so any hit is a user-owned section.
func pipGlobalHeaderIndex(data []byte) int {
	lines, _ := splitLines(data)
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "[global]" {
			return i
		}
	}
	return -1
}

// pipSpliceBlock places the chainsaw block immediately after the existing
// [global] header instead of at end of file (H8).
//
// The header-stripping above assumed the block would land under [global], but
// replaceOrAppend appends at EOF — so with a pip.conf shaped
//
//	[global]
//	timeout = 60
//
//	[freeze]
//	timeout = 10
//
// the keys inherited [freeze]. configparser confirmed it: `global has
// index-url? False` / `freeze has index-url? True`. Installs were not routed
// through the proxy at all — a silent enforcement bypass — and index-url is
// not even a valid option for `pip freeze`.
//
// globalIdx < 0 means the body still carries its own [global] header, so
// appending is correct and the section boundary is unambiguous.
func pipSpliceBlock(data, block []byte, globalIdx int) []byte {
	if globalIdx < 0 {
		return replaceOrAppend(data, block)
	}
	nl := detectNewline(data)
	lines, trailingNL := splitLines(data)
	insertAt := globalIdx + 1
	normalized := normalizeNewlines(block, nl)
	var buf bytes.Buffer
	writeLines(&buf, lines[:insertAt], nl, true)
	buf.Write(normalized)
	if !bytes.HasSuffix(normalized, []byte(nl)) {
		buf.WriteString(nl)
	}
	if insertAt < len(lines) {
		writeLines(&buf, lines[insertAt:], nl, trailingNL)
	}
	return buf.Bytes()
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
	// the user having to export PIP_INDEX_URL. A credential-bearing file is
	// created 0600 and an existing looser one is chmod'd down — except at
	// ScopeSystem, where every user has to be able to read it (see
	// credentialFileMode).
	pypiPath, err := orgScopedRepoPath(opts.OrgSlug, "pypi")
	if err != nil {
		return "", err
	}
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		user, pass, err := parseCreds(creds)
		if err != nil {
			return "", err
		}
		// BUG-A6: index-url path must be /repository/@<org>/pypi/simple/.
		// Trailing slash matters — pip treats the suffix as a directory.
		return fmt.Sprintf(`# chainsaw: credentials embedded in index-url below; tighten this
# file's permissions (chmod 600) if your home directory is shared.
[global]
index-url = %s%s:%s@%s/%s/simple/
trusted-host = %s
%s`, scheme, url.PathEscape(user), url.PathEscape(pass), rest, pypiPath, host, defaults), nil
	}
	// pip does not expand env vars in pip.conf, so without embedded creds
	// we only emit the unauthenticated index-url. Users whose proxy
	// requires auth should either re-run install-hook with credentials or
	// set PIP_INDEX_URL with embedded creds in their shell.
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

// parseCreds is splitCreds plus the content check every renderer needs (H4).
//
// Credentials were previously only checked for "both halves non-empty", while
// ServerURL went through rejectDangerous. A secret carrying a newline or a
// sentinel marker could therefore tear the managed block open from inside;
// the syntax-specific hazards (quotes, `&`, `$`) are handled by each
// renderer's own escaper. Returns a precise error rather than a bare bool so
// the user learns which half is wrong.
func parseCreds(raw string) (string, string, error) {
	id, secret, ok := splitCreds(raw)
	if !ok {
		return "", "", fmt.Errorf("credentials: expected \"client_id:client_secret\"")
	}
	if reason := rejectDangerous(id); reason != "" {
		return "", "", fmt.Errorf("credentials: client_id %s", reason)
	}
	if reason := rejectDangerous(secret); reason != "" {
		return "", "", fmt.Errorf("credentials: client_secret %s", reason)
	}
	return id, secret, nil
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
