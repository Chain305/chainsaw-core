package hook

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// bunManager wires bun via its npm-compat config (.npmrc) — NOT via
// bunfig.toml's [install.registry] block.
//
// Wave U (2026-05-23) live-verify against bun 1.3.12 (smoke org
// smoke-appsec-20260520) confirmed BOTH bunfig.toml shapes are silently
// ignored by bun for authenticated chainsaw proxies:
//
//   - URL-embedded single-line:  registry = "https://user:pass@host/..."
//   - Two-field form we shipped: [install.registry] url=..., token=...
//
// In both cases bun makes ZERO requests to chain305 and falls back to
// registry.npmjs.org via Cloudflare — supply-chain protection bypassed
// entirely. Evidence:
//   - qa/smoke-evidence/20260523-wave-S-deep/21_bun_block.txt
//   - qa/smoke-evidence/20260523-wave-S-deep/22_bun_two_field_probe.txt
//
// bun's npm-compat layer DOES honor the .npmrc form (registry= +
// //host/path:_auth=<base64> + :always-auth=true), so we emit exactly the
// shape renderNpm uses on the server config-snippet path. The file we
// touch is .npmrc — the bun config-path mapping is renamed accordingly.
type bunManager struct{}

func (bunManager) Name() string { return "bun" }

func (bunManager) IsInstalled() bool {
	_, err := exec.LookPath("bun")
	return err == nil
}

func (m bunManager) ConfigPath() (string, error) {
	return m.ConfigPathForScope(ScopeUser)
}

// ConfigPathForScope returns the .npmrc bun's npm-compat layer reads.
// Wave U: previously we wrote bunfig.toml; bun ignored every shape we
// could emit for authenticated registries (see bun.go preamble).
func (bunManager) ConfigPathForScope(scope Scope) (string, error) {
	switch scope {
	case ScopeProject:
		cwd, err := os.Getwd()
		if err != nil || cwd == "" {
			return "", fmt.Errorf("resolve working dir: %w", err)
		}
		return filepath.Join(cwd, ".npmrc"), nil
	case ScopeSystem:
		if runtime.GOOS == "windows" {
			pd := os.Getenv("ProgramData")
			if pd == "" {
				return "", fmt.Errorf("ProgramData not set")
			}
			return filepath.Join(pd, "npm", "etc", "npmrc"), nil
		}
		return "/etc/npmrc", nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".npmrc"), nil
}

func (m bunManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	body, err := bunBlockBody(opts)
	if err != nil {
		return err
	}
	return writeWithBackup(path, body)
}

func (m bunManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	return unwireBlock(path)
}

func (m bunManager) Status() (Status, error) {
	return statusForConfig(m.ConfigPath, m.IsInstalled)
}

// bunBlockBody renders the .npmrc body bun's npm-compat layer honors.
// Shape mirrors renderNpm in internal/server/server_configsnippets.go —
// the gold standard for base64 _auth — exactly so the two surfaces
// cannot drift apart.
func bunBlockBody(opts WireOpts) (string, error) {
	const header = "# Wave U (2026-05-23): bun's bunfig.toml install.registry block is\n" +
		"# silently ignored by bun 1.3.12 for authenticated chainsaw proxies\n" +
		"# (both the URL-embedded and two-field forms fall back to\n" +
		"# registry.npmjs.org). bun DOES honor .npmrc via its npm-compat\n" +
		"# layer, so chainsaw install-hook bun writes here instead.\n"
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return header +
			"# Uncomment and re-run `chainsaw --server <url> install-hook bun` to\n" +
			"# populate real proxy URLs. Chainsaw mounts bun packages under the\n" +
			"# org-scoped npmjs repo at /repository/@<org>/npmjs/.\n" +
			"# registry=https://<chainsaw-server>/repository/@<org>/npmjs/\n" +
			"# //<chainsaw-server>/repository/@<org>/npmjs/:_auth=<base64(client_id:secret)>\n" +
			"# //<chainsaw-server>/repository/@<org>/npmjs/:always-auth=true", nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	hostPath, ok := bunNpmHostPath(base)
	if !ok {
		return "", fmt.Errorf("invalid server URL: could not derive host/path")
	}
	// BUG-A6: org-scoped path required (/repository/@<org>/npmjs/).
	bunPath := OrgScopedRepoPath(opts.OrgSlug, "npmjs")
	authLine := "<base64(client_id:secret)>"
	credsNote := ""
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		id, secret, ok := splitCreds(creds)
		if !ok {
			return "", fmt.Errorf("credentials: expected \"client_id:client_secret\"")
		}
		authLine = base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
		credsNote = "# chainsaw: credentials embedded as base64(client_id:secret) in :_auth\n" +
			"# below; tighten this file's permissions (chmod 600) if your home\n" +
			"# directory is shared.\n"
	}
	// hostPath carries the leading `//` already (npm _auth line format).
	return fmt.Sprintf("%s%sregistry=%s/%s/\n%s/%s/:_auth=%s\n%s/%s/:always-auth=true",
		header, credsNote, base, bunPath, hostPath, bunPath, authLine, hostPath, bunPath), nil
}

// bunNpmHostPath strips the scheme from a server URL so it can be used
// as the //host/path/ key in an .npmrc _auth line. Mirrors npm.go's
// npmAuthHostPath — we keep a separate copy rather than exporting it
// from npm.go because bun's wire path may diverge in future (e.g.,
// :_authToken vs :_auth shape choice).
func bunNpmHostPath(server string) (string, bool) {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return "", false
	}
	path := strings.TrimRight(u.Path, "/")
	return "//" + u.Host + path, true
}
