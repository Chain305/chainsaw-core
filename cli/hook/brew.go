package hook

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// brewManager edits brew's user env file (~/.homebrew/brew.env, or
// $XDG_CONFIG_HOME/homebrew/brew.env). brew reads only HOMEBREW_* lines from
// it, literally (NAME=value, no quoting, no expansion), and ignores the rest,
// so the "#" sentinel block is safe there.
//
// A proxy can enforce only the bottle hop (docs/PLANS_INTELLIGENCE.md
// #plan-homebrew-ecosystem): HOMEBREW_ARTIFACT_DOMAIN rewrites ghcr.io
// bottle URLs only, and HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1 is the one
// fail-closed knob brew has. HOMEBREW_API_DOMAIN is cache-only — the API is
// JWS-signed and brew falls back to formulae.brew.sh on any error.
type brewManager struct{}

// brewRepoName is the repository the proxy serves Homebrew from.
const brewRepoName = "homebrew"

// BrewSystemEnvPath is the machine-wide brew.env (MDM delivery). A var so
// tests never read the developer's real /etc.
var BrewSystemEnvPath = "/etc/homebrew/brew.env"

// BrewUserEnvPath is the per-user brew.env brew reads.
func BrewUserEnvPath() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "homebrew", "brew.env"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".homebrew", "brew.env"), nil
}

func (brewManager) Name() string { return "brew" }

func (brewManager) IsInstalled() bool {
	_, err := exec.LookPath("brew")
	return err == nil
}

func (m brewManager) ConfigPath() (string, error) { return m.ConfigPathForScope(ScopeUser) }

func (brewManager) ConfigPathForScope(scope Scope) (string, error) {
	switch scope {
	case ScopeSystem:
		return BrewSystemEnvPath, nil
	case ScopeProject:
		return "", errors.New("brew has no project-scoped config; use --scope user or --scope system")
	}
	return BrewUserEnvPath()
}

func (m brewManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	body, err := brewBlockBody(opts)
	if err != nil {
		return err
	}
	return writeWithBackup(m.Name(), path, body, opts)
}

func (m brewManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	return unwireBlock(path)
}

// Status reports Wired only when brew would actually route bottles through
// a Chainsaw repository and fail closed: the effective brew.env (system file,
// then the user file, which brew loads last) sets HOMEBREW_ARTIFACT_DOMAIN to
// a /repository/ URL and HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1. A block of
// commented placeholders, or a domain without NO_FALLBACK (brew silently
// falls back to ghcr.io), is not wired.
func (m brewManager) Status() (Status, error) {
	path, err := m.ConfigPath()
	if err != nil {
		return Status{}, err
	}
	env := map[string]string{}
	for _, p := range []string{BrewSystemEnvPath, path} {
		data, rerr := readOrEmpty(p)
		if rerr != nil {
			return Status{ConfigPath: path, Installed: m.IsInstalled()}, rerr
		}
		for k, v := range ParseBrewEnv(data) {
			env[k] = v
		}
	}
	routed := strings.Contains(env["HOMEBREW_ARTIFACT_DOMAIN"], "/repository/") &&
		brewTruthy(env["HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK"])
	return Status{ConfigPath: path, Wired: routed, Installed: m.IsInstalled()}, nil
}

// brewTruthy is brew's boolean env reading: set and not one of its falsy
// spellings.
func brewTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "0", "false", "no", "off":
		return false
	}
	return true
}

// ParseBrewEnv reads brew.env the way brew does: HOMEBREW_* lines only,
// literal NAME=value, later lines win.
func ParseBrewEnv(data []byte) map[string]string {
	out := map[string]string{}
	lines, _ := splitLines(data)
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "HOMEBREW_") {
			continue
		}
		if k, v, ok := strings.Cut(ln, "="); ok {
			out[k] = v
		}
	}
	return out
}

// brewBlockBody renders the routing lines. Credentials ride as
// HOMEBREW_DOCKER_REGISTRY_BASIC_AUTH_TOKEN (base64 id:secret), which brew
// sends on the ghcr-style bottle requests; without them the repository must
// allow anonymous reads.
func brewBlockBody(opts WireOpts) (string, error) {
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return `# Re-run ` + "`chainsaw --server <url> install-hook brew`" + ` to populate real
# proxy URLs. The chainsaw proxy serves Homebrew at /repository/<repo-name>/
# (default repo name: "homebrew").
# HOMEBREW_API_DOMAIN=https://<chainsaw-server>/repository/homebrew/api
# HOMEBREW_ARTIFACT_DOMAIN=https://<chainsaw-server>/repository/homebrew
# HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1`, nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	repo, err := orgScopedRepoPath(opts.OrgSlug, brewRepoName)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(credentialHeaderNote("HOMEBREW_DOCKER_REGISTRY_BASIC_AUTH_TOKEN below, base64", opts))
	fmt.Fprintf(&b, "HOMEBREW_API_DOMAIN=%s/%s/api\n", base, repo)
	fmt.Fprintf(&b, "HOMEBREW_ARTIFACT_DOMAIN=%s/%s\n", base, repo)
	b.WriteString("HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1")
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		if _, _, err := parseCreds(creds); err != nil {
			return "", err
		}
		b.WriteString("\nHOMEBREW_DOCKER_REGISTRY_BASIC_AUTH_TOKEN=" + base64.StdEncoding.EncodeToString([]byte(creds)))
	}
	return b.String(), nil
}

// ── the server-compiled policy block (`chainsaw brew env --write`) ─────────

// The policy block has its own markers so it never collides with the
// install-hook routing block in the same file.
const (
	brewPolicyBodyStart = ">>> chainsaw-brew-policy >>>"
	brewPolicyBodyEnd   = "<<< chainsaw-brew-policy <<<"
)

// BrewPolicyMarkers are the policy block's marker lines, so a caller can
// refuse content that would forge them.
var BrewPolicyMarkers = []string{"# " + brewPolicyBodyStart, "# " + brewPolicyBodyEnd}

func brewPolicyMarker(line string) markerKind {
	switch strings.TrimSpace(line) {
	case BrewPolicyMarkers[0]:
		return markerStart
	case BrewPolicyMarkers[1]:
		return markerEnd
	}
	return markerNone
}

// WriteBrewPolicy replaces (or appends) the policy block in path, keeping
// every other line, atomically; a new file is 0644 (brew.env carries no
// secret here and /etc/homebrew/brew.env must stay world-readable). The
// caller validates body first.
func WriteBrewPolicy(path, body string) error {
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if corrupt, why := sentinelCorrupt(data, brewPolicyMarker); corrupt {
		return fmt.Errorf("%s has a malformed chainsaw-brew-policy block (%s); fix or remove it by hand", path, why)
	}
	block := BrewPolicyMarkers[0] + "\n" + strings.TrimRight(body, "\n") + "\n" + BrewPolicyMarkers[1] + "\n"
	return writeAtomicMode(path, replaceOrAppendWith(data, []byte(block), brewPolicyMarker), 0o644)
}
