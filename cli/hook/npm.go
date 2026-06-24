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

// npmManager edits ~/.npmrc (or $NPM_CONFIG_USERCONFIG when set). npm uses
// the same file name on Windows as on POSIX.
type npmManager struct{}

func (npmManager) Name() string { return "npm" }

func (npmManager) IsInstalled() bool {
	_, err := exec.LookPath("npm")
	return err == nil
}

func (m npmManager) ConfigPath() (string, error) {
	return m.ConfigPathForScope(ScopeUser)
}

// ConfigPathForScope returns ~/.npmrc for ScopeUser and ./.npmrc in the
// current directory for ScopeProject. npm reads the project file
// automatically when present, so dropping it in cwd is enough.
func (npmManager) ConfigPathForScope(scope Scope) (string, error) {
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
	if p := os.Getenv("NPM_CONFIG_USERCONFIG"); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".npmrc"), nil
}

func (m npmManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	body, err := npmBlockBody(opts)
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
	}
	block := buildBlock(body)
	return writeAtomic(path, replaceOrAppend(data, block))
}

func (m npmManager) Unwire(scope Scope) error {
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

func (m npmManager) Status() (Status, error) {
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

// npmBlockBody renders the scaffolded body for .npmrc.
//
// The chainsaw proxy exposes npm traffic at /repository/<repo-name>/ — the
// default seed.yaml registers the upstream registry.npmjs.org mirror under the
// name "npmjs" (see configs/seed.yaml:188). Authentication is basic-auth
// style "client_id:client_secret"; the proxy also accepts the same value as
// "Authorization: Bearer <client_id>:<client_secret>" which is what npm emits
// when _authToken is set. We reference ${CHAINSAW_TOKEN} as the env var the
// user populates with their client_id:client_secret pair (see
// configs/seed.yaml for the client-configuration guide).
//
// When opts.ServerURL is empty we keep the lines commented so the config
// stays valid; ignore-scripts=true is a defensive default that hardens
// installs regardless of proxy status.
//
// A non-empty ServerURL is passed through validateServerURL. If it fails
// validation the caller gets an error and we do NOT fall back to placeholder
// content — a user who passed a URL explicitly should be told it is bad, not
// have it silently swallowed.
func npmBlockBody(opts WireOpts) (string, error) {
	const defaults = "ignore-scripts=true"
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return `# Uncomment and re-run ` + "`chainsaw --server <url> install-hook npm`" + ` to
# populate real proxy URLs. The chainsaw proxy mounts npm at
# /repository/<repo-name>/ (default repo name: "npmjs").
# registry=https://<chainsaw-server>/repository/npmjs/
# //<chainsaw-server>/repository/npmjs/:_authToken=${CHAINSAW_TOKEN}
` + defaults, nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	hostPath, ok := npmAuthHostPath(base)
	if !ok {
		return "", fmt.Errorf("invalid server URL: could not derive host/path")
	}
	// When creds are provided, write the literal client_id:client_secret
	// into _authToken. npm sends it as "Authorization: Bearer <token>"
	// which the proxy splits back into id/secret via splitTokenCredential.
	token := "${CHAINSAW_TOKEN}"
	header := ""
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		if _, _, ok := splitCreds(creds); !ok {
			return "", fmt.Errorf("credentials: expected \"client_id:client_secret\"")
		}
		token = creds
		header = "# chainsaw: credentials embedded in _authToken below; tighten this\n# file's permissions (chmod 600) if your home directory is shared.\n"
	}
	// BUG-A6: org-scoped path required (/repository/@<org>/npmjs/).
	npmPath := OrgScopedRepoPath(opts.OrgSlug, "npmjs")
	// hostPath already carries the leading `//` (npm _authToken line
	// format); don't prepend another one here.
	return fmt.Sprintf(`%sregistry=%s/%s/
%s/%s/:_authToken=%s
%s`, header, base, npmPath, hostPath, npmPath, token, defaults), nil
}

// npmAuthHostPath strips the scheme from a server URL so it can be used as
// the //host/path/ key in an .npmrc _authToken line. Returns ("", false) for
// URLs we can't parse.
func npmAuthHostPath(server string) (string, bool) {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return "", false
	}
	path := strings.TrimRight(u.Path, "/")
	return "//" + u.Host + path, true
}
