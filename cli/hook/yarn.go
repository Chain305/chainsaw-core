package hook

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// yarnManager edits .yarnrc.yml (Yarn Berry) or falls back to .npmrc
// semantics for Yarn Classic. In practice Classic reads the npm manager's
// files — this manager targets the Berry-era .yarnrc.yml, which neither
// npm nor Berry share with the legacy .yarnrc.
type yarnManager struct{}

func (yarnManager) Name() string { return "yarn" }

func (yarnManager) IsInstalled() bool {
	_, err := exec.LookPath("yarn")
	return err == nil
}

func (m yarnManager) ConfigPath() (string, error) {
	return m.ConfigPathForScope(ScopeUser)
}

func (yarnManager) ConfigPathForScope(scope Scope) (string, error) {
	switch scope {
	case ScopeProject:
		cwd, err := os.Getwd()
		if err != nil || cwd == "" {
			return "", fmt.Errorf("resolve working dir: %w", err)
		}
		return filepath.Join(cwd, ".yarnrc.yml"), nil
	case ScopeSystem:
		if runtime.GOOS == "windows" {
			pd := os.Getenv("ProgramData")
			if pd == "" {
				return "", fmt.Errorf("ProgramData not set")
			}
			return filepath.Join(pd, "yarn", ".yarnrc.yml"), nil
		}
		return "/etc/yarnrc.yml", nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".yarnrc.yml"), nil
}

func (m yarnManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	body, err := yarnBlockBody(opts)
	if err != nil {
		return err
	}
	return writeWithBackup(path, body)
}

func (m yarnManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	return unwireBlock(path)
}

func (m yarnManager) Status() (Status, error) {
	return statusForConfig(m.ConfigPath, m.IsInstalled)
}

func yarnBlockBody(opts WireOpts) (string, error) {
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return `# Uncomment and re-run ` + "`chainsaw --server <url> install-hook yarn`" + `
# to populate real proxy URLs. Chainsaw mounts yarn at
# /repository/yarnpkg/ by default.
# npmRegistryServer: "https://<chainsaw-server>/repository/yarnpkg/"
# npmAuthToken: "${CHAINSAW_TOKEN}"`, nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	token := "${CHAINSAW_TOKEN}"
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		if _, _, ok := splitCreds(creds); !ok {
			return "", fmt.Errorf("credentials: expected \"client_id:client_secret\"")
		}
		token = creds
	}
	// BUG-A6: org-scoped path required.
	return fmt.Sprintf(`npmRegistryServer: %q
npmAuthToken: %q`, base+"/"+OrgScopedRepoPath(opts.OrgSlug, "yarnpkg")+"/", token), nil
}
