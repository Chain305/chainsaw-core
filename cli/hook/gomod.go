package hook

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// goModManager writes a go env file (Go 1.21+'s $GOENV) rather than
// touching ~/.netrc or /etc/environment. GOPROXY / GOPRIVATE / GOSUMDB
// are the enforcement levers; the file format is one `KEY=value` per line
// and `go env -w` persists there.
type goModManager struct{}

func (goModManager) Name() string { return "go" }

func (goModManager) IsInstalled() bool {
	_, err := exec.LookPath("go")
	return err == nil
}

func (m goModManager) ConfigPath() (string, error) {
	return m.ConfigPathForScope(ScopeUser)
}

func (goModManager) ConfigPathForScope(scope Scope) (string, error) {
	switch scope {
	case ScopeProject:
		cwd, err := os.Getwd()
		if err != nil || cwd == "" {
			return "", fmt.Errorf("resolve working dir: %w", err)
		}
		return filepath.Join(cwd, "go.env"), nil
	case ScopeSystem:
		if runtime.GOOS == "windows" {
			pd := os.Getenv("ProgramData")
			if pd == "" {
				return "", fmt.Errorf("ProgramData not set")
			}
			return filepath.Join(pd, "go", "env"), nil
		}
		return "/etc/go/env", nil
	}
	if p := strings.TrimSpace(os.Getenv("GOENV")); p != "" {
		return p, nil
	}
	if p := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); p != "" {
		return filepath.Join(p, "go", "env"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Roaming", "go", "env"), nil
	}
	return filepath.Join(home, ".config", "go", "env"), nil
}

func (m goModManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	body, err := goBlockBody(opts)
	if err != nil {
		return err
	}
	return writeWithBackup(path, body)
}

func (m goModManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	return unwireBlock(path)
}

func (m goModManager) Status() (Status, error) {
	return statusForConfig(m.ConfigPath, m.IsInstalled)
}

func goBlockBody(opts WireOpts) (string, error) {
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return `# Re-run ` + "`chainsaw --server <url> install-hook go`" + ` to
# populate GOPROXY. Credentials go in ~/.netrc, not GOPROXY.
# GOPROXY=https://<chainsaw-server>/repository/gomod
# GOSUMDB=sum.golang.org`, nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	// No `,direct` fallback — see enforcement guidance in seed.yaml's go
	// client guide. Orgs that need to fetch private modules must set
	// GOPRIVATE for those paths explicitly.
	// BUG-A6: org-scoped path required.
	return fmt.Sprintf(`GOPROXY=%s/%s
GOSUMDB=sum.golang.org
GOFLAGS=
# Set GOPRIVATE in your shell profile for internal VCS paths, e.g.:
#   GOPRIVATE=github.com/myorg/*`, base, OrgScopedRepoPath(opts.OrgSlug, "gomod")), nil
}
