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
	// H10: the block used to emit a bare `GOFLAGS=`. Go's readEnvFile has no
	// first-wins guard, so the LAST occurrence wins — and our block is
	// appended at the end. A user with `GOFLAGS=-mod=vendor` silently lost
	// it and vendored builds switched to module mode. Read what is there and
	// carry it forward.
	existing, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	goflags, dropped := sanitizeGoflags(existingGoflags(existing))
	for _, tok := range dropped {
		opts.notify("dropped %q from GOFLAGS in %s — it disables module verification and would bypass the chainsaw proxy", tok, path)
	}
	body, err := goBlockBody(opts, goflags)
	if err != nil {
		return err
	}
	return writeWithBackup(m.Name(), path, body, opts)
}

// existingGoflags returns the last NON-EMPTY GOFLAGS value in a go env file.
//
// "Last" matches Go's own resolution. Non-empty skips the `GOFLAGS=` line an
// earlier chainsaw release wrote, so re-running install-hook does not make
// that release's damage permanent — while still honouring a value a user set
// with `go env -w` after we wired (which Go rewrites in place, INSIDE our
// block; see H11).
func existingGoflags(data []byte) string {
	lines, _ := splitLines(data)
	out := ""
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if !strings.HasPrefix(t, "GOFLAGS=") {
			continue
		}
		if v := strings.TrimSpace(strings.TrimPrefix(t, "GOFLAGS=")); v != "" {
			out = v
		}
	}
	return out
}

// goflagsDenyList are GOFLAGS tokens chainsaw strips when carrying a user's
// value forward.
//
// GOFLAGS pinning is a documented enforcement lever, not incidental:
// configs/seed.yaml:1215 lists GOFLAGS among the env vars "MDM should pin",
// and :1221 names `GOFLAGS=-insecure` as a bypass to watch for. So we neither
// clear the value (that removes a control the product documents) nor pass it
// through unchanged (that would let the bypass ride along).
var goflagsDenyList = map[string]bool{
	"-insecure":       true,
	"-insecure=true":  true,
	"-insecure=1":     true,
	"-mod=mod":        false, // legitimate; listed to document the decision
	"-modcacherw":     false,
	"-mod=vendor":     false,
	"-mod=readonly":   false,
	"-buildvcs=false": false,
}

// sanitizeGoflags returns the value with denied tokens removed, plus the list
// of tokens that were dropped so the caller can tell the user.
func sanitizeGoflags(value string) (string, []string) {
	if strings.TrimSpace(value) == "" {
		return "", nil
	}
	var kept []string
	var dropped []string
	for _, tok := range strings.Fields(value) {
		if goflagsDenyList[tok] {
			dropped = append(dropped, tok)
			continue
		}
		kept = append(kept, tok)
	}
	return strings.Join(kept, " "), dropped
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

func goBlockBody(opts WireOpts, goflags string) (string, error) {
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
	// BUG-A6: org-scoped path required.
	gomodPath, err := orgScopedRepoPath(opts.OrgSlug, "gomod")
	if err != nil {
		return "", err
	}
	// No `,direct` fallback — see enforcement guidance in seed.yaml's go
	// client guide. Orgs that need to fetch private modules must set
	// GOPRIVATE for those paths explicitly.
	//
	// GOFLAGS is re-stated (not cleared) so chainsaw keeps the pin without
	// discarding the user's flags — see sanitizeGoflags.
	return fmt.Sprintf(`GOPROXY=%s/%s
GOSUMDB=sum.golang.org
GOFLAGS=%s
# GOFLAGS above is pinned by chainsaw: your existing value is preserved
# minus any token that would disable module verification.
# Set GOPRIVATE in your shell profile for internal VCS paths, e.g.:
#   GOPRIVATE=github.com/myorg/*`, base, gomodPath, goflags), nil
}
