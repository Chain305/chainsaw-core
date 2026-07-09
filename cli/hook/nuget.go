package hook

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type nugetManager struct{}

func (nugetManager) Name() string { return "nuget" }

func (nugetManager) IsInstalled() bool {
	for _, bin := range []string{"dotnet", "nuget"} {
		if _, err := exec.LookPath(bin); err == nil {
			return true
		}
	}
	return false
}

func (m nugetManager) ConfigPath() (string, error) {
	return m.ConfigPathForScope(ScopeUser)
}

func (nugetManager) ConfigPathForScope(scope Scope) (string, error) {
	switch scope {
	case ScopeProject:
		cwd, err := os.Getwd()
		if err != nil || cwd == "" {
			return "", fmt.Errorf("resolve working dir: %w", err)
		}
		return filepath.Join(cwd, "nuget.config"), nil
	case ScopeSystem:
		switch runtime.GOOS {
		case "windows":
			pd := os.Getenv("ProgramData")
			if pd == "" {
				return "", fmt.Errorf("ProgramData not set")
			}
			return filepath.Join(pd, "NuGet", "Config", "Chainsaw.Config"), nil
		case "darwin":
			return "/Library/Application Support/NuGet/Config/Chainsaw.Config", nil
		default:
			return "/etc/opt/NuGet/Config/Chainsaw.Config", nil
		}
	}
	switch runtime.GOOS {
	case "windows":
		ad := os.Getenv("AppData")
		if ad == "" {
			ad = os.Getenv("APPDATA")
		}
		if ad == "" {
			return "", fmt.Errorf("APPDATA not set")
		}
		return filepath.Join(ad, "NuGet", "NuGet.Config"), nil
	default:
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		return filepath.Join(home, ".nuget", "NuGet", "NuGet.Config"), nil
	}
}

func (m nugetManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) == 0 {
		return writeAtomic(path, []byte(nugetStandaloneConfig(opts)))
	}
	body, err := nugetBlockBody(opts)
	if err != nil {
		return err
	}
	return writeWithBackup(path, body)
}

func (m nugetManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	return unwireBlock(path)
}

func (m nugetManager) Status() (Status, error) {
	return statusForConfig(m.ConfigPath, m.IsInstalled)
}

func nugetBlockBody(opts WireOpts) (string, error) {
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return `# Uncomment and re-run ` + "`chainsaw --server <url> install-hook nuget`" + `.
# Credentials must go in NuGet's encrypted per-user credential store
# (dotnet nuget add source --username ... --password ...) or in CI
# env vars of the form NuGetPackageSourceCredentials_Chainsaw.`, nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	// BUG-A6: org-scoped path required.
	return fmt.Sprintf(`# chainsaw: source URL for nuget.config — an existing file is in place,
# so this block is a hint. Run the CLI with --scope=system to emit a
# standalone Chainsaw.Config instead. Target URL:
# %s/%s/`, base, OrgScopedRepoPath(opts.OrgSlug, "nuget-official")), nil
}

func nugetStandaloneConfig(opts WireOpts) string {
	server := strings.TrimSpace(opts.ServerURL)
	nugetPath := OrgScopedRepoPath(opts.OrgSlug, "nuget-official")
	base := "https://your-chainsaw-server/" + nugetPath + "/"
	if server != "" {
		if validated, err := validateServerURL(server); err == nil {
			base = validated + "/" + nugetPath + "/"
		}
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<!-- %s
chainsaw: source installed via install-hook nuget. Credentials live in the
per-user encrypted store (dotnet nuget add source) or in
NuGetPackageSourceCredentials_Chainsaw env var on CI.
%s -->
<configuration>
  <packageSources>
    <clear />
    <add key="Chainsaw" value="%s" />
  </packageSources>
  <disabledPackageSources>
    <add key="nuget.org" value="true" />
  </disabledPackageSources>
</configuration>
`, sentinelStart, sentinelEnd, base)
}
