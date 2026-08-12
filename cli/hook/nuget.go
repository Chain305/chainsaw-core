package hook

// NuGet.Config is XML and carries the identical H1/H2 defects maven had — the
// seed missed the nuget copy. Same resolution: write a complete standalone
// document, or refuse. See maven.go and xmlsentinel.go for the reasoning.

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
	// H12: build the document FIRST so a bad --server aborts before any
	// file is created. The old code swallowed the validation error and
	// wrote a config whose only source was https://your-chainsaw-server/,
	// with nuget.org disabled — every dotnet restore then failed DNS with
	// no hint that the URL had been rejected.
	sourceURL, err := nugetSourceURL(opts)
	if err != nil {
		return err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	switch {
	case len(data) == 0:
		// Fresh install: we own the whole document.
	case xmlHasSentinel(data):
		// Ours (possibly with the legacy same-line markers) — re-render.
	default:
		return xmlRefuseError("nuget", path, nugetMergeFragment(sourceURL))
	}
	return writeConfigFile(path, []byte(nugetStandaloneConfig(sourceURL)), opts)
}

func (m nugetManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	// NOT removeSentinel: stripping the markers would leave <clear /> plus
	// a disabled nuget.org in place while reporting success.
	return xmlUnwire(path)
}

func (m nugetManager) Status() (Status, error) {
	return xmlStatus(m.ConfigPath, m.IsInstalled)
}

// nugetSourceURL resolves the package-source URL to install. A non-empty but
// invalid --server is a hard error (H12); an absent one yields the visible
// placeholder host so the generated file fails loud rather than silently
// routing to the public registry.
func nugetSourceURL(opts WireOpts) (string, error) {
	nugetPath, err := orgScopedRepoPath(opts.OrgSlug, "nuget-official")
	if err != nil {
		return "", err
	}
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return "https://your-chainsaw-server/" + nugetPath + "/", nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	return base + "/" + nugetPath + "/", nil
}

// nugetMergeFragment is the XML an operator must paste into their own
// NuGet.Config when chainsaw refuses to edit it (H1).
func nugetMergeFragment(sourceURL string) string {
	return fmt.Sprintf(`  <!-- inside <configuration><packageSources> -->
    <add key="Chainsaw" value="%s" />

  <!-- inside <configuration>; disables the public source -->
  <disabledPackageSources>
    <add key="nuget.org" value="true" />
  </disabledPackageSources>
`, xmlEscape(sourceURL))
}

// nugetStandaloneConfig renders a complete NuGet.Config with each sentinel
// marker on its own line (H2) and every interpolated value XML-escaped (H4).
func nugetStandaloneConfig(sourceURL string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<!--
%s
     This file is managed by chainsaw. Remove it with
     `+"`chainsaw uninstall-hook nuget`"+` rather than editing it by hand.
     Credentials live in NuGet's per-user encrypted store
     (dotnet nuget add source ...) or in a
     NuGetPackageSourceCredentials_Chainsaw env var on CI.
%s
-->
<configuration>
  <packageSources>
    <clear />
    <add key="Chainsaw" value="%s" />
  </packageSources>
  <disabledPackageSources>
    <add key="nuget.org" value="true" />
  </disabledPackageSources>
</configuration>
`, sentinelStart, sentinelEnd, xmlEscape(sourceURL))
}
