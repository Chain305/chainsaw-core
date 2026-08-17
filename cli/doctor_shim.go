package cli

// Shell-shim detection for `doctor`. `chainsaw guard init` protects installs by
// defining shell functions (npm() → `chainsaw npm`), a DIFFERENT mechanism from
// the per-manager config-file block that the WIRED column checks. A user who ran
// `eval "$(chainsaw guard init zsh)"` is protected even though every config file
// is untouched — so doctor must not flatly report "no", which reads as
// "unprotected" in a trust tool. We detect the shim from the shell rc files and
// surface a third state ("shim").

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// guardShimMarker is the substring doctor looks for in shell rc files: the
// `chainsaw guard init` invocation users add to source the shim. Matching the
// invocation (not the emitted marker comment) is robust across bash/zsh/fish.
const guardShimMarker = "chainsaw guard init"

// shellRCCandidates returns the shell config files doctor scans for the guard
// shim, most-common first. Overridable in tests. Missing paths are fine — the
// scanner skips unreadable files.
var shellRCCandidates = func() []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	return shellRCCandidatesFor(runtime.GOOS, home)
}

// shellRCCandidatesFor is the pure, GOOS-parameterised core of
// shellRCCandidates, split out so the Windows list is testable without a
// Windows runner.
//
// The POSIX files are scanned everywhere — Git Bash and WSL users on Windows do
// have a ~/.bashrc, and a Windows-only list would report them unprotected. On
// top of that we add the PowerShell profiles, without which `chainsaw doctor`
// could never see an installed shim on Windows at all (the bug this fixes).
func shellRCCandidatesFor(goos, home string) []string {
	c := []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".zshenv"),
		filepath.Join(home, ".zprofile"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".config", "fish", "config.fish"),
	}
	if goos != "windows" {
		// PowerShell 7+ is cross-platform; its profiles live under XDG on
		// macOS/Linux.
		return append(c,
			filepath.Join(home, ".config", "powershell", "profile.ps1"),
			filepath.Join(home, ".config", "powershell", "Microsoft.PowerShell_profile.ps1"),
		)
	}
	// Windows: both the all-hosts (profile.ps1) and console-host
	// (Microsoft.PowerShell_profile.ps1) profiles, for PowerShell 7+
	// (Documents\PowerShell) and Windows PowerShell 5.1
	// (Documents\WindowsPowerShell). The OneDrive variants cover Known Folder
	// Move, which silently relocates Documents on most modern Windows installs.
	for _, docs := range []string{
		filepath.Join(home, "Documents"),
		filepath.Join(home, "OneDrive", "Documents"),
	} {
		for _, host := range []string{"PowerShell", "WindowsPowerShell"} {
			c = append(c,
				filepath.Join(docs, host, "profile.ps1"),
				filepath.Join(docs, host, "Microsoft.PowerShell_profile.ps1"),
			)
		}
	}
	return c
}

// detectGuardShim reports whether the guard shell-shim is sourced in any of the
// given rc files, and which file. Best-effort: unreadable/missing files are
// skipped, and a commented-out invocation does NOT count (we scan line by line
// and ignore comment lines) so a disabled shim isn't reported as active.
func detectGuardShim(candidates []string) (bool, string) {
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if strings.Contains(t, guardShimMarker) {
				return true, path
			}
		}
	}
	return false, ""
}

// guardedManagerSet is the set of package-manager names the shell shim wraps
// (derived from guardedTools in guard_init.go): npm/pip/go/cargo/gem. Only
// these managers can be in the "shim" state; the shim doesn't touch
// maven/gradle/nuget/etc.
func guardedManagerSet() map[string]bool {
	set := make(map[string]bool, len(guardedTools))
	for _, t := range guardedTools {
		set[t.tool] = true
	}
	return set
}
