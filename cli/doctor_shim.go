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
	return []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".zshenv"),
		filepath.Join(home, ".zprofile"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".config", "fish", "config.fish"),
	}
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
// (derived from guardedTools in guard_init.go). Only these managers can be in
// the "shim" state; the shim doesn't touch cargo/maven/etc.
func guardedManagerSet() map[string]bool {
	set := make(map[string]bool, len(guardedTools))
	for _, t := range guardedTools {
		set[t.tool] = true
	}
	return set
}
