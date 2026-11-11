package cli

// Shell-shim detection for `doctor`. `chainsaw guard init` protects installs by
// defining shell functions (npm() → `chainsaw npm`), a DIFFERENT mechanism from
// the per-manager config-file block that the WIRED column checks. A user who ran
// `eval "$(chainsaw guard init zsh)"` is protected even though every config file
// is untouched — so doctor must not flatly report "no", which reads as
// "unprotected" in a trust tool. We detect the shim from the shell rc files and
// surface a third state ("shim").

import (
	"maps"
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
// given rc files, the first file that sources it, and EVERY active activation
// line across all of them. Best-effort: unreadable/missing files are skipped,
// and a commented-out invocation does NOT count (we scan line by line and
// ignore comment lines) so a disabled shim isn't reported as active.
//
// All lines are returned because the shell defines the union of what each one
// wraps: a later line with a skip list does not unset an earlier line's
// functions (see guardShimSkips).
func detectGuardShim(candidates []string) (bool, string, []string) {
	first := ""
	var lines []string
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
				if first == "" {
					first = path
				}
				lines = append(lines, t)
			}
		}
	}
	return first != "", first, lines
}

// guardShimState is what the shell guard does for the user's CURRENT shell
// (detectShell): only rc files that shell reads count, so an old line in
// ~/.bashrc does not make doctor report a zsh user's npm as guarded. Lines in
// other shells' files are reported separately (OtherFiles) so doctor can say
// "set up for bash, but your shell is zsh" instead of a bare "no".
type shimState struct {
	Found      bool            // an activation line is active for this shell
	Path       string          // first rc file holding one
	Lines      []string        // every active line for this shell
	Skip       map[string]bool // functions left unwrapped (see guardShimSkipsWithEnv)
	Shell      string          // the current shell
	OtherFiles []string        // other shells' rc files that also hold a line
}

func guardShimState() shimState {
	shell := detectShell()
	var mine, others []string
	for _, p := range shellRCCandidates() {
		if shellReadsRC(shell, rcShellOf(p)) {
			mine = append(mine, p)
		} else {
			others = append(others, p)
		}
	}
	st := shimState{Shell: shell, Skip: map[string]bool{}}
	for _, p := range others {
		if ok, _, _ := detectGuardShim([]string{p}); ok {
			st.OtherFiles = append(st.OtherFiles, p)
		}
	}
	found, path, lines := detectGuardShim(mine)
	if !found {
		return st
	}
	st.Found, st.Path, st.Lines = true, path, lines
	st.Skip = guardShimSkipsWithEnv(os.Getenv(guardSkipEnv), lines...)
	return st
}

// rcShellOf names the shell family that reads an rc file, from its name.
func rcShellOf(path string) string {
	base := filepath.Base(path)
	switch {
	case strings.HasSuffix(strings.ToLower(base), ".ps1"):
		return "powershell"
	case base == "config.fish":
		return "fish"
	case strings.HasPrefix(base, ".zsh") || base == ".zlogin":
		return "zsh"
	case strings.HasPrefix(base, ".bash"):
		return "bash"
	case base == ".profile":
		return "sh"
	}
	return ""
}

// shellReadsRC reports whether shell loads an rc file of family rc. bash also
// reads ~/.profile (login shells without ~/.bash_profile). An unknown shell
// or file counts, which is the conservative old behaviour.
func shellReadsRC(shell, rc string) bool {
	if rc == "" {
		return true
	}
	switch shell {
	case "zsh":
		return rc == "zsh"
	case "bash":
		return rc == "bash" || rc == "sh"
	case "sh":
		return rc == "sh"
	case "fish":
		return rc == "fish"
	case "powershell", "pwsh":
		return rc == "powershell"
	}
	return true
}

// guardShimSkipsWithEnv is guardShimSkips with an exported guardSkipEnv value
// applied the way the shell applies it: to each line that does NOT assign the
// variable itself. A line written by --install sets it inline
// (`CHAINSAW_GUARD_SKIP=npm chainsaw …`), which replaces any exported value
// for that `guard init`; a plain or --skip line inherits it.
func guardShimSkipsWithEnv(env string, lines ...string) map[string]bool {
	var out map[string]bool
	for _, line := range lines {
		values, assigns := guardShimSkipValues(line)
		if !assigns {
			values = append(values, env)
		}
		skip, _, _ := parseGuardSkip(values)
		if out == nil {
			out = skip
			continue
		}
		for fn := range out {
			if !skip[fn] {
				delete(out, fn)
			}
		}
	}
	if out == nil {
		out = map[string]bool{}
	}
	return out
}

// guardShimSkips returns the shell function names left unwrapped by the given
// activation lines. Each line's list is read from both forms `guard init`
// accepts — `CHAINSAW_GUARD_SKIP=npm,brew` (what --install writes) and
// `--skip npm,brew` / `--skip=npm` (hand-written) — with the same parse
// (parseGuardSkip) the CLI applies, unknown names ignored as at shell startup.
// Across several lines a function is unwrapped only if EVERY line skips it.
func guardShimSkips(lines ...string) map[string]bool {
	return guardShimSkipsWithEnv("", lines...)
}

// guardShimSkipValues extracts the raw skip values from one activation line,
// and reports whether the line assigns guardSkipEnv itself.
func guardShimSkipValues(line string) (values []string, assigns bool) {
	// Every assignment counts: the PowerShell line reads the variable, sets
	// it, and restores it, and only the quoted literal is a skip list (the
	// restore's `$__chainsawSkip` resolves to no known manager).
	for off := 0; ; {
		i := strings.Index(line[off:], guardSkipEnv)
		if i < 0 {
			break
		}
		rest := strings.TrimLeft(line[off+i+len(guardSkipEnv):], " \t")
		off += i + len(guardSkipEnv)
		if strings.HasPrefix(rest, "=") {
			assigns = true
			rest = strings.TrimLeft(rest[1:], " \t")
			if rest != "" && (rest[0] == '\'' || rest[0] == '"') {
				if j := strings.IndexByte(rest[1:], rest[0]); j >= 0 {
					values = append(values, rest[1:1+j])
				}
			} else if j := strings.IndexAny(rest, " \t;)|\"'"); j >= 0 {
				values = append(values, rest[:j])
			} else {
				values = append(values, rest)
			}
		}
	}
	i := strings.Index(line, guardShimMarker)
	if i < 0 {
		return values, assigns
	}
	// Stop at the end of the command substitution or pipe: anything after it
	// is not an argument to guard init.
	rest := line[i+len(guardShimMarker):]
	if j := strings.IndexAny(rest, ")|;"); j >= 0 {
		rest = rest[:j]
	}
	fields := strings.Fields(strings.NewReplacer(`"`, " ", `'`, " ").Replace(rest))
	for k := 0; k < len(fields); k++ {
		v := ""
		switch {
		case strings.HasPrefix(fields[k], "--skip="):
			v = strings.TrimPrefix(fields[k], "--skip=")
		case fields[k] == "--skip" && k+1 < len(fields):
			k++
			v = fields[k]
		default:
			continue
		}
		// A quoted `--skip "npm, brew"` is ONE argument to the CLI, which
		// splits it on commas. Rejoin the fields the quote-stripping split.
		for k+1 < len(fields) && (strings.HasSuffix(v, ",") || strings.HasPrefix(fields[k+1], ",")) {
			k++
			v += fields[k]
		}
		values = append(values, v)
	}
	return values, assigns
}

// guardShimSkipNames renders a skip set in guardedTools order, for messages.
func guardShimSkipNames(skip map[string]bool) string {
	var names []string
	for _, t := range guardedTools {
		if skip[t.fn] {
			names = append(names, t.fn)
		}
	}
	return strings.Join(names, ", ")
}

// sameSkipSet reports whether an rc line's resolved skip set equals the one a
// --skip flag list resolves to.
func sameSkipSet(have map[string]bool, want []string) bool {
	w, _, _ := parseGuardSkip(want)
	return maps.Equal(have, w)
}

// guardShimRoutes reports whether the shell shim still wraps manager name
// given the skip set. A manager counts as routed while ANY of its functions
// is wrapped: skipping only pip3 leaves pip guarded.
func guardShimRoutes(name string, skip map[string]bool) bool {
	for _, fn := range guardShimFuncs(name) {
		if !skip[fn] {
			return true
		}
	}
	return false
}

// guardShimFuncs lists the shell functions that route manager name: pip is
// both pip and pip3.
func guardShimFuncs(name string) []string {
	var fns []string
	for _, t := range guardedTools {
		if t.fn == name || t.tool == name {
			fns = append(fns, t.fn)
		}
	}
	return fns
}
