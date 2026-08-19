package cli

// Unicode capability selection — the decision, separated from the platform.
//
// WHY THIS FILE HAS NO BUILD TAG. The failure it governs is Windows-only, and
// there is no Windows runner (GitHub Actions billing is off by standing
// decision). A rule that can only be exercised on a machine we do not have is
// a rule that stops being tested. So the LADDER lives here as a pure function
// over an injected environment, and the two build-tagged files shrink to
// adapters that fill the struct. Every branch below runs on the Linux/macOS
// test host.
//
// WHAT REPLACED WHAT, AND WHY. The previous probe asked Windows for the
// console OUTPUT CODEPAGE (GetConsoleOutputCP) and enabled Unicode only for
// 65001. That question cannot answer this problem:
//
//   - Go never consults the output codepage. A console handle is kindConsole
//     in internal/poll/fd_windows.go, which routes through writeConsole:
//     UTF-8 is transcoded to UTF-16 in-process and handed to WriteConsoleW,
//     which takes UTF-16 directly. The output codepage is read only by
//     WriteConsoleA and WriteFile-on-console, neither of which Go uses.
//     Nothing decodes, so nothing the codepage says applies.
//   - The probe therefore had no true-positive path. The config it flagged
//     (codepage != 65001) is not the config that breaks, and the config that
//     does break — any codepage at all, plus a console font with no glyph for
//     the codepoint — it scored as capable. A `chcp 65001` console running
//     Consolas is exactly the setup users are told to adopt for Unicode, and
//     it draws ✓ U+2713 as a .notdef box while rendering — U+2014 on the same
//     line, because Consolas covers one and not the other.
//   - It also fired for output that was never going to a console at all.
//     GetConsoleOutputCP succeeds whenever the PROCESS has a console attached,
//     regardless of whether stdout is that console, so
//     `chainsaw doctor --offline > report.txt` launched from a legacy window
//     wrote the ASCII fallback into the FILE. A redirected artifact varying
//     with the codepage of a console it never touched is precisely the
//     host-dependence the machine-output boundary exists to prevent.
//
// THIS IS A HEURISTIC. Deliberately, and it is stated rather than dressed up:
// glyph capability is NOT inferable on Windows. No Win32 call answers "does
// the current console font have U+2713". GetCurrentConsoleFontEx returns a
// face name; turning that into coverage means parsing the font's cmap, which
// is absurd, and wrong anyway for terminals that do runtime font fallback
// (Windows Terminal does; classic conhost does not). Any refinement of a
// capability probe refines an unanswerable question. So the ladder below does
// not claim to detect capability — it recognises the small set of TERMINALS
// that are known to render the set, and defaults everything else to ASCII.
//
// It is defensible because it is safe when wrong in BOTH directions:
//   - wrong toward ASCII (a capable console we failed to recognise) costs that
//     user their ticks. The output is still legible, and one env var
//     (CHAINSAW_UNICODE=1) fixes it.
//   - wrong toward Unicode cannot happen for a default conhost window, because
//     the default IS now ASCII. Only an explicit opt-in reaches it.
//
// What did NOT change, and should not: we still refuse to call
// SetConsoleOutputCP(65001) to "fix" the user's console. It is process-global,
// outlives chainsaw in some host shells, and has broken unrelated programs'
// output in the same window. Adapting what we print is reversible; mutating
// the user's console is not. (It would also not have fixed anything.)

// consoleEnv is everything decideUnicode is allowed to look at. Injecting it
// rather than reading the process environment is what makes the Windows
// branches testable off Windows.
type consoleEnv struct {
	// goos is the target platform, normally runtime.GOOS.
	goos string
	// stdoutIsConsole reports whether stdout IS a console handle — not merely
	// whether the process has one attached. A pipe or a file is false.
	stdoutIsConsole bool
	// lookup resolves an environment variable, normally os.LookupEnv. The
	// bool distinguishes "set to empty" from "unset", which rule 1 depends on.
	lookup func(string) (string, bool)
}

// look resolves an environment variable, tolerating a nil lookup so a
// zero-value consoleEnv behaves as "nothing is set" rather than panicking.
func (e consoleEnv) look(k string) (string, bool) {
	if e.lookup == nil {
		return "", false
	}
	return e.lookup(k)
}

// env returns the value of an environment variable, or "" when unset.
func (e consoleEnv) env(k string) string {
	v, _ := e.look(k)
	return v
}

// decideUnicode reports whether the Unicode glyph set may be printed.
//
// Precedence, highest first:
//
//  1. CHAINSAW_NO_UNICODE set and not explicitly falsey -> false.
//  2. CHAINSAW_UNICODE truthy                           -> true.
//  3. non-Windows                                       -> true.
//  4. stdout is not a console (pipe/file)               -> true.
//  5. WT_SESSION set (Windows Terminal)                 -> true.
//  6. TERM_PROGRAM == "vscode"                          -> true.
//  7. WSL_DISTRO_NAME or MSYSTEM set                    -> true.
//  8. TERM set, non-empty, != "dumb"                    -> true.
//  9. otherwise (classic conhost)                       -> false.
//
// Rule 2 sits BELOW rule 1 on purpose. CHAINSAW_NO_UNICODE is the older,
// documented opt-out and the one a user reaches for when their terminal is
// visibly broken; an opt-IN must never be able to override an opt-OUT the user
// set for exactly that reason.
//
// Rule 4 is the fix for redirected output: a file has no font, so nothing can
// box, and an artifact must not vary with the console that happened to launch
// it. Note that on non-Windows this is unreachable anyway (rule 3 short-
// circuits first), which is why the adapter there does not bother probing.
//
// Rules 5-8 are the recogniser. Windows Terminal, the VS Code integrated
// terminal, WSL, and the MSYS/mintty family (Git Bash) all render the set.
// TERM is the catch-all for anything Unix-ish running on Windows: classic
// conhost never sets it, so its presence is a positive signal on this platform
// even though it says nothing about fonts anywhere else. "dumb" is excluded
// because it is the conventional "assume nothing" value.
//
// Rule 9 is the change. CMD or PowerShell 5.1 in a native conhost window is
// the one configuration with no signal at all, it is the one where the boxes
// were actually reported, and it is now ASCII by default.
func decideUnicode(e consoleEnv) bool {
	// 1. Explicit opt-out wins over everything, including the opt-in.
	if v, ok := e.look("CHAINSAW_NO_UNICODE"); ok && !envFalsey(v) {
		return false
	}
	// 2. Explicit opt-in. The escape hatch for a capable console the ladder
	//    below does not recognise. It may well produce boxes if the user is
	//    wrong about their font — that is the accepted cost of an override.
	if envTruthy(e.env("CHAINSAW_UNICODE")) {
		return true
	}
	// 3. macOS and Linux terminals are UTF-8 with fallback-capable fonts.
	//    Everything after this point is Windows-only reasoning, which also
	//    keeps doc generation on a Linux/macOS host deterministic: rules 4-9
	//    can never be inputs there.
	if e.goos != "windows" {
		return true
	}
	// 4. Not a console: a pipe, a file, a CI log collector. No font is
	//    involved and UTF-8 is the right assumption for the bytes.
	if !e.stdoutIsConsole {
		return true
	}
	// 5-7. Terminals known to render the set.
	if e.env("WT_SESSION") != "" {
		return true
	}
	if e.env("TERM_PROGRAM") == "vscode" {
		return true
	}
	if e.env("WSL_DISTRO_NAME") != "" || e.env("MSYSTEM") != "" {
		return true
	}
	// 8. Anything that bothered to set TERM is not classic conhost.
	if t := e.env("TERM"); t != "" && t != "dumb" {
		return true
	}
	// 9. Classic conhost — CMD / PowerShell 5.1 native window.
	return false
}
