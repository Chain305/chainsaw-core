package cli

// `chainsaw guard init [shell]` — print shell functions that transparently route
// npm/pip/go through the install guard, so `npm install …` is checked
// automatically with zero per-command effort (the Socket-`sfw` UX).
//
// Add to your shell config:
//
//	# ~/.zshrc or ~/.bashrc
//	eval "$(chainsaw guard init zsh)"
//
// The functions call `command chainsaw <tool>`, which evaluates packages locally
// then delegates to the REAL tool. This is recursion-safe: chainsaw resolves the
// real `npm`/`pip`/`go` via PATH (exec.LookPath), which shell functions don't
// shadow — so `npm` (function) → `chainsaw npm` → real `npm` binary. The same
// argument holds for PowerShell functions and cmd doskey macros: neither is
// visible to the OS-level process lookup chainsaw uses.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// supportedShellsHint is the one string every "unsupported shell" error and the
// command's Use line derive from, so adding a target can't leave a stale list
// behind in an error message.
const supportedShellsHint = "bash, zsh, sh, fish, powershell, pwsh, cmd"

var guardInitCmd = &cobra.Command{
	Use:   "init [bash|zsh|fish|powershell|pwsh|cmd]",
	Short: "Print shell functions that route npm, pip, go, cargo and gem through the guard",
	Long: `Print shell functions that route your package managers through the Chainsaw
install guard, so installs are checked automatically without typing "chainsaw"
each time.

Add to your shell config and reload:

  # ~/.zshrc or ~/.bashrc
  eval "$(chainsaw guard init zsh)"

  # ~/.config/fish/config.fish
  chainsaw guard init fish | source

  # PowerShell $PROFILE (Windows, macOS, Linux)
  chainsaw guard init powershell | Invoke-Expression

  # cmd.exe — current console session only, see below
  chainsaw guard init cmd

The functions delegate to the real npm, pip, pip3, go, cargo and gem after the
check.

The default path is offline. Two opt-in paths do reach the network, and
neither runs unless you ask for it: "chainsaw guard update" downloads the
OpenSSF malicious-package set, and CHAINSAW_GUARD_DEEP=1 fetches package
bytes for artifact analysis.

With --install, append the activation line to your shell rc file (idempotent)
instead of printing the functions, so setup is a single command with no
copy-paste:

  chainsaw guard init --install

--install supports every shell that HAS a startup file: bash, zsh, sh, fish and
PowerShell. cmd.exe has none — doskey macros live only in the console session
that defined them — so --install refuses for cmd rather than writing a file no
shell reads. Use PowerShell on Windows for a persistent wiring.`,
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE:         runGuardInit,
}

func init() {
	guardInitCmd.Flags().Bool("install", false,
		"Append the guard activation line to your shell rc file (idempotent) instead of printing it.")
	guardInitCmd.Flags().Bool("dry-run", false,
		"With --install: print the target rc file and the exact line that would be added, without writing anything.")
	guardCmd.AddCommand(guardInitCmd)
}

// guardedTools are the package managers the shim wraps. pip3 maps to the pip
// guard so both common invocations are covered. cargo and gem are included so
// the shim matches what the installer advertises ("routes npm/pip/go/cargo/gem
// installs"); the standalone `chainsaw cargo`/`chainsaw gem` guards these
// delegate to already parse install/add subcommands and pass through the rest.
var guardedTools = []struct{ fn, tool string }{
	{"npm", "npm"},
	{"pip", "pip"},
	{"pip3", "pip"},
	{"go", "go"},
	{"cargo", "cargo"},
	{"gem", "gem"},
}

func runGuardInit(cmd *cobra.Command, args []string) error {
	shell := ""
	if len(args) == 1 {
		shell = strings.ToLower(args[0])
	} else {
		shell = detectShell()
	}

	if install, _ := cmd.Flags().GetBool("install"); install {
		return installGuardInit(cmd, shell)
	}

	out := cmd.OutOrStdout()
	switch shell {
	case "fish":
		fmt.Fprintln(out, "# chainsaw install guard — https://chain305.com")
		for _, t := range guardedTools {
			fmt.Fprintf(out, "function %s; command chainsaw %s $argv; end\n", t.fn, t.tool)
		}
	case "powershell", "pwsh":
		// PowerShell functions shadow same-named commands for the shell only;
		// chainsaw still resolves the real npm/pip/go through the OS PATH, so
		// this is recursion-safe exactly like the POSIX branch. @args forwards
		// every argument (including switches) verbatim.
		fmt.Fprintln(out, "# chainsaw install guard — https://chain305.com")
		for _, t := range guardedTools {
			fmt.Fprintf(out, "function %s { chainsaw %s @args }\n", t.fn, t.tool)
		}
	case "cmd":
		// doskey macros are the only cmd.exe equivalent of a shell function.
		// $* forwards the whole argument tail. These are SESSION-LOCAL: cmd.exe
		// has no rc file, so they vanish when the console closes (see
		// shellRCPath, which refuses --install for cmd for exactly this reason).
		fmt.Fprintln(out, ":: chainsaw install guard — https://chain305.com")
		for _, t := range guardedTools {
			fmt.Fprintf(out, "doskey %s=chainsaw %s $*\n", t.fn, t.tool)
		}
	case "bash", "zsh", "sh", "":
		fmt.Fprintln(out, "# chainsaw install guard — https://chain305.com")
		for _, t := range guardedTools {
			fmt.Fprintf(out, "%s() { command chainsaw %s \"$@\"; }\n", t.fn, t.tool)
		}
	default:
		return fmt.Errorf("unsupported shell %q (supported: %s)", shell, supportedShellsHint)
	}
	// Bare `chainsaw guard init` on a terminal dumps shell functions with no
	// context — a user who ran it expecting a setup action is left staring at
	// them. Point them at the one-shot installer. stdout stays clean for the
	// documented `eval "$(chainsaw guard init bash)"` usage (piped → not a
	// terminal → no hint); the note goes to stderr regardless.
	if stdoutIsTerminal() {
		if shell == "cmd" {
			// Never point a cmd user at --install: it cannot work there, and
			// saying otherwise is the false-success this branch exists to avoid.
			fmt.Fprintln(cmd.ErrOrStderr(), ":: ^ these are doskey macros for THIS console session only — cmd.exe has no startup file.")
			fmt.Fprintln(cmd.ErrOrStderr(), ":: For a wiring that survives a reboot, use PowerShell: chainsaw guard init --install powershell")
		} else {
			fmt.Fprintln(cmd.ErrOrStderr(), "# ^ these are shell functions meant for `eval`. To install them for good, run: chainsaw guard init --install")
		}
	}
	return nil
}

// shellRCPath returns the rc file --install writes to for a shell. fish uses
// config.fish under XDG; the POSIX shells use the conventional dotfile;
// PowerShell uses $PROFILE, which we ask the interpreter itself for (see
// powerShellProfilePath) because Windows "Documents" is routinely redirected
// into OneDrive and a guessed path would write a file PowerShell never loads.
func shellRCPath(shell string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("cannot determine home directory")
	}
	if shell == "powershell" || shell == "pwsh" {
		if p, err := powerShellProfilePath(shell); err == nil && p != "" {
			return p, nil
		}
		// Fall through to the conventional location below.
	}
	return shellRCPathFor(runtime.GOOS, shell, home)
}

// shellRCPathFor is the pure, GOOS-parameterised core of shellRCPath: given a
// target OS, shell and home directory it returns the startup file to write, or
// an error explaining why the shell has none. Split out so the Windows paths are
// testable on the Linux/macOS CI we actually run.
func shellRCPathFor(goos, shell, home string) (string, error) {
	switch shell {
	case "zsh":
		return filepath.Join(home, ".zshrc"), nil
	case "bash":
		return filepath.Join(home, ".bashrc"), nil
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish"), nil
	case "powershell":
		// Windows PowerShell 5.1 ships only on Windows.
		if goos != "windows" {
			return "", fmt.Errorf("windows powershell is only available on Windows; use %q for PowerShell 7+ on %s", "pwsh", goos)
		}
		return filepath.Join(home, "Documents", "WindowsPowerShell", "profile.ps1"), nil
	case "pwsh":
		// PowerShell 7+ is cross-platform and its profile location differs.
		if goos == "windows" {
			return filepath.Join(home, "Documents", "PowerShell", "profile.ps1"), nil
		}
		return filepath.Join(home, ".config", "powershell", "profile.ps1"), nil
	case "cmd":
		return "", errCmdNotPersistable
	case "sh", "":
		return filepath.Join(home, ".profile"), nil
	default:
		return "", fmt.Errorf("unsupported shell %q (supported: %s)", shell, supportedShellsHint)
	}
}

// errCmdNotPersistable is the honest answer to `--install cmd`.
//
// cmd.exe has no rc file. The only ways to make a doskey macro survive a new
// console are (a) the HKCU\…\Command Processor\AutoRun registry value, which
// runs for EVERY cmd.exe including `cmd /c` inside build scripts and CI (it
// corrupts piped output and is a textbook malware-persistence key that EDR
// flags), or (b) a batch file the user chooses to run themselves. Neither is
// something a security tool should do silently on the user's behalf.
//
// There is a second, harder limit: doskey macros are expanded only at the
// interactive prompt, never inside .bat/.cmd scripts. Even a persisted cmd
// wiring would miss every scripted `npm install`. So the coverage a "successful"
// cmd install would advertise does not exist — which is precisely the false
// success this error replaces.
var errCmdNotPersistable = errors.New(
	"cmd.exe has no startup file, so --install cannot persist a guard wiring there\n" +
		"  doskey macros last only for the console session that defines them, and are not\n" +
		"  expanded inside .bat/.cmd scripts at all.\n" +
		"\n" +
		"  For a persistent wiring on Windows, use PowerShell:\n" +
		"      chainsaw guard init --install powershell\n" +
		"\n" +
		"  For this cmd session only:\n" +
		"      chainsaw guard init cmd > \"%TEMP%\\chainsaw-guard.cmd\" && \"%TEMP%\\chainsaw-guard.cmd\"")

// shellSourceLine is the one line a user adds to their rc to activate the guard.
func shellSourceLine(shell string) string {
	switch shell {
	case "fish":
		return "chainsaw guard init fish | source"
	case "powershell", "pwsh":
		return fmt.Sprintf("chainsaw guard init %s | Invoke-Expression", shell)
	default:
		return fmt.Sprintf("eval \"$(chainsaw guard init %s)\"", shell)
	}
}

// installGuardInit appends the guard activation line to the shell rc file,
// collapsing install→activate into one command. Idempotent: if an active
// invocation is already present it does nothing. Best-effort and explicit — this
// runs only when the user passes --install, so it writes without prompting.
//
// It never reports success without having written a file a shell actually
// loads: shells with no startup file (cmd.exe) fail loudly with instructions
// instead.
func installGuardInit(cmd *cobra.Command, shell string) error {
	if shell == "" {
		shell = detectShell()
	}
	rc, err := shellRCPath(shell)
	if err != nil {
		return err
	}

	// '#' is the comment leader for every shell --install can reach: the POSIX
	// shells, fish and PowerShell all use it. cmd.exe (which would need '::')
	// never gets here — shellRCPath refuses it above.
	out := cmd.OutOrStdout()
	block := fmt.Sprintf("\n# chainsaw install guard — https://chain305.com\n%s\n", shellSourceLine(shell))

	// --dry-run shows the target file and the exact line without touching the rc
	// file — a preview before mutating a shell config (especially useful in CI
	// or when scripting, where --install otherwise writes unconditionally).
	if dry, _ := cmd.Flags().GetBool("dry-run"); dry {
		if found, _ := detectGuardShim([]string{rc}); found {
			fmt.Fprintf(out, "chainsaw: guard already active in %s — --install would be a no-op.\n", rc)
			return nil
		}
		fmt.Fprintf(out, "chainsaw: --install would append to %s:\n%s", rc, block)
		return nil
	}

	// Reuse doctor's line-aware detection so a commented-out invocation doesn't
	// count as installed (it would re-activate on append, which is what we want).
	if found, _ := detectGuardShim([]string{rc}); found {
		fmt.Fprintf(out, "chainsaw: guard already active in %s — nothing to do.\n", rc)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(rc), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	f, err := os.OpenFile(rc, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", rc, err)
	}
	defer f.Close()
	if _, err := f.WriteString(block); err != nil {
		return fmt.Errorf("write %s: %w", rc, err)
	}

	fmt.Fprintf(out, "chainsaw: added the install guard to %s.\n", rc)
	if shell == "powershell" || shell == "pwsh" {
		fmt.Fprintf(out, "chainsaw: restart PowerShell or run: . %s\n", rc)
	} else {
		fmt.Fprintf(out, "chainsaw: restart your shell or run: source %s\n", rc)
	}
	return nil
}

// powerShellProfilePath asks the PowerShell interpreter for its own profile
// path. Overridable in tests, and deliberately best-effort: callers fall back to
// the conventional location when the interpreter is absent (every non-Windows CI
// box) or slow. Asking beats guessing on Windows, where OneDrive's Known Folder
// Move relocates Documents and a guessed ~/Documents path would silently write a
// file PowerShell never loads — a false success of the exact kind this file's
// changes exist to remove.
var powerShellProfilePath = queryPowerShellProfile

func queryPowerShellProfile(shell string) (string, error) {
	exe := "pwsh"
	if shell == "powershell" {
		exe = "powershell"
	}
	bin, err := exec.LookPath(exe)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// CurrentUserAllHosts (profile.ps1) loads in every PowerShell host — console,
	// ISE, VS Code — so the guard covers more of where installs actually happen
	// than the console-only CurrentUserCurrentHost profile.
	out, err := exec.CommandContext(ctx, bin, "-NoProfile", "-NonInteractive",
		"-Command", "$PROFILE.CurrentUserAllHosts").Output()
	if err != nil {
		return "", err
	}
	p := strings.TrimSpace(string(out))
	if p == "" {
		return "", fmt.Errorf("%s returned an empty $PROFILE", exe)
	}
	return p, nil
}

// detectShell guesses the shell from $SHELL. On POSIX it defaults to
// bash-compatible; on Windows $SHELL is normally unset, and defaulting to bash
// there emitted POSIX functions that no Windows shell can load — so Windows
// defaults to PowerShell instead.
func detectShell() string { return detectShellFor(runtime.GOOS, os.Getenv("SHELL")) }

// detectShellFor is the pure, GOOS-parameterised core of detectShell so the
// Windows default is testable without a Windows runner.
func detectShellFor(goos, shellEnv string) string {
	base := shellBaseName(shellEnv)
	switch base {
	case "fish", "zsh", "bash", "sh":
		return base
	}
	// pwsh is cross-platform, so honour it whatever the GOOS. Matched
	// case-insensitively (and only here) to keep the POSIX cases above
	// byte-identical to the pre-Windows behaviour.
	switch strings.ToLower(base) {
	case "pwsh":
		return "pwsh"
	case "powershell":
		return "powershell"
	}
	if goos == "windows" {
		return "powershell"
	}
	return "bash"
}

// shellBaseName strips the directory and any ".exe" suffix from a $SHELL value.
// It splits on both separators rather than using filepath.Base so a Windows path
// resolves identically when the test runs on Linux.
func shellBaseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	if ext := filepath.Ext(p); strings.EqualFold(ext, ".exe") {
		p = p[:len(p)-len(ext)]
	}
	return p
}
