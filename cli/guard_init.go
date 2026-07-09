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
// shadow — so `npm` (function) → `chainsaw npm` → real `npm` binary.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var guardInitCmd = &cobra.Command{
	Use:   "init [bash|zsh|fish]",
	Short: "Print shell functions that route npm/pip/go through the guard",
	Long: `Print shell functions that route your package managers through the Chainsaw
install guard, so installs are checked automatically without typing "chainsaw"
each time.

Add to your shell config and reload:

  # ~/.zshrc or ~/.bashrc
  eval "$(chainsaw guard init zsh)"

  # ~/.config/fish/config.fish
  chainsaw guard init fish | source

The functions delegate to the real npm/pip/go after the check; the default path
is offline and sends nothing off your machine.

With --install, append the activation line to your shell rc file (idempotent)
instead of printing the functions, so setup is a single command with no
copy-paste:

  chainsaw guard init --install`,
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
// guard so both common invocations are covered.
var guardedTools = []struct{ fn, tool string }{
	{"npm", "npm"},
	{"pip", "pip"},
	{"pip3", "pip"},
	{"go", "go"},
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
	case "bash", "zsh", "sh", "":
		fmt.Fprintln(out, "# chainsaw install guard — https://chain305.com")
		for _, t := range guardedTools {
			fmt.Fprintf(out, "%s() { command chainsaw %s \"$@\"; }\n", t.fn, t.tool)
		}
	default:
		return fmt.Errorf("unsupported shell %q (supported: bash, zsh, fish)", shell)
	}
	return nil
}

// shellRCPath returns the rc file --install writes to for a shell. fish uses
// config.fish under XDG; the POSIX shells use the conventional dotfile.
func shellRCPath(shell string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("cannot determine home directory")
	}
	switch shell {
	case "zsh":
		return filepath.Join(home, ".zshrc"), nil
	case "bash":
		return filepath.Join(home, ".bashrc"), nil
	case "fish":
		return filepath.Join(home, ".config", "fish", "config.fish"), nil
	case "sh", "":
		return filepath.Join(home, ".profile"), nil
	default:
		return "", fmt.Errorf("unsupported shell %q (supported: bash, zsh, fish)", shell)
	}
}

// shellSourceLine is the one line a user adds to their rc to activate the guard.
func shellSourceLine(shell string) string {
	if shell == "fish" {
		return "chainsaw guard init fish | source"
	}
	return fmt.Sprintf("eval \"$(chainsaw guard init %s)\"", shell)
}

// installGuardInit appends the guard activation line to the shell rc file,
// collapsing install→activate into one command. Idempotent: if an active
// invocation is already present it does nothing. Best-effort and explicit — this
// runs only when the user passes --install, so it writes without prompting.
func installGuardInit(cmd *cobra.Command, shell string) error {
	if shell == "" {
		shell = detectShell()
	}
	rc, err := shellRCPath(shell)
	if err != nil {
		return err
	}

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
	fmt.Fprintf(out, "chainsaw: restart your shell or run: source %s\n", rc)
	return nil
}

// detectShell guesses the shell from $SHELL, defaulting to bash-compatible.
func detectShell() string {
	base := filepath.Base(os.Getenv("SHELL"))
	switch base {
	case "fish", "zsh", "bash", "sh":
		return base
	default:
		return "bash"
	}
}
