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
is offline and sends nothing off your machine.`,
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE:         runGuardInit,
}

func init() {
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
