package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// guardWrapperCmds are the five package-manager passthrough wrappers. They are
// the free tier's front door, so their help is held to a higher bar than the
// rest of the tree.
func guardWrapperCmds() map[string]*cobra.Command {
	return map[string]*cobra.Command{
		"npm":   npmGuardCmd,
		"go":    goGuardCmd,
		"pip":   pipGuardCmd,
		"cargo": cargoGuardCmd,
		"gem":   gemGuardCmd,
	}
}

// TestGuardWrappersHaveLongAndExample pins that every wrapper carries real
// help. Before this landed all five had a one-line Short, no Long and no
// Example — the thinnest help in the CLI, on the commands a new user runs
// first.
func TestGuardWrappersHaveLongAndExample(t *testing.T) {
	for name, cmd := range guardWrapperCmds() {
		t.Run(name, func(t *testing.T) {
			if strings.TrimSpace(cmd.Long) == "" {
				t.Fatalf("%s wrapper has no Long help", name)
			}
			if strings.TrimSpace(cmd.Example) == "" {
				t.Fatalf("%s wrapper has no Example", name)
			}
			// The three questions a first-time user arrives with.
			for _, want := range []string{
				"Offline by default", // does it send anything?
				"Fails open",         // what happens when it can't tell?
				"Exit codes",         // how do I gate on it?
				"guard init",         // how do I make it automatic?
			} {
				if !strings.Contains(cmd.Long, want) {
					t.Errorf("%s Long help does not mention %q", name, want)
				}
			}
			if !strings.Contains(cmd.Example, "chainsaw "+name) {
				t.Errorf("%s Example does not show a `chainsaw %s` invocation", name, name)
			}
		})
	}
}

// TestGuardWrappersForwardHelpToWrappedTool pins the FORWARDING behaviour, and
// exists to stop a well-meaning future change from "fixing" it.
//
// `chainsaw guard init` installs shell functions — `npm() { command chainsaw
// npm "$@"; }` — so after the documented `eval "$(chainsaw guard init)"` a user
// typing `npm --help` IS running `chainsaw npm --help`. If these commands
// intercepted a bare `--help` to show Chainsaw's own text, they would replace
// npm's help with Chainsaw's for every guard user on the machine, and break the
// wrapper's stated contract that flags pass through untouched.
//
// The mechanism that guarantees forwarding is DisableFlagParsing: with it set,
// cobra hands `--help` to RunE as an ordinary argument instead of intercepting
// it. Asserting on the field is the honest test — actually executing the
// command would shell out to whichever npm/go/pip happens to exist on the
// machine running the suite.
func TestGuardWrappersForwardHelpToWrappedTool(t *testing.T) {
	for name, cmd := range guardWrapperCmds() {
		t.Run(name, func(t *testing.T) {
			if !cmd.DisableFlagParsing {
				t.Fatalf("%s wrapper must keep DisableFlagParsing so --help reaches the "+
					"wrapped tool; intercepting it would break `npm --help` for every "+
					"user who ran `chainsaw guard init`", name)
			}
			if cmd.Args == nil {
				t.Errorf("%s wrapper should accept arbitrary args for passthrough", name)
			}
			// The Long text tells the user where their own tool's help went.
			// Without this, forwarding reads as a bug rather than a contract.
			if !strings.Contains(cmd.Long, "chainsaw help "+name) {
				t.Errorf("%s Long help must point at `chainsaw help %s`, since "+
					"`chainsaw %s --help` deliberately shows %s's help instead",
					name, name, name, name)
			}
		})
	}
}
