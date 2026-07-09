package cli

// completion.go — shell completion wiring (P1.7).
//
// Cobra auto-generates the `completion` subcommand (bash/zsh/fish/powershell)
// for every root command unless CompletionOptions.DisableDefaultCmd is set.
// chainsaw never sets that, so `chainsaw completion <shell>` already works out
// of the box. This file does two small, additive things and deliberately
// nothing more:
//
//  1. Defensively asserts the default completion command stays ENABLED and
//     VISIBLE — so a future CompletionOptions tweak elsewhere can't silently
//     hide it (help_groups.go already files `completion` under DEBUG &
//     DIAGNOSTICS via SetCompletionCommandGroupID).
//
//  2. Registers value completion for the global --format flag (table|json) so
//     `chainsaw --format <TAB>` offers the two valid values.
//
// SECURITY NOTE (guard safety): the guard wrappers (npm/pip/go/cargo/gem) run
// with DisableFlagParsing and pass their args straight to the wrapped package
// manager. We intentionally do NOT attach a ValidArgsFunction to those
// commands — completion must never run guard logic or risk shifting the
// install verb. Flag-value completion here only touches chainsaw's own global
// --format flag, never the wrapped-manager argv.

import "github.com/spf13/cobra"

func init() {
	// Keep the default `completion` command enabled and visible. These are the
	// cobra defaults; setting them explicitly makes the intent regression-proof.
	rootCmd.CompletionOptions.DisableDefaultCmd = false
	rootCmd.CompletionOptions.HiddenDefaultCmd = false

	// --format value completion must run AFTER the persistent flag is
	// registered. Go initializes files in alphabetical order, so this file's
	// init() runs before root.go's init() where --format is added; registering
	// the completion func here directly would fail because the flag doesn't
	// exist yet. cobra.OnInitialize defers it to Execute()-time (it appends to
	// the initializer list, so root.go's initConfig hook is preserved), by
	// which point every persistent flag exists.
	cobra.OnInitialize(registerFormatCompletion)
}

// registerFormatCompletion offers table|json for the --format flag. Idempotent
// and tolerant: it no-ops if the flag is somehow absent so completion setup can
// never break command dispatch.
func registerFormatCompletion() {
	if rootCmd.PersistentFlags().Lookup("format") == nil {
		return
	}
	_ = rootCmd.RegisterFlagCompletionFunc("format",
		func(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
			return []string{"table", "json"}, cobra.ShellCompDirectiveNoFileComp
		})
}
