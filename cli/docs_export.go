package cli

// docs_export.go — the one exported hook into the assembled command tree,
// for the `gen-cli-docs` generator that renders
// docs.chain305.com/cli-reference/ from cobra itself.
//
// Why this exists rather than the generator reaching for rootCmd: rootCmd is
// unexported, and it should stay that way — an exported mutable *cobra.Command
// invites callers to add commands to a shipped binary from outside the
// package. This returns the same pointer but names the single supported
// read-only use, and it is the only place that documents the two setup steps a
// caller must not skip.

import "github.com/spf13/cobra"

// RootCommandForDocs returns the fully assembled root command with help groups
// applied, for read-only introspection by documentation generators.
//
// It performs the same assignCommandGroups() step Execute() does, because a
// command's GroupID is only populated at that point for the ~30 commands that
// are grouped by name rather than at definition time (see help_groups.go). A
// generator that read rootCmd directly would therefore see most of the tree
// ungrouped and emit a reference whose sections did not match `chainsaw
// --help` — the exact drift a generated reference exists to prevent.
//
// Deliberately NOT called: resolveVersion(). Execute() overwrites
// rootCmd.Version with the resolved build info (commit hash, build date,
// ad-hoc/modified markers), all of which vary per machine and per commit.
// Generated docs must be a pure function of the source tree so the
// check-cli-docs-sync CI guard can diff a fresh run against the committed
// output — see the determinism note in cmd/gen-cli-docs. Nothing in the
// generated reference prints .Version for the same reason.
//
// The returned tree is shared mutable state owned by this package. Callers
// must treat it as read-only; mutating it would change the behavior of the
// CLI in the same process.
func RootCommandForDocs() *cobra.Command {
	assignCommandGroups()
	return rootCmd
}

// HelpGroupsForDocs returns the ordered help groups exactly as they render in
// `chainsaw --help`, so a generator can lay its index out in the same order
// instead of hardcoding a second copy that silently drifts when a group is
// added or reordered.
//
// Returns the ID and Title of each group; the slice is freshly allocated so a
// caller cannot reorder the package's own registration list.
func HelpGroupsForDocs() []struct{ ID, Title string } {
	out := make([]struct{ ID, Title string }, 0, len(helpGroups))
	for _, g := range helpGroups {
		out = append(out, struct{ ID, Title string }{ID: g.ID, Title: g.Title})
	}
	return out
}

// ExitCodeForDocs is one row of the exit-code contract.
type ExitCodeForDocs struct {
	Code int
	Name string
	Kind string // "shared" for the 0–4 buckets, "command" for the >=10 codes.
	Desc string
}

// ExitCodesForDocs returns the process exit-code contract from exitcodes.go so
// the generated reference publishes the real constants rather than a
// hand-copied table. The Desc text is the operator-facing summary of each
// constant's doc comment; the Code values are the constants themselves, so a
// renumber cannot silently desync the published table from the binary.
func ExitCodesForDocs() []ExitCodeForDocs {
	return []ExitCodeForDocs{
		{ExitOK, "ExitOK", "shared", "Success."},
		{ExitBlocked, "ExitBlocked", "shared", "The expected enforcement outcome: a policy block, a failed gate, or findings at or above the configured threshold. Stays 1 so existing block-gating scripts keep working."},
		{ExitOpError, "ExitOpError", "shared", "Operational failure: network, server, IO, or internal error. Distinct from a block so CI can tell infrastructure trouble apart from enforcement."},
		{ExitConfigAuth, "ExitConfigAuth", "shared", "Configuration or authentication problem (no server configured, unauthorized, forbidden)."},
		{ExitUsage, "ExitUsage", "shared", "The invocation itself was wrong: unknown command, unknown flag, or bad argument shape."},
		{ExitSoakNotCleared, "ExitSoakNotCleared", "command", "`admission soak clear` ran successfully but the shadow-mode soak gate is not yet cleared."},
		{ExitIntelBlock, "ExitIntelBlock", "command", "`intel scan` found at least one Quarantine or Replace node — the strongest block the command emits. Weaker Warn/UpgradeAvailable trees still exit 1."},
	}
}
