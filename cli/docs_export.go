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

import (
	"strings"

	"github.com/spf13/cobra"
)

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
// hand-copied table.
//
// It is a projection of exitCodeAllocations — the single allocation ledger in
// exitcodes.go — rather than a second hand-maintained list. That matters
// because this function used to be BOTH incomplete and misleading: it omitted
// ExitManifestParseError(30) entirely, and it published 10 as though
// "ExitSoakNotCleared" were its only meaning while `pr-scan --help`,
// `scan-repo --help` and `doctor --strict` told other readers that 10 meant
// warning-level findings and drift. `make check-cli-docs-sync` could not catch
// either, because it only diffs the generated file against this function.
// TestExitCodesForDocsIsComplete now asserts the reverse direction against an
// AST parse of exitcodes.go, so an added or renumbered constant fails the build
// instead of silently vanishing from the published contract.
//
// Name carries the Go constant for the exported Exit* codes (what a reader
// greps for) and the owning command for the rest, which are unexported
// per-command constants no customer can reference. Code values are the
// constants themselves, so a renumber cannot desync the table from the binary.
func ExitCodesForDocs() []ExitCodeForDocs {
	out := make([]ExitCodeForDocs, 0, len(exitCodeAllocations))
	for _, a := range exitCodeAllocations {
		if a.Kind == "" {
			continue
		}
		out = append(out, ExitCodeForDocs{
			Code: a.Code,
			Name: exitCodeDocsName(a),
			Kind: a.Kind,
			Desc: a.Desc,
		})
	}
	return out
}

// exitCodeDocsName picks the Name column for one allocation: the exported
// constant when there is one, otherwise the owning command. Every exported
// exit-code constant in this package is named Exit*, and the unexported
// per-command ones (prScanExitWarning, doctorExitDrift, …) are not part of any
// public API, so printing them in customer docs would send readers looking for
// an identifier they cannot use.
func exitCodeDocsName(a exitCodeAllocation) string {
	for _, c := range a.Consts {
		if strings.HasPrefix(c, "Exit") {
			return c
		}
	}
	return a.Owner
}
