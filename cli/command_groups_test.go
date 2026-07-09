package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

// command_groups_test.go enforces the help-grouping contract: every
// top-level command registered on rootCmd MUST set a GroupID at
// definition time so it renders under one of the seven section headers
// in `chainsaw --help` instead of falling into cobra's catch-all
// "Additional Commands" bucket.
//
// Why direct children only: GroupID is a top-level concept in cobra —
// groups partition the root command's immediate subcommands. Nested
// subcommands (e.g. `auth login`, `policy create`) intentionally leave
// GroupID empty; cobra never renders a group header for them. Asserting
// GroupID on deep subcommands would be wrong, so the walk checks the
// direct children of rootCmd.
//
// This test is the guard rail that catches a future command author who
// adds `rootCmd.AddCommand(fooCmd)` but forgets `GroupID: GrpX`. It
// deliberately does NOT call assignCommandGroups(): that helper backfills
// GroupID from a name→group map and would mask a missing definition-time
// tag, defeating the regression check.

// cobraBuiltinNames are the auto-generated commands cobra wires up
// (help, completion). They are not registered by chainsaw code, so they
// are exempt from the GroupID requirement — cobra assigns their group
// separately via SetHelpCommandGroupID / SetCompletionCommandGroupID in
// assignCommandGroups (the production path).
var cobraBuiltinNames = map[string]bool{
	"help":       true,
	"completion": true,
}

// TestEveryTopLevelCommandHasGroupID asserts that every command directly
// registered on rootCmd carries a non-empty GroupID set at definition
// time. A failure here means a new top-level command was added without a
// help group — tag it with one of the Grp* constants (help_groups.go).
func TestEveryTopLevelCommandHasGroupID(t *testing.T) {
	// Make sure cobra has materialized any lazily-created built-ins (help /
	// completion) so the exemption list below actually matches what would
	// appear in help. These are idempotent no-ops when already initialized.
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()

	var untagged []string
	for _, c := range rootCmd.Commands() {
		if cobraBuiltinNames[c.Name()] {
			continue
		}
		// Additional help topics are documentation pseudo-commands, not
		// runnable surfaces, and never carry a group.
		if c.IsAdditionalHelpTopicCommand() {
			continue
		}
		if c.GroupID == "" {
			untagged = append(untagged, c.Name())
		}
	}

	if len(untagged) > 0 {
		t.Errorf("the following top-level commands have no GroupID (tag each with a Grp* constant from help_groups.go): %v", untagged)
	}
}

// TestTopLevelGroupIDsAreRegistered asserts that every GroupID set on a
// top-level command refers to one of the seven registered groups. A
// command pointing at an unregistered group ID makes cobra panic during
// Execute (checkCommandGroups), so this catches a typo'd constant before
// it reaches a user.
func TestTopLevelGroupIDsAreRegistered(t *testing.T) {
	// registerHelpGroups runs in help_groups.go's init(), but call it
	// defensively so this test does not depend on init ordering.
	registerHelpGroups()

	valid := map[string]bool{
		GrpScan:   true,
		GrpPolicy: true,
		GrpIntel:  true,
		GrpGuard:  true,
		GrpAudit:  true,
		GrpConfig: true,
		GrpDebug:  true,
	}

	walk := func(c *cobra.Command) {
		if c.GroupID != "" && !valid[c.GroupID] {
			t.Errorf("command %q has unregistered GroupID %q", c.Name(), c.GroupID)
		}
	}
	for _, c := range rootCmd.Commands() {
		walk(c)
	}
}
