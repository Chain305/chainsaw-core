package cli

import (
	"testing"

	"github.com/spf13/cobra"
)

// TestHelpGroupsRegistered asserts all seven required groups exist on rootCmd
// with the exact IDs and titles the command-group contract specifies.
func TestHelpGroupsRegistered(t *testing.T) {
	assignCommandGroups()

	want := map[string]string{
		GrpScan:   "TARGET & SCAN:",
		GrpPolicy: "POLICY & ENFORCEMENT:",
		GrpIntel:  "INTELLIGENCE:",
		GrpGuard:  "GUARD (install-time):",
		GrpAudit:  "AUDIT & FINDINGS:",
		GrpConfig: "CONFIG & AUTH:",
		GrpDebug:  "DEBUG & DIAGNOSTICS:",
	}

	got := map[string]string{}
	for _, g := range rootCmd.Groups() {
		got[g.ID] = g.Title
	}
	for id, title := range want {
		if got[id] != title {
			t.Errorf("group %q title = %q; want %q", id, got[id], title)
		}
	}
	// The exported ID constants must match the contract string values.
	ids := []struct{ name, val, exp string }{
		{"GrpScan", GrpScan, "grp-scan"},
		{"GrpPolicy", GrpPolicy, "grp-policy"},
		{"GrpIntel", GrpIntel, "grp-intel"},
		{"GrpGuard", GrpGuard, "grp-guard"},
		{"GrpAudit", GrpAudit, "grp-audit"},
		{"GrpConfig", GrpConfig, "grp-config"},
		{"GrpDebug", GrpDebug, "grp-debug"},
	}
	for _, c := range ids {
		if c.val != c.exp {
			t.Errorf("%s = %q; want %q", c.name, c.val, c.exp)
		}
	}
}

// TestNoCommandReferencesUndefinedGroup guards against a command setting a
// GroupID that was never registered (cobra panics on this during Execute).
func TestNoCommandReferencesUndefinedGroup(t *testing.T) {
	assignCommandGroups()

	defined := map[string]bool{}
	for _, g := range rootCmd.Groups() {
		defined[g.ID] = true
	}
	walk := func(c *cobra.Command) {
		if c.GroupID != "" && !defined[c.GroupID] {
			t.Errorf("command %q references undefined group %q", c.Name(), c.GroupID)
		}
	}
	for _, c := range rootCmd.Commands() {
		walk(c)
	}
}

// TestCommandGroupMapMatchesDefinitions guards commandGroupByName against
// silent drift. Every root command sets GroupID on its own literal, so every
// entry in the map is currently inert — nothing executes it and nothing fails
// when it is wrong. Seven entries had drifted to contradict the real group and
// two named commands that do not exist before this test was added.
//
// The map is kept as a fallback for a future command that forgets its GroupID,
// so it must not be allowed to say something false in the meantime: an entry
// that disagrees with the definition-time group is worse than no entry, and an
// entry for a non-existent command is dead weight that reads as a real
// grouping. Assert both.
func TestCommandGroupMapMatchesDefinitions(t *testing.T) {
	assignCommandGroups()

	byName := map[string]*cobra.Command{}
	for _, c := range rootCmd.Commands() {
		byName[c.Name()] = c
	}
	for name, mapped := range commandGroupByName {
		c, ok := byName[name]
		if !ok {
			t.Errorf("commandGroupByName has %q -> %q, but no such command is registered on rootCmd; remove the entry", name, mapped)
			continue
		}
		if c.GroupID != mapped {
			t.Errorf("commandGroupByName says %q -> %q, but the command literal sets GroupID %q (which wins); the map entry is dead AND wrong",
				name, mapped, c.GroupID)
		}
	}
}

// TestLogsCommandHidden pins `chainsaw logs` out of `--help` and the generated
// public reference. Its default path shells out to a real kubectl subprocess
// against the ambient kubeconfig, so advertising it as a developer diagnostic
// means anyone with a kubecontext makes a live cluster call from --help. It
// must stay REGISTERED and runnable for operators — assert both halves, and
// that the tail subcommand needs no separate hiding.
func TestLogsCommandHidden(t *testing.T) {
	assignCommandGroups()

	logs, _, err := rootCmd.Find([]string{"logs"})
	if err != nil || logs == nil || logs.Name() != "logs" {
		t.Fatalf("`logs` must stay registered and runnable, not removed: %v", err)
	}
	if !logs.Hidden {
		t.Error("`logs` must be Hidden — it shells out to kubectl against the ambient kubeconfig")
	}
	if logs.IsAvailableCommand() {
		t.Error("hidden `logs` should not be an available command in help listings")
	}

	// Hiding the parent is sufficient: cobra never walks into a hidden
	// command when rendering root help, and gen-cli-docs skips the whole
	// subtree. `tail` therefore needs no Hidden of its own, and must not
	// have one — it has to stay usable via `chainsaw logs tail`.
	tail, _, err := rootCmd.Find([]string{"logs", "tail"})
	if err != nil || tail == nil || tail.Name() != "tail" {
		t.Fatalf("`logs tail` must stay reachable: %v", err)
	}
	if tail.Hidden {
		t.Error("`logs tail` should not be independently hidden; the parent's Hidden covers help + docs")
	}
	if tail.RunE == nil {
		t.Error("`logs tail` must stay runnable")
	}
}

// TestGuardCommandsGroupedUnderGuard double-checks (via assignCommandGroups,
// the production path) that the guard wrappers land in GrpGuard.
func TestGuardCommandsGroupedUnderGuard(t *testing.T) {
	assignCommandGroups()
	for _, name := range []string{"npm", "pip", "go", "cargo", "gem"} {
		cmd, _, err := rootCmd.Find([]string{name})
		if err != nil || cmd == nil {
			t.Fatalf("command %q not found: %v", name, err)
		}
		if cmd.GroupID != GrpGuard {
			t.Errorf("command %q GroupID = %q; want GrpGuard(%q)", name, cmd.GroupID, GrpGuard)
		}
	}
}
