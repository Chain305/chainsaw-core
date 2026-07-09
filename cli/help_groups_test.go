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
