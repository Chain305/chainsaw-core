package cli

// intel_health_test.go pins the registration of `intel health`. The
// runtime behaviour changed in two ways that require a live (or
// black-holed) server and are covered manually:
//   - the network Health call is now bounded by a 10s context timeout
//     derived from cmd.Context() (previously context.Background(), which
//     could hang forever), and
//   - a failed Health call now prints a remediation hint to stderr before
//     exiting 2.
// Both are exercised against an unreachable server in the manual test plan.

import "testing"

func TestIntelHealthCmdRegistered(t *testing.T) {
	c, _, err := intelCmd.Find([]string{"health"})
	if err != nil {
		t.Fatalf("intel health not registered: %v", err)
	}
	if c.Use != "health" {
		t.Errorf("found wrong command: %q", c.Use)
	}
	if c.RunE == nil {
		t.Error("intel health has no RunE")
	}
}
