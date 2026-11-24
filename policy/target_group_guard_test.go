package policy

import "testing"

// TestSecurityGuard_TargetGroupRefusedUntilWired — pentest #59: nothing
// populates EvaluationContext.ClientGroups, so a targetGroup-scoped rule can
// never match and an operator's "block for group X" silently enforced
// nothing. Saving an enabled one is refused until the dimension is wired; a
// disabled one (and so disabling an existing row) is still accepted.
func TestSecurityGuard_TargetGroupRefusedUntilWired(t *testing.T) {
	base := Policy{
		Name: "g", Mode: ModeBlock, Status: StatusEnabled,
		Identifier: Identifier{TargetPackageName: "lodash"},
	}
	grouped := base
	grouped.Scope.TargetGroup = []string{"platform"}
	if err := validatePolicy(grouped); err == nil {
		t.Error("an enabled targetGroup rule was accepted; it can never match")
	}
	pending := grouped
	pending.Status = StatusPendingApproval
	if err := validatePolicy(pending); err == nil {
		t.Error("a pending targetGroup rule was accepted; approving it would enable an inert rule")
	}

	// Positive controls.
	disabled := grouped
	disabled.Status = StatusDisabled
	if err := validatePolicy(disabled); err != nil {
		t.Errorf("disabling a targetGroup rule was refused: %v", err)
	}
	if err := validatePolicy(base); err != nil {
		t.Errorf("a plain enabled rule was refused: %v", err)
	}
	blank := base
	blank.Scope.TargetGroup = []string{" "}
	if err := validatePolicy(blank); err != nil {
		t.Errorf("a blank targetGroup entry was refused: %v", err)
	}
}
