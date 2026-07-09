package policy

import "testing"

// KEYSTONE (Item-2, ADR-007): a pending_approval exception must NEVER
// bypass a malware block. The evaluator only honours StatusEnabled rules
// (evaluatePolicies skips `policy.Status != StatusEnabled`), so a
// KindException rule in StatusPendingApproval is naturally inert — the
// later malware block fires. This test pins that invariant so a future
// change to the status filter can't silently let a pending exception
// through.
func TestEvaluatePolicies_PendingException_DoesNotBypassMalwareBlock(t *testing.T) {
	t.Parallel()

	eval := NewEvaluator(nil)
	isMal := true
	policies := []Policy{
		{
			ID:         "pending-exception",
			Precedence: -1, // sorts first, just like a live exception
			Mode:       ModeAllow,
			Kind:       KindException,
			Status:     StatusPendingApproval, // <-- not enabled yet
			Identifier: Identifier{
				TargetPackageRepo:    "npmjs",
				TargetPackageName:    "evil-pkg",
				TargetPackageVersion: "1.0.0",
			},
		},
		{
			ID:         "block-known-malware",
			Precedence: 100,
			Mode:       ModeBlock,
			Status:     StatusEnabled,
			Identifier: Identifier{TargetPackageRepo: "*", TargetPackageName: "*", TargetPackageVersion: "*"},
			Conditions: Conditions{IsKnownMalicious: &isMal},
		},
	}

	ctx := EvaluationContext{
		Repository:       "npmjs",
		PackageName:      "evil-pkg",
		PackageVersion:   "1.0.0",
		IsKnownMalicious: true,
	}
	res := eval.EvaluateWithPolicies(ctx, policies, 0)
	if res.Action != ModeBlock {
		t.Fatalf("pending_approval exception must NOT bypass malware block; want ModeBlock, got %s (matched %+v)",
			res.Action, res.MatchedPolicy)
	}
	if res.MatchedPolicy == nil || res.MatchedPolicy.ID != "block-known-malware" {
		t.Fatalf("expected the malware block to match, got %+v", res.MatchedPolicy)
	}
}

// Companion: once approved (StatusEnabled), the SAME exception DOES
// bypass the malware block — proving the gate is purely the status, and
// that approval restores today's bypass behaviour.
func TestEvaluatePolicies_ApprovedException_BypassesMalwareBlock(t *testing.T) {
	t.Parallel()

	eval := NewEvaluator(nil)
	isMal := true
	policies := []Policy{
		{
			ID:         "approved-exception",
			Precedence: -1,
			Mode:       ModeAllow,
			Kind:       KindException,
			Status:     StatusEnabled, // approved
			Identifier: Identifier{
				TargetPackageRepo:    "npmjs",
				TargetPackageName:    "evil-pkg",
				TargetPackageVersion: "1.0.0",
			},
		},
		{
			ID:         "block-known-malware",
			Precedence: 100,
			Mode:       ModeBlock,
			Status:     StatusEnabled,
			Identifier: Identifier{TargetPackageRepo: "*", TargetPackageName: "*", TargetPackageVersion: "*"},
			Conditions: Conditions{IsKnownMalicious: &isMal},
		},
	}
	ctx := EvaluationContext{
		Repository:       "npmjs",
		PackageName:      "evil-pkg",
		PackageVersion:   "1.0.0",
		IsKnownMalicious: true,
	}
	res := eval.EvaluateWithPolicies(ctx, policies, 0)
	if res.Action != ModeAllow {
		t.Fatalf("approved exception should bypass malware block; want ModeAllow, got %s", res.Action)
	}
}
