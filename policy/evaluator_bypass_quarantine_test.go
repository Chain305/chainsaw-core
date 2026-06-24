package policy

// D.12 follow-on: BYPASS_SUSPECTED reason injection coverage.
//
// The unit tests below pin the four-quadrant matrix called out in the
// task contract for the policy-gate:
//
//   1. client NOT quarantined + engine ALLOW  → reason untouched
//   2. client quarantined     + engine ALLOW  → reason == BYPASS_SUSPECTED
//   3. client quarantined     + engine BLOCK  → reason carries BOTH
//                                                the engine reason AND
//                                                BYPASS_SUSPECTED, but
//                                                Action stays Block
//   4. no checker wired                       → no-op (backwards-compat)
//
// The checker is a function-adapter stub so the policy package stays
// free of any database dependency — the production wire-up lives in
// internal/server/policy_support_matrix.go.

import (
	"context"
	"strings"
	"testing"
)

// quarantineStub returns true for any (org, clientID) in the seeded
// set. Recorded calls let assertions check the evaluator actually
// consulted the hook (so a future refactor can't silently regress).
type quarantineStub struct {
	quarantined map[string]bool // key: orgID+"|"+clientID
	calls       int
}

func (q *quarantineStub) IsBypassQuarantined(_ context.Context, orgID, clientID string) bool {
	q.calls++
	if q.quarantined == nil {
		return false
	}
	return q.quarantined[orgID+"|"+clientID]
}

func newQuarantineStub(pairs ...string) *quarantineStub {
	q := &quarantineStub{quarantined: map[string]bool{}}
	for _, p := range pairs {
		q.quarantined[p] = true
	}
	return q
}

// Quadrant 1 + 4: no quarantine match → engine ALLOW reason untouched.
func TestApplyBypassQuarantine_NotQuarantined_AllowUnchanged(t *testing.T) {
	t.Parallel()

	stub := newQuarantineStub("org-a|safe-client") // different client
	eval := NewEvaluator(nil).WithBypassQuarantineChecker(stub)

	ctx := EvaluationContext{
		OrgID:          "org-a",
		ClientID:       "untracked-client",
		PackageName:    "leftpad",
		PackageVersion: "1.0.0",
	}
	// Empty policy list → "no matching policy" allow.
	result := eval.EvaluateWithPolicies(ctx, nil, 0)

	if result.Action != ModeAllow {
		t.Fatalf("expected ModeAllow, got %s", result.Action)
	}
	if strings.Contains(result.Reason, ReasonBypassSuspected) {
		t.Fatalf("did not expect BYPASS_SUSPECTED stamp, got reason=%q", result.Reason)
	}
	if stub.calls != 1 {
		t.Fatalf("expected exactly one quarantine lookup, got %d", stub.calls)
	}
}

// Quadrant 2: client in quarantine + policy engine ALLOW → request still
// allowed, reason stamped with BYPASS_SUSPECTED.
func TestApplyBypassQuarantine_Quarantined_AllowKeepsActionStampReason(t *testing.T) {
	t.Parallel()

	stub := newQuarantineStub("org-a|noisy-client")
	eval := NewEvaluator(nil).WithBypassQuarantineChecker(stub)

	ctx := EvaluationContext{
		OrgID:          "org-a",
		ClientID:       "noisy-client",
		PackageName:    "leftpad",
		PackageVersion: "1.0.0",
	}
	result := eval.EvaluateWithPolicies(ctx, nil, 0)

	if result.Action != ModeAllow {
		t.Fatalf("BYPASS_SUSPECTED must not block; expected ModeAllow, got %s", result.Action)
	}
	if !strings.Contains(result.Reason, ReasonBypassSuspected) {
		t.Fatalf("expected reason to carry BYPASS_SUSPECTED, got %q", result.Reason)
	}
	if stub.calls != 1 {
		t.Fatalf("expected exactly one quarantine lookup, got %d", stub.calls)
	}
}

// Quadrant 3: client in quarantine + policy engine BLOCK → block fires,
// reason carries both the engine reason and BYPASS_SUSPECTED.
func TestApplyBypassQuarantine_Quarantined_BlockKeepsActionAdditiveReason(t *testing.T) {
	t.Parallel()

	stub := newQuarantineStub("org-a|noisy-client")
	eval := NewEvaluator(nil).WithBypassQuarantineChecker(stub)

	isMaliciousTrue := true
	policies := []Policy{
		{
			ID:         "block-malware",
			Precedence: 10,
			Mode:       ModeBlock,
			Status:     StatusEnabled,
			Identifier: Identifier{
				TargetPackageRepo:    "*",
				TargetPackageName:    "*",
				TargetPackageVersion: "*",
			},
			Conditions: Conditions{IsKnownMalicious: &isMaliciousTrue},
		},
	}

	ctx := EvaluationContext{
		OrgID:            "org-a",
		ClientID:         "noisy-client",
		PackageName:      "evil-pkg",
		PackageVersion:   "1.0.0",
		IsKnownMalicious: true,
	}
	result := eval.EvaluateWithPolicies(ctx, policies, 0)

	if result.Action != ModeBlock {
		t.Fatalf("engine BLOCK must remain BLOCK with bypass stamp; got %s", result.Action)
	}
	if !strings.Contains(result.Reason, "block-malware") {
		t.Fatalf("expected engine reason (policy ID) preserved, got %q", result.Reason)
	}
	if !strings.Contains(result.Reason, ReasonBypassSuspected) {
		t.Fatalf("expected BYPASS_SUSPECTED appended to engine reason, got %q", result.Reason)
	}
	if result.MatchedPolicy == nil || result.MatchedPolicy.ID != "block-malware" {
		t.Fatalf("MatchedPolicy must still surface the original block, got %+v", result.MatchedPolicy)
	}
}

// Quadrant 4: no checker wired → applyBypassQuarantine is a no-op.
// Pins the backwards-compat contract — pre-D.12 callers see unchanged
// behaviour.
func TestApplyBypassQuarantine_NoChecker_NoOp(t *testing.T) {
	t.Parallel()

	eval := NewEvaluator(nil) // no WithBypassQuarantineChecker

	ctx := EvaluationContext{
		OrgID:          "org-a",
		ClientID:       "any-client",
		PackageName:    "leftpad",
		PackageVersion: "1.0.0",
	}
	result := eval.EvaluateWithPolicies(ctx, nil, 0)

	if result.Action != ModeAllow {
		t.Fatalf("expected ModeAllow, got %s", result.Action)
	}
	if strings.Contains(result.Reason, ReasonBypassSuspected) {
		t.Fatalf("nil checker must never stamp BYPASS_SUSPECTED, got %q", result.Reason)
	}
}

// Empty ClientID or OrgID is a fail-safe degrade: the stub must not be
// queried, and no stamp is applied. Mirrors IsBypassQuarantined's own
// "empty → false" contract so the policy-gate inherits the same
// fail-open posture.
func TestApplyBypassQuarantine_EmptyIdentity_NoLookup(t *testing.T) {
	t.Parallel()

	stub := newQuarantineStub("org-a|*") // any
	eval := NewEvaluator(nil).WithBypassQuarantineChecker(stub)

	// Empty ClientID
	ctx := EvaluationContext{OrgID: "org-a"}
	result := eval.EvaluateWithPolicies(ctx, nil, 0)
	if strings.Contains(result.Reason, ReasonBypassSuspected) {
		t.Fatalf("empty ClientID must skip the lookup, got reason=%q", result.Reason)
	}

	// Empty OrgID
	ctx = EvaluationContext{ClientID: "c"}
	result = eval.EvaluateWithPolicies(ctx, nil, 0)
	if strings.Contains(result.Reason, ReasonBypassSuspected) {
		t.Fatalf("empty OrgID must skip the lookup, got reason=%q", result.Reason)
	}
	if stub.calls != 0 {
		t.Fatalf("checker must not be called with empty identity; got %d calls", stub.calls)
	}
}

// Sanity check on the func-adapter: BypassQuarantineCheckerFunc(nil)
// must degrade to "false" so a forgotten wire-up doesn't panic.
func TestBypassQuarantineCheckerFunc_NilSafe(t *testing.T) {
	t.Parallel()

	var f BypassQuarantineCheckerFunc
	if f.IsBypassQuarantined(context.Background(), "org-a", "c-1") {
		t.Fatalf("nil func must return false")
	}
}
