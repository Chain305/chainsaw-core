package policy

import (
	"testing"
	"time"
)

// --- B9: checksum-unavailable fail-open contract lock ---------------------
//
// When ctx.ChecksumUnavailable is true, a policy whose decision depends
// on integrity-derived signals (isVulnerable → ConditionCVE, or
// hasProvenance) is SKIPPED with SkipReasonChecksumUnavailable and the
// evaluator falls open (does not block). This is INTENTIONAL per the
// two-layer fail-posture design: infra/signal-unavailable fails CLOSED
// at admission (failmode.go / webhook) and at publish (opt-in Rego
// input.signalsUnavailable), NOT inside the native evaluator loop.
// These tests LOCK that contract so a refactor cannot silently collapse
// the native skip into a block (mass false-block) or drop the audit
// reason (loss of operator visibility). See B9 in the remediation plan.

// TestChecksumUnavailable_HasProvenance_SkippedFailOpen exercises the
// hasProvenance branch (the isVulnerable branch is covered by
// TestEvaluateEmitsChecksumUnavailableSkip). The policy WOULD block
// (hasProvenance:true against a context whose provenance is missing) —
// but with ChecksumUnavailable it must be skipped and fail open.
func TestChecksumUnavailable_HasProvenance_SkippedFailOpen(t *testing.T) {
	t.Parallel()

	auditor := &captureAuditor{}
	eval := (&Evaluator{}).WithSkipAuditor(auditor)

	wantProvenance := true
	pol := Policy{
		ID:         "block-missing-provenance",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{HasProvenance: &wantProvenance},
	}

	ctx := EvaluationContext{
		Repository:          "npmjs",
		PackageName:         "left-pad",
		PackageVersion:      "1.0.0",
		ChecksumUnavailable: true,
		HasProvenance:       false, // would satisfy a "require provenance" block if evaluated
	}

	res := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)

	// (a) fail-open: the integrity-gated block did NOT fire.
	if res.Action != ModeAllow {
		t.Fatalf("checksum-unavailable must fail OPEN (allow), got %s", res.Action)
	}
	if res.MatchedPolicy != nil {
		t.Fatalf("no policy should match on a checksum-unavailable skip, got %+v", res.MatchedPolicy)
	}

	// (b) the skip was recorded with the distinct reason + condition.
	events := auditor.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 skip event, got %d (%+v)", len(events), events)
	}
	if events[0].Reason != SkipReasonChecksumUnavailable {
		t.Fatalf("reason: want %s, got %s", SkipReasonChecksumUnavailable, events[0].Reason)
	}
	if events[0].Condition != string(ConditionHasProvenance) {
		t.Fatalf("condition: want %s, got %s", ConditionHasProvenance, events[0].Condition)
	}
}

// TestChecksumAvailable_HasProvenance_Enforces is the companion that
// pins the OTHER side of the contract: when checksum IS available the
// same policy enforces normally. Together with the skip test this makes
// the fail-open a deliberate, checksum-gated branch rather than a
// blanket exemption — a refactor that broke either side turns red.
func TestChecksumAvailable_HasProvenance_Enforces(t *testing.T) {
	t.Parallel()

	wantProvenance := true
	pol := Policy{
		ID:         "block-missing-provenance",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{HasProvenance: &wantProvenance},
	}

	ctx := EvaluationContext{
		Repository:          "npmjs",
		PackageName:         "left-pad",
		PackageVersion:      "1.0.0",
		ChecksumUnavailable: false, // checksum present → rule is live
		HasProvenance:       true,  // matches HasProvenance:true → block
	}

	res := (&Evaluator{}).EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if res.Action != ModeBlock {
		t.Fatalf("with checksum available the provenance rule must enforce, got %s", res.Action)
	}
}

// --- B10: maintainer-account-age day-0 known limitation -------------------
//
// Convention: MaintainerAccountAgeDays == 0 means "no age signal"; the
// matcher guards with `<= 0` and stays inert. A GENUINE day-0 account is
// therefore indistinguishable from "no signal" and also fails open. This
// is a KNOWN LIMITATION deferred until the (flag-off) maintainer-age
// provider ships a real -1 sentinel end-to-end. The test PINS the
// current behaviour so the limitation is documented in code and a future
// change that makes age 0 actionable is forced to update this test.

// TestMaintainerAge_DayZero_DoesNotFire documents that a day-0 account
// (MaintainerAccountAgeDays == 0) does NOT trip a MaintainerAccountAgeDaysMax
// rule, because 0 is the "no signal" sentinel.
func TestMaintainerAge_DayZero_DoesNotFire(t *testing.T) {
	t.Parallel()

	max := 30 // block accounts <= 30 days old
	pol := Policy{
		ID:         "block-young-maintainer",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{MaintainerAccountAgeDaysMax: &max},
	}

	base := EvaluationContext{
		Repository:     "npmjs",
		PackageName:    "typosquat-pkg",
		PackageVersion: "1.0.0",
	}

	// Day-0 account: reads as "no signal" → rule inert → fails open.
	// This is the ATO/typosquat-publisher case the guard cannot catch.
	dayZero := base
	dayZero.MaintainerAccountAgeDays = 0
	if res := (&Evaluator{}).EvaluateWithPolicies(dayZero, []Policy{pol}, 0); res.Action != ModeAllow {
		t.Fatalf("KNOWN LIMITATION: day-0 (age==0) must NOT fire (fails open), got %s", res.Action)
	}

	// Control: a genuine 1-day-old account IS caught (age within max).
	oneDay := base
	oneDay.MaintainerAccountAgeDays = 1
	if res := (&Evaluator{}).EvaluateWithPolicies(oneDay, []Policy{pol}, 0); res.Action != ModeBlock {
		t.Fatalf("age==1 within max should block, got %s", res.Action)
	}

	// Control: an old account (above max) is not caught.
	old := base
	old.MaintainerAccountAgeDays = 365
	if res := (&Evaluator{}).EvaluateWithPolicies(old, []Policy{pol}, 0); res.Action != ModeAllow {
		t.Fatalf("age above max should allow, got %s", res.Action)
	}
}
