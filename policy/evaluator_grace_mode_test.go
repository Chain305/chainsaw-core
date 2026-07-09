package policy

import (
	"context"
	"testing"
	"time"
)

// staticFlag is a GraceModeFlagChecker that returns a fixed value.
type staticFlag bool

func (s staticFlag) GraceModeEnabled(string) bool { return bool(s) }

// recordingPreexisting is a PreexistingChecker that returns a fixed
// answer and records the cutoff it was asked about, so tests can assert
// the evaluator passed the policy's created_at as the boundary.
type recordingPreexisting struct {
	seen   bool
	called bool
	before time.Time
}

func (r *recordingPreexisting) SeenBefore(_ context.Context, _, _, _ string, before time.Time) bool {
	r.called = true
	r.before = before
	return r.seen
}

// blockAfterGracePolicy builds a ModeBlockAfterGrace policy created at
// createdAt with the given (nil → default 7) grace override. It matches
// everything so the test controls the verdict purely via mode + context.
func blockAfterGracePolicy(id string, createdAt time.Time, graceDays *int) Policy {
	return Policy{
		ID:         id,
		Precedence: 100,
		Mode:       ModeBlockAfterGrace,
		Status:     StatusEnabled,
		CreatedAt:  createdAt,
		Identifier: Identifier{
			TargetPackageRepo:    "*",
			TargetPackageName:    "*",
			TargetPackageVersion: "*",
		},
		GraceDays: graceDays,
	}
}

func graceCtx() EvaluationContext {
	return EvaluationContext{
		OrgID:          "org-1",
		Repository:     "npmjs",
		PackageName:    "leftpad",
		PackageVersion: "1.0.0",
	}
}

// (a) FLAG-OFF PARITY: a block_after_grace policy must behave EXACTLY
// like a plain block when the grace flag is off — even for a
// pre-existing, in-window package. This proves an un-flagged deploy
// never weakens enforcement.
func TestBlockAfterGrace_FlagOff_BehavesAsPlainBlock(t *testing.T) {
	t.Parallel()

	createdAt := time.Now().Add(-1 * 24 * time.Hour) // 1 day ago → in any window
	pol := blockAfterGracePolicy("bag-1", createdAt, nil)

	// Even with a checker that WOULD say "pre-existing", a flag-off
	// evaluator must NOT downgrade. Two evaluators exercise both wiring
	// shapes: (1) no grace wiring at all, (2) wiring present but flag OFF.
	cases := []struct {
		name string
		eval *Evaluator
	}{
		{"no-grace-wiring", NewEvaluator(nil)},
		{"flag-off-wired", NewEvaluator(nil).WithGraceMode(staticFlag(false), &recordingPreexisting{seen: true})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := tc.eval.EvaluateWithPolicies(graceCtx(), []Policy{pol}, 0)
			if res.Action != ModeBlock {
				t.Fatalf("flag-off block_after_grace must resolve to ModeBlock, got %s", res.Action)
			}
			if res.MatchedPolicy == nil || res.MatchedPolicy.ID != "bag-1" {
				t.Fatalf("expected bag-1 to match, got %+v", res.MatchedPolicy)
			}
		})
	}
}

// (b) KEYSTONE: with the flag ON and the package pre-existing + in-window,
// a malware (IsKnownMalicious) or vuln (IsVulnerable) package must STILL
// be blocked. The grace downgrade must never weaken a malware/vuln block.
func TestBlockAfterGrace_FlagOn_MalwareAndVulnNeverDowngraded(t *testing.T) {
	t.Parallel()

	createdAt := time.Now().Add(-1 * 24 * time.Hour)
	pol := blockAfterGracePolicy("bag-keystone", createdAt, nil)
	// seen=true and in-window: the ONLY thing keeping these blocked is the
	// malware/vuln keystone guard.
	eval := NewEvaluator(nil).WithGraceMode(staticFlag(true), &recordingPreexisting{seen: true})

	t.Run("malware-stays-blocked", func(t *testing.T) {
		ctx := graceCtx()
		ctx.IsKnownMalicious = true
		res := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
		if res.Action != ModeBlock {
			t.Fatalf("in-grace malware package must stay BLOCKED, got %s", res.Action)
		}
	})
	t.Run("vuln-stays-blocked", func(t *testing.T) {
		ctx := graceCtx()
		ctx.IsVulnerable = true
		res := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
		if res.Action != ModeBlock {
			t.Fatalf("in-grace vulnerable package must stay BLOCKED, got %s", res.Action)
		}
	})
}

// (b) KEYSTONE (precedence variant): even if a higher-precedence
// block_after_grace policy matches FIRST, a malware package must not slip
// through via a downgrade. This covers the "block_after_grace sorts above
// the real malware block" ordering concern.
func TestBlockAfterGrace_FlagOn_MalwareBlockNotShadowed(t *testing.T) {
	t.Parallel()

	createdAt := time.Now().Add(-1 * 24 * time.Hour)
	isMal := true
	policies := []Policy{
		// block_after_grace at LOWER precedence number → evaluated first.
		blockAfterGracePolicy("bag-first", createdAt, nil),
		{
			ID:         "real-malware-block",
			Precedence: 200,
			Mode:       ModeBlock,
			Status:     StatusEnabled,
			Identifier: Identifier{TargetPackageRepo: "*", TargetPackageName: "*", TargetPackageVersion: "*"},
			Conditions: Conditions{IsKnownMalicious: &isMal},
		},
	}
	// bag-first has lower precedence (100) so it's first in the list.
	policies[0].Precedence = 100
	eval := NewEvaluator(nil).WithGraceMode(staticFlag(true), &recordingPreexisting{seen: true})

	ctx := graceCtx()
	ctx.IsKnownMalicious = true
	res := eval.EvaluateWithPolicies(ctx, policies, 0)
	if res.Action != ModeBlock {
		t.Fatalf("malware package must be BLOCKED even though block_after_grace matched first, got %s (matched %+v)",
			res.Action, res.MatchedPolicy)
	}
}

// (d) GRACE DOWNGRADE: flag ON, pre-existing, in-window, not malware/vuln
// → block downgrades to monitor; outside the window → blocks; brand-new
// (not pre-existing) → blocks; default 7d applies when GraceDays is nil.
func TestBlockAfterGrace_FlagOn_DowngradeRules(t *testing.T) {
	t.Parallel()

	t.Run("pre-existing-in-window-downgrades", func(t *testing.T) {
		createdAt := time.Now().Add(-2 * 24 * time.Hour) // 2 days into a 7d window
		pol := blockAfterGracePolicy("bag-dg", createdAt, nil)
		pre := &recordingPreexisting{seen: true}
		eval := NewEvaluator(nil).WithGraceMode(staticFlag(true), pre)
		res := eval.EvaluateWithPolicies(graceCtx(), []Policy{pol}, 0)
		if res.Action != ModeMonitor {
			t.Fatalf("pre-existing in-window package must downgrade to ModeMonitor, got %s", res.Action)
		}
		if !pre.called {
			t.Fatalf("expected the pre-existing lookup to be consulted")
		}
		// The cutoff handed to the lookup must be the policy's created_at.
		if !pre.before.Equal(createdAt) {
			t.Fatalf("expected SeenBefore cutoff == policy.CreatedAt (%s), got %s", createdAt, pre.before)
		}
	})

	t.Run("not-pre-existing-blocks", func(t *testing.T) {
		createdAt := time.Now().Add(-2 * 24 * time.Hour)
		pol := blockAfterGracePolicy("bag-new", createdAt, nil)
		eval := NewEvaluator(nil).WithGraceMode(staticFlag(true), &recordingPreexisting{seen: false})
		res := eval.EvaluateWithPolicies(graceCtx(), []Policy{pol}, 0)
		if res.Action != ModeBlock {
			t.Fatalf("brand-new (not pre-existing) package must be BLOCKED, got %s", res.Action)
		}
	})

	t.Run("after-window-blocks", func(t *testing.T) {
		// Created 10 days ago, default 7d window → window elapsed.
		createdAt := time.Now().Add(-10 * 24 * time.Hour)
		pol := blockAfterGracePolicy("bag-expired", createdAt, nil)
		eval := NewEvaluator(nil).WithGraceMode(staticFlag(true), &recordingPreexisting{seen: true})
		res := eval.EvaluateWithPolicies(graceCtx(), []Policy{pol}, 0)
		if res.Action != ModeBlock {
			t.Fatalf("package past the grace window must be BLOCKED, got %s", res.Action)
		}
	})

	t.Run("default-7d-when-grace-days-nil", func(t *testing.T) {
		// 6 days in: inside default 7d → downgrade. 8 days in: outside.
		inWindow := blockAfterGracePolicy("bag-6d", time.Now().Add(-6*24*time.Hour), nil)
		outWindow := blockAfterGracePolicy("bag-8d", time.Now().Add(-8*24*time.Hour), nil)
		eval := NewEvaluator(nil).WithGraceMode(staticFlag(true), &recordingPreexisting{seen: true})

		if got := eval.EvaluateWithPolicies(graceCtx(), []Policy{inWindow}, 0).Action; got != ModeMonitor {
			t.Fatalf("6d-old policy with nil grace_days must use 7d default and downgrade, got %s", got)
		}
		if got := eval.EvaluateWithPolicies(graceCtx(), []Policy{outWindow}, 0).Action; got != ModeBlock {
			t.Fatalf("8d-old policy with nil grace_days must use 7d default and block, got %s", got)
		}
	})

	t.Run("per-policy-grace-days-override", func(t *testing.T) {
		// 5 days in, but grace_days=3 → window elapsed → block.
		three := 3
		pol := blockAfterGracePolicy("bag-3d", time.Now().Add(-5*24*time.Hour), &three)
		eval := NewEvaluator(nil).WithGraceMode(staticFlag(true), &recordingPreexisting{seen: true})
		if got := eval.EvaluateWithPolicies(graceCtx(), []Policy{pol}, 0).Action; got != ModeBlock {
			t.Fatalf("grace_days=3 override must block a 5-day-old package, got %s", got)
		}
		// 2 days in with grace_days=3 → still in window → downgrade.
		pol2 := blockAfterGracePolicy("bag-3d-in", time.Now().Add(-2*24*time.Hour), &three)
		if got := eval.EvaluateWithPolicies(graceCtx(), []Policy{pol2}, 0).Action; got != ModeMonitor {
			t.Fatalf("grace_days=3 override must downgrade a 2-day-old package, got %s", got)
		}
	})
}

// EffectiveGraceDays unit coverage: nil and non-positive overrides fall
// back to the 7-day default; a positive override wins.
func TestEffectiveGraceDays(t *testing.T) {
	t.Parallel()
	if got := (Policy{}).EffectiveGraceDays(); got != DefaultGraceDays {
		t.Fatalf("nil grace_days → %d, want %d", got, DefaultGraceDays)
	}
	zero := 0
	if got := (Policy{GraceDays: &zero}).EffectiveGraceDays(); got != DefaultGraceDays {
		t.Fatalf("zero grace_days → %d, want default %d", got, DefaultGraceDays)
	}
	neg := -5
	if got := (Policy{GraceDays: &neg}).EffectiveGraceDays(); got != DefaultGraceDays {
		t.Fatalf("negative grace_days → %d, want default %d", got, DefaultGraceDays)
	}
	five := 5
	if got := (Policy{GraceDays: &five}).EffectiveGraceDays(); got != 5 {
		t.Fatalf("grace_days=5 → %d, want 5", got)
	}
}
