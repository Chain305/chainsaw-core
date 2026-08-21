package policyengine_test

// decide_input_test.go — DecideInput, the Input-native entry point added
// so callers holding a canonical policy.Input stop manufacturing an
// EvaluationContext for Decide to immediately project back into an Input.
//
// The bug that motivated it: `chainsaw policy gate` carried a
// hand-maintained Input→EvaluationContext copy that had fallen three
// fields behind — including SignalsUnavailable, the documented
// fail-CLOSED knob — so the same bundle and fixture blocked under
// `policy eval` and allowed under `policy gate`.

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/chain305/chainsaw-core/policy"
	"github.com/chain305/chainsaw-core/policy/dsl"
	"github.com/chain305/chainsaw-core/policyengine"
)

func compileInline(t *testing.T, src string) *dsl.Engine {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rule.rego"), []byte(src), 0o644); err != nil {
		t.Fatalf("write rego: %v", err)
	}
	eng, err := dsl.New(context.Background(), dsl.Options{Sources: []string{dir}})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return eng
}

// TestDecideInputSeesLateAddedFields is the regression proper. Each of
// these three fields was added to policy.Input after the CLI's copy layer
// was written, and each was silently dropped by it. A rule keyed on any
// of them must fire.
func TestDecideInputSeesLateAddedFields(t *testing.T) {
	cases := []struct {
		name  string
		rego  string
		input policy.Input
	}{
		{
			name: "signalsUnavailable (the fail-closed knob)",
			rego: `package chainsaw.policy
decision contains d if {
	input.signalsUnavailable == true
	d := {"rule_id": "fail-closed-signals", "action": "block", "message": "signals unavailable"}
}`,
			input: policy.Input{Surface: policy.SurfacePublish, SignalsUnavailable: true},
		},
		{
			name: "releaseDate",
			rego: `package chainsaw.policy
decision contains d if {
	input.releaseDate == "2026-01-01T00:00:00Z"
	d := {"rule_id": "cooldown", "action": "block", "message": "too new"}
}`,
			input: policy.Input{Surface: policy.SurfacePublish, PackageReleaseDate: "2026-01-01T00:00:00Z"},
		},
		{
			name: "buildRsExecutes",
			rego: `package chainsaw.policy
decision contains d if {
	input.buildRsExecutes == true
	d := {"rule_id": "build-rs", "action": "block", "message": "build.rs executes"}
}`,
			input: policy.Input{Surface: policy.SurfacePublish, BuildRsExecutes: true},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := policyengine.New(policyengine.Config{DSL: compileInline(t, c.rego)})
			dec, err := e.DecideInput(context.Background(), c.input)
			if err != nil {
				t.Fatalf("DecideInput: %v", err)
			}
			if dec.Action != dsl.ActionBlock {
				t.Fatalf("action = %q, want block — the field never reached OPA", dec.Action)
			}
			if dec.Surface != c.input.Surface {
				t.Errorf("surface = %q, want %q (in.Surface is authoritative)", dec.Surface, c.input.Surface)
			}
			if dec.BundleDigest == "" {
				t.Error("BundleDigest must still be stamped so the decision is reproducible")
			}
		})
	}
}

// TestDecideInputFailsOpenOnRuleError keeps the posture Decide has: a
// broken custom rule must not wedge production traffic. Here the rule
// divides by zero at eval time.
func TestDecideInputFailsOpenOnRuleError(t *testing.T) {
	e := policyengine.New(policyengine.Config{DSL: compileInline(t, `package chainsaw.policy
decision contains d if {
	x := 1 / input.trustScore
	d := {"rule_id": "boom", "action": "block", "message": sprintf("%v", [x])}
}`)})

	dec, err := e.DecideInput(context.Background(), policy.Input{
		Surface:    policy.SurfaceProxy,
		TrustScore: new(int), // explicit 0 — a real score, not "unknown"
	})
	if err != nil {
		t.Fatalf("a rule error must not be promoted to the caller: %v", err)
	}
	if dec.Action != dsl.ActionAllow {
		t.Errorf("action = %q, want allow (fail-open on a buggy rule)", dec.Action)
	}
}

// TestDecideInputWithNoDSLIsAllow: an engine with no Rego bundle is a
// no-op, not an error. DecideInput does not consult the native evaluator
// (an Input cannot reconstruct an EvaluationContext), so MatchedNative
// stays ModeAllow.
func TestDecideInputWithNoDSLIsAllow(t *testing.T) {
	e := policyengine.New(policyengine.Config{})
	dec, err := e.DecideInput(context.Background(), policy.Input{Surface: policy.SurfaceRuntime})
	if err != nil {
		t.Fatalf("DecideInput: %v", err)
	}
	if dec.Action != dsl.ActionAllow || dec.MatchedNative != policy.ModeAllow {
		t.Errorf("action=%q matchedNative=%q; want allow/allow", dec.Action, dec.MatchedNative)
	}
	if dec.Surface != policy.SurfaceRuntime {
		t.Errorf("surface = %q, want runtime", dec.Surface)
	}
}
