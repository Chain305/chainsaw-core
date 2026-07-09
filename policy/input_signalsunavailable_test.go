package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestContextToInput_SignalsUnavailable guards the publish fail-closed
// knob's Rego contract. A repo opts into fail-closed publishing with a
// rule keyed on `input.signalsUnavailable == true`, so two properties
// must hold:
//
//  1. EvaluationContext.SignalsUnavailable projects into Input.
//  2. The field is `omitempty`: absent (NOT false) from the OPA document
//     when signals WERE available, so a `== true` rule fires ONLY on
//     genuine unavailability and never on a normal publish. If the
//     `omitempty` tag is ever dropped, a clean publish would emit
//     `signalsUnavailable: false` and — while `== true` still wouldn't
//     match — a `!= true` / negation rule could behave surprisingly. This
//     test pins the intended wire shape.
func TestContextToInput_SignalsUnavailable(t *testing.T) {
	// (1) projects through.
	unavail := ContextToInput(SurfacePublish, EvaluationContext{SignalsUnavailable: true})
	if !unavail.SignalsUnavailable {
		t.Fatalf("SignalsUnavailable=true did not project into Input")
	}

	// (2a) omitted when false.
	cleanJSON, err := json.Marshal(ContextToInput(SurfacePublish, EvaluationContext{}))
	if err != nil {
		t.Fatalf("marshal clean input: %v", err)
	}
	if strings.Contains(string(cleanJSON), "signalsUnavailable") {
		t.Errorf("signalsUnavailable must be omitted from the OPA document when false; got %s", cleanJSON)
	}

	// (2b) present and true when unavailable.
	unavailJSON, err := json.Marshal(unavail)
	if err != nil {
		t.Fatalf("marshal unavailable input: %v", err)
	}
	if !strings.Contains(string(unavailJSON), `"signalsUnavailable":true`) {
		t.Errorf("signalsUnavailable must serialize as true when unavailable; got %s", unavailJSON)
	}
}
