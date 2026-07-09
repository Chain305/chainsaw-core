package policy

import (
	"sync"
	"testing"
)

// TestConditionFireRecorder verifies the per-condition fire metric
// callback fires exactly when a matched policy is driven by exactly
// one condition — no fire for zero-condition (identifier-only) or
// multi-condition matches.
func TestConditionFireRecorder(t *testing.T) {
	isVuln := true
	hasProv := false

	singleCondition := Policy{
		ID:     "pol-single",
		Status: StatusEnabled,
		Mode:   ModeBlock,
		Conditions: Conditions{
			IsVulnerable: &isVuln,
		},
	}
	multiCondition := Policy{
		ID:     "pol-multi",
		Status: StatusEnabled,
		Mode:   ModeBlock,
		Conditions: Conditions{
			IsVulnerable:  &isVuln,
			HasProvenance: &hasProv,
		},
	}
	identifierOnly := Policy{
		ID:     "pol-identifier",
		Status: StatusEnabled,
		Mode:   ModeBlock,
		Identifier: Identifier{
			TargetPackageName: "left-pad",
		},
	}

	vulnerableCtx := EvaluationContext{
		PackageName:   "left-pad",
		IsVulnerable:  true,
		HasProvenance: false,
	}

	cases := []struct {
		name       string
		policies   []Policy
		wantResult Mode
		wantFires  []string // ConditionType labels expected
	}{
		{
			name:       "single-condition block fires labelled fire",
			policies:   []Policy{singleCondition},
			wantResult: ModeBlock,
			wantFires:  []string{string(ConditionCVE)},
		},
		{
			name:       "multi-condition match does NOT emit (ambiguous attribution)",
			policies:   []Policy{multiCondition},
			wantResult: ModeBlock,
			wantFires:  nil,
		},
		{
			name:       "identifier-only match does NOT emit (no condition driver)",
			policies:   []Policy{identifierOnly},
			wantResult: ModeBlock,
			wantFires:  nil,
		},
		{
			name:       "no match does NOT emit",
			policies:   nil,
			wantResult: ModeAllow,
			wantFires:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				mu    sync.Mutex
				fires []string
			)
			SetConditionFireRecorder(func(condition, _ string) {
				mu.Lock()
				defer mu.Unlock()
				fires = append(fires, condition)
			})
			t.Cleanup(func() { SetConditionFireRecorder(nil) })

			eval := NewEvaluator(nil)
			got := eval.EvaluateWithPolicies(vulnerableCtx, tc.policies, 0)
			if got.Action != tc.wantResult {
				t.Errorf("action: got %s, want %s", got.Action, tc.wantResult)
			}

			mu.Lock()
			defer mu.Unlock()
			if len(fires) != len(tc.wantFires) {
				t.Fatalf("fires: got %v, want %v", fires, tc.wantFires)
			}
			for i, want := range tc.wantFires {
				if fires[i] != want {
					t.Errorf("fires[%d]: got %q, want %q", i, fires[i], want)
				}
			}
		})
	}
}
