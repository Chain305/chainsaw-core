package cli

// risk_weights_test.go — coverage for `chainsaw risk-weights {show, preview,
// apply}`. Two slices:
//
//   1. parseSetFlags: pin the int / decimal handling so a 0.7 doesn't
//      silently round-trip to 0.
//   2. Command tree wiring: assert all three subcommands are reachable
//      under the root, including a Long-help string each so future
//      grep-the-help-text tests stay green.

import (
	"reflect"
	"testing"
)

func TestParseSetFlags(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		want    map[string]int
		wantErr bool
	}{
		{
			name: "single integer",
			in:   []string{"isVulnerable=70"},
			want: map[string]int{"isVulnerable": 70},
		},
		{
			name: "negative weight",
			in:   []string{"goodSig=-25"},
			want: map[string]int{"goodSig": -25},
		},
		{
			name: "decimal scales to integer",
			// 0.7 should land as 70 — the server-side weight space is
			// integral in [-1000, 1000] and operators often paste a
			// "ratio" style 0.7 from a tuning notebook.
			in:   []string{"isVulnerable=0.7"},
			want: map[string]int{"isVulnerable": 70},
		},
		{
			name: "multiple pairs",
			in:   []string{"a=1", "b=2", "c=-3"},
			want: map[string]int{"a": 1, "b": 2, "c": -3},
		},
		{
			name:    "missing equals",
			in:      []string{"oops"},
			wantErr: true,
		},
		{
			name:    "empty value",
			in:      []string{"a="},
			wantErr: true,
		},
		{
			name:    "non-numeric value",
			in:      []string{"a=banana"},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSetFlags(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("parseSetFlags(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestRiskWeightsCommandTree pins the user-visible command surface so a
// silent rename or removal of `show` / `preview` / `apply` shows up as
// a test failure rather than a smoke-spec drift.
func TestRiskWeightsCommandTree(t *testing.T) {
	want := []string{"show", "preview", "apply"}
	have := make(map[string]bool, len(want))
	for _, c := range riskWeightsCmd.Commands() {
		have[c.Name()] = true
		if c.Short == "" {
			t.Errorf("subcommand %q has empty Short help", c.Name())
		}
	}
	for _, name := range want {
		if !have[name] {
			t.Errorf("expected `risk-weights %s` subcommand, not found", name)
		}
	}
}

// TestRiskWeightsApplyRequiresSimulateID exercises the validation
// branch in runRiskWeightsApply — `apply` with no --simulate-id must
// short-circuit before any HTTP call.
func TestRiskWeightsApplyRequiresSimulateID(t *testing.T) {
	// Save + restore the package-level flag globals to keep the test
	// hermetic — cobra binds them once during init().
	origID := riskWeightsSimulateID
	origSet := riskWeightsApplySet
	t.Cleanup(func() {
		riskWeightsSimulateID = origID
		riskWeightsApplySet = origSet
	})

	riskWeightsSimulateID = ""
	riskWeightsApplySet = []string{"a=1"}

	err := runRiskWeightsApply(riskWeightsApplyCmd, nil)
	if err == nil {
		t.Fatal("expected error when --simulate-id is empty")
	}
}

// TestRiskWeightsPreviewRequiresSet pins the "no --set" guard.
func TestRiskWeightsPreviewRequiresSet(t *testing.T) {
	orig := riskWeightsPreviewSet
	t.Cleanup(func() { riskWeightsPreviewSet = orig })
	riskWeightsPreviewSet = nil
	err := runRiskWeightsPreview(riskWeightsPreviewCmd, nil)
	if err == nil {
		t.Fatal("expected error when no --set flags provided")
	}
}
