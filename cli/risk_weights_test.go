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
	"errors"
	"reflect"
	"strings"
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

// TestRiskWeightsApplyFailsLoudly is P3. `apply` PUT its --set values to
// /api/v1/intel/weights, which reads proposed_signal_weights only to
// re-derive the simulate inputs hash and then writes an
// orgweights.Overrides row — a struct with no signal-weight field. Every
// per-signal value was discarded, while the command printed
// "Weights applied." and exited 0, so the whole preview-then-confirm gate
// guarded a write that never happened.
//
// It now fails instead, BEFORE any network call. The CLI-only workaround
// (looping PUT /api/risk/overrides/{signal}) is deliberately not taken:
// that is a non-atomic multi-request write which can strand the org on a
// weight set nobody previewed, and it performs the real write outside the
// simulate_id guard — worse than the no-op. The real fix is server-side.
func TestRiskWeightsApplyFailsLoudly(t *testing.T) {
	origID := riskWeightsSimulateID
	origSet := riskWeightsApplySet
	t.Cleanup(func() {
		riskWeightsSimulateID = origID
		riskWeightsApplySet = origSet
	})

	riskWeightsSimulateID = "sim-abc123"
	riskWeightsApplySet = []string{"isVulnerable=70"}

	err := runRiskWeightsApply(riskWeightsApplyCmd, nil)
	if err == nil {
		t.Fatal("`risk-weights apply` must not report success for a write the server discards")
	}
	if !errors.Is(err, errRiskWeightsApplyNotPersisted) {
		t.Fatalf("unexpected error: %v", err)
	}
	// The command must not print a success line at all. Belt and braces:
	// the only place "Weights applied." may still appear in the binary is
	// inside this error's own explanation of what used to happen.
	if strings.Contains(riskWeightsApplyCmd.Long, "Re-run preview if apply returns") {
		t.Error("the help text still describes apply as a working write path")
	}
	msg := err.Error()
	for _, want := range []string{"proposed_signal_weights", "risk-weights show"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error must explain the gap and give a next step (missing %q): %s", want, msg)
		}
	}
}

// TestRiskWeightsApplyStillValidatesFlagsFirst keeps the flag guards
// ahead of the refusal, so an operator who forgot --simulate-id sees that
// rather than a confusing "not persisted" message about a request they
// never fully formed.
func TestRiskWeightsApplyStillValidatesFlagsFirst(t *testing.T) {
	origID := riskWeightsSimulateID
	origSet := riskWeightsApplySet
	t.Cleanup(func() {
		riskWeightsSimulateID = origID
		riskWeightsApplySet = origSet
	})

	riskWeightsSimulateID = ""
	riskWeightsApplySet = []string{"isVulnerable=70"}
	err := runRiskWeightsApply(riskWeightsApplyCmd, nil)
	if err == nil || errors.Is(err, errRiskWeightsApplyNotPersisted) {
		t.Fatalf("missing --simulate-id must surface as its own usage error, got %v", err)
	}

	riskWeightsSimulateID = "sim-abc123"
	riskWeightsApplySet = []string{"not-a-pair"}
	err = runRiskWeightsApply(riskWeightsApplyCmd, nil)
	if err == nil || errors.Is(err, errRiskWeightsApplyNotPersisted) {
		t.Fatalf("a malformed --set must surface as its own parse error, got %v", err)
	}
}
