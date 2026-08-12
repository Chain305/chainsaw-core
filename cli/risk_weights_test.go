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
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/viper"
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

// ── P3: apply must prove the write landed ───────────────────────────────
//
// The defect: `apply` PUT its --set values to /api/v1/intel/weights,
// which read proposed_signal_weights only to re-derive the simulate
// inputs hash and then wrote an orgweights.Overrides row — a struct with
// no signal-weight field. Every per-signal value was discarded, while the
// command printed "Weights applied." and exited 0.
//
// The server now persists them. The CLI-side guard against that class of
// rot is verifyRiskWeightsPersisted: a 200 is not evidence, only the
// server reading the values back out of storage is. The tests below pin
// that a silently-dropped write can never again print success.

// riskWeightsApplyTestServer stands in for the proxy. signalWeights is
// what the fake server claims is now persisted — set it to something
// other than the request to simulate a dropped write.
func riskWeightsApplyTestServer(t *testing.T, signalWeights map[string]int, captured *map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/intel/weights" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPut && captured != nil {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, captured)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"apiVersion": "v1",
			"data": map[string]any{
				"overridden":    true,
				"effective":     map[string]float64{"vulnerability": 0.3},
				"signalWeights": signalWeights,
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// withRiskWeightsApplyEnv points the CLI at srv and sets the apply flags,
// restoring both on cleanup.
func withRiskWeightsApplyEnv(t *testing.T, serverURL, simulateID string, set []string) {
	t.Helper()
	prevURL := viper.GetString("server_url")
	prevTok := viper.GetString("token")
	prevID := riskWeightsSimulateID
	prevSet := riskWeightsApplySet
	t.Cleanup(func() {
		viper.Set("server_url", prevURL)
		viper.Set("token", prevTok)
		riskWeightsSimulateID = prevID
		riskWeightsApplySet = prevSet
	})
	viper.Set("server_url", serverURL)
	viper.Set("token", "test-token")
	riskWeightsSimulateID = simulateID
	riskWeightsApplySet = set
}

// TestRiskWeightsApplyPersists is the happy path: the server reports the
// requested weight as stored, so apply succeeds. It also pins that the
// request actually carries proposed_signal_weights AND the simulate_id —
// the gate must not be dropped along with the fix.
func TestRiskWeightsApplyPersists(t *testing.T) {
	captured := map[string]any{}
	srv := riskWeightsApplyTestServer(t, map[string]int{"vuln.cvss_high": 70}, &captured)
	withRiskWeightsApplyEnv(t, srv.URL, "sim-abc123", []string{"vuln.cvss_high=70"})

	if err := runRiskWeightsApply(riskWeightsApplyCmd, nil); err != nil {
		t.Fatalf("apply returned %v, want success when the server persisted the weights", err)
	}
	if captured["simulate_id"] != "sim-abc123" {
		t.Errorf("simulate_id = %v, want sim-abc123 — the confirm gate must still be sent",
			captured["simulate_id"])
	}
	psw, ok := captured["proposed_signal_weights"].(map[string]any)
	if !ok {
		t.Fatalf("request carried no proposed_signal_weights: %+v", captured)
	}
	if psw["vuln.cvss_high"] != float64(70) {
		t.Errorf("proposed_signal_weights[vuln.cvss_high] = %v, want 70", psw["vuln.cvss_high"])
	}
}

// TestRiskWeightsApplyRejectsDroppedWrite is the regression test for the
// original defect, reproduced at the wire level: the server answers 200
// but reports NO persisted signal weights (exactly what the broken
// handler did). apply must fail rather than print "Weights applied."
func TestRiskWeightsApplyRejectsDroppedWrite(t *testing.T) {
	srv := riskWeightsApplyTestServer(t, map[string]int{}, nil)
	withRiskWeightsApplyEnv(t, srv.URL, "sim-abc123", []string{"vuln.cvss_high=70"})

	err := runRiskWeightsApply(riskWeightsApplyCmd, nil)
	if err == nil {
		t.Fatal("apply must not report success when the server persisted nothing")
	}
	if !errors.Is(err, errRiskWeightsNotPersisted) {
		t.Fatalf("unexpected error: %v", err)
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitOpError {
		t.Errorf("a dropped write must exit %d, got %v", ExitOpError, err)
	}
}

// TestRiskWeightsApplyRejectsPartialWrite covers the other half: the
// server persisted a DIFFERENT value than the one previewed. Silently
// accepting that would leave the org on a weight set nobody modelled.
func TestRiskWeightsApplyRejectsPartialWrite(t *testing.T) {
	srv := riskWeightsApplyTestServer(t, map[string]int{"vuln.cvss_high": 70}, nil)
	withRiskWeightsApplyEnv(t, srv.URL, "sim-abc123",
		[]string{"vuln.cvss_high=70", "sc.publisher_changed=50"})

	err := runRiskWeightsApply(riskWeightsApplyCmd, nil)
	if err == nil || !errors.Is(err, errRiskWeightsNotPersisted) {
		t.Fatalf("a half-applied weight set must fail loudly, got %v", err)
	}
	if !strings.Contains(err.Error(), "sc.publisher_changed") {
		t.Errorf("the error must name the signal that didn't land: %v", err)
	}
}

// TestVerifyRiskWeightsPersisted unit-tests the comparison directly,
// including the value-drift case that a presence-only check would miss.
func TestVerifyRiskWeightsPersisted(t *testing.T) {
	cases := []struct {
		name    string
		want    map[string]int
		got     map[string]int
		wantErr bool
	}{
		{
			name: "exact match",
			want: map[string]int{"a": 70},
			got:  map[string]int{"a": 70},
		},
		{
			name: "server has extra signals from other overrides",
			want: map[string]int{"a": 70},
			got:  map[string]int{"a": 70, "b": -25},
		},
		{
			name:    "absent from read-back",
			want:    map[string]int{"a": 70},
			got:     map[string]int{},
			wantErr: true,
		},
		{
			name:    "value drifted",
			want:    map[string]int{"a": 70},
			got:     map[string]int{"a": 69},
			wantErr: true,
		},
		{
			name:    "nil read-back",
			want:    map[string]int{"a": 70},
			got:     nil,
			wantErr: true,
		},
		{
			name: "nothing requested",
			want: map[string]int{},
			got:  nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyRiskWeightsPersisted(tc.want, tc.got)
			if (err != nil) != tc.wantErr {
				t.Fatalf("verifyRiskWeightsPersisted(%v, %v) = %v, wantErr %v",
					tc.want, tc.got, err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, errRiskWeightsNotPersisted) {
				t.Fatalf("error must wrap the sentinel: %v", err)
			}
		})
	}
}

// TestRiskWeightsApplyStillValidatesFlagsFirst keeps the flag guards
// ahead of the network call, so an operator who forgot --simulate-id sees
// that rather than a confusing failure about a request they never fully
// formed. Both cases must short-circuit BEFORE any HTTP call — there is
// no server configured here, so a leak past the guard would surface as a
// transport error instead.
func TestRiskWeightsApplyStillValidatesFlagsFirst(t *testing.T) {
	withRiskWeightsApplyEnv(t, "http://127.0.0.1:1", "", []string{"vuln.cvss_high=70"})

	err := runRiskWeightsApply(riskWeightsApplyCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--simulate-id") {
		t.Fatalf("missing --simulate-id must surface as its own usage error, got %v", err)
	}

	riskWeightsSimulateID = "sim-abc123"
	riskWeightsApplySet = []string{"not-a-pair"}
	err = runRiskWeightsApply(riskWeightsApplyCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid --set") {
		t.Fatalf("a malformed --set must surface as its own parse error, got %v", err)
	}
}
