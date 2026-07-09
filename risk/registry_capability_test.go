package risk

import (
	"testing"
)

// TestCapabilitySignalsRegistered verifies that all cap.* signal IDs are
// present in the Registry and have valid shape.
func TestCapabilitySignalsRegistered(t *testing.T) {
	t.Parallel()
	ids := []string{
		SignalCapNetwork,
		SignalCapShell,
		SignalCapFilesystemWrite,
		SignalCapFilesystemRead,
		SignalCapEnvAccess,
		SignalCapNativeCode,
		SignalCapDynamicEval,
	}
	for _, id := range ids {
		sig, ok := Registry[id]
		if !ok {
			t.Errorf("signal %q not found in Registry", id)
			continue
		}
		if sig.ID != id {
			t.Errorf("signal %q: ID field mismatch %q", id, sig.ID)
		}
		if sig.Title == "" {
			t.Errorf("signal %q: empty Title", id)
		}
		if sig.Fires == nil {
			t.Errorf("signal %q: nil Fires", id)
		}
		if sig.Category == "" {
			t.Errorf("signal %q: empty Category", id)
		}
	}
}

// TestCapabilitySignalDefaultSeverities verifies the default severities
// match the documented values: most are info, dynamic_eval is low.
func TestCapabilitySignalDefaultSeverities(t *testing.T) {
	t.Parallel()
	cases := []struct {
		id   string
		want Severity
	}{
		{SignalCapNetwork, SevInfo},
		{SignalCapShell, SevInfo},
		{SignalCapFilesystemWrite, SevInfo},
		{SignalCapFilesystemRead, SevInfo},
		{SignalCapEnvAccess, SevInfo},
		{SignalCapNativeCode, SevInfo},
		{SignalCapDynamicEval, SevLow},
	}
	for _, tc := range cases {
		sig, ok := Registry[tc.id]
		if !ok {
			t.Errorf("signal %q not in Registry", tc.id)
			continue
		}
		if sig.Severity != tc.want {
			t.Errorf("signal %q: got severity %q, want %q", tc.id, sig.Severity, tc.want)
		}
	}
}

// TestCapShellFiresEndToEnd verifies that a risk.Input with CapShell=true
// produces a fired cap.shell signal when evaluated through the full
// signal registry.
func TestCapShellFiresEndToEnd(t *testing.T) {
	t.Parallel()

	in := Input{
		Ecosystem: "npm",
		Package:   "child-process-user",
		Version:   "1.0.0",
		CapShell:  true,
		CapShellEvidence: []CapEvidenceEntry{
			{File: "index.js", Line: 3, Snippet: "const {execSync} = require('child_process');"},
		},
	}

	sig, ok := Registry[SignalCapShell]
	if !ok {
		t.Fatal("cap.shell not in Registry")
	}

	fired, detail, evidence := sig.Fires(in)
	if !fired {
		t.Fatal("cap.shell signal did not fire for CapShell=true input")
	}
	if detail == "" {
		t.Error("expected non-empty detail string")
	}
	// Evidence should contain the locations list.
	if evidence == nil {
		t.Error("expected non-nil evidence map")
	}
	if _, ok := evidence["locations"]; !ok {
		t.Error("evidence map should contain 'locations' key")
	}
}

// TestCapNetworkDoesNotFireWhenFalse verifies the signal stays dormant.
func TestCapNetworkDoesNotFireWhenFalse(t *testing.T) {
	t.Parallel()
	in := Input{CapNetwork: false}
	sig := Registry[SignalCapNetwork]
	fired, _, _ := sig.Fires(in)
	if fired {
		t.Error("cap.network should not fire when CapNetwork=false")
	}
}

// TestCapDynamicEvalFiresAndHasLowWeight verifies eval is flagged at low
// severity with a small negative weight.
func TestCapDynamicEvalFiresAndHasLowWeight(t *testing.T) {
	t.Parallel()
	in := Input{CapDynamicEval: true}
	sig := Registry[SignalCapDynamicEval]
	fired, _, _ := sig.Fires(in)
	if !fired {
		t.Error("cap.dynamic_eval should fire when CapDynamicEval=true")
	}
	if sig.Weight >= 0 {
		t.Errorf("cap.dynamic_eval weight should be negative, got %v", sig.Weight)
	}
}

// TestCapEvidenceNilWhenNoEvidence verifies that a signal with no evidence
// entries returns nil (not an empty map) from its Fires function.
func TestCapEvidenceNilWhenNoEvidence(t *testing.T) {
	t.Parallel()
	in := Input{CapShell: true} // no CapShellEvidence populated
	sig := Registry[SignalCapShell]
	fired, _, evidence := sig.Fires(in)
	if !fired {
		t.Fatal("expected fired=true")
	}
	// With zero-length evidence slice, capEvidence should return nil.
	if evidence != nil {
		t.Errorf("expected nil evidence for empty evidence slice, got %v", evidence)
	}
}
