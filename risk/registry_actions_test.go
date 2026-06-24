package risk

import "testing"

func TestActionSignalsRegistered(t *testing.T) {
	cases := []struct {
		id           string
		wantCategory Category
		wantSeverity Severity
		wantWeight   float64
	}{
		{SignalActionUnpinnedRef, CategorySupplyChain, SevMedium, -15},
		{SignalActionUnknownPublisher, CategorySupplyChain, SevLow, -5},
		{SignalActionTyposquat, CategorySupplyChain, SevHigh, -40},
		{SignalActionMalicious, CategorySupplyChain, SevHigh, -50},
	}

	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			sig, ok := Registry[c.id]
			if !ok {
				t.Fatalf("signal %q missing from Registry", c.id)
			}
			if sig.ID != c.id {
				t.Errorf("ID got %q want %q", sig.ID, c.id)
			}
			if sig.Category != c.wantCategory {
				t.Errorf("category got %q want %q", sig.Category, c.wantCategory)
			}
			if sig.Severity != c.wantSeverity {
				t.Errorf("severity got %q want %q", sig.Severity, c.wantSeverity)
			}
			if sig.Weight != c.wantWeight {
				t.Errorf("weight got %v want %v", sig.Weight, c.wantWeight)
			}
			if sig.Title == "" {
				t.Errorf("signal %q has empty Title", c.id)
			}
			if sig.Fires == nil {
				t.Errorf("signal %q has nil Fires", c.id)
			}
		})
	}
}

func TestActionUnpinnedRefFires(t *testing.T) {
	sig := Registry[SignalActionUnpinnedRef]

	cases := []struct {
		name string
		in   Input
		want bool
	}{
		{
			name: "unpinned ref present — fires",
			in:   Input{ActionRefUnpinned: true, ActionRefUnpinnedRefs: []string{"actions/checkout@v4"}},
			want: true,
		},
		{
			name: "no unpinned ref — silent",
			in:   Input{},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fired, _, _ := sig.Fires(c.in)
			if fired != c.want {
				t.Fatalf("fired got %v want %v", fired, c.want)
			}
		})
	}
}

func TestActionUnknownPublisherFires(t *testing.T) {
	sig := Registry[SignalActionUnknownPublisher]

	cases := []struct {
		name string
		in   Input
		want bool
	}{
		{
			name: "unknown publisher — fires",
			in:   Input{ActionRefUnknownPublisher: true, ActionRefUnknownPublishers: []string{"randoperson"}},
			want: true,
		},
		{
			name: "zero input — silent",
			in:   Input{},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fired, _, _ := sig.Fires(c.in)
			if fired != c.want {
				t.Fatalf("fired got %v want %v", fired, c.want)
			}
		})
	}
}

func TestActionTyposquatFires(t *testing.T) {
	sig := Registry[SignalActionTyposquat]

	cases := []struct {
		name string
		in   Input
		want bool
	}{
		{
			name: "typosquat detected — fires",
			in:   Input{ActionRefTyposquat: true, ActionRefTyposquats: []string{"actoins/checkout@v4"}},
			want: true,
		},
		{
			name: "zero input — silent",
			in:   Input{},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fired, _, _ := sig.Fires(c.in)
			if fired != c.want {
				t.Fatalf("fired got %v want %v", fired, c.want)
			}
		})
	}
}

func TestActionMaliciousFires(t *testing.T) {
	sig := Registry[SignalActionMalicious]

	cases := []struct {
		name string
		in   Input
		want bool
	}{
		{
			name: "malicious ref present — fires",
			in:   Input{ActionRefMalicious: true, ActionRefMaliciousRefs: []string{"evil/runner@v1"}},
			want: true,
		},
		{
			name: "zero input — silent",
			in:   Input{},
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fired, msg, evidence := sig.Fires(c.in)
			if fired != c.want {
				t.Fatalf("fired got %v want %v", fired, c.want)
			}
			if c.want {
				if msg == "" {
					t.Errorf("expected non-empty message when fired")
				}
				refs, ok := evidence["refs"].([]string)
				if !ok || len(refs) != 1 || refs[0] != "evil/runner@v1" {
					t.Errorf("expected evidence refs to contain evil/runner@v1, got %v", evidence)
				}
			}
		})
	}
}
