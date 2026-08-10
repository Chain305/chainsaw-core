package coverage

import (
	"testing"
	"time"
)

func TestPostureValidateAcceptsDefaults(t *testing.T) {
	p := Posture{Version: 1, Mode: ModeOff}
	if err := p.Validate(); err != nil {
		t.Errorf("default posture rejected: %v", err)
	}
}

func TestPostureValidateRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		p    Posture
	}{
		{"unknown mode", Posture{Version: 1, Mode: "block"}},
		{"unsupported version", Posture{Version: 2, Mode: ModeOff}},
		{
			// grace >= max_ledger_age makes the grace window unreachable,
			// silently disabling blip tolerance. Reject loudly.
			"grace not shorter than max ledger age",
			Posture{Version: 1, Mode: ModeClosed, Required: []Source{SourceCVE},
				Grace: 15 * time.Minute, MaxLedgerAge: 15 * time.Minute},
		},
		{
			"closed with no required sources",
			Posture{Version: 1, Mode: ModeClosed},
		},
		{
			"negative grace",
			Posture{Version: 1, Mode: ModeClosed, Required: []Source{SourceCVE},
				Grace: -time.Second, MaxLedgerAge: time.Hour},
		},
	}
	for _, tc := range cases {
		if err := tc.p.Validate(); err == nil {
			t.Errorf("%s: Validate() succeeded, want error", tc.name)
		}
	}
}

func TestPostureValidateAcceptsWorkingConfig(t *testing.T) {
	p := Posture{
		Version:      1,
		Mode:         ModeClosed,
		Required:     []Source{SourceMalware, SourceCVE},
		Grace:        30 * time.Second,
		MaxLedgerAge: 15 * time.Minute,
	}
	if err := p.Validate(); err != nil {
		t.Errorf("valid posture rejected: %v", err)
	}
}
