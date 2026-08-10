package coverage

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)

func closedPosture(required ...Source) Posture {
	return Posture{
		Version:      1,
		Mode:         ModeClosed,
		Required:     required,
		Grace:        30 * time.Second,
		MaxLedgerAge: 15 * time.Minute,
	}
}

// fresh builds a just-observed entry. LastOKAt is set only for StatusOK: a
// source that is unavailable right now has not been healthy "zero seconds
// ago", and claiming otherwise would hand every unavailable fixture a free
// pass through the grace window.
func fresh(s Status) Entry {
	e := Entry{Status: s, ObservedAt: testNow}
	if s == StatusOK {
		e.LastOKAt = testNow
	}
	return e
}

func TestGateOffNeverBlocks(t *testing.T) {
	p := closedPosture(SourceCVE)
	p.Mode = ModeOff
	led := Ledger{SourceCVE: fresh(StatusUnavailable)}
	if d := Gate(p, led, testNow); d.Block || d.Warn {
		t.Errorf("mode=off produced %+v, want a zero decision", d)
	}
}

func TestGateBlocksOnUnavailableRequiredSource(t *testing.T) {
	led := Ledger{SourceCVE: fresh(StatusUnavailable)}
	d := Gate(closedPosture(SourceCVE), led, testNow)
	if !d.Block {
		t.Fatalf("want block, got %+v", d)
	}
	if len(d.Missing) != 1 || d.Missing[0] != SourceCVE {
		t.Errorf("Missing = %v, want [cve]", d.Missing)
	}
}

func TestGateAllowsWhenRequiredSourcesAreOK(t *testing.T) {
	led := Ledger{SourceCVE: fresh(StatusOK), SourceMalware: fresh(StatusOK)}
	if d := Gate(closedPosture(SourceCVE, SourceMalware), led, testNow); d.Block {
		t.Errorf("want allow, got %+v", d)
	}
}

// error is our bug; not_applicable is out of scope. Neither may block.
func TestGateNeverBlocksOnErrorOrNotApplicable(t *testing.T) {
	for _, s := range []Status{StatusError, StatusNotApplicable} {
		led := Ledger{SourceCVE: fresh(s)}
		if d := Gate(closedPosture(SourceCVE), led, testNow); d.Block {
			t.Errorf("status %q blocked; want allow", s)
		}
	}
}

// A source absent from the ledger was never consulted — indistinguishable
// from consulted-and-failed, so it blocks.
func TestGateBlocksOnMissingLedgerEntry(t *testing.T) {
	if d := Gate(closedPosture(SourceCVE), Ledger{}, testNow); !d.Block {
		t.Errorf("absent entry did not block: %+v", d)
	}
}

// Non-required sources being down is irrelevant.
func TestGateIgnoresUnrequiredSources(t *testing.T) {
	led := Ledger{
		SourceCVE:        fresh(StatusOK),
		SourceProvenance: fresh(StatusUnavailable),
	}
	if d := Gate(closedPosture(SourceCVE), led, testNow); d.Block {
		t.Errorf("unrequired source caused a block: %+v", d)
	}
}

func TestGateWarnModeReportsWithoutBlocking(t *testing.T) {
	p := closedPosture(SourceCVE)
	p.Mode = ModeWarn
	led := Ledger{SourceCVE: fresh(StatusUnavailable)}
	d := Gate(p, led, testNow)
	if d.Block {
		t.Errorf("warn mode blocked: %+v", d)
	}
	if !d.Warn || len(d.Missing) != 1 {
		t.Errorf("warn mode did not report: %+v", d)
	}
}

// Grace: a source down right now but OK moments ago is a blip, not an outage.
func TestGateGraceRescuesRecentlyHealthySource(t *testing.T) {
	led := Ledger{SourceCVE: {
		Status:     StatusUnavailable,
		ObservedAt: testNow,
		LastOKAt:   testNow.Add(-10 * time.Second), // inside the 30s grace
	}}
	if d := Gate(closedPosture(SourceCVE), led, testNow); d.Block {
		t.Errorf("grace did not rescue a 10s-old healthy observation: %+v", d)
	}
}

func TestGateGraceExpires(t *testing.T) {
	led := Ledger{SourceCVE: {
		Status:     StatusUnavailable,
		ObservedAt: testNow,
		LastOKAt:   testNow.Add(-31 * time.Second), // outside the 30s grace
	}}
	if d := Gate(closedPosture(SourceCVE), led, testNow); !d.Block {
		t.Errorf("expired grace did not block: %+v", d)
	}
}

// A source that has never been OK is not a blip.
func TestGateGraceDoesNotRescueNeverHealthySource(t *testing.T) {
	led := Ledger{SourceCVE: {Status: StatusUnavailable, ObservedAt: testNow}}
	if d := Gate(closedPosture(SourceCVE), led, testNow); !d.Block {
		t.Errorf("never-healthy source was rescued by grace: %+v", d)
	}
}

// max_ledger_age is the outer bound and always wins: stale-healthy coverage
// must never vouch for a source during an outage.
func TestGateStaleLedgerIsUnavailableEvenWhenOK(t *testing.T) {
	led := Ledger{SourceCVE: {
		Status:     StatusOK,
		ObservedAt: testNow.Add(-16 * time.Minute), // beyond the 15m bound
		LastOKAt:   testNow.Add(-16 * time.Minute),
	}}
	if d := Gate(closedPosture(SourceCVE), led, testNow); !d.Block {
		t.Errorf("stale OK observation vouched for the source: %+v", d)
	}
}

// Precedence: max_ledger_age beats grace.
func TestGateStalenessBeatsGrace(t *testing.T) {
	led := Ledger{SourceCVE: {
		Status:     StatusUnavailable,
		ObservedAt: testNow.Add(-16 * time.Minute),
		LastOKAt:   testNow.Add(-5 * time.Second), // would be inside grace
	}}
	if d := Gate(closedPosture(SourceCVE), led, testNow); !d.Block {
		t.Errorf("grace overrode the staleness bound: %+v", d)
	}
}

func TestGateMissingIsSortedForStableMessages(t *testing.T) {
	led := Ledger{
		SourceTyposquat: fresh(StatusUnavailable),
		SourceCVE:       fresh(StatusUnavailable),
		SourceMalware:   fresh(StatusUnavailable),
	}
	d := Gate(closedPosture(SourceTyposquat, SourceCVE, SourceMalware), led, testNow)
	want := []Source{SourceCVE, SourceMalware, SourceTyposquat}
	if len(d.Missing) != len(want) {
		t.Fatalf("Missing = %v, want %v", d.Missing, want)
	}
	for i := range want {
		if d.Missing[i] != want[i] {
			t.Fatalf("Missing = %v, want %v (sorted)", d.Missing, want)
		}
	}
}
