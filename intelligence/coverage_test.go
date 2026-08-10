package intelligence

import (
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/coverage"
)

func TestLedgerFromReportMarksRanProvidersOK(t *testing.T) {
	at := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	r := &Report{}
	r.Observation.CollectedAt = at
	r.Observation.ProviderTimings = []ProviderTiming{{Provider: "cve"}, {Provider: "malware"}}

	led := LedgerFromReport(r)
	for _, src := range []coverage.Source{coverage.SourceCVE, coverage.SourceMalware} {
		if got := led[src].Status; got != coverage.StatusOK {
			t.Errorf("%s = %q, want ok", src, got)
		}
		if !led[src].ObservedAt.Equal(at) {
			t.Errorf("%s ObservedAt = %v, want %v", src, led[src].ObservedAt, at)
		}
	}
}

func TestLedgerFromReportMarksWarnedProvidersFromCode(t *testing.T) {
	at := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	r := &Report{}
	r.Observation.CollectedAt = at
	r.Observation.ProviderTimings = []ProviderTiming{{Provider: "cve"}}
	r.Observation.Warnings = []Warning{{Provider: "cve", Code: "http_503", At: at}}

	led := LedgerFromReport(r)
	if got := led[coverage.SourceCVE].Status; got != coverage.StatusUnavailable {
		t.Errorf("cve = %q, want unavailable", got)
	}
}

// The bug this pins: a provider that RAN gets an OK entry (with LastOKAt) from
// ProviderTimings, and its warning is applied on top. If the warning inherited
// that same-scan LastOKAt, Gate's grace window would rescue the failure — for
// the whole grace period after every scan, i.e. always, since the gate reads
// the report the instant it is produced. That would make mode=closed inert on
// every server surface while looking perfectly configured.
func TestLedgerFromReportDoesNotLetASameScanOKRescueItsOwnFailure(t *testing.T) {
	at := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	r := &Report{}
	r.Observation.CollectedAt = at
	r.Observation.ProviderTimings = []ProviderTiming{{Provider: "cve"}}
	r.Observation.Warnings = []Warning{{Provider: "cve", Code: "timeout", At: at}}

	e := LedgerFromReport(r)[coverage.SourceCVE]
	if !e.LastOKAt.IsZero() {
		t.Fatalf("LastOKAt = %v, want zero — the OK stamp came from the same scan that failed", e.LastOKAt)
	}

	p := coverage.Posture{
		Version: 1, Mode: coverage.ModeClosed,
		Required:     []coverage.Source{coverage.SourceCVE},
		Grace:        coverage.DefaultGrace,
		MaxLedgerAge: coverage.DefaultMaxLedgerAge,
	}
	if d := coverage.Gate(p, LedgerFromReport(r), at); !d.Block {
		t.Fatal("a required source that just timed out must refuse, not be rescued by grace")
	}
}

// A "not_found" warning is a real answer from the source, not an outage — it
// must not downgrade an otherwise-healthy entry.
func TestLedgerFromReportKeepsOKForAnswerWarnings(t *testing.T) {
	at := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	r := &Report{}
	r.Observation.CollectedAt = at
	r.Observation.ProviderTimings = []ProviderTiming{{Provider: "registrymetadata"}}
	r.Observation.Warnings = []Warning{{Provider: "registrymetadata", Code: "not_found", At: at}}

	led := LedgerFromReport(r)
	if got := led[coverage.SourceRegistryMetadata].Status; got != coverage.StatusOK {
		t.Errorf("registry_metadata = %q, want ok (not_found is an answer)", got)
	}
}

func TestLedgerFromReportOmitsProvidersThatNeverRan(t *testing.T) {
	r := &Report{}
	r.Observation.CollectedAt = time.Now()
	r.Observation.ProviderTimings = []ProviderTiming{{Provider: "cve"}}

	led := LedgerFromReport(r)
	if _, ok := led[coverage.SourceChecksum]; ok {
		t.Error("checksum has an entry but never ran; Gate must treat it as absent")
	}
}

func TestLedgerFromReportHandlesNilReport(t *testing.T) {
	if led := LedgerFromReport(nil); len(led) != 0 {
		t.Errorf("nil report produced %v, want an empty ledger", led)
	}
}
