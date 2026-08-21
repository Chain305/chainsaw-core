package intelligence

// Regression tests for the matcher epoch — the mechanism that stops a cached
// Report produced by a superseded matcher or risk engine from being served
// forever.
//
// The defect these pin is not theoretical. Two verdict-changing fixes shipped
// (the OSV GIT-range false positive in v0.20.8, the missing MaxImpact ceiling
// on vuln.cvss_critical in v0.21.2) and an external QA pass reproduced both
// afterwards, because every read path is cache-first and the cache had no
// notion of which generation of the engine wrote a row. The 24h TTL did not
// help: a refresh re-ran the same logic and copied the wrong answer forward.

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestMatcherStale covers the four states a cached Report can be in. The
// legacy case (epoch 0) is the load-bearing one: every row written before the
// epoch existed decodes to zero, and those are exactly the rows carrying the
// defects the epoch was introduced to retract.
func TestMatcherStale(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		rep   *Report
		stale bool
	}{
		{
			name:  "nil report is stale",
			rep:   nil,
			stale: true,
		},
		{
			name:  "legacy row with no epoch is stale",
			rep:   &Report{},
			stale: true,
		},
		{
			name:  "superseded epoch is stale",
			rep:   &Report{Observation: ObservationSection{MatcherEpoch: CurrentMatcherEpoch - 1}},
			stale: true,
		},
		{
			name:  "current epoch is fresh",
			rep:   &Report{Observation: ObservationSection{MatcherEpoch: CurrentMatcherEpoch}},
			stale: false,
		},
		{
			// A row from a newer binary during a rolling deploy. Serving it
			// is correct: it was produced by a strictly better matcher than
			// this replica runs, so discarding it would be a downgrade.
			name:  "future epoch is fresh",
			rep:   &Report{Observation: ObservationSection{MatcherEpoch: CurrentMatcherEpoch + 1}},
			stale: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.rep.MatcherStale(); got != tc.stale {
				t.Fatalf("MatcherStale() = %v, want %v", got, tc.stale)
			}
		})
	}
}

// TestScanStampsCurrentMatcherEpoch asserts the write side. Without the stamp
// in runFanout every freshly computed Report would decode as epoch 0 on the
// next read, so every coordinate would be permanently stale and the cache
// would stop working entirely — a failure mode that is quiet in a unit test
// and extremely loud in production.
func TestScanStampsCurrentMatcherEpoch(t *testing.T) {
	t.Parallel()

	svc := New(Config{
		Providers: []Provider{&fakeProvider{name: "fake", signal: SignalAll}},
		Now:       func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})

	got, err := svc.Scan(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got.Observation.MatcherEpoch != CurrentMatcherEpoch {
		t.Fatalf("Observation.MatcherEpoch = %d, want CurrentMatcherEpoch (%d)",
			got.Observation.MatcherEpoch, CurrentMatcherEpoch)
	}
	if got.MatcherStale() {
		t.Fatal("a Report that Scan just computed reports itself as matcher-stale")
	}
}

// TestMatcherEpochSurvivesRoundTrip pins the storage contract. The epoch lives
// inside the Report JSONB blob rather than in its own column, so persistence
// is entirely a question of whether it marshals and unmarshals. If a future
// change adds `json:"-"` or moves the field, the epoch silently reads back as
// 0, every row looks stale forever, and the cache degrades to a no-op.
func TestMatcherEpochSurvivesRoundTrip(t *testing.T) {
	t.Parallel()

	in := &Report{Observation: ObservationSection{MatcherEpoch: CurrentMatcherEpoch}}
	blob, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out Report
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Observation.MatcherEpoch != CurrentMatcherEpoch {
		t.Fatalf("epoch did not survive the round trip: got %d, want %d",
			out.Observation.MatcherEpoch, CurrentMatcherEpoch)
	}
	if out.MatcherStale() {
		t.Fatal("round-tripped Report reports itself as matcher-stale")
	}
}

// TestLegacyReportJSONDecodesToStale is the other half of the storage
// contract, from the direction that actually matters on deploy day: a row
// persisted before the field existed carries no matcherEpoch key at all, and
// must decode to the stale state rather than to anything that looks current.
func TestLegacyReportJSONDecodesToStale(t *testing.T) {
	t.Parallel()

	// Deliberately hand-written rather than produced by marshalling a
	// Report: the point is to model bytes written by an older binary.
	const legacy = `{"identity":{"ecosystem":"npm","package":"lodash","version":"4.17.21"},
	                 "observation":{"collectedAt":"2026-05-01T00:00:00Z"}}`

	var out Report
	if err := json.Unmarshal([]byte(legacy), &out); err != nil {
		t.Fatalf("unmarshal legacy row: %v", err)
	}
	if out.Observation.MatcherEpoch != 0 {
		t.Fatalf("legacy row decoded to epoch %d, want 0", out.Observation.MatcherEpoch)
	}
	if !out.MatcherStale() {
		t.Fatal("a row written before the epoch existed must be treated as stale")
	}
}

// TestLookupDepReportSkipsMatcherStaleRow pins the transitive-risk read path.
// It matters more than it looks: transitive alerts are assembled by walking
// the cache directly rather than by calling Scan, so this is the one place a
// retracted verdict could keep surfacing as a dependency alert long after the
// direct lookup for the same coordinate started returning the corrected one.
func TestLookupDepReportSkipsMatcherStaleRow(t *testing.T) {
	t.Parallel()

	store := newFakeStore()
	stale := newReport("npm", "left-pad", "1.3.0")
	stale.Observation.MatcherEpoch = CurrentMatcherEpoch - 1
	store.put("npm", "left-pad", "1.3.0", stale)

	_, got, outcome, err := lookupDepReport(context.Background(), store, "org", "npm", "left-pad", "1.3.0")
	if err != nil {
		t.Fatalf("lookupDepReport: %v", err)
	}
	if got != nil {
		t.Fatalf("a matcher-stale row was returned as a resolved dependency: %+v", got.Observation)
	}
	if outcome == lookupResolved {
		t.Fatal("outcome is lookupResolved for a row that must be treated as a miss")
	}

	// Control: the identical lookup resolves once the row carries the
	// current epoch, so the assertion above is about staleness and not
	// about the fixture being unreachable for some other reason.
	store.put("npm", "left-pad", "1.3.0", newReport("npm", "left-pad", "1.3.0"))
	if _, got, _, err = lookupDepReport(context.Background(), store, "org", "npm", "left-pad", "1.3.0"); err != nil || got == nil {
		t.Fatalf("current-epoch row did not resolve: report=%v err=%v", got, err)
	}
}
