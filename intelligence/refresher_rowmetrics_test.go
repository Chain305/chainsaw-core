package intelligence

// The producer half of D-2's denominator. The exporter half is
// TestIntelRefreshRowCountersHaveWorkingProducers in internal/observability.
//
// Both halves are needed and neither is sufficient: a correct producer nobody
// reads exports a flat zero forever, and a correctly wired exporter over a
// producer nobody increments does the same. A flat zero on this counter reads
// as "the refresher walked nothing", which is indistinguishable from a broken
// wire, and it would silently make D-2's cost-per-coordinate a division by zero
// at exactly the moment someone quotes it in a pricing decision.

import (
	"context"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/metadata"
)

func TestRefreshRowCountersAreIncrementedByTheWalk(t *testing.T) {
	resetRefreshRowMetrics()
	t.Cleanup(resetRefreshRowMetrics)

	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	// One fresh row (skipped, at most a probe) and one stale row (scanned,
	// full fan-out). They must land in DIFFERENT counters: a skipped row and
	// a scanned row cost different amounts, and collapsing them would hide
	// the v0.22.8 amplifier class of bug entirely — that defect changed
	// nothing about how many rows were walked and everything about how many
	// were scanned.
	src := &fakeMetadataSource{
		rows: []metadata.PackageMetadataRow{
			{OrgID: "org1", PackageMetadata: metadata.PackageMetadata{
				Repository: "npmjs", Package: "fresh", Version: "1.0.0",
				UpdatedAt: now.Add(-1 * time.Hour),
			}},
			{OrgID: "org1", PackageMetadata: metadata.PackageMetadata{
				Repository: "npmjs", Package: "stale", Version: "1.0.0",
				UpdatedAt: now.Add(-100 * time.Hour),
			}},
		},
	}
	ref := NewRefresher(RefresherConfig{
		Service:      &fakeService{},
		Metadata:     src,
		MaxStaleness: 24 * time.Hour,
		Concurrency:  1,
		PageSize:     10,
		LatestProber: func(context.Context, metadata.PackageMetadataRow) (string, error) {
			return "1.0.0", nil
		},
		EcosystemResolver: func(string) string { return "npm" },
	})
	ref.now = func() time.Time { return now }

	summary := ref.RunOnce(context.Background())

	if got := RefreshRowsScannedTotal(); got != uint64(summary.Scanned) {
		t.Errorf("RefreshRowsScannedTotal() = %d, want %d (this tick's Scanned) — "+
			"the cumulative counter is not fed by the walk, so D-2's denominator stays at zero", got, summary.Scanned)
	}
	if got := RefreshRowsSkippedTotal(); got != uint64(summary.Skipped) {
		t.Errorf("RefreshRowsSkippedTotal() = %d, want %d (this tick's Skipped)", got, summary.Skipped)
	}
	if summary.Scanned == 0 || summary.Skipped == 0 {
		t.Fatalf("fixture produced Scanned=%d Skipped=%d; the assertions above are "+
			"vacuous unless both are non-zero", summary.Scanned, summary.Skipped)
	}

	// Cumulative across ticks, not per-tick. A second walk must ADD, because
	// forwardCounterDelta on the exporter side subtracts the previous read —
	// a counter that resets each tick would export a negative delta, which
	// that helper clamps to zero, and the series would flatline while work
	// continued.
	before := RefreshRowsScannedTotal()
	second := ref.RunOnce(context.Background())
	if got, want := RefreshRowsScannedTotal(), before+uint64(second.Scanned); got != want {
		t.Errorf("after a second tick RefreshRowsScannedTotal() = %d, want %d — the counter is "+
			"being replaced rather than accumulated", got, want)
	}
}
