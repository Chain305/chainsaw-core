package intelligence

// Cumulative counters for the package_metadata walk, so the cost of a refresh
// cycle can be DIVIDED by the coordinates it covered.
//
// The `chainsaw_upstream_fetch_total` counter answers "how many upstream
// requests did we make". On its own that is not a cost model: 500 requests is
// cheap across 500 coordinates and ruinous across 5. declared_inventory D-2 —
// the refresh-cost measurement that gates pricing — needs the denominator, and
// Prometheus had the numerator with nothing to divide it by.
//
// The per-tick numbers already existed on TickSummary and in the tick-complete
// log line, and neither is queryable: a log line cannot be graphed against the
// request counter over the same window, and TickSummary is overwritten every
// tick, so a restart or a missed read loses it. These are monotonic and survive
// both.
//
// SCANNED vs SKIPPED matters more than the total here. A skipped row costs at
// most the latest-version probe; a scanned row costs a full provider fan-out
// plus an artifact fetch. Reporting only "rows walked" would hide the v0.22.8
// amplifier class of bug entirely — that defect changed nothing about how many
// rows were walked and everything about how many were scanned.

import "sync/atomic"

var (
	refreshRowsScannedTotal atomic.Uint64
	refreshRowsSkippedTotal atomic.Uint64
)

// RefreshRowsScannedTotal is the cumulative count of package_metadata rows the
// walk has fully rescanned (provider fan-out, and an artifact fetch where the
// ecosystem supports one). Producer for chainsaw_intel_refresh_rows_scanned_total.
func RefreshRowsScannedTotal() uint64 { return refreshRowsScannedTotal.Load() }

// RefreshRowsSkippedTotal is the cumulative count of rows the walk examined and
// left alone because the stored report was still fresh. Producer for
// chainsaw_intel_refresh_rows_skipped_total.
func RefreshRowsSkippedTotal() uint64 { return refreshRowsSkippedTotal.Load() }

func resetRefreshRowMetrics() {
	refreshRowsScannedTotal.Store(0)
	refreshRowsSkippedTotal.Store(0)
}
