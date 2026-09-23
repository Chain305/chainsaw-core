package intelligence

// Phase four of the tick: refresh reports the primary walk cannot reach.
//
// THE PROBLEM. The primary walk iterates `package_metadata`, which records what
// the PROXY has SERVED. `intelligence_reports` is larger and org-less: a
// coordinate scanned on the public path, enqueued as a transitive dependency,
// or served before a metadata row existed has a report and no metadata row, so
// the walk never visits it. Measured in production 2026-09-24:
//
//	walked coordinates      2,213 fresh /     28 stale  (98.8% fresh)
//	NOT-walked coordinates  1,048 fresh / 11,754 stale  (91.8% STALE)
//
// The walk keeps its own rows current. The other 11,754 were written once and
// never looked at again — which is also why Go artifact coverage sits at 4 of
// 6,139 no matter how many times the fetch path is fixed: 6,117 of those rows
// are orphans.
//
// WHY A SWEEP AND NOT A WIDER WALK. The walk needs an org, a repository and an
// upstream URL per row, and `intelligence_reports` has none of them — it has no
// `org_id` column at all (that is L-02). It does not need them: `Scan` produces
// the org-independent report, and the matcher-epoch sweep next door already
// refreshes coordinates by Key alone. So this mirrors that sweep rather than
// widening the walk.
//
// NO ANTI-JOIN AGAINST package_metadata, deliberately. A coordinate the walk
// covers is kept fresh by the walk, so the staleness predicate already excludes
// it. Adding the join would buy nothing and cost a scan of both tables.
//
// OFF BY DEFAULT. This is the one sweep that materially raises upstream fetch
// volume — it is a ~6x wider population than the walk — so an operator opts in
// rather than discovering it. The two sibling sweeps default ON because they
// are database-only or already-bounded work; this one reaches registries that
// rate-limit us, so the polarity is deliberately inverted relative to
// RecomputeDisabled and CoverageRecomputeDisabled.
//
// PACING. StaleReportMaxRows bounds one tick (default 200). The backlog drains
// over successive ticks; at the default hourly interval 11,754 rows take about
// two and a half days, after which the sweep only sees rows that have genuinely
// aged past the bound.

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultStaleReportMaxRows is the per-tick budget. Deliberately well below
// the matcher-epoch sweep's 500: that sweep runs after an epoch bump and is
// expected to be bursty, whereas this one is continuous and competes with the
// primary walk for the same upstream budget.
const DefaultStaleReportMaxRows = 200

// RefreshReasonStaleReport is stamped on Observation.RefreshReason for every
// Report this sweep produces, so a row can be attributed to it rather than to
// the scheduled walk. The operator's first question about a refreshed orphan is
// "what reached this coordinate, given nothing walks it", and the answer has to
// be legible from the row itself.
const RefreshReasonStaleReport = "stale_report_refresh"

var (
	staleReportBacklog      atomic.Int64
	staleReportSweptTotal   atomic.Uint64
	staleReportRefreshedTot atomic.Uint64
)

// StaleReportBacklog reads the most recently sampled backlog. Producer for the
// chainsaw_intel_stale_report_backlog gauge.
func StaleReportBacklog() float64 { return float64(staleReportBacklog.Load()) }

// StaleReportSweptTotal is the cumulative count of coordinates this sweep has
// attempted. Producer for chainsaw_intel_stale_report_swept_total.
func StaleReportSweptTotal() uint64 { return staleReportSweptTotal.Load() }

// StaleReportRefreshedTotal is the cumulative count that refreshed without
// error. Reported SEPARATELY from swept because a sweep that attempts
// everything and succeeds at nothing is the exact failure this session found in
// the primary walk, and one counter cannot show it.
func StaleReportRefreshedTotal() uint64 { return staleReportRefreshedTot.Load() }

func resetStaleReportMetrics() {
	staleReportBacklog.Store(0)
	staleReportSweptTotal.Store(0)
	staleReportRefreshedTot.Store(0)
}

// StaleReportSummary reports one sweep's work.
type StaleReportSummary struct {
	// Backlog is the depth sampled at the START of the sweep.
	Backlog int
	// Examined counts coordinates the sweep attempted.
	Examined int
	// Refreshed counts those whose Scan returned without error.
	Refreshed int
	// Failed counts those whose Scan errored.
	Failed int
	// Truncated is true when the budget stopped the walk short.
	Truncated bool
}

// StaleReportSource is the narrowed read surface the sweep needs, declared as
// an interface so the budget and ordering logic are testable without Postgres.
// A skipped DB test reports its package "ok", which is how a sweep that never
// runs reaches production unnoticed.
type StaleReportSource interface {
	CountStaleReports(ctx context.Context, olderThan time.Time) (int, error)
	IterateStaleReports(ctx context.Context, olderThan time.Time, after StaleReportCursor, limit int) ([]StaleReportRow, StaleReportCursor, error)
}

func (r *Refresher) staleReportSource() StaleReportSource {
	if r == nil {
		return nil
	}
	if r.cfg.StaleReportSource != nil {
		return r.cfg.StaleReportSource
	}
	if r.cfg.Store != nil {
		return r.cfg.Store
	}
	return nil
}

func (r *Refresher) refreshStaleReportsOnce(ctx context.Context) StaleReportSummary {
	var summary StaleReportSummary
	if r == nil || !r.cfg.StaleReportRefreshEnabled {
		return summary
	}
	src := r.staleReportSource()
	if src == nil {
		return summary
	}

	olderThan := r.now().Add(-r.cfg.MaxStaleness)

	// Sample the backlog before any work — this is the gauge's only producer,
	// so it must run even when the budget is zero or the sweep finds nothing.
	if n, err := src.CountStaleReports(ctx, olderThan); err == nil {
		summary.Backlog = n
		staleReportBacklog.Store(int64(n))
	} else {
		r.cfg.Logger.Warn("intelligence stale-report backlog count failed", "error", err)
	}

	budget := r.cfg.StaleReportMaxRows
	if budget <= 0 {
		budget = DefaultStaleReportMaxRows
	}

	var examined, refreshed, failed atomic.Int64
	sem := make(chan struct{}, r.cfg.Concurrency)
	var wg sync.WaitGroup

	var cursor StaleReportCursor
	seen := 0
walk:
	for seen < budget {
		if ctx.Err() != nil {
			break
		}
		page := r.cfg.PageSize
		if remaining := budget - seen; page > remaining {
			page = remaining
		}
		rows, next, err := src.IterateStaleReports(ctx, olderThan, cursor, page)
		if err != nil {
			r.cfg.Logger.Warn("intelligence stale-report pagination failed", "error", err)
			break
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			if ctx.Err() != nil {
				break walk
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break walk
			}
			seen++
			wg.Add(1)
			go func(row StaleReportRow) {
				defer wg.Done()
				defer func() { <-sem }()
				examined.Add(1)
				staleReportSweptTotal.Add(1)
				if r.refreshStaleReportRow(ctx, row) {
					refreshed.Add(1)
					staleReportRefreshedTot.Add(1)
				} else {
					failed.Add(1)
				}
			}(row)
		}
		if next.IsZero() {
			break
		}
		cursor = next
	}
	wg.Wait()

	summary.Examined = int(examined.Load())
	summary.Refreshed = int(refreshed.Load())
	summary.Failed = int(failed.Load())
	summary.Truncated = seen >= budget

	if seen > 0 || summary.Backlog > 0 {
		r.cfg.Logger.Info("intelligence stale-report sweep complete",
			"backlog", summary.Backlog,
			"examined", summary.Examined,
			"refreshed", summary.Refreshed,
			"failed", summary.Failed,
			"truncated", summary.Truncated)
	}
	return summary
}

// refreshStaleReportRow issues the Scan. By Key alone: intelligence_reports has
// no org, and Scan's federated half does not need one.
func (r *Refresher) refreshStaleReportRow(ctx context.Context, row StaleReportRow) bool {
	req := Request{
		Key: Key{
			Ecosystem: row.Ecosystem,
			Package:   row.Package,
			Version:   row.Version,
		},
		Options: Options{
			RefreshReason: RefreshReasonStaleReport,
			// AllowStale:false forces the fan-out. The row is stale by
			// construction — it was selected on collected_at — so Scan's
			// cache-first read will miss and do real work.
			AllowStale:   false,
			MaxStaleness: r.cfg.MaxStaleness,
		},
	}
	if _, err := r.cfg.Service.Scan(ctx, req); err != nil {
		r.cfg.Logger.Debug("stale-report refresh failed",
			"ecosystem", row.Ecosystem, "package", row.Package,
			"version", row.Version, "error", err)
		return false
	}
	return true
}
