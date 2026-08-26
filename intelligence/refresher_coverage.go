package intelligence

// The drain side of the incomplete-transitive-coverage backlog. See
// store_coverage_recompute.go for what the backlog IS and the production
// numbers that motivated it.
//
// WHY IT IS NOT A Scan
//
// The matcher-epoch sweep calls Service.Scan, because an epoch bump means the
// row's FACTS may be wrong — a provider lane that never ran, a decoder that
// dropped fields, a probe that was never made — and only a real fetch can fix
// that. This sweep is the opposite case. The root's own facts are unchanged;
// what changed is that descendants which were absent from the cache when the
// parent was scored have since been scanned. Re-running the overlay against
// the current cache is therefore sufficient AND correct, and it costs zero
// upstream requests.
//
// That difference is the whole reason this can run at a useful rate. A Scan
// per row would put this sweep in competition with the epoch sweep for the
// same registry budget; an in-process re-evaluation does not.
//
// WHY IT RIDES RunOnce
//
// Same reasoning as the matcher-epoch sweep: a third goroutine with its own
// ticker would need its own leader election, its own shutdown path and its own
// failure mode, to do work that is naturally paced by the same tick.

import (
	"context"
	"sync"
	"sync/atomic"
)

// DefaultCoverageRecomputeMaxRows caps how many partial-closure rows one tick
// re-evaluates.
//
// Set higher than DefaultRecomputeMaxRows (500) on purpose: this sweep issues
// no upstream requests, so the ceiling is local CPU and the cache-read budget
// rather than a third party's rate limit. It is still bounded, because each
// row's re-evaluation walks a dependency closure and a pathological manifest
// can make that walk large.
const DefaultCoverageRecomputeMaxRows = 2000

var (
	coverageSweptTotal    atomic.Uint64
	coverageImprovedTotal atomic.Uint64
	coverageBacklog       atomic.Int64
)

// CoverageSweptTotal is a process-local monotonic count of rows examined.
func CoverageSweptTotal() uint64 { return coverageSweptTotal.Load() }

// CoverageImprovedTotal counts rows whose closure had actually grown and were
// therefore rewritten. The GAP between this and CoverageSweptTotal is the
// signal an operator wants: a sweep that examines thousands and improves none
// is spending its budget on rows whose dependencies are never going to arrive.
func CoverageImprovedTotal() uint64 { return coverageImprovedTotal.Load() }

// CoverageBacklog is the most recently sampled depth of the backlog.
func CoverageBacklog() float64 { return float64(coverageBacklog.Load()) }

func resetCoverageMetrics() {
	coverageSweptTotal.Store(0)
	coverageImprovedTotal.Store(0)
	coverageBacklog.Store(0)
}

// CoverageSummary reports one sweep's work.
type CoverageSummary struct {
	// Backlog is the depth sampled at the START of the sweep.
	Backlog int
	// Examined counts rows the sweep re-evaluated.
	Examined int
	// Improved counts rows whose closure had grown and were rewritten.
	Improved int
	// VerdictChanged counts the subset of Improved whose VERDICT moved.
	// Tracked separately because that is the number with user impact: a
	// row that gains closure without changing verdict was already being
	// reported correctly.
	VerdictChanged int
	// Failed counts rows that could not be re-evaluated.
	Failed int
	// Truncated is true when the sweep stopped on the row budget rather
	// than because the backlog was exhausted.
	Truncated bool
}

// recomputeCoverageOnce re-evaluates up to the configured budget of rows whose
// rollup was computed against a partial dependency closure.
func (r *Refresher) recomputeCoverageOnce(ctx context.Context) CoverageSummary {
	var summary CoverageSummary
	if r == nil || r.cfg.CoverageRecomputeDisabled {
		return summary
	}
	src := r.coverageSource()
	if src == nil {
		return summary
	}

	// Sample the backlog before doing any work — this is the gauge's only
	// producer, so it must run even when the budget is zero or the sweep
	// finds nothing.
	if n, err := src.CountCoverageStale(ctx); err == nil {
		summary.Backlog = n
		coverageBacklog.Store(int64(n))
	} else {
		r.cfg.Logger.Warn("intelligence coverage backlog count failed", "error", err)
	}

	budget := r.cfg.CoverageRecomputeMaxRows
	if budget <= 0 {
		budget = DefaultCoverageRecomputeMaxRows
	}

	var examined, improved, verdictChanged, failed atomic.Int64
	sem := make(chan struct{}, r.cfg.Concurrency)
	var wg sync.WaitGroup

	var cursor CoverageStaleCursor
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
		rows, next, err := src.IterateCoverageStale(ctx, cursor, page)
		if err != nil {
			r.cfg.Logger.Warn("intelligence coverage pagination failed", "error", err)
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
			go func(row CoverageStaleRow) {
				defer wg.Done()
				defer func() { <-sem }()
				examined.Add(1)
				coverageSweptTotal.Add(1)
				grew, moved, err := r.recomputeCoverageRow(ctx, row)
				switch {
				case err != nil:
					failed.Add(1)
				case grew:
					improved.Add(1)
					coverageImprovedTotal.Add(1)
					if moved {
						verdictChanged.Add(1)
					}
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
	summary.Improved = int(improved.Load())
	summary.VerdictChanged = int(verdictChanged.Load())
	summary.Failed = int(failed.Load())
	summary.Truncated = seen >= budget

	if seen > 0 || summary.Backlog > 0 {
		r.cfg.Logger.Info("intelligence coverage sweep complete",
			"backlog", summary.Backlog,
			"examined", summary.Examined,
			"improved", summary.Improved,
			"verdict_changed", summary.VerdictChanged,
			"failed", summary.Failed,
			"truncated", summary.Truncated)
	}
	return summary
}

// CoverageReportStore is the narrowed read/write surface the per-row
// recompute needs. Declared as an interface, rather than reaching for the
// concrete *Store on the config, so the row logic — and in particular the
// churn guard that decides whether to write at all — is testable without a
// Postgres handle. A skipped DB test reports its package "ok", which is
// exactly how a broken churn guard would reach production unnoticed.
//
// *Store satisfies this. So does any in-memory fake.
type CoverageReportStore interface {
	Get(ctx context.Context, orgID string, key Key) (*Report, error)
	ListVersions(ctx context.Context, orgID, ecosystem, name string) ([]string, error)
	Upsert(ctx context.Context, orgID string, r *Report) error
}

// coverageReportStore resolves the read/write handle: an injected
// CoverageStore wins (tests), otherwise the real Store. Returns nil when
// neither is set, which makes the per-row recompute a no-op rather than a
// panic — same degradation contract as the rest of the refresher.
func (r *Refresher) coverageReportStore() CoverageReportStore {
	if r.cfg.CoverageStore != nil {
		return r.cfg.CoverageStore
	}
	if r.cfg.Store != nil {
		return r.cfg.Store
	}
	return nil
}

// coverageSource resolves the walk source: an explicitly injected
// CoverageRecomputeSource wins (tests), otherwise the store the refresher
// already holds. Returns nil when neither is available, which disables the
// sweep rather than panicking.
func (r *Refresher) coverageSource() CoverageRecomputeSource {
	if r.cfg.Coverage != nil {
		return r.cfg.Coverage
	}
	if r.cfg.Store != nil {
		return r.cfg.Store
	}
	return nil
}

// recomputeCoverageRow re-runs the risk + transitive overlay for one stored
// report against the CURRENT cache and rewrites it only if the closure
// actually grew.
//
// Returns (grew, verdictMoved, err).
//
// The write is gated on the closure having grown for a specific reason: the
// backlog predicate is "this row's last walk was incomplete", and a row whose
// dependencies are simply not in the estate stays incomplete forever. Without
// the gate the sweep would rewrite the same rows on every tick — churning the
// table, bumping updated_at, and reporting steady progress while changing
// nothing. With it, a row is touched only when there is something new to say.
//
// The re-evaluation mirrors the scanner's own ordering exactly
// (ComputeTrustScoreForOrg -> evaluateTransitiveRisk ->
// ReapplyKnownFixAfterTransitive). Getting that order wrong is not a subtle
// bug: the overlay replaces Verdict and Resolution wholesale, so skipping the
// reapply would drop every upgrade promotion the row had earned.
func (r *Refresher) recomputeCoverageRow(ctx context.Context, row CoverageStaleRow) (bool, bool, error) {
	store := r.coverageReportStore()
	if store == nil {
		return false, false, nil
	}
	key := Key{Ecosystem: row.Ecosystem, Package: row.Package, Version: row.Version}
	rep, err := store.Get(ctx, "", key)
	if err != nil || rep == nil {
		return false, false, err
	}
	// A matcher-stale row is skipped, not re-rolled. Its FACTS are the
	// problem, not its closure: a retired epoch means a provider lane that
	// never ran, a decoder that dropped fields, or a probe that was never
	// made. The matcher-epoch sweep owns that row and fixes it with a real
	// Scan — which re-runs this same overlay against correct facts on the
	// way through, so re-rolling it here would at best duplicate that work
	// and at worst persist a rollup derived from facts already known to be
	// wrong. Store.Upsert does not re-stamp the epoch, so such a write
	// would not be SERVED, but it would still churn the row and fight the
	// improvement gate below.
	if rep.MatcherStale() {
		return false, false, nil
	}

	beforeResolved := 0
	if rep.SupplyChain.TransitiveCoverage != nil {
		beforeResolved = rep.SupplyChain.TransitiveCoverage.Resolved
	}
	beforeVerdict := ""
	if rep.Risk != nil {
		beforeVerdict = string(rep.Risk.Verdict)
	}

	// Same sequence as scanner.go. ComputeTrustScoreForOrg first, so the
	// overlay folds descendants into a freshly-derived DIRECT evaluation
	// rather than into the previous run's rolled-up one — compounding a
	// rollup onto a rollup would drag the score down a little further on
	// every sweep.
	ComputeTrustScoreForOrg(rep, "")
	evaluateTransitiveRisk(ctx, store, "", rep)
	ReapplyKnownFixAfterTransitive(rep, "")

	afterResolved := 0
	if rep.SupplyChain.TransitiveCoverage != nil {
		afterResolved = rep.SupplyChain.TransitiveCoverage.Resolved
	}
	if afterResolved <= beforeResolved {
		return false, false, nil
	}

	rep.Observation.RefreshReason = RefreshReasonCoverageRecompute
	if err := store.Upsert(ctx, "", rep); err != nil {
		return false, false, err
	}
	afterVerdict := ""
	if rep.Risk != nil {
		afterVerdict = string(rep.Risk.Verdict)
	}
	return true, afterVerdict != beforeVerdict, nil
}

// RefreshReasonCoverageRecompute is stamped on Observation.RefreshReason for
// every Report this sweep rewrites, so a row can be attributed to it rather
// than to the scheduled walk, a live request, or the matcher-epoch sweep.
// After a coverage sweep the operator's first question is "did this row get
// re-rolled against the warmed cache", and the answer has to be legible from
// the row itself.
const RefreshReasonCoverageRecompute = "coverage_recompute"
