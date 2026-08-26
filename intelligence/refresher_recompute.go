package intelligence

// The matcher-epoch recompute sweep — the second walk source on the Refresher.
//
// WHY A SECOND WALK
//
// The primary walk iterates package_metadata (refresher.go, RunOnce). That
// table is written by the proxy download path, the internal-package upload
// handler and the CocoaPods trunk handler — and by nothing else. Every other
// producer of an intelligence_reports row writes a coordinate the primary walk
// cannot see:
//
//	internal/scan/worker.go            async CLI lockfile-scan jobs
//	internal/scan/lockfile_scan.go     inline lockfile scan
//	internal/server/api_v1_intel.go    `chainsaw intel package` / `intel scan`
//	core/intelligence/dep_enqueuer.go  transitive dependency fan-out
//	core/intelligence/cache_warm.go    direct-dependency cache warming
//	internal/server/intelligence_publish_prerun.go
//	internal/server/server_mcp_friction.go
//	internal/server/admin_intelligence_scan.go
//	internal/server/intelligence_upload_trigger.go
//	internal/server/intelligence_artifact_followup.go
//	core/intelligence/refresher.go:380 the primary walk's OWN new-version
//	                                   discovery, which documents that it
//	                                   deliberately does not insert a stub
//
// Those rows sat below CurrentMatcherEpoch permanently. Every read path that
// treats a superseded row as a miss (public lookup, admin inspect, the v1 API,
// both scan paths, the dep enqueuer, the transitive-risk provider) kept
// refusing them, and the inventory list kept serving them marked "recompute
// pending" against a recompute that was never coming. Three further epoch
// bumps onto that were going to compound into a permanently stale inventory.
//
// A second cause had the same effect on rows the primary walk COULD see: the
// skip rule (refresher.go, refreshRow) short-circuits on
// `reportFresh && latest == row.Version` without consulting the epoch, so a
// coordinate whose package_metadata row is touched by live proxy traffic more
// often than MaxStaleness — i.e. the most-pulled packages in the estate — is
// skipped before Scan is ever called, and Scan is the only thing that checks
// the epoch. That skip rule is left alone on purpose: adding an epoch probe
// there costs a DB round-trip per row on a walk that already spans the whole
// table, and this sweep subsumes the population anyway, because its predicate
// is the epoch and it never looks at updated_at.
//
// WHY IT RIDES RunOnce
//
// No new ticker, no new goroutine, no new enable gate to forget: the sweep is
// a second phase of the existing tick, so it inherits the refresher's
// interval, its Concurrency semaphore, its logger, its context, and the
// operator's existing CHAINSAW_INTELLIGENCE_REFRESH_ENABLED switch. It also
// inherits the admin "refresh now" endpoint for free. This is also the answer
// to the dead-function hazard that has bitten this tree repeatedly
// (SafeUpgradeVersion, backfillRepositoryGuides, ReapplyKnownFixAfterTransitive):
// the sweep is not a new exported entry point waiting to be wired, it is a
// call inside a chain that production already runs. TestRecomputeSweepIsCalledFromRunOnce
// pins that call.
//
// CROSS-REPLICA COORDINATION
//
// None is added, for the same reason the primary walk adds none: the work all
// funnels through Service.Scan, which collapses concurrent work on a
// coordinate through the in-process singleflight AND the cross-replica
// xreplicaflight leader/peek machinery (scanner.go). Two replicas sweeping the
// same backlog fan out to upstream once per coordinate, and the follower reads
// the leader's persisted row. Electing a single sweeper would be strictly
// worse — it would idle N-1 replicas' Scan budget while the backlog drains at
// one replica's rate.
//
// PACING
//
// RecomputeMaxRows bounds the rows a single tick will recompute (default 500).
// A bump can strand tens of thousands of rows at once and Scan fans out to
// upstream registries; without a cap the first tick after a deploy would try
// to recompute the entire cache. The cap is a per-tick budget, not a total:
// the backlog drains over successive ticks, and at the default hourly interval
// 500/tick is strictly less additional upstream traffic than the uncapped
// package_metadata walk running beside it already generates.

import (
	"context"
	"sync"
	"sync/atomic"
)

// DefaultRecomputeMaxRows is the per-tick recompute budget. See the PACING
// note above for why there is a cap at all and why this number is safe beside
// the uncapped primary walk.
const DefaultRecomputeMaxRows = 500

// recomputeSweptTotal is a process-local monotonic count of coordinates the
// sweep has recomputed, and recomputeBacklog is the most recently sampled
// backlog depth.
//
// Package-level rather than fields on Refresher because the observability
// exporter (internal/observability, ExporterSources) takes plain reader
// functions and is wired in cmd/chainsaw-proxy before the refresher is
// constructed — the same shape events.RecordErrors and siem.ScanErrors use.
// There is one refresher per process, so a package-level pair is not a
// multi-instance hazard; tests that need isolation call resetRecomputeMetrics.
var (
	recomputeSweptTotal atomic.Uint64
	recomputeBacklog    atomic.Int64
)

// RecomputeSweptTotal reads the cumulative number of coordinates the
// matcher-epoch sweep has recomputed since process start. Producer for the
// chainsaw_intel_recompute_swept_total counter.
func RecomputeSweptTotal() uint64 { return recomputeSweptTotal.Load() }

// RecomputeBacklog reads the most recently sampled recompute backlog — the
// number of intelligence_reports rows below CurrentMatcherEpoch. Producer for
// the chainsaw_intel_recompute_backlog gauge.
//
// Sampled once per refresher tick rather than once per metrics scrape on
// purpose: the underlying COUNT is a full scan over a JSONB expression, and a
// backlog that drains on an hourly ticker does not need five-second
// resolution. It reads 0 until the first tick completes, which on a fresh
// process is seconds after boot because Run primes the pump before arming the
// ticker.
//
// Read this TOGETHER with the swept counter. Backlog flat and swept-rate zero
// means the sweep has stopped draining — which is the original defect
// returning, and is the condition worth alerting on. Backlog flat with a
// healthy swept rate means recomputes are running but not clearing the
// predicate, i.e. Scan is failing or writing rows that are still behind.
func RecomputeBacklog() float64 { return float64(recomputeBacklog.Load()) }

// resetRecomputeMetrics zeroes the package-level counters. Test-only seam.
func resetRecomputeMetrics() {
	recomputeSweptTotal.Store(0)
	recomputeBacklog.Store(0)
}

// RecomputeSummary reports one sweep's work.
type RecomputeSummary struct {
	// Backlog is the depth sampled at the START of the sweep, before any
	// recompute ran. Reported as-sampled so a reader can compute
	// Backlog-Recomputed and compare it against the next tick's Backlog;
	// a divergence means something else is minting stale rows.
	Backlog int
	// Recomputed counts coordinates handed to Scan without error.
	Recomputed int
	// Failed counts coordinates whose Scan returned an error. Those rows
	// stay in the backlog and are retried on the next tick.
	Failed int
	// Truncated is true when the sweep stopped on RecomputeMaxRows rather
	// than because the backlog was exhausted.
	Truncated bool
}

// recomputeStaleOnce drains up to RecomputeMaxRows coordinates from the
// matcher-epoch backlog. Called from RunOnce; see this file's header for why
// it is a phase of the existing tick rather than a worker of its own.
func (r *Refresher) recomputeStaleOnce(ctx context.Context) RecomputeSummary {
	var summary RecomputeSummary
	if r == nil || r.cfg.RecomputeDisabled {
		return summary
	}
	src := r.recomputeSource()
	if src == nil {
		return summary
	}

	// Sample the backlog before doing any work. This is the gauge's only
	// producer, so it must run even when the budget is zero or the sweep
	// finds nothing — a sweep that reports no work while the backlog is
	// 3,000 deep is exactly the state an operator needs to see.
	if n, err := src.CountMatcherStale(ctx); err == nil {
		summary.Backlog = n
		recomputeBacklog.Store(int64(n))
	} else {
		r.cfg.Logger.Warn("intelligence recompute backlog count failed", "error", err)
	}

	budget := r.cfg.RecomputeMaxRows
	if budget <= 0 {
		budget = DefaultRecomputeMaxRows
	}

	var recomputed, failed atomic.Int64
	sem := make(chan struct{}, r.cfg.Concurrency)
	var wg sync.WaitGroup

	var cursor MatcherStaleCursor
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
		rows, next, err := src.IterateMatcherStale(ctx, cursor, page)
		if err != nil {
			r.cfg.Logger.Warn("intelligence recompute pagination failed", "error", err)
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
			go func(row MatcherStaleRow) {
				defer wg.Done()
				defer func() { <-sem }()
				if r.recomputeRow(ctx, row) {
					recomputed.Add(1)
					recomputeSweptTotal.Add(1)
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

	summary.Recomputed = int(recomputed.Load())
	summary.Failed = int(failed.Load())
	summary.Truncated = seen >= budget

	if seen > 0 || summary.Backlog > 0 {
		r.cfg.Logger.Info("intelligence recompute sweep complete",
			"backlog", summary.Backlog,
			"recomputed", summary.Recomputed,
			"failed", summary.Failed,
			"truncated", summary.Truncated)
	}
	return summary
}

// recomputeSource resolves the walk source: an explicitly injected
// RecomputeSource wins (tests), otherwise the store the refresher already
// holds. Returns nil when neither is available, which disables the sweep
// rather than panicking — same degradation contract as the primary walk's
// nil-Store handling.
func (r *Refresher) recomputeSource() RecomputeSource {
	if r.cfg.Recompute != nil {
		return r.cfg.Recompute
	}
	if r.cfg.Store != nil {
		return r.cfg.Store
	}
	return nil
}

// recomputeRow drives one coordinate through Scan. Reports whether the Scan
// succeeded.
//
// The Request carries no OrgID, RepoName or UpstreamURL, and that is correct
// rather than a gap: intelligence_reports has no org_id column, so the sweep
// genuinely does not know which tenant first minted the row, and the same
// applies to the transitive dep-enqueuer, which scans coordinates it knows
// only by (ecosystem, package, version). Providers that need a registry base
// resolve it from the ecosystem; the ones that need a proxy repository handle
// no-op, and Store.Upsert's merge preserves the sections an empty fan-out
// would otherwise blank.
//
// AllowStale is false so Scan cannot serve the very row being retired. It
// would not anyway — Scan's cache-first read treats a matcher-stale row as a
// miss with no escape hatch, including under AllowStale — but stating it here
// keeps the sweep correct if that ever loosens.
func (r *Refresher) recomputeRow(ctx context.Context, row MatcherStaleRow) bool {
	req := Request{
		Key: Key{
			Ecosystem: row.Ecosystem,
			Package:   row.Package,
			Version:   row.Version,
		},
		Options: Options{
			RefreshReason: RefreshReasonMatcherEpoch,
			AllowStale:    false,
			MaxStaleness:  r.cfg.MaxStaleness,
		},
	}
	if _, err := r.cfg.Service.Scan(ctx, req); err != nil {
		r.cfg.Logger.Debug("matcher-epoch recompute failed",
			"ecosystem", row.Ecosystem, "package", row.Package,
			"version", row.Version, "epoch", row.Epoch, "error", err)
		return false
	}
	return true
}

// RefreshReasonMatcherEpoch is stamped on Observation.RefreshReason for every
// Report the sweep produces, so a row can be attributed to the sweep rather
// than to the scheduled walk ("scheduled") or a live request. Distinct from
// the primary walk's reasons on purpose: after an epoch bump the operator's
// first question is "did the recompute reach this coordinate", and the answer
// has to be legible from the row itself.
const RefreshReasonMatcherEpoch = "matcher_epoch_recompute"
