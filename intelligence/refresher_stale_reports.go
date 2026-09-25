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
	"errors"
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

// DefaultStaleReportArtifactCooldown is the retry interval for a report that
// has never had an artifact scan. Twelve hours, not one tick: a package whose
// bytes cannot be fetched at all would otherwise be refreshed every hour, and
// repeated work that changes nothing is the waste the 2026-09-24 refresher
// wave spent eight releases removing.
const DefaultStaleReportArtifactCooldown = 12 * time.Hour

// staleReportArtifactTimeout bounds one artifact download. Matches the walk's
// 30s: the same registries, the same sizes.
const staleReportArtifactTimeout = 30 * time.Second

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
	CountStaleReports(ctx context.Context, scope StaleReportScope) (int, error)
	IterateStaleReports(ctx context.Context, scope StaleReportScope, after StaleReportCursor, limit int) ([]StaleReportRow, StaleReportCursor, error)
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

	scope := r.staleReportScope()

	// Sample the backlog before any work — this is the gauge's only producer,
	// so it must run even when the budget is zero or the sweep finds nothing.
	if n, err := src.CountStaleReports(ctx, scope); err == nil {
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
		rows, next, err := src.IterateStaleReports(ctx, scope, cursor, page)
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

// staleReportScope is the population one sweep draws from. The artifact half is
// empty unless the sweep can actually fetch bytes, so it can never turn into a
// loop of bytes-less rescans.
func (r *Refresher) staleReportScope() StaleReportScope {
	now := r.now()
	scope := StaleReportScope{OlderThan: now.Add(-r.cfg.MaxStaleness)}
	if r.cfg.ArtifactEnabled && r.cfg.StaleReportArtifactFetcher != nil && len(r.cfg.StaleReportArtifactEcosystems) > 0 {
		scope.ArtifactEcosystems = r.cfg.StaleReportArtifactEcosystems
		scope.ArtifactOlderThan = now.Add(-r.staleReportArtifactCooldown())
	}
	return scope
}

func (r *Refresher) staleReportArtifactCooldown() time.Duration {
	c := r.cfg.StaleReportArtifactCooldown
	if c <= 0 {
		c = DefaultStaleReportArtifactCooldown
	}
	if r.cfg.MaxStaleness > 0 && c > r.cfg.MaxStaleness {
		c = r.cfg.MaxStaleness
	}
	return c
}

// staleReportMaxStaleness is the MaxStaleness each sweep Scan runs with: the
// cool-down while the artifact half is active, else the ordinary bound.
func (r *Refresher) staleReportMaxStaleness() time.Duration {
	if len(r.staleReportScope().ArtifactEcosystems) > 0 {
		return r.staleReportArtifactCooldown()
	}
	return r.cfg.MaxStaleness
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
			// AllowStale:false plus a MaxStaleness no longer than the row's
			// age forces the fan-out. A plainly stale row is older than
			// MaxStaleness; a never-scanned row picked for its bytes may be
			// FRESH, and against the full bound Scan's cache-first read would
			// hand back the cached report and drop the bytes on the floor.
			// Every selected row is older than the cool-down, which is
			// clamped to MaxStaleness, so the cool-down forces both.
			AllowStale:   false,
			MaxStaleness: r.staleReportMaxStaleness(),
		},
	}
	// Attach artifact bytes where we can. Without them Scan skips every
	// provider that declares NeedsArtifact (scanner.go:477) and records
	// WarnNeedsArtifact instead, so the refreshed report would carry current
	// metadata, vulnerability and provenance facts and an EMPTY artifact
	// section — which is what the first cut of this sweep did, and why Go
	// artifact coverage did not move when it shipped.
	//
	// Best-effort: a fetch failure logs and continues, exactly as the walk's
	// does. Refusing to refresh the other signals because the bytes were
	// unavailable would trade a partial improvement for none.
	if r.cfg.ArtifactEnabled && r.cfg.StaleReportArtifactFetcher != nil {
		fetchCtx, cancel := context.WithTimeout(ctx, staleReportArtifactTimeout)
		handle, err := r.cfg.StaleReportArtifactFetcher(fetchCtx, row.Ecosystem, row.Package, row.Version)
		cancel()
		if err != nil {
			// Recorded on the report, and it takes the row out of the
			// never-scanned half of the scope (StaleReportScope).
			req.ArtifactTooLarge = errors.Is(err, ErrArtifactTooLarge)
			r.cfg.Logger.Debug("stale-report artifact fetch failed",
				"ecosystem", row.Ecosystem, "package", row.Package,
				"version", row.Version, "error", err)
		} else if handle != nil {
			req.Artifact = handle
		}
	}

	if _, err := r.cfg.Service.Scan(ctx, req); err != nil {
		r.cfg.Logger.Debug("stale-report refresh failed",
			"ecosystem", row.Ecosystem, "package", row.Package,
			"version", row.Version, "error", err)
		return false
	}
	return true
}
