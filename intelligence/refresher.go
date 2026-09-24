package intelligence

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chain305/chainsaw-core/metadata"
)

// Refresher walks package_metadata on a ticker and drives intelligence.Scan
// for every row so dashboards reflect live signals instead of whatever was
// observed the day the package was first proxied.
//
// The walk is paginated by (updated_at ASC, org_id, repository, package,
// version) so stale rows refresh first and a long-running walk never
// duplicates or skips rows even when the live proxy is mutating the table
// concurrently. Per-row work runs behind a semaphore (Concurrency) so a
// large tenant doesn't burst upstream registries.
//
// Skip rules (AND): (a) the cached Report's updated_at is within
// MaxStaleness AND (b) the cached upstream-latest-version probe is also
// within MaxStaleness AND the latest version didn't change. Any miss on
// (a) or (b) kicks a fresh Scan for the (org, eco, pkg, version) tuple.
// Scans coalesce through DefaultService.sf so a proxy hit and the
// refresher on the same coordinate fan out once.
//
// New-version discovery: when the upstream latest version is newer than
// the row under refresh AND no row yet exists for that version, the
// refresher enqueues a Scan for the new version. It does NOT insert a
// stub into package_metadata — the Scan's own upsert writes an
// intelligence_reports row, and package_metadata stays driven by live
// proxy traffic (the stub would have no upstream_url or source_repo
// until someone downloads it).
type Refresher struct {
	cfg RefresherConfig
	now func() time.Time

	mu      sync.Mutex
	running bool

	lastScanned atomic.Int64
	lastSkipped atomic.Int64
	lastNewVers atomic.Int64
	lastTickEnd atomic.Int64 // unix nanos

	// alerter is the issue #20 hook. Nil disables the feature; set via
	// SetVulnAlerter during bootstrap. See vuln_alert.go for the
	// per-CVE diff semantics.
	alerter VulnAlerter
}

// RefresherConfig wires the refresher. Defaults apply when fields are
// zero: Interval=1h, MaxStaleness=DefaultMaxStaleness (24h),
// Concurrency=4, PageSize=200.
type RefresherConfig struct {
	// Service is the intelligence service the refresher drives. Required.
	Service Service
	// Store is the direct handle to the intelligence DB so the refresher
	// can read/write intelligence_latest_probes without going through the
	// Service's interface surface. Nil disables the new-version skip
	// optimisation (refresher still runs, just without probe caching).
	Store *Store
	// Metadata is the per-org package_metadata store. Required — the walk
	// source. Narrowed to an interface so tests can inject an in-memory
	// implementation without a real Postgres handle.
	Metadata MetadataSource

	// Recompute is the SECOND walk source: intelligence_reports rows whose
	// persisted matcher epoch is behind CurrentMatcherEpoch. Nil falls back
	// to Store, which satisfies the interface — so production needs no extra
	// wiring and tests can inject an in-memory slice. See
	// refresher_recompute.go for why package_metadata alone cannot drain the
	// backlog.
	Recompute RecomputeSource

	// LatestProber, when non-nil, is called by the refresher to learn
	// the current upstream "latest version" for a package. When nil, the
	// refresher skips new-version discovery and only re-runs Scan for
	// stale rows.
	LatestProber LatestVersionProber

	// EcosystemResolver maps a chainsaw proxy repository name to the
	// provider bucket Scan expects on Key.Ecosystem (npm / pip / maven /
	// docker / ...). Required in production so per-repo format overrides
	// (yarn→npm, gradle→maven) flow through correctly.
	//
	// When nil — or when it cannot resolve a row — the ecosystem is left
	// EMPTY. It is deliberately not filled in with the repository name: a
	// repository name is not an ecosystem (Phase 7 Wave 6), and a
	// fabricated bucket is read downstream as a fact about the package.
	EcosystemResolver EcosystemResolver

	// ArtifactFetcher, when non-nil AND ArtifactEnabled is true, is
	// called per row to produce artifact bytes so Tier-2 providers
	// (install-scripts, hidden-unicode, checksum) re-run on scheduled
	// refresh. When nil, scheduled refresh is Tier-1 only — signals
	// that need the bytes keep whatever was recorded at install time.
	ArtifactFetcher ArtifactFetcher

	Interval        time.Duration
	MaxStaleness    time.Duration
	Concurrency     int
	PageSize        int
	ArtifactEnabled bool

	// RecomputeMaxRows caps how many matcher-stale coordinates one tick
	// recomputes. Zero means DefaultRecomputeMaxRows.
	RecomputeMaxRows int

	// StaleReportRefreshEnabled turns on the stale-report sweep (phase four).
	//
	// OFF by default, and the polarity is inverted relative to
	// RecomputeDisabled / CoverageRecomputeDisabled on purpose: those two are
	// database-only or already-bounded work, while this one reaches registries
	// that rate-limit us across a population roughly 6x the primary walk's. An
	// operator opts into that rather than discovering it.
	StaleReportRefreshEnabled bool

	// StaleReportMaxRows caps how many stale reports one tick refreshes.
	// Zero means DefaultStaleReportMaxRows.
	StaleReportMaxRows int

	// StaleReportSource overrides the store for the stale-report sweep, so the
	// budget and ordering logic can be tested without Postgres.
	StaleReportSource StaleReportSource

	// StaleReportArtifactFetcher fetches artifact bytes for a coordinate that
	// has NO org and NO repository, by ecosystem alone.
	//
	// The walk's ArtifactFetcher cannot serve the sweep: it takes a
	// metadata.PackageMetadataRow, and the sweep exists precisely because
	// these coordinates have no such row. Production already answers "which
	// repository fetches a coordinate nobody owns" on the public deep-scan
	// path — publicArtifactFetcher resolves a per-format upstream base from
	// config — so this is wired to the same fetcher rather than inventing a
	// second answer.
	//
	// Gated by ArtifactEnabled, the same knob as the walk: "do we fetch
	// artifacts while refreshing" deserves one answer, and the sweep is
	// already opt-in on top of it.
	StaleReportArtifactFetcher func(ctx context.Context, ecosystem, pkg, version string) (*ArtifactHandle, error)

	// CoverageRecomputeMaxRows caps how many partial-closure rows one tick
	// re-evaluates. Zero means DefaultCoverageRecomputeMaxRows.
	CoverageRecomputeMaxRows int

	// Coverage is an explicitly injected walk source for the coverage
	// sweep. Nil means "use Store" — tests inject, production does not.
	Coverage CoverageRecomputeSource

	// CoverageStore is an explicitly injected read/write handle for the
	// coverage sweep's per-row recompute. Nil means "use Store".
	CoverageStore CoverageReportStore

	// CoverageRecomputeDisabled turns the incomplete-coverage sweep off.
	//
	// Same inverted polarity as RecomputeDisabled and for the same reason:
	// the sweep must be ON for the zero value of this struct, so a caller
	// building a RefresherConfig by hand cannot ship a refresher that
	// silently leaves partial rollups uncorrected. Production measurement
	// before this sweep existed: 699 rows scored against a partial closure,
	// 122 of them serving a verdict strictly better than the tree warranted.
	CoverageRecomputeDisabled bool

	// RecomputeDisabled turns the matcher-epoch sweep off.
	//
	// The polarity is inverted relative to ArtifactEnabled deliberately: the
	// sweep must be ON for the zero value of this struct, so that a caller
	// constructing a RefresherConfig without going through
	// RefresherConfigFromEnv cannot silently ship a refresher that leaves the
	// backlog undrained. That is the failure this whole file exists to
	// prevent, and it should not be reachable by forgetting a field.
	RecomputeDisabled bool

	Logger *slog.Logger
}

// LatestVersionProber returns the current upstream "latest" version for a
// package. Implementations should be cheap metadata calls (one registry
// round-trip per invocation) and must honour ctx cancellation. Returning
// ("", nil) is valid — it means "the registry answered but we couldn't
// decide on a latest" (e.g. an ecosystem without a well-defined stable
// release concept like Docker tags or OS-package repos).
//
// The row is passed in full so the implementation can resolve the proxy
// repository handle (for RemoteDefinition / auth headers) rather than
// reconstructing the upstream from a bare URL string.
type LatestVersionProber func(ctx context.Context, row metadata.PackageMetadataRow) (string, error)

// ArtifactFetcher returns artifact bytes for a specific (ecosystem, pkg,
// version). Return (nil, nil) when the artifact can't be fetched within
// budget — the refresher falls back to a Tier-1-only Scan for that row.
type ArtifactFetcher func(ctx context.Context, row metadata.PackageMetadataRow) (*ArtifactHandle, error)

// EcosystemResolver translates a chainsaw proxy repository name to the
// intelligence ecosystem bucket (Key.Ecosystem) its providers check via
// Supports(). Implementations are expected to consult the in-memory
// repository manager, not the database — the refresher holds per-row
// loops that can't afford a round-trip per resolution.
type EcosystemResolver func(repoName string) string

// MetadataSource is the narrowed surface the refresher needs from the
// per-org metadata.Store. Tests implement this with an in-memory slice;
// production wiring passes through the real *metadata.Store (which
// satisfies this interface).
type MetadataSource interface {
	IteratePackageMetadata(ctx context.Context, after metadata.PackageMetadataCursor, limit int) ([]metadata.PackageMetadataRow, metadata.PackageMetadataCursor, error)
	PackageVersionExists(ctx context.Context, orgID, repository, packageName, version string) (bool, error)
}

// NewRefresher constructs a Refresher with the supplied config. Returns
// nil when required fields (Service, Metadata) are missing so callers can
// fall back silently in degraded deployments.
func NewRefresher(cfg RefresherConfig) *Refresher {
	if cfg.Service == nil || cfg.Metadata == nil {
		return nil
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Hour
	}
	if cfg.MaxStaleness <= 0 {
		cfg.MaxStaleness = DefaultMaxStaleness
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 4
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = 200
	}
	if cfg.RecomputeMaxRows <= 0 {
		cfg.RecomputeMaxRows = DefaultRecomputeMaxRows
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Refresher{cfg: cfg, now: func() time.Time { return time.Now().UTC() }}
}

// Run is the ticker loop. Blocks until ctx is cancelled. Safe to call
// exactly once per Refresher; a second call is a no-op.
func (r *Refresher) Run(ctx context.Context) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	r.running = true
	r.mu.Unlock()

	r.cfg.Logger.Info("intelligence refresher starting",
		"interval", r.cfg.Interval,
		"max_staleness", r.cfg.MaxStaleness,
		"concurrency", r.cfg.Concurrency,
		"page_size", r.cfg.PageSize,
		"artifact_enabled", r.cfg.ArtifactEnabled,
		"recompute_enabled", !r.cfg.RecomputeDisabled,
		"recompute_max_rows", r.cfg.RecomputeMaxRows)

	// Prime the pump once so a fresh boot starts walking immediately
	// rather than sitting idle for the first Interval. The walk honours
	// ctx cancellation internally.
	r.RunOnce(ctx)

	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.cfg.Logger.Info("intelligence refresher stopping", "reason", ctx.Err())
			return
		case <-ticker.C:
			r.RunOnce(ctx)
		}
	}
}

// RunOnce performs a single end-to-end walk of package_metadata. Exported
// so the admin endpoint can trigger a synchronous refresh. Reports the
// counters via the atomic last* fields and returns a summary.
type TickSummary struct {
	Scanned     int
	Skipped     int
	NewVersions int
	Duration    time.Duration

	// Recompute reports the matcher-epoch sweep that runs as the second
	// phase of every tick. Zero-valued when the sweep is disabled or has no
	// walk source. See refresher_recompute.go.
	Recompute RecomputeSummary

	// Coverage reports the incomplete-transitive-coverage sweep that runs
	// as the third phase of every tick. Zero-valued when the sweep is
	// disabled or has no walk source. See refresher_coverage.go.
	Coverage CoverageSummary

	// StaleReports reports the stale-report sweep that runs as the fourth
	// phase of every tick — the one that reaches coordinates with no
	// package_metadata row. Zero-valued unless StaleReportRefreshEnabled.
	// See refresher_stale_reports.go.
	StaleReports StaleReportSummary
}

func (r *Refresher) RunOnce(ctx context.Context) TickSummary {
	if r == nil {
		return TickSummary{}
	}
	start := r.now()
	var scanned, skipped, newVers atomic.Int64

	sem := make(chan struct{}, r.cfg.Concurrency)
	var wg sync.WaitGroup

	var cursor metadata.PackageMetadataCursor
	for {
		if ctx.Err() != nil {
			break
		}
		rows, next, err := r.cfg.Metadata.IteratePackageMetadata(ctx, cursor, r.cfg.PageSize)
		if err != nil {
			r.cfg.Logger.Warn("intelligence refresher pagination failed", "error", err)
			break
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			if ctx.Err() != nil {
				break
			}
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				break
			}
			wg.Add(1)
			go func(row metadata.PackageMetadataRow) {
				defer wg.Done()
				defer func() { <-sem }()
				action := r.refreshRow(ctx, row)
				switch action {
				case actionScanned:
					scanned.Add(1)
				case actionSkipped:
					skipped.Add(1)
				case actionNewVersion:
					scanned.Add(1)
					newVers.Add(1)
				}
			}(row)
		}
		if next.IsZero() {
			break
		}
		cursor = next
	}
	wg.Wait()

	// Phase two of the same tick: drain the matcher-epoch backlog. Runs
	// AFTER the package_metadata walk so the walk's own Scans have already
	// lifted whatever they cover out of the backlog, and the sweep spends
	// its budget on the coordinates nothing else can reach. See
	// refresher_recompute.go.
	recompute := r.recomputeStaleOnce(ctx)

	// Phase three: re-roll rows whose rollup was computed against a partial
	// dependency closure. Runs LAST, after both the walk and the epoch
	// sweep, because both of those warm dependency rows — a coverage
	// recompute that ran first would re-evaluate against the cache as it
	// was before this tick's own Scans landed, and would then find nothing
	// new to say. See refresher_coverage.go.
	coverage := r.recomputeCoverageOnce(ctx)

	// Phase four: refresh reports the primary walk cannot reach — the ones
	// with no package_metadata row. Runs LAST because it is the widest and
	// most upstream-expensive phase, so the three cheaper ones get the tick's
	// budget first. See refresher_stale_reports.go.
	staleReports := r.refreshStaleReportsOnce(ctx)

	summary := TickSummary{
		Scanned:      int(scanned.Load()),
		Skipped:      int(skipped.Load()),
		NewVersions:  int(newVers.Load()),
		Duration:     r.now().Sub(start),
		Recompute:    recompute,
		Coverage:     coverage,
		StaleReports: staleReports,
	}
	r.lastScanned.Store(int64(summary.Scanned))
	r.lastSkipped.Store(int64(summary.Skipped))
	// Cumulative, alongside the per-tick last* values. The per-tick numbers
	// are overwritten every tick and live only in a log line; D-2 needs a
	// denominator it can graph against chainsaw_upstream_fetch_total over the
	// same window. See refresher_rowmetrics.go.
	refreshRowsScannedTotal.Add(uint64(summary.Scanned))
	refreshRowsSkippedTotal.Add(uint64(summary.Skipped))
	r.lastNewVers.Store(int64(summary.NewVersions))
	r.lastTickEnd.Store(r.now().UnixNano())

	r.cfg.Logger.Info("intelligence refresher tick complete",
		"rows_scanned", summary.Scanned,
		"rows_skipped", summary.Skipped,
		"new_versions", summary.NewVersions,
		"recompute_backlog", summary.Recompute.Backlog,
		"recomputed", summary.Recompute.Recomputed,
		"coverage_backlog", summary.Coverage.Backlog,
		"coverage_improved", summary.Coverage.Improved,
		"coverage_verdict_changed", summary.Coverage.VerdictChanged,
		"stale_report_backlog", summary.StaleReports.Backlog,
		"stale_reports_refreshed", summary.StaleReports.Refreshed,
		"duration", summary.Duration)
	return summary
}

// LastSummary reports the most recent RunOnce counters for the admin
// status endpoint and metrics.
func (r *Refresher) LastSummary() TickSummary {
	if r == nil {
		return TickSummary{}
	}
	end := r.lastTickEnd.Load()
	var dur time.Duration
	if end > 0 {
		dur = r.now().Sub(time.Unix(0, end))
	}
	return TickSummary{
		Scanned:     int(r.lastScanned.Load()),
		Skipped:     int(r.lastSkipped.Load()),
		NewVersions: int(r.lastNewVers.Load()),
		Duration:    dur,
	}
}

type refreshAction int

const (
	actionSkipped refreshAction = iota
	actionScanned
	actionNewVersion
)

func (r *Refresher) refreshRow(ctx context.Context, row metadata.PackageMetadataRow) refreshAction {
	// Resolve the intelligence ecosystem bucket from the proxy repo name.
	//
	// A REPOSITORY NAME IS NOT AN ECOSYSTEM, and this used to fall back to
	// one. That is the leak Phase 7 Wave 6 adjudicated — the upload and
	// publish paths were moved to `string(repo.Format)` there, and this
	// path was missed. It looked harmless because every provider's
	// Supports() rejected the name and the row simply no-opped; it stopped
	// being harmless when P8-05 started reading the ecosystem string as a
	// statement about advisory coverage, at which point an org's own
	// `maven-hosted` uploads read as "no advisory source covers this
	// ecosystem" — false, since they are ordinary Maven packages.
	//
	// The fallback is now the empty string: unresolved, and honestly so.
	// Nothing downstream may invent a bucket for it (markNoAdvisoryCoverage
	// declines to speak about a string that is not an ecosystem), and the
	// row is still walked so the dashboard keeps rendering it.
	ecosystem := ""
	if r.cfg.EcosystemResolver != nil {
		ecosystem = strings.TrimSpace(r.cfg.EcosystemResolver(row.Repository))
	}

	latest := ""
	probeErr := error(nil)
	// probeAnswered: the latest-version probe has a CURRENT answer, whether
	// that answer is a version or a failure. The distinction matters for the
	// skip rule below — see the comment there.
	probeAnswered := false
	if r.cfg.LatestProber != nil {
		probe := r.lookupProbe(ctx, row.OrgID, ecosystem, row.Package)
		if probe != nil && probe.FreshUntil.After(r.now()) {
			latest = probe.LatestVersion
			probeAnswered = true
		} else {
			probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			latest, probeErr = r.cfg.LatestProber(probeCtx, row)
			cancel()
			r.storeProbe(ctx, row.OrgID, ecosystem, row.Package, latest, probeErr)
			probeAnswered = true
		}
	}

	// Skip rule: both the per-version Report AND the latest-version probe
	// are within the staleness window, and the latest upstream version is
	// already represented in the store. The Report staleness is measured
	// by row.UpdatedAt as a proxy because the refresher's own Scan writes
	// update both.
	staleAfter := r.now().Add(-r.cfg.MaxStaleness)

	// Staleness is measured on the REPORT, not on package_metadata.
	//
	// This read `row.UpdatedAt`, a package_metadata column, and the comment
	// above justified it with "the refresher's own Scan writes update both".
	// That premise is false, measured against production 2026-09-24: **zero
	// package_metadata rows were touched in any two-hour window** while ticks
	// ran. Meanwhile scanFederated gates its own cache-first read on the
	// report's Observation.CollectedAt, so the two ends were reading different
	// clocks — the refresher passed a row through as stale because a column
	// nothing updates looked old, and Scan then answered it from cache.
	//
	// Three consecutive ticks logged byte-identical
	// `scanned=934 skipped=1661 new_versions=626` on three different images,
	// against ~35 rows actually written in the hour containing one. Each of
	// those 934 fetched an ARTIFACT first (the fetch below runs before Scan),
	// so the cost was a discarded multi-megabyte download per row per hour
	// against upstreams we are already rate-limited on — not merely a wasted
	// database read.
	//
	// The gate was also wrong in the OTHER direction, which is the half that
	// lost data rather than wasting work: 15 coordinate pairs in production
	// had a FRESH package_metadata row and a STALE report, so they were
	// skipped every tick and never refreshed at all.
	//
	// Fallback to row.UpdatedAt only when there is NO store to ask. A store
	// that is present and returns nothing means no report exists, which is a
	// reason to scan, not to skip — and loadPriorReport also returns nil on
	// error, so an unreachable store fails toward doing the work.
	var priorReport *Report
	if r.cfg.Store != nil {
		priorReport = r.loadPriorReport(ctx, row, ecosystem)
	}
	reportFresh := reportIsFresh(priorReport, r.cfg.Store != nil, row.UpdatedAt, staleAfter)
	if reportFresh && probeAnswered && (latest == "" || latest == row.Version) {
		// `latest == ""` is the part that was missing, and it was a 24x
		// amplifier on exactly the rows least worth rescanning.
		//
		// A probe that FAILS — package deleted, renamed, made private, or
		// upstream refusing us — stores LatestVersion:"" with a 24h
		// FreshUntil, so the probe itself is not retried. But the old
		// condition required `latest != ""` to skip, so the row fell through
		// to a full Scan plus an artifact fetch on EVERY tick. At a 1h
		// interval against a 24h staleness bound that is **24 refreshes per
		// day instead of one**, and every one of them is a request upstream
		// has already said it cannot satisfy.
		//
		// Measured shape in production: npm 80 not_found against 30 ok,
		// registry.yarnpkg.com 36 requests and zero successes — the yarn host
		// is healthy, it was this loop at saturation.
		//
		// Skipping is safe because `reportFresh` still gates it: once the
		// stored report ages past MaxStaleness the row scans regardless, and
		// the probe's own TTL expiring is what schedules the retry. A package
		// that comes back gets picked up on the next probe, not the next tick.
		return actionSkipped
	}

	// New-version discovery: enqueue a separate Tier-1 Scan for the newer
	// version when the row under refresh is still on an older version.
	// We never insert a stub into package_metadata from here — the live
	// proxy path owns that table's lifecycle, and an orphan stub would
	// lack upstream_url, source_repo, and the other columns the policy
	// evaluator needs.
	action := actionScanned
	if latest != "" && latest != row.Version {
		exists := false
		if r.cfg.Metadata != nil {
			if ok, err := r.cfg.Metadata.PackageVersionExists(ctx, row.OrgID, row.Repository, row.Package, latest); err == nil && ok {
				exists = true
			}
		}
		// package_metadata is not the only place a version can already be
		// covered. It records what the PROXY has served; a coordinate scanned
		// on the public path, or enqueued as a transitive dependency, has an
		// intelligence_reports row and no metadata row. This check asked only
		// the first table, so such a version counted as new on EVERY tick —
		// 626 of the 934 rows the walk "scanned" each hour in production, each
		// one issuing a Scan that the report cache then answered without
		// writing, forever, because nothing here ever inserts into
		// package_metadata (deliberately — see the comment above).
		//
		// Asking the report store closes that loop. Same reasoning as the
		// staleness gate in refresher_staleness_gate.go: the question is "do we
		// already have current intelligence on this version", and the table
		// that answers it is the one holding the reports.
		if !exists && r.cfg.Store != nil {
			latestKey := Key{Ecosystem: ecosystem, Package: row.Package, Version: latest}
			if rep := r.loadReportForKey(ctx, row.OrgID, latestKey); rep != nil &&
				rep.Observation.CollectedAt.After(staleAfter) {
				exists = true
			}
		}
		if !exists {
			newReq := Request{
				Key: Key{
					Ecosystem: ecosystem,
					Package:   row.Package,
					Version:   latest,
				},
				OrgID:       row.OrgID,
				RepoName:    row.Repository,
				UpstreamURL: row.UpstreamURL,
				Options: Options{
					RefreshReason: "scheduled_new_version",
					AllowStale:    false,
					MaxStaleness:  r.cfg.MaxStaleness,
				},
			}
			if _, err := r.cfg.Service.Scan(ctx, newReq); err != nil {
				r.cfg.Logger.Debug("scheduled new-version scan failed",
					"ecosystem", ecosystem, "package", row.Package, "version", latest,
					"error", err)
			}
			action = actionNewVersion
		} else if reportFresh && probeAnswered {
			// Nothing left to do for this row. Its OWN report is fresh, and
			// the newer version upstream is already covered — so the only
			// reason it fell past the skip gate above has been answered.
			//
			// The gate could not know that: it fires before `exists` is
			// computed, and its condition requires `latest == row.Version`.
			// So a row with a newer version upstream never skipped, even when
			// both versions were already current. In production that was 626
			// rows an hour, each fetching an artifact and running a Scan the
			// report cache then answered without writing.
			//
			// Returning here is what avoids the artifact fetch; the fetch is
			// below, and it is the expensive half.
			return actionSkipped
		}
	}

	// Refresh the row's own Scan. AllowStale:false forces the fan-out
	// when the cached Report is older than MaxStaleness, but falls back
	// to the cache when it's still fresh — the Scanner's internal cache
	// check handles both branches so the refresher never duplicates work
	// against a hot cache.
	req := Request{
		Key: Key{
			Ecosystem: ecosystem,
			Package:   row.Package,
			Version:   row.Version,
		},
		OrgID:       row.OrgID,
		RepoName:    row.Repository,
		UpstreamURL: row.UpstreamURL,
		Options: Options{
			RefreshReason: "scheduled",
			AllowStale:    false,
			MaxStaleness:  r.cfg.MaxStaleness,
		},
	}
	if r.cfg.ArtifactEnabled && r.cfg.ArtifactFetcher != nil {
		fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		handle, err := r.cfg.ArtifactFetcher(fetchCtx, row)
		cancel()
		if err != nil {
			r.cfg.Logger.Debug("scheduled artifact fetch failed",
				"ecosystem", ecosystem, "package", row.Package, "version", row.Version,
				"error", err)
		} else if handle != nil {
			req.Artifact = handle
		}
	}
	// Issue #20: the alerter diffs CVE state across the refresh boundary
	// against the prior on-disk Report. That snapshot is already in hand —
	// the staleness gate above loaded it — so this no longer re-reads it.
	// When there is no store, priorReport is nil and the alerter simply sees
	// no prior, which is what it saw before.
	if r.alerter != nil && priorReport == nil && r.cfg.Store == nil {
		priorReport = r.loadPriorReport(ctx, row, ecosystem)
	}
	nextReport, err := r.cfg.Service.Scan(ctx, req)
	if err != nil {
		r.cfg.Logger.Debug("scheduled scan failed",
			"ecosystem", ecosystem, "package", row.Package, "version", row.Version,
			"error", err)
	}
	if r.alerter != nil && nextReport != nil {
		r.alerter.OnRefreshedReport(ctx, row, ecosystem, priorReport, nextReport)
	}
	return action
}

func (r *Refresher) lookupProbe(ctx context.Context, orgID, ecosystem, pkg string) *LatestVersionProbe {
	if r.cfg.Store == nil {
		return nil
	}
	probe, err := r.cfg.Store.GetLatestVersionProbe(ctx, orgID, ecosystem, pkg)
	if err != nil {
		return nil
	}
	return probe
}

func (r *Refresher) storeProbe(ctx context.Context, orgID, ecosystem, pkg, latest string, probeErr error) {
	if r.cfg.Store == nil {
		return
	}
	now := r.now()
	errStr := ""
	if probeErr != nil {
		errStr = probeErr.Error()
	}
	_ = r.cfg.Store.UpsertLatestVersionProbe(ctx, orgID, LatestVersionProbe{
		Ecosystem:     ecosystem,
		Package:       pkg,
		LatestVersion: latest,
		ProbedAt:      now,
		FreshUntil:    now.Add(r.cfg.MaxStaleness),
		Error:         errStr,
	})
}

// RefresherConfigFromEnv hydrates the tunables from CHAINSAW_INTELLIGENCE_REFRESH_*
// env vars, leaving unset fields at their zero value for downstream
// defaulting inside NewRefresher. Callers are expected to assign
// Service / Metadata / LatestProber themselves.
func RefresherConfigFromEnv() RefresherConfig {
	var cfg RefresherConfig
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_INTELLIGENCE_REFRESH_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Interval = d
		}
	}
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_INTELLIGENCE_REFRESH_MAX_STALENESS")); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.MaxStaleness = d
		}
	}
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_INTELLIGENCE_REFRESH_CONCURRENCY")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Concurrency = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_INTELLIGENCE_REFRESH_PAGE_SIZE")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.PageSize = n
		}
	}
	cfg.ArtifactEnabled = envBool("CHAINSAW_INTELLIGENCE_REFRESH_ARTIFACT", true)
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_INTELLIGENCE_RECOMPUTE_MAX_ROWS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.RecomputeMaxRows = n
		}
	}
	// Default ON, matching the refresher itself: an operator who has not
	// thought about matcher epochs should still get a draining backlog.
	cfg.RecomputeDisabled = !envBool("CHAINSAW_INTELLIGENCE_RECOMPUTE_ENABLED", true)

	// Default OFF, and the polarity is inverted relative to the two sweeps
	// above on purpose. Those are database-only or already-bounded work, so an
	// operator who has not thought about them should still get a draining
	// backlog. This one reaches registries that rate-limit us, across a
	// population roughly 6x the primary walk's, so it is opted into.
	cfg.StaleReportRefreshEnabled = envBool("CHAINSAW_INTELLIGENCE_STALE_REFRESH_ENABLED", false)
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_INTELLIGENCE_STALE_REFRESH_MAX_ROWS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.StaleReportMaxRows = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_INTELLIGENCE_COVERAGE_RECOMPUTE_MAX_ROWS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.CoverageRecomputeMaxRows = n
		}
	}
	cfg.CoverageRecomputeDisabled = !envBool("CHAINSAW_INTELLIGENCE_COVERAGE_RECOMPUTE_ENABLED", true)
	return cfg
}

// RefresherEnabled returns whether the scheduled refresher should start.
// Default on — operators opt out by setting the env var to a falsy value
// (the 2026 model sensibly assumes supply-chain freshness matters).
func RefresherEnabled() bool {
	return envBool("CHAINSAW_INTELLIGENCE_REFRESH_ENABLED", true)
}

func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "":
		return def
	case "1", "true", "on", "yes", "enable", "enabled":
		return true
	default:
		return false
	}
}
