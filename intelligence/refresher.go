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

	summary := TickSummary{
		Scanned:     int(scanned.Load()),
		Skipped:     int(skipped.Load()),
		NewVersions: int(newVers.Load()),
		Duration:    r.now().Sub(start),
		Recompute:   recompute,
		Coverage:    coverage,
	}
	r.lastScanned.Store(int64(summary.Scanned))
	r.lastSkipped.Store(int64(summary.Skipped))
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
	if r.cfg.LatestProber != nil {
		probe := r.lookupProbe(ctx, row.OrgID, ecosystem, row.Package)
		if probe != nil && probe.FreshUntil.After(r.now()) {
			latest = probe.LatestVersion
		} else {
			probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			latest, probeErr = r.cfg.LatestProber(probeCtx, row)
			cancel()
			r.storeProbe(ctx, row.OrgID, ecosystem, row.Package, latest, probeErr)
		}
	}

	// Skip rule: both the per-version Report AND the latest-version probe
	// are within the staleness window, and the latest upstream version is
	// already represented in the store. The Report staleness is measured
	// by row.UpdatedAt as a proxy because the refresher's own Scan writes
	// update both.
	staleAfter := r.now().Add(-r.cfg.MaxStaleness)
	reportFresh := row.UpdatedAt.After(staleAfter)
	if reportFresh && latest != "" && latest == row.Version {
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
	// Issue #20: snapshot the prior on-disk Report before Scan overwrites
	// it so the alerter can diff CVE state across the refresh boundary.
	// Cheap when alerter is nil — we skip the read entirely.
	var priorReport *Report
	if r.alerter != nil {
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
