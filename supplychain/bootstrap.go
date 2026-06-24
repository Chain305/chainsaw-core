package supplychain

import (
	"context"
	"crypto/x509"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/metadata"
	"github.com/chain305/chainsaw-core/provenance"
	"github.com/chain305/chainsaw-core/typosquat"
)

// popularBootstrapJitterMax caps the randomised pre-bootstrap delay
// (item #3 from the concurrency-hardening review). Zero impact on a
// single-instance deploy — it's just 0..30s of idle time before the
// first popular-package fetch — but prevents a thundering herd against
// npm/pypi/crates when many replicas restart within the same second
// (rolling deploy, full node rotation, etc.). Upper bound deliberately
// small (30s) so startup observability isn't muddied.
const popularBootstrapJitterMax = 30 * time.Second

// popularRefreshBase + popularRefreshJitter define the cadence of the
// weekly popular-package refresh (item #4). The base is 7d; each
// iteration adds a random delta in [-jitter/2, +jitter/2), i.e. ±6h,
// so N replicas sharing a single DB don't refresh in lockstep. Keeping
// jitter << base (12h/168h ≈ 7%) preserves the "roughly once a week"
// operational expectation.
const (
	popularRefreshBase   = 7 * 24 * time.Hour
	popularRefreshJitter = 12 * time.Hour
)

// BootstrapConfig holds configuration for supply chain system initialization.
type BootstrapConfig struct {
	// DataDir is the base directory for persistent data (malware DB clone, etc.).
	DataDir string
	// PopularPackageLimit is the max number of popular packages to fetch per ecosystem.
	PopularPackageLimit int
	// MalwareSyncInterval is how often to sync the malware database.
	MalwareSyncInterval time.Duration
	// MetadataStore for persisting supply chain results.
	MetadataStore *metadata.Store
	// Logger for supply chain operations.
	Logger *slog.Logger
	// ProvenanceOptions are forwarded to provenance.NewChecker — use to
	// disable specific ecosystems or enable offline mode in egress-
	// restricted deployments. Zero-length slice means all ecosystems
	// enabled.
	ProvenanceOptions []provenance.CheckerOption
	// EnableGHSAMalware toggles the supplementary GHSA Swift malware
	// fetcher in the malware syncer. Defaults to false when this field
	// is left unset; main.go should pass cfg.Malware.GHSAEnabled() so
	// the user-facing default-on contract is preserved.
	EnableGHSAMalware bool
	// EnableDockerMalware toggles the Docker malware feed (embedded
	// seed + optional remote). Defaults to true — callers that want it
	// off must set the field to a *bool explicitly; see the pointer
	// below. The Docker syncer is cheap (no network unless
	// DockerMalwareFeedURL is set) so default-on has no operational
	// cost.
	EnableDockerMalware *bool
	// DockerMalwareFeedURL, when non-empty, is fetched on each sync
	// and its entries are merged on top of the embedded Docker seed.
	// Empty means seed-only.
	DockerMalwareFeedURL string
	// EnableHuggingFaceMalware toggles the HuggingFace malware feed
	// (embedded seed + optional remote). Defaults to true — callers
	// that want it off must set the field to a *bool explicitly. The
	// HF syncer is cheap (no network unless HuggingFaceMalwareFeedURL
	// is set) and the embedded corpus is tiny, so default-on has no
	// operational cost. Mirrors EnableDockerMalware.
	EnableHuggingFaceMalware *bool
	// HuggingFaceMalwareFeedURL, when non-empty, is fetched on each
	// sync and its entries are merged on top of the embedded HF seed.
	// Empty means seed-only.
	HuggingFaceMalwareFeedURL string
	// SwiftRegistryURL configures the Swift provenance probe's target
	// registry. Empty disables the Swift probe entirely.
	SwiftRegistryURL string
	// SwiftTrustRoots is the CA pool used by the Swift CMS verifier
	// when SwiftFullVerify is enabled. Nil means "use system trust
	// pool".
	SwiftTrustRoots *x509.CertPool
	// SwiftFullVerify, when true, enables full SE-0391 cryptographic
	// verification in the Swift provenance probe. When false the probe
	// only confirms signature presence.
	SwiftFullVerify bool
	// APTKeyringPath configures the trust anchor used by the APT
	// provenance checker (InRelease signature verification). Accepts a
	// single key file or a directory (`/etc/apt/trusted.gpg.d/` style)
	// containing `.asc` / `.gpg` public keys. When empty, falls back to
	// the CHAINSAW_APT_KEYRING env var, then to keys embedded at build
	// time under internal/provenance/keys/apt/. A missing/empty keyring
	// degrades apt provenance to StatusUnavailable with a descriptive
	// reason — no fatal error at startup.
	APTKeyringPath string
	// RPMKeyringPath is the yum/dnf counterpart to APTKeyringPath. Used
	// to verify detached repomd.xml.asc signatures. When empty, falls
	// back to the CHAINSAW_RPM_KEYRING env var, then to embedded keys
	// under internal/provenance/keys/rpm/.
	RPMKeyringPath string

	// UpstreamHTTPClient is the shared per-host-rate-limited HTTP client
	// used for every outbound registry fetch (popular-package lists,
	// provenance verifications, etc.). Wired once at startup by
	// cmd/chainsaw-proxy/init_server.go so every goroutine shares one
	// npm / pypi / crates budget instead of each re-deriving its own.
	// nil is tolerated — the typosquat Fetcher and provenance Checker
	// fall back to their internal default clients (no rate limiting,
	// preserves pre-wiring behaviour). Tests leave this nil.
	UpstreamHTTPClient *http.Client

	// MalwareTestOverrides is the raw comma-separated value of
	// CHAINSAW_TEST_MALWARE_OVERRIDES (or its YAML mirror) resolved by
	// the caller. TEST-ONLY: injects synthetic (ecosystem, package,
	// version) → malware-id tuples into MalwareIndex so QA can
	// live-fire the malware-feed → dispatchOrgWebhooks code path on
	// chain305.com against any still-available package. Real OSV hits
	// take precedence inside Index.Lookup; this never masks a genuine
	// block. Empty (the production default) is a no-op. Bootstrap
	// emits a loud WARN at startup when non-empty so a misconfigured
	// production pod is loud, not silent. Parse errors are logged and
	// the offending entry is dropped; the rest of the list still
	// loads.
	MalwareTestOverrides string

	// EnableRepoLivenessCheck toggles the PR 11 repo-liveness enricher.
	// Nil (the zero value) is treated as "on" so existing operators get
	// the feature automatically; pass a pointer to false to disable. The
	// pointer shape matches the "feature flags" pattern used for other
	// optional syncers.
	EnableRepoLivenessCheck *bool
	// RepoLivenessCheckInterval is the TTL between re-probes of a
	// previously-classified repository. Zero falls back to
	// DefaultRepoLivenessInterval (7 days).
	RepoLivenessCheckInterval time.Duration

	// OnPopularBootstrapComplete fires once when the initial
	// popular-package bootstrap loop has iterated every
	// EcosystemsWithTyposquatRisk() entry — successful fetches loaded,
	// failed fetches logged-and-skipped. Invoked from the bootstrap
	// goroutine after the for-loop returns, regardless of how many
	// ecosystems succeeded; the typosquat detector degrades to "skip"
	// for any ecosystem whose tree never loaded, so partial success is
	// still serving traffic correctly. Used by the /readyz dataset-load
	// barrier in the server package. nil is a no-op.
	OnPopularBootstrapComplete func()
}

// Components holds all initialized supply chain components.
//
// Phase D retired the Orchestrator field: the sync check + async
// enrichment pipeline now lives inside internal/intelligence. The
// components here are the raw sources (malware index, typosquat
// detector, provenance checker, repo-liveness probe) that both the
// intelligence service and any remaining legacy caller depend on.
type Components struct {
	TyposquatDetector *typosquat.Detector
	TyposquatFetcher  *typosquat.Fetcher
	MalwareIndex      *malware.Index
	MalwareSyncer     *malware.Syncer
	// DockerMalwareSyncer maintains the Docker-image malware corpus
	// (digest + name+tag paths) on the shared MalwareIndex. nil when
	// EnableDockerMalware is explicitly disabled.
	DockerMalwareSyncer *malware.DockerSyncer
	// HuggingFaceMalwareSyncer maintains the HuggingFace coordinate
	// malware corpus on the shared MalwareIndex. nil when
	// EnableHuggingFaceMalware is explicitly disabled. Mirrors the
	// DockerMalwareSyncer lifecycle.
	HuggingFaceMalwareSyncer *malware.HuggingFaceSyncer
	ProvenanceChecker        *provenance.Checker
	// RepoLiveness classifies source-repository URLs. Retained here
	// because the checker is reused by intelligence providers and by
	// tests that target it directly.
	RepoLiveness *RepoLivenessChecker
}

// Bootstrap initializes all supply chain components and starts background
// goroutines for data syncing. Call this after the server is listening.
func Bootstrap(ctx context.Context, cfg BootstrapConfig) *Components {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.PopularPackageLimit <= 0 {
		cfg.PopularPackageLimit = 5000
	}
	if cfg.MalwareSyncInterval <= 0 {
		cfg.MalwareSyncInterval = malware.DefaultSyncInterval
	}

	logger.Info("initializing supply chain integrity system")

	// Initialize components.
	detector := typosquat.NewDetector(logger)
	var fetcherOpts []typosquat.FetcherOption
	if cfg.UpstreamHTTPClient != nil {
		fetcherOpts = append(fetcherOpts, typosquat.WithHTTPClient(cfg.UpstreamHTTPClient))
	}
	fetcher := typosquat.NewFetcher(logger, fetcherOpts...)
	malwareIdx := malware.NewIndex(logger)

	// TEST-ONLY: load synthetic malware-index overrides from
	// CHAINSAW_TEST_MALWARE_OVERRIDES (or its YAML mirror) so QA can
	// live-fire the malware-feed → dispatchOrgWebhooks path. Loud WARN
	// when the list is non-empty — a production pod that boots with
	// overrides set should be immediately obvious in the log
	// aggregator. Parse failure logs and proceeds with zero overrides
	// rather than failing startup, because losing the real malware
	// path to a typo in a test env var is the strictly worse outcome.
	if rawOverrides := strings.TrimSpace(cfg.MalwareTestOverrides); rawOverrides != "" {
		parsed, err := malware.ParseOverrides(rawOverrides)
		if err != nil {
			logger.Warn("MALWARE TEST OVERRIDES PARSE FAILED",
				"error", err,
				"raw", rawOverrides,
				"action", "ignoring overrides; real OSV index unaffected")
		} else if len(parsed) > 0 {
			malwareIdx.LoadOverrides(parsed)
			specs := malwareIdx.OverrideSpecs()
			logger.Warn("MALWARE TEST OVERRIDES ACTIVE",
				"count", len(specs),
				"entries", strings.Join(specs, ","),
				"warning", "must be empty in production")
		}
	}

	var syncerOpts []malware.SyncerOption
	if cfg.EnableGHSAMalware {
		syncerOpts = append(syncerOpts, malware.WithGHSAFetcher(malware.NewGHSAFetcher(logger)))
	}
	malwareSyncer := malware.NewSyncer(malwareIdx, cfg.DataDir, logger, syncerOpts...)

	// Docker malware syncer. Default-on: nil means "enabled", an
	// explicit &false disables the feed entirely. The embedded seed
	// is tiny and its load has no network cost, so the only reason to
	// flip this off is in tests that want a pristine Index.
	dockerMalwareEnabled := cfg.EnableDockerMalware == nil || *cfg.EnableDockerMalware
	var dockerSyncer *malware.DockerSyncer
	if dockerMalwareEnabled {
		var dockerOpts []malware.DockerSyncerOption
		if url := cfg.DockerMalwareFeedURL; url != "" {
			dockerOpts = append(dockerOpts, malware.WithDockerFeedURL(url))
		}
		dockerSyncer = malware.NewDockerSyncer(malwareIdx, logger, dockerOpts...)
	}

	// HuggingFace malware syncer. Default-on mirroring the Docker
	// syncer: nil means "enabled", an explicit &false disables. The
	// embedded HF seed is tiny and exists primarily for defense-in-
	// depth on coordinates whose artifacts were taken down post-
	// disclosure (e.g. baller423/goober2 from JFrog 2024).
	hfMalwareEnabled := cfg.EnableHuggingFaceMalware == nil || *cfg.EnableHuggingFaceMalware
	var hfSyncer *malware.HuggingFaceSyncer
	if hfMalwareEnabled {
		var hfOpts []malware.HuggingFaceSyncerOption
		if url := cfg.HuggingFaceMalwareFeedURL; url != "" {
			hfOpts = append(hfOpts, malware.WithHuggingFaceFeedURL(url))
		}
		hfSyncer = malware.NewHuggingFaceSyncer(malwareIdx, logger, hfOpts...)
	}

	// The APT/RPM provenance backends read their keyring path from env
	// (CHAINSAW_APT_KEYRING / CHAINSAW_RPM_KEYRING) at construction
	// time. Setting the env here lets operators configure the paths via
	// BootstrapConfig without duplicating plumbing into the provenance
	// dispatcher. We only override when the Bootstrap caller actually
	// supplied a value, so a pre-set env var still wins.
	if cfg.APTKeyringPath != "" {
		if err := os.Setenv("CHAINSAW_APT_KEYRING", cfg.APTKeyringPath); err != nil {
			logger.Warn("failed to set CHAINSAW_APT_KEYRING", "error", err)
		}
	}
	if cfg.RPMKeyringPath != "" {
		if err := os.Setenv("CHAINSAW_RPM_KEYRING", cfg.RPMKeyringPath); err != nil {
			logger.Warn("failed to set CHAINSAW_RPM_KEYRING", "error", err)
		}
	}

	provOpts := cfg.ProvenanceOptions
	if cfg.UpstreamHTTPClient != nil {
		// Prepend so an explicit caller-supplied WithHTTPClient still
		// wins if one was passed in cfg.ProvenanceOptions (unlikely,
		// but the precedence is "caller override > bootstrap default").
		provOpts = append([]provenance.CheckerOption{provenance.WithHTTPClient(cfg.UpstreamHTTPClient)}, provOpts...)
	}
	provChecker := provenance.NewChecker(logger, provOpts...)
	if cfg.SwiftRegistryURL != "" {
		provChecker.WithSwiftRegistryURL(cfg.SwiftRegistryURL)
	}
	if cfg.SwiftFullVerify {
		provChecker.WithSwiftFullVerify(cfg.SwiftTrustRoots)
	}

	// Repo liveness enricher (PR 11). Default-on per the bootstrap
	// contract; opt-out via EnableRepoLivenessCheck = &false.
	enableLiveness := true
	if cfg.EnableRepoLivenessCheck != nil {
		enableLiveness = *cfg.EnableRepoLivenessCheck
	}
	var livenessChecker *RepoLivenessChecker
	if enableLiveness {
		livenessChecker = NewRepoLivenessChecker(nil, logger)
	}
	livenessInterval := cfg.RepoLivenessCheckInterval
	if livenessInterval <= 0 {
		livenessInterval = DefaultRepoLivenessInterval
	}

	// livenessInterval is captured below for future wiring into the
	// intelligence service's enrichment loop (Phase E repo-liveness
	// migration). The orchestrator that previously consumed it was
	// retired in Phase D.
	_ = livenessInterval

	comp := &Components{
		TyposquatDetector:        detector,
		TyposquatFetcher:         fetcher,
		MalwareIndex:             malwareIdx,
		MalwareSyncer:            malwareSyncer,
		DockerMalwareSyncer:      dockerSyncer,
		HuggingFaceMalwareSyncer: hfSyncer,
		ProvenanceChecker:        provChecker,
		RepoLiveness:             livenessChecker,
	}

	// 0. Docker malware feed bootstrap + refresh loop. Runs before the
	// popular-package fetch because the embedded seed is always
	// available synchronously — starting the loop here keeps the
	// refresh cadence aligned with the OSV feed (6h) without coupling
	// the two lifecycles.
	if dockerSyncer != nil {
		go func() {
			bootstrapCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			if err := dockerSyncer.Bootstrap(bootstrapCtx); err != nil {
				logger.Warn("docker malware bootstrap failed; feed will retry on next tick",
					"error", err)
			}
			dockerSyncer.RunSyncLoop(ctx, cfg.MalwareSyncInterval)
		}()
	}

	// 0b. HuggingFace malware feed bootstrap + refresh loop. Same
	// shape as the Docker syncer (sibling pattern) — embedded seed
	// loads synchronously inside the goroutine, then the loop ticks
	// on cfg.MalwareSyncInterval. Independent of the Docker loop so
	// either can refresh without coupling.
	if hfSyncer != nil {
		go func() {
			bootstrapCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			if err := hfSyncer.Bootstrap(bootstrapCtx); err != nil {
				logger.Warn("huggingface malware bootstrap failed; feed will retry on next tick",
					"error", err)
			}
			hfSyncer.RunSyncLoop(ctx, cfg.MalwareSyncInterval)
		}()
	}

	// Start background bootstrap goroutines (non-blocking).

	// 1. Popular package index fetch.
	//
	// A small randomised pre-delay (0..popularBootstrapJitterMax) spreads
	// the initial burst when N replicas of chainsaw-proxy start in the
	// same second — otherwise each one sends the same ~20 HTTPS calls to
	// registry.npmjs.org at t=0 and shares a single per-IP rate-limit
	// budget. On a single-instance deploy the delay is wasted idle time
	// but costs nothing else.
	//
	// Wave P perf: this loop is the dominant cold-start cost (7m44s
	// observed in Wave O when network-bound) but is NOT a /readyz gate
	// — the pod serves traffic with typosquat detection degraded
	// ("skip" in Check) during the warm-up window. See
	// docs/runbooks/cold-start.md.
	go func() {
		bootstrapCtx, cancel := context.WithTimeout(ctx, 10*time.Minute+popularBootstrapJitterMax)
		defer cancel()

		jitter := time.Duration(rand.Int63n(int64(popularBootstrapJitterMax)))
		if jitter > 0 {
			logger.Info("popular package index bootstrap deferred",
				"jitter", jitter)
			select {
			case <-bootstrapCtx.Done():
				return
			case <-time.After(jitter):
			}
		}

		warmStart := time.Now()
		logger.Info("popular package index warm-up started; typosquat detection degraded until complete",
			"ecosystems", len(typosquat.EcosystemsWithTyposquatRisk()))
		for _, ecosystem := range typosquat.EcosystemsWithTyposquatRisk() {
			select {
			case <-bootstrapCtx.Done():
				return
			default:
			}
			pkgs, err := fetcher.FetchPopularPackages(bootstrapCtx, ecosystem, cfg.PopularPackageLimit)
			if err != nil {
				logger.Warn("failed to fetch popular packages",
					"ecosystem", ecosystem, "error", err)
				continue
			}
			if len(pkgs) > 0 {
				detector.LoadEcosystem(ecosystem, pkgs)
			}
		}
		logger.Info("popular package index bootstrap complete",
			"warm_up_duration", time.Since(warmStart))
		// Observability flag — flips /readyz body's warming.typosquat
		// off. Runs even when a subset of ecosystems failed (logged Warn
		// above); per-ecosystem misses degrade to "skip" in Check, so
		// the pod is genuinely ready to serve. NOT a /readyz 200 gate
		// (see internal/server/server_lifecycle.go datasetsReady).
		if cfg.OnPopularBootstrapComplete != nil {
			cfg.OnPopularBootstrapComplete()
		}
	}()

	// 2. Weekly popular package refresh, with ±6h jitter per iteration
	// so co-located replicas don't all refresh in lockstep. We use a
	// recomputed time.Timer rather than a fixed-interval time.Ticker
	// because the ticker would hold a constant period regardless of how
	// long each refresh pass took.
	go func() {
		for {
			jitter := time.Duration(rand.Int63n(int64(popularRefreshJitter))) - popularRefreshJitter/2
			next := popularRefreshBase + jitter
			timer := time.NewTimer(next)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				refreshPopularPackages(ctx, fetcher, detector, cfg.PopularPackageLimit, logger)
			}
		}
	}()

	// TODO(pr-9-followup): wire a 10-minute ticker that recomputes
	// package_metadata.publish_velocity_24h for packages updated in the
	// last 24h. PR 9 (publishVelocityAnomaly) ships with only the live
	// sync-query path used by the evaluator; the cached counter is
	// persisted inline via PersistSyncResults so the UI/BOM views
	// stay roughly-current without a dedicated refresh loop. The ticker
	// is worth adding once tenants with long-tail inactive packages
	// complain about stale counters.

	return comp
}

func refreshPopularPackages(ctx context.Context, fetcher *typosquat.Fetcher, detector *typosquat.Detector, limit int, logger *slog.Logger) {
	refreshCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	for _, ecosystem := range typosquat.EcosystemsWithTyposquatRisk() {
		select {
		case <-refreshCtx.Done():
			return
		default:
		}
		pkgs, err := fetcher.FetchPopularPackages(refreshCtx, ecosystem, limit)
		if err != nil {
			logger.Warn("failed to refresh popular packages",
				"ecosystem", ecosystem, "error", err)
			continue
		}
		if len(pkgs) > 0 {
			detector.LoadEcosystem(ecosystem, pkgs)
		}
	}
	logger.Info("popular package index refresh complete")
}
