package intelligence

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/chain305/chainsaw-core/intelligence/osv"
	"github.com/chain305/chainsaw-core/kev"
	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/metadata"
	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/provenance"
	"github.com/chain305/chainsaw-core/supplychain"
	"github.com/chain305/chainsaw-core/typosquat"
	"github.com/chain305/chainsaw-core/xreplicaflight"
)

// BootstrapConfig wires the Service and its providers in a single call.
// Each dependency is optional: nil values degrade the corresponding
// provider rather than fail the construction. This lets tests and
// single-tenant deployments opt into only the pieces they need.
type BootstrapConfig struct {
	// DB is the shared postgres store. Nil disables persistence — Scan
	// still works but no rows are written and Get always returns
	// ErrNotFound.
	DB *pgstore.Store

	// MetadataStore is the persisted-metadata read path. Shared with
	// the rest of the server. Nil disables providers that depend on
	// historical version rows (metadiff, publishvelocity, cve).
	MetadataStore *metadata.Store

	// MalwareIndex is the malware lookup source shared with
	// supplychain.Components. Nil disables the malware provider.
	MalwareIndex *malware.Index

	// TyposquatDetector is the BK-tree + reorder matcher shared with
	// supplychain.Components. Nil disables the typosquat provider.
	TyposquatDetector *typosquat.Detector

	// ProvenanceChecker verifies per-ecosystem provenance. Nil
	// disables the provenance provider.
	ProvenanceChecker *provenance.Checker

	// KEVIndex is the CISA Known Exploited Vulnerabilities catalog.
	// Nil disables the KEV cross-reference provider — the risk
	// engine's vuln-kev signal stays dormant in that case.
	KEVIndex *kev.Index

	// RepoLiveness classifies source-repository URLs into ok / archived
	// / missing / ownership_mismatch / unknown. Nil disables the probe;
	// the maintenance enricher then degrades to its pre-probe behaviour
	// (passing through whatever earlier providers wrote into
	// SupplyChain.RepoLink* fields).
	RepoLiveness *supplychain.RepoLivenessChecker

	// Logger routes provider diagnostics.
	Logger *slog.Logger

	// FeatureMode toggles shadow / on / off. The CLI / env passes one
	// of: "" (default) -> Mode from env var; "off" -> NoopService;
	// "on" -> DefaultService with full provider set; "shadow" is
	// reserved for future Phase B/C plumbing.
	FeatureMode string

	// OnOSVLoaded fires once when the OSV bundle index is live — either
	// because newOSVProvider succeeded at boot, or after the first
	// runtime hot-swap. Invoked exactly once; subsequent loads are
	// silent. Used by the /readyz dataset-load barrier in the server
	// package; nil callback is a no-op so non-server callers (tests,
	// CLI tooling) don't need to wire anything.
	OnOSVLoaded func()
}

// Mode is the parsed feature-flag state.
//
// Phase-D retirement of internal/supplychain/orchestrator.go is
// intentionally deferred: the orchestrator still owns the in-flight
// decision path (CheckSync, PersistSyncResults, EnrichAsync) and carries
// a bounded-concurrency semaphore plus graceful-drain WaitGroup that
// must soak before removal. Once operators have run `on` (or `shadow`)
// for a release cycle and the `intelligence_reports` rows agree with
// orchestrator CheckResult output on every live signal, the retirement
// lands in a single commit that: (a) deletes orchestrator.go, (b)
// removes this Mode type, (c) reduces the proxy pipeline's supply-chain
// block to a single intel.Scan call.
type Mode string

const (
	// ModeOff installs a NoopService. Admin API still responds but with
	// empty results; proxy pipeline does not call Scan on the hot path.
	ModeOff Mode = "off"
	// ModeShadow runs the DefaultService in parallel with the legacy
	// orchestrator for output comparison. Reserved for Phase B/C wiring
	// in server_repo_pipeline.go. At the Service layer, shadow behaves
	// identically to ModeOn.
	ModeShadow Mode = "shadow"
	// ModeOn uses the DefaultService as the primary path.
	ModeOn Mode = "on"
)

// ResolveMode reads CHAINSAW_INTELLIGENCE_SERVICE with a ModeOff default.
// Unrecognised values also fall back to ModeOff so a typo can't
// accidentally activate the service.
func ResolveMode(override string) Mode {
	v := strings.ToLower(strings.TrimSpace(override))
	if v == "" {
		v = strings.ToLower(strings.TrimSpace(os.Getenv("CHAINSAW_INTELLIGENCE_SERVICE")))
	}
	switch v {
	case "on", "enable", "enabled", "true", "1":
		return ModeOn
	case "shadow":
		return ModeShadow
	default:
		return ModeOff
	}
}

// Bootstrap constructs a Service. Phase D removed the shadow/off
// toggle: the service is always the primary decision path. The Mode
// helpers and CHAINSAW_INTELLIGENCE_SERVICE env var are retained only
// to keep older operator scripts parsing cleanly; they have no effect.
func Bootstrap(cfg BootstrapConfig) Service {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	store := NewStore(cfg.DB)
	providers := buildProviders(cfg)
	svc := New(Config{
		Store:     store,
		Providers: providers,
		Logger:    logger,
	})

	// Wire the OSV runtime refresher. Runs every 6h by default (matches
	// the Trivy DB OCI updater and the EPSS / typosquat refreshers).
	// Disabled when CHAINSAW_OFFLINE=1 OR
	// CHAINSAW_OSV_REFRESH_INTERVAL is the kill-switch value
	// (0/off/disabled/false). Override the cadence via the same env
	// var with a Go duration string ("12h") or bare seconds ("21600").
	// NewRefresher returns nil for the dormant cases so Start becomes
	// a no-op. We thread context.Background here because the Service
	// has no per-request lifecycle and the goroutine is expected to
	// live for the pod's lifetime; pod shutdown via SIGTERM tears the
	// process down which terminates the loop naturally.
	startOSVRefresher(providers, logger)

	// /readyz dataset-load barrier — attach the readiness callback to the
	// registered osvProvider so /readyz flips its osv sub-flag the first
	// time the bundle index is live (either the synchronous LoadFile in
	// newOSVProvider, or the first runtime hot-swap if the bundle wasn't
	// on disk at boot). Callback is nil-safe so non-server callers don't
	// have to wire anything.
	if cfg.OnOSVLoaded != nil {
		for _, prov := range providers {
			if op, ok := prov.(*osvProvider); ok {
				op.setOnLoad(cfg.OnOSVLoaded)
				break
			}
		}
	}

	// Cross-replica singleflight: feature-flagged OFF by default. When
	// CHAINSAW_XREPLICA_SINGLEFLIGHT=true AND a writable *sql.DB is
	// available, swap the NoopFlight default for a PGFlight that
	// coalesces concurrent Scan calls across every replica sharing the
	// same DB. See internal/xreplicaflight for the protocol.
	if xreplicaflight.Enabled() && cfg.DB != nil && cfg.DB.DB() != nil {
		svc.SetFlight(xreplicaflight.NewPG(cfg.DB.DB(), logger))
		logger.Info("cross-replica singleflight enabled", "env", xreplicaflight.EnvFlag)
	} else {
		logger.Info("cross-replica singleflight disabled", "env", xreplicaflight.EnvFlag)
	}
	return svc
}

// buildProviders assembles the provider list from the wired dependencies.
//
// Behaviour is identical to the historical hand-written body: same
// providers, same order, same nil-dependency / env gating. The sequence
// and per-provider gating now live in registry_providers.go as ordered
// RegisterProvider calls; this function just materialises that registry
// against cfg. See registry.go for the seam's contract and the open-core
// rationale.
//
// Each registration's factory is nil-checked at materialisation time, so
// partial bootstraps (tests, egress-restricted deployments) still degrade
// gracefully instead of panicking — a factory that returns nil is skipped
// order-preservingly, exactly as the old `if cfg.X != nil` guards did.
//
// Trust score is a post-merge helper, NOT a provider. The Scanner calls
// ComputeTrustScore(report) after the fan-out converges.
func buildProviders(cfg BootstrapConfig) []Provider {
	return buildRegisteredProviders(cfg)
}

// startOSVRefresher locates the registered osvProvider in the provider
// list and wires the runtime refresher against it. The refresher reads
// CHAINSAW_OSV_REFRESH_INTERVAL / CHAINSAW_OFFLINE internally and
// returns nil when either disables the loop, so this function is
// always-safe to call: nothing happens unless the operator opted in.
//
// We thread context.Background here because the goroutine's natural
// lifetime is the pod's. SIGTERM tears the process down and the loop
// exits with it. If a future graceful-drain path needs explicit
// cancellation, plumb a Service-owned context through here.
func startOSVRefresher(providers []Provider, logger *slog.Logger) {
	var p *osvProvider
	for _, prov := range providers {
		if op, ok := prov.(*osvProvider); ok {
			p = op
			break
		}
	}
	if p == nil {
		return
	}
	path := p.BundlePath()
	if path == "" {
		return
	}
	r := osv.NewRefresher(osv.RefresherConfig{
		Path:   path,
		Logger: logger,
		Swap:   p.SwapIndex,
	})
	if r == nil {
		return
	}
	r.Start(context.Background())
}
