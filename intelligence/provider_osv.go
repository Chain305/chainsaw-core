package intelligence

// provider_osv.go — the offline OSV.dev CVE provider.
//
// Why this exists alongside the Trivy-backed cveProvider: the Trivy DB
// is great when the OCI updater can keep it fresh, but in airgapped or
// first-boot scenarios the DB can be empty / stale. OSV ships as
// structured JSON and we bake a pre-processed snapshot into the image
// the same way trivy.db is baked today. Both providers register on the
// SignalCVE bit and write into VulnSection — mergePartial does a
// wholesale replace (last write wins), so the merge order across
// Tier-1 fan-out is non-deterministic. That's acceptable: the
// CVEs []string the projection consumes tolerates duplicates, and any
// version observed by either provider is reported.
//
// Bundle path resolution:
//   1. CHAINSAW_OSV_BUNDLE_PATH env var (operator override).
//   2. /system/osv-bundle.json.gz (the path the Dockerfile bakes to —
//      /system is image-resident; /data is the PVC mount in prod and
//      hides anything COPYd there at runtime).
//
// Missing or unreadable bundle → the provider stays dormant. Its
// Supports() still returns true for covered ecosystems (so the matrix
// stays honest) but Run() returns an empty PartialReport — no Vulns,
// no warnings. The boot path logs the missing-bundle state once via
// logOSVBundleStateOnce.

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/intelligence/osv"
)

// OSVBundleEnvVar lets operators override the bundle path. Defaults to
// the in-image location the Dockerfile bakes to.
const OSVBundleEnvVar = "CHAINSAW_OSV_BUNDLE_PATH"

// DefaultOSVBundlePath is the in-image path where dockerized/Dockerfile
// COPYs the bundle. Kept on /system (not /data) because /data is a PVC
// mount in production — anything baked to /data is masked at runtime.
// Operators can override via CHAINSAW_OSV_BUNDLE_PATH.
const DefaultOSVBundlePath = "/system/osv-bundle.json.gz"

// osvProvider surfaces OSV.dev advisory hits into VulnSection. The
// underlying index is loaded once at construction time and shared
// across every Run call.
//
// idxMu guards the idx pointer so the runtime refresher
// (internal/intelligence/osv.Refresher) can hot-swap a freshly
// downloaded bundle without racing the read-heavy Run path. Run takes
// only an RLock for a single pointer load — overhead is in the
// nanoseconds and never blocks unless a refresher swap is in flight.
type osvProvider struct {
	idxMu  sync.RWMutex
	idx    *osv.Index
	path   string
	logger *slog.Logger
	logOK  sync.Once

	// onLoad fires the first time an index becomes live (either initial
	// LoadFile in newOSVProvider or the first SwapIndex). Subsequent
	// loads are silent — sync.Once gates it. Wired by Bootstrap from
	// BootstrapConfig.OnOSVLoaded so the server's /readyz dataset-load
	// barrier flips its osv sub-flag when the bundle is live.
	onLoad     func()
	onLoadOnce sync.Once
}

// setOnLoad installs the readiness callback. Idempotent — last writer
// wins, but in practice Bootstrap only calls this once.
func (p *osvProvider) setOnLoad(cb func()) {
	if p == nil || cb == nil {
		return
	}
	p.idxMu.Lock()
	p.onLoad = cb
	idxAlreadyLoaded := p.idx != nil
	p.idxMu.Unlock()
	// Bundle loaded synchronously in newOSVProvider before the callback
	// got attached — fire the one-shot now so a successful boot-time
	// load isn't missed.
	if idxAlreadyLoaded {
		p.fireOnLoad()
	}
}

func (p *osvProvider) fireOnLoad() {
	if p == nil {
		return
	}
	p.onLoadOnce.Do(func() {
		if p.onLoad != nil {
			p.onLoad()
		}
	})
}

// newOSVProvider loads the OSV bundle off disk (path resolved via the
// env var override or the default in-image location) and returns a
// ready-to-register provider. A missing or unreadable bundle returns
// a non-nil provider whose Run is a no-op — caller is responsible for
// logging the dormancy state, which Bootstrap does via the provider's
// IndexLoaded helper.
func newOSVProvider(logger *slog.Logger) *osvProvider {
	if logger == nil {
		logger = slog.Default()
	}
	path := strings.TrimSpace(os.Getenv(OSVBundleEnvVar))
	if path == "" {
		path = DefaultOSVBundlePath
	}
	p := &osvProvider{logger: logger, path: path}
	if _, err := os.Stat(path); err == nil {
		idx, loadErr := osv.LoadFile(path)
		if loadErr != nil {
			// Bad bundle is loud — operators almost certainly want to
			// know. We don't fail boot because the Trivy provider may
			// still cover us; staying dormant is the safer degrade.
			logger.Warn("osv: failed to load bundle", "path", path, "err", loadErr)
		} else {
			p.idx = idx
			logger.Info("osv: bundle loaded",
				"path", path,
				"advisories", idx.Total(),
				"loaded_at", idx.LoadedAt().Format(time.RFC3339))
		}
	} else {
		// Missing bundle is the common "not yet generated" state — log
		// once at info level so the boot banner is readable.
		logger.Info("osv: bundle not present, provider dormant", "path", path, "env", OSVBundleEnvVar)
	}
	return p
}

func (p *osvProvider) Name() string { return "osv" }

// Signal reuses SignalCVE so the OSV provider rides the same enable /
// skip toggle operators already wire for CVE lookups. mergePartial
// handles the case where both providers fire — wholesale-replace on
// Vulns means the Tier-1 fan-out is non-deterministic, but the
// downstream projection tolerates duplicate CVE IDs and rolls them up
// to the worst-case severity.
func (p *osvProvider) Signal() SignalMask { return SignalCVE }

func (p *osvProvider) Tier() int { return 1 }

// NeedsArtifact is false — pure in-memory lookup against the loaded bundle.
func (p *osvProvider) NeedsArtifact() bool { return false }

// supportedOSVEcosystems mirrors the ecosystems the OSV.dev dump has
// real coverage for. Caller-facing aliases (yarn / bun / pip / gradle /
// composer) are accepted because the canonicaliser folds them onto
// the OSV-native key before lookup.
var supportedOSVEcosystems = map[string]struct{}{
	"npm": {}, "yarn": {}, "bun": {},
	"pip": {}, "pypi": {},
	"maven": {}, "gradle": {},
	"cargo": {}, "crates": {}, "crates.io": {},
	"rubygems": {}, "gem": {},
	"nuget":    {},
	"composer": {}, "packagist": {},
	"go": {}, "gomod": {},
}

// Supports reports whether the OSV feed covers the given ecosystem.
// Returns true regardless of whether the bundle actually loaded — the
// matrix cell stays honest, and Run handles the dormant-index case.
func (p *osvProvider) Supports(ecosystem string) bool {
	_, ok := supportedOSVEcosystems[strings.ToLower(strings.TrimSpace(ecosystem))]
	return ok
}

// Run looks the package up in the loaded OSV index and projects any
// hits onto VulnSection.
//
// Three observable shapes:
//
//  1. Index dormant (nil) — return PartialReport{} so this provider
//     doesn't touch Vulns. The companion Trivy provider remains the
//     source of truth in that case.
//  2. Index loaded, package not covered — return PartialReport{} (do
//     NOT stamp a clean Vulns section; "we don't have data" is
//     distinct from "we scanned and found nothing").
//  3. Index loaded, package covered — return a non-nil VulnSection
//     populated from the matching advisories. When the version is
//     clean (no advisories match), VulnSection is non-nil but
//     IsVulnerable=false / CVEs empty, so policy "we scanned, clean"
//     logic fires correctly.
func (p *osvProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	p.idxMu.RLock()
	idx := p.idx
	p.idxMu.RUnlock()
	if idx == nil {
		return PartialReport{}, nil
	}
	eco := req.Key.Ecosystem
	pkg := req.Key.Package
	ver := req.Key.Version

	if !idx.HasPackage(eco, pkg) {
		// Bundle doesn't cover this package at all — say nothing,
		// leave Trivy to speak. Distinct from the "covered + clean"
		// case below.
		return PartialReport{}, nil
	}

	hits := idx.Lookup(eco, pkg, ver)
	scannedAt := idx.LoadedAt()
	vuln := &VulnSection{
		ScannedAt:       &scannedAt,
		ScannerDBDigest: "osv-bundle",
	}
	if len(hits) == 0 {
		// Covered but clean. Return a non-nil empty Vulns so
		// VulnDataAvailable fires downstream — operators can tell the
		// difference between "scanned, clean" and "not scanned".
		return PartialReport{Vulns: vuln}, nil
	}

	vuln.IsVulnerable = true
	vuln.CVEs = make([]string, 0, len(hits))
	vuln.CVEDetails = make([]CVEDetail, 0, len(hits))
	var maxCVSS float64
	for _, a := range hits {
		cve := a.PreferredCVE()
		if cve == "" {
			continue
		}
		vuln.CVEs = append(vuln.CVEs, cve)
		if a.CVSSScore > maxCVSS {
			maxCVSS = a.CVSSScore
		}
		detail := CVEDetail{CVE: cve}
		if len(a.FixedVersions) > 0 {
			detail.FixedVersion = a.FixedVersions[0]
			detail.FixAvailable = true
		}
		vuln.CVEDetails = append(vuln.CVEDetails, detail)
	}
	vuln.CVSSScore = maxCVSS
	return PartialReport{Vulns: vuln}, nil
}

// IndexLoaded reports whether the underlying OSV bundle was successfully
// loaded. Exposed for diagnostics (chainsaw doctor) and for the
// bootstrap log line that announces dormant-vs-live state.
func (p *osvProvider) IndexLoaded() bool {
	if p == nil {
		return false
	}
	p.idxMu.RLock()
	defer p.idxMu.RUnlock()
	return p.idx != nil
}

// BundlePath returns the on-disk path the provider was constructed
// with. Used by the bootstrap path to wire the runtime refresher
// against the exact same file.
func (p *osvProvider) BundlePath() string {
	if p == nil {
		return ""
	}
	return p.path
}

// SwapIndex installs idx as the live read pointer. Called by the
// runtime refresher after a successful refresh. Nil idx is a no-op (we
// never want to demote a working index to nil on a transient upstream
// blip — fail-closed is enforced one level up).
func (p *osvProvider) SwapIndex(idx *osv.Index) {
	if p == nil || idx == nil {
		return
	}
	p.idxMu.Lock()
	p.idx = idx
	p.idxMu.Unlock()
	p.logger.Info("osv: bundle hot-swapped",
		"path", p.path,
		"advisories", idx.Total(),
		"loaded_at", idx.LoadedAt().Format(time.RFC3339),
	)
	// /readyz dataset-load barrier — first SwapIndex (or first
	// boot-time LoadFile completion) flips the osv sub-flag. Subsequent
	// hot-swaps are no-ops (sync.Once).
	p.fireOnLoad()
}

var _ Provider = (*osvProvider)(nil)
