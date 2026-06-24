package intelligence

import (
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/intelligence/artifactmap"
)

// SignalMask is a bitmask of the Report sections / supply-chain signals a
// caller wants the Scan pipeline to populate. The zero value (0) is treated
// as SignalAll so the simplest call site — Service.Scan(ctx, Request{Key: ...}) —
// gets the full Report.
type SignalMask uint64

// Individual signal bits. Providers consult these to decide whether to run.
const (
	SignalRegistryMetadata SignalMask = 1 << iota
	SignalProvenance
	SignalMalware
	SignalTyposquat
	SignalCVE
	SignalInstallScripts
	SignalHiddenUnicode
	SignalChecksum
	SignalPublisherChanged
	SignalVersionAnomaly
	SignalPublishVelocity
	SignalReservedNamespaces
	SignalRepoLiveness
	SignalTrustScore
	SignalLatestVersion
	// SignalKEV activates the CISA KEV cross-reference on the merged
	// CVE list. Post-merge (Tier 3) provider.
	SignalKEV
	// SignalMaintenance activates the maintenance enricher that
	// populates Report.Maintenance from data other providers already
	// fetched. Post-merge (Tier 3) provider.
	SignalMaintenance

	// Socket-gap Wave 1 (see SOCKET_GAP_IMPLEMENTATION_PLAN.md §10).
	SignalShrinkwrap
	SignalManifestConfusion

	// Socket-gap Wave 3 — Tier-2 source-code scanners. All nine ride
	// the Wave-0 shared ArtifactFileMap so archive decompression is
	// paid once regardless of how many of these run.
	SignalUsesEval
	SignalNetworkAccess
	SignalShellAccess
	SignalFilesystemAccess
	SignalEnvVarAccess
	SignalNativeBinary
	SignalHighEntropyStrings
	SignalURLStrings
	SignalMinifiedCode

	// Socket-gap Wave 4. The first two ride the shared artifact map;
	// the last three gate network RTTs through internal/upstreamhttp
	// and are feature-flagged OFF by default.
	SignalTrivialPackage
	SignalTooManyFiles
	SignalNonExistentAuthor
	SignalFirstTimeCollaborator
	SignalSuspiciousRepoStars
	// SignalMaintainerAccountAge populates MaintainerAccountAgeDays
	// on ArtifactScanSection. Feature-flagged off by default through
	// CHAINSAW_WAVE4_MAINTAINER_AGE_<ECO>=1, mirroring the other
	// Wave-4 RTT signals.
	SignalMaintainerAccountAge

	// AI artifact signals. SignalPickleScan walks pickle/torch/checkpoint
	// files for dangerous opcodes (HuggingFace primary). SignalModelCard
	// scans README.md / config.json for prompt-injection markers.
	// SignalAgentTool scans manifests across host ecosystems (npm, pypi)
	// for MCP server declarations and dangerous tool capabilities.
	SignalPickleScan
	SignalModelCard
	SignalAgentTool

	// Gap 2: per-package capability grading (CHAINSAW_CAPABILITY_SCAN=1).
	// Tier 2 — extracts the npm tgz to a temp dir and runs
	// capability.Analyze + risk.DetectMinified. Gated behind the env var
	// so the default Scan path is unchanged.
	SignalCapability

	// Gap 4b: weekly-download-count fetcher for npm and PyPI.
	// Tier 1 (no artifact needed). Air-gap fail-open: skipped when
	// CHAINSAW_OFFLINE=1; on fetch error sets sentinel -1 → SevUnknown.
	SignalWeeklyDownloads
)

// SignalAll activates every provider the service knows about. Callers who
// don't care to be selective should leave Options.Signals at zero.
const SignalAll SignalMask = 0xFFFFFFFFFFFFFFFF

// Has reports whether the mask includes the given bit. SignalAll (sentinel
// zero on the wire) is treated as "everything".
func (m SignalMask) Has(bit SignalMask) bool {
	if m == 0 {
		return true
	}
	return m&bit != 0
}

// Request is the argument to Service.Scan. Only Key is required.
type Request struct {
	Key         Key
	OrgID       string
	RepoName    string          // chainsaw proxy repo name (not the source repo)
	UpstreamURL string          // preserves the gradle→maven override + swift registry config
	Artifact    *ArtifactHandle // nil when the caller has no artifact bytes (scheduled refresh, CLI)
	Options     Options

	// RegistryMetadataBytes is the raw registry JSON the proxy already
	// fetched for this package (e.g. npm /<pkg> document). Set by
	// callers that have it — the ManifestConfusion provider reads it
	// to compare against the tarball's package.json. Nil means "not
	// provided" and the provider degrades to a no-op, keeping the
	// contract zero-network.
	RegistryMetadataBytes []byte

	// ArtifactSubtype mirrors common.PackageCoordinate.Subtype. Empty
	// for traditional ecosystems. Set by the proxy hot path when the
	// resolver emits a subtype-tagged coordinate (HuggingFace
	// model/dataset/space). The scanner stamps this onto the Report's
	// IdentitySection so AI-artifact providers can vary behaviour.
	ArtifactSubtype string
}

// ArtifactHandle gives Tier 2 providers (install scripts, hidden unicode,
// checksum extraction) access to the bytes without pulling them into the
// Request value directly for small artifacts.
type ArtifactHandle struct {
	// Bytes is set for small inline artifacts (the proxy hot path wraps
	// its response body here). Empty when Path is set instead.
	Bytes []byte
	// Path is set when the caller has already spooled the artifact to
	// disk (blobstore cache) and wants to avoid copying.
	Path string
	// SHA256 is the caller-declared hash. Providers compare this to
	// prior-persisted scans to decide whether a cached Tier-2 section is
	// still valid.
	SHA256 string
	// MediaType is the registry-advertised content type ("application/zip"
	// / "application/x-tar" / etc.) used by the extractor to pick the
	// right archive reader.
	MediaType string

	// mapOnce + mapResult lazily cache a single decompressed walk of
	// Bytes so every Tier-2 provider on the same Scan shares the work.
	// See artifactmap.Build. Unexported: callers go through
	// SharedArtifactMap below. Safe under Scan's fan-out concurrency —
	// sync.Once serializes the first build and all other providers see
	// the cached result.
	mapOnce   sync.Once
	mapResult artifactmap.Result
}

// SharedArtifactMap returns the lazily-built artifact file map for this
// handle, consolidating the per-Scan archive walk across every Tier-2
// provider. The first caller pays the decompression cost; subsequent
// callers return the cached map in O(1). Returns a zero Result when the
// handle is nil or carries no bytes.
//
// The orchestrator (Scan) does NOT need to prime this map — providers
// read it lazily. This keeps the contract simple and guarantees
// backwards compatibility for narrow test paths that construct a
// provider directly without a Service.
func (h *ArtifactHandle) SharedArtifactMap() artifactmap.Result {
	if h == nil || len(h.Bytes) == 0 {
		return artifactmap.Result{Files: artifactmap.ArtifactFileMap{}}
	}
	h.mapOnce.Do(func() {
		h.mapResult = artifactmap.Build(h.Bytes, artifactmap.Options{})
	})
	return h.mapResult
}

// Options control cache behaviour, deadline, and the signal shape.
type Options struct {
	// Signals selects which providers run. Zero means SignalAll.
	Signals SignalMask
	// SkipSignals is subtracted from the effective mask — lets a caller
	// say "everything except install scripts" without enumerating the
	// rest.
	SkipSignals SignalMask
	// MaxStaleness bounds how old a cached Report can be and still be
	// returned. Zero falls back to DefaultMaxStaleness (24h).
	MaxStaleness time.Duration
	// AllowStale, when true, returns a cached Report even if
	// fresh_until < now and kicks off an async refresh in the background
	// (stale-while-revalidate). Inline proxy should usually set this to
	// false; admin UI and scheduled refresh should set it true.
	AllowStale bool
	// Deadline is the hard upper bound on the whole Scan. Zero falls
	// back to DefaultDeadline (15s).
	Deadline time.Duration
	// RefreshReason tags the Scan for observability — "proxy" | "ui" |
	// "api" | "scheduled". Surfaces on Observation.RefreshReason.
	RefreshReason string

	// Ephemeral makes the Scan compute-only: every provider still runs and
	// the full Report is returned, but the result is NEVER written back to
	// the shared, coordinate-keyed intelligence_reports cache (no
	// store.Upsert, no reportSink denormalisation) AND the cache-first read
	// is skipped so the scan always reflects THESE bytes rather than a row
	// another tenant/the proxy authored.
	//
	// This is the isolation switch for the direct artifact-upload API: an
	// uploaded artifact declares a client-asserted coordinate (or the
	// generic:<sha256> fallback), and that coordinate must NEVER be allowed
	// to overwrite the authoritative proxy/registry-keyed report the rest of
	// the system reads. Cross-tenant cache poisoning is the threat; Ephemeral
	// closes it by making the artifact scan a pure read of the uploaded bytes
	// with no shared-state side effect.
	Ephemeral bool

	// MaxTier caps how far the tiered fan-out runs. 0 (the default)
	// means "no cap — run every tier the registered providers expose".
	// MaxTier=1 runs only Tier-1 providers from the parallel phase-1
	// pool, MaxTier=2 runs Tier-1 + Tier-2 (the full phase-1 pool),
	// MaxTier=N>=3 also runs post-merge tiers up to and including
	// Tier-N. The tiered POST /api/intelligence/.../scan endpoint uses
	// MaxTier=2 to return a usable partial report inside the request
	// deadline while a background goroutine runs the unbounded Scan to
	// fill in higher tiers. Reports computed under a non-zero MaxTier
	// have Observation.Partial=true so consumers can poll for the
	// fully-populated row.
	MaxTier int
}

// DefaultMaxStaleness is the 24h cache TTL per the plan.
const DefaultMaxStaleness = 24 * time.Hour

// DefaultDeadline caps a Scan call. Exceeding it does not error — the
// partial Report is returned with timeout warnings on the providers that
// did not finish.
const DefaultDeadline = 15 * time.Second

// DefaultProviderTimeout is the per-provider context timeout inside the
// Scan fan-out. Specific providers override this (CVE 8s, metadata 10s).
const DefaultProviderTimeout = 3 * time.Second

// SearchQuery powers Service.Search for the admin UI list view.
//
// Filter semantics: every filter is ANDed. Leaving a filter empty (zero
// value) means "do not restrict on this axis". Q is the free-text
// substring filter — it matches against package name, version, and
// ecosystem simultaneously so operators can paste a coordinate like
// "lodash@4.17.21" or a bare name "lodash" and find relevant rows.
type SearchQuery struct {
	OrgID         string
	Q             string // free-text — matches name, version, or ecosystem substring
	Ecosystem     string // empty = any
	OnlyMalicious bool
	OnlyTyposquat bool
	OnlyHasCVE    bool
	// OnlyHasWarnings narrows to reports whose providers logged at least
	// one Warning. Useful when triaging scans that degraded (timeout,
	// breaker_open, upstream_5xx) so an operator can see which packages
	// are partially analyzed.
	OnlyHasWarnings bool
	// OnlyArtifactScan narrows to reports whose Tier-2 providers ran —
	// i.e. we have install-script and hidden-unicode results, not just
	// metadata.
	OnlyArtifactScan bool
	MinTrustScore    *int
	MaxTrustScore    *int
	SinceScannedAt   *time.Time
	Limit            int // default 50, max 500
	// Sort controls ordering. Supported values: "recent" (default,
	// collected_at DESC), "trust_asc" (low trust first — surfaces risk),
	// "trust_desc", "cvss_desc", "name".
	Sort string
	// Cursor implements keyset pagination. Empty = first page; otherwise
	// an opaque value returned by a prior call's NextCursor.
	Cursor string
}

// FacetCounts returns the aggregate counts used by the Shodan-style
// sidebar in the admin UI. One request pulls every cell the filter bar
// needs — ecosystem breakdown, signal toggle counts, risk tiers.
type FacetCounts struct {
	Total        int           `json:"total"`
	Ecosystems   []FacetBucket `json:"ecosystems"`
	Malicious    int           `json:"malicious"`
	Typosquat    int           `json:"typosquat"`
	HasCVE       int           `json:"hasCve"`
	HasWarnings  int           `json:"hasWarnings"`
	ArtifactScan int           `json:"artifactScan"`
	TrustBuckets []FacetBucket `json:"trustBuckets"` // low (<40), medium (40-70), high (70-100)
	Last24h      int           `json:"last24h"`
}

// FacetBucket is one labeled cell in a facet list — label + count.
type FacetBucket struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// SearchResults is the response shape for the admin list view.
type SearchResults struct {
	Rows       []SearchRow `json:"rows"`
	NextCursor string      `json:"nextCursor,omitempty"`
}

// SearchRow is the flattened per-row payload the list view needs. The
// full Report is fetched on the inspect page, not in the list.
type SearchRow struct {
	Ecosystem       string    `json:"ecosystem"`
	Package         string    `json:"package"`
	Version         string    `json:"version"`
	CollectedAt     time.Time `json:"collectedAt"`
	FreshUntil      time.Time `json:"freshUntil"`
	TrustScore      int       `json:"trustScore,omitempty"`
	MaxCVSS         float64   `json:"maxCvss,omitempty"`
	IsMalicious     bool      `json:"isMalicious,omitempty"`
	IsTyposquat     bool      `json:"isTyposquat,omitempty"`
	HasArtifactScan bool      `json:"hasArtifactScan,omitempty"`
	WarningCount    int       `json:"warningCount,omitempty"`
	// V2 risk-engine verdict. Empty string when the evaluation
	// short-circuited — callers treat empty as "not evaluated" and fall
	// back to the trust-score/signal-chip heuristics.
	Verdict string `json:"verdict,omitempty"`
	// Rolled-up overall score (0-100) from the v2 evaluation. Pointer so
	// a true zero score is distinguishable from "not evaluated".
	OverallScore *int `json:"overallScore,omitempty"`
}

// ChecksumRequest is the input to Service.VerifyChecksum — the fail-closed
// fast path reused by the proxy's checksum enforcer.
type ChecksumRequest struct {
	Key      Key
	OrgID    string
	Declared string
	Actual   string
}

// ChecksumVerdict is the hot-path result shape.
type ChecksumVerdict struct {
	Matched bool
	Status  string // matched|mismatch|unavailable
	Reason  string
}
