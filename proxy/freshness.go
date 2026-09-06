package proxy

import (
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/storage"
)

// staleWarning is the RFC 7234 §5.5.1 warn-code served alongside a
// cached body the proxy knows may not be current.
const staleWarning = `110 chainsaw "Response is stale"`

// Results recorded on the metadata-revalidation metric.
const (
	// revalidationFresh — upstream answered 304: the cached body was
	// already current and only its CachedAt stamp was refreshed.
	revalidationFresh = "fresh"
	// revalidationChanged — upstream answered with a new body, which
	// replaced the expired entry.
	revalidationChanged = "changed"
	// revalidationStaleServed — the entry was expired but NO upstream
	// was reachable, so the expired body was served with Warning: 110.
	// This is the air-gap / DNS-blackhole path. A deployment that is
	// deliberately offline sits at 100% stale_served and never talks
	// upstream; a sustained rise anywhere else means the origin is
	// unreachable and cached metadata is drifting.
	revalidationStaleServed = "stale_served"
)

// metadataRevalidationRecorder is the observability seam, installed via
// SetMetadataRevalidationRecorder. nil is a no-op, matching
// upstreamErrorRecorder above.
var metadataRevalidationRecorder func(ecosystem, result string)

// SetMetadataRevalidationRecorder installs (or clears) the recorder that
// feeds chainsaw_proxy_metadata_revalidation_total. Called once at
// startup from cmd/chainsaw-proxy/init_server.go. Pass nil to disable.
func SetMetadataRevalidationRecorder(rec func(ecosystem, result string)) {
	metadataRevalidationRecorder = rec
}

// recordMetadataRevalidation forwards one outcome to the installed
// recorder. Safe for nil. The ecosystem label goes through the same
// allow-list as recordUpstreamError so the CounterVec stays
// cardinality-bounded.
func recordMetadataRevalidation(ecosystem, result string) {
	rec := metadataRevalidationRecorder
	if rec == nil {
		return
	}
	rec(normalizeEcosystemLabel(ecosystem), result)
}

// isMutableDocument reports whether logicalPath names a registry
// document that CHANGES at the origin, and therefore may be expired by
// the positive metadata TTL.
//
// # Why this is not the predicate from internal/server
//
// internal/server/repository_passthrough.go already draws this line
// (isPackageMetadataPath vs isPackageDownloadRequest) and reusing it
// would be preferable, but it cannot be imported: core/ is its own Go
// module (github.com/chain305/chainsaw-core) and the root module
// (github.com/chain305/chainsaw) depends on IT. Importing internal/server
// from core/proxy inverts the module direction and does not compile.
// Nor can the predicate be passed in — it takes a
// *repository.Repository, a root-module type.
//
// So the distinction is re-derived from what the facet already holds:
// the format string and the logical path — the same two inputs
// needsEncodingRepair keys on. The npm and pip arms below mirror
// isNpmMetadataPath and isPipMetadataPath deliberately; keep them in
// sync.
//
// # Why the default is false
//
// An unrecognised path is treated as IMMUTABLE. Getting that wrong in
// this direction reproduces today's behaviour (the entry is cached
// forever), which is a staleness bug. Getting it wrong in the other
// direction would expire tarballs, wheels, jars, gems and crates —
// content-addressed artifacts that never change — and turn every
// install into an upstream round trip. One is the status quo; the other
// is an outage. Formats without an arm here simply keep the old
// never-expire behaviour.
func isMutableDocument(format, logicalPath string) bool {
	path := strings.TrimSpace(strings.TrimPrefix(logicalPath, "/"))
	if path == "" {
		return false
	}
	lower := strings.ToLower(path)

	switch strings.ToLower(strings.TrimSpace(format)) {
	case "npm", "yarn", "bun":
		// The packument is everything that is not a tarball, and npm
		// tarballs are always served under a "-" path segment
		// ("lodash/-/lodash-4.17.21.tgz", or "-/..." for the registry's
		// own endpoints). Mirrors isNpmMetadataPath.
		if strings.HasPrefix(lower, "-/") || strings.Contains(lower, "/-/") {
			return false
		}
		return true

	case "pip":
		// PEP 503 index pages ("simple/", "simple/requests/") gain a
		// link every time a version is published.
		//
		// Deliberately NARROWER than isPipMetadataPath, which also
		// returns true for ".metadata": a PEP 658 sidecar describes one
		// already-published wheel, is pinned to that wheel's filename,
		// and never changes. It is metadata for routing purposes but
		// immutable for caching purposes, so it must not expire.
		if strings.HasSuffix(lower, ".metadata") {
			return false
		}
		return lower == "simple" || lower == "simple/" || strings.HasPrefix(lower, "simple/")

	default:
		return false
	}
}

// metadataExpired reports whether a cached entry has outlived the
// positive metadata TTL and should be revalidated.
//
// It does NOT decide whether the entry may be treated as a cache miss —
// that also requires a reachable upstream. See upstreamReachable.
func (f *facet) metadataExpired(logicalPath string, meta storage.ContentMetadata) bool {
	if f == nil || f.metadataTTL <= 0 {
		return false
	}
	if !isMutableDocument(f.format, logicalPath) {
		return false
	}
	// A missing CachedAt is an entry of UNKNOWN age, which in practice
	// means it predates the stamp. Treating it as expired costs one
	// conditional revalidation, after which it carries a stamp and
	// behaves normally; treating it as fresh would freeze it forever,
	// which is the bug being fixed.
	if meta.CachedAt.IsZero() {
		return true
	}
	return time.Since(meta.CachedAt) > f.metadataTTL
}

// upstreamReachable reports whether an expired entry may safely be
// downgraded to a cache MISS.
//
// # The air-gap guard
//
// An expired entry becomes a miss, and a miss enters the fetch path. On
// an air-gapped or DNS-blackholed box that fetch cannot succeed, and the
// circuit breaker does NOT catch it: RecordNetworkFailure returns early
// for DNS errors (circuitbreaker.go, "do not open the circuit on this
// alone"), so consecutiveFail never increments and the breaker never
// opens. A DNS blackhole is the classic air-gap failure mode, so the
// breaker is precisely blind to the case that matters.
//
// Today such a box, with a warm metadata cache, never talks upstream at
// all. That property is load-bearing and must survive this change. So
// expiry is gated on an upstream that is actually there:
//
//   - no BaseURL or no Client — the remote is unconfigured; there is
//     nothing to revalidate against, ever.
//   - circuit breaker OPEN — the upstream is known-down; the fetch path
//     would only queue behind it.
//
// In both cases the caller serves the expired body with Warning: 110
// instead of routing into a fetch. Note the breaker's own open→half-open
// timeout still applies: once ResetTimeout elapses, State() reports
// half-open, this returns true again, and a probe is allowed. Expiry
// resumes on its own the moment the upstream might be back.
func (f *facet) upstreamReachable() bool {
	if f == nil {
		return false
	}
	remote := f.currentRemote()
	if remote.BaseURL == nil || remote.Client == nil {
		return false
	}
	if f.circuitBreaker != nil && f.circuitBreaker.State() == CircuitOpen {
		return false
	}
	return true
}
