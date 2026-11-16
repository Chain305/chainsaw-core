package proxy

import (
	"path"
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
	// revalidationRepointPinned — the new body moved an existing
	// version to a different commit and the format kept serving the
	// cached entry instead (Composer re-pointed tags; see
	// internal/formats/composer/repoint.go). Any non-zero rate is worth
	// a look: it is either a compromised package or a maintainer
	// force-moving an old tag.
	revalidationRepointPinned = "repoint_pinned"
)

// RecordRepointPinned counts one revalidation in which a format
// transformer refused an upstream re-point of an existing version.
// Exported because the transformers live outside this module.
func RecordRepointPinned(ecosystem string) {
	recordMetadataRevalidation(ecosystem, revalidationRepointPinned)
}

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
// sync. The composer, docker, maven/gradle, apt and yum/dnf arms are
// NARROWER than their internal/server counterparts: they name only the
// index documents that change at the origin, never the digest- or
// version-addressed files beside them.
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

	case "composer":
		// packages.json and the p2/ documents change on every tag push
		// (and on every tag RE-point — laravel-lang, 2026-05-22). The v1
		// provider files under p/ are immutable only when the path carries
		// their content hash ("p/vendor/name$<sha256>.json"). Dist zips
		// live under dists/ and are content-addressed by commit SHA.
		if lower == "packages.json" || strings.HasPrefix(lower, "p2/") {
			return true
		}
		return strings.HasPrefix(lower, "p/") && !strings.Contains(lower, "$")

	case "docker":
		// v2/<name>/manifests/<ref>: a tag moves, a digest
		// ("sha256:...") never does; tags can never contain ':'. Blobs
		// are always digest-addressed. tags/list grows with every push.
		segments := strings.Split(lower, "/")
		if len(segments) < 4 || segments[0] != "v2" {
			return false
		}
		n := len(segments)
		if segments[n-2] == "manifests" {
			return !strings.Contains(segments[n-1], ":")
		}
		return segments[n-2] == "tags" && segments[n-1] == "list"

	case "homebrew":
		// One homebrew repo fronts two upstreams (internal/formats/homebrew):
		// api/... is formulae.brew.sh's JSON API, regenerated on every
		// homebrew-core merge (cache-control max-age=600), and v2/... is
		// ghcr.io, where a bottle manifest tag ("1.8.2-1") moves on a
		// rebuild and blobs are digest-addressed.
		if lower == "api" || strings.HasPrefix(lower, "api/") {
			return true
		}
		segments := strings.Split(lower, "/")
		if len(segments) < 4 || segments[0] != "v2" {
			return false
		}
		n := len(segments)
		if segments[n-2] == "manifests" {
			return !strings.Contains(segments[n-1], ":")
		}
		return segments[n-2] == "tags" && segments[n-1] == "list"

	case "maven", "gradle":
		// maven-metadata.xml (and its .sha1/.md5/... sidecars) lists the
		// versions and moves <latest>/<release>; everything else under a
		// version directory is a published, immutable file.
		return strings.Contains(baseName(lower), "maven-metadata.xml")

	case "apt":
		// dists/<suite>/{InRelease,Release,Release.gpg,.../Packages*} are
		// rewritten on every archive update; dists/.../by-hash/ files are
		// named by their own digest and pool/ holds the .debs. The bare
		// index names also cover flat repositories, which have no dists/.
		if strings.Contains(lower, "/by-hash/") || strings.HasPrefix(lower, "pool/") || strings.Contains(lower, "/pool/") {
			return false
		}
		if strings.HasPrefix(lower, "dists/") || strings.Contains(lower, "/dists/") {
			return true
		}
		name := baseName(lower)
		return name == "release" || name == "inrelease" || name == "release.gpg" ||
			strings.HasPrefix(name, "packages") || strings.HasPrefix(name, "sources")

	case "yum", "dnf":
		// repodata/repomd.xml points at the current index files. Modern
		// createrepo names those "<checksum>-primary.xml.gz", so they are
		// immutable; the legacy un-prefixed names are rewritten in place.
		if !strings.HasPrefix(lower, "repodata/") && !strings.Contains(lower, "/repodata/") {
			return false
		}
		name := baseName(lower)
		if i := strings.IndexByte(name, '-'); i >= 40 && isHexString(name[:i]) {
			return false
		}
		return true

	case "go":
		// GOPROXY: @v/list and @latest move on every release; the
		// version-addressed .info/.mod/.zip beside them do not.
		return strings.HasSuffix(lower, "/@v/list") || strings.HasSuffix(lower, "/@latest")

	case "cargo":
		// Sparse-index files gain a line per publish (and change on yank).
		// Only the exact shard shapes count, so crates/... downloads and
		// api/v1/... never match. config.json is static and stays cached.
		return isCargoIndexPath(lower)

	case "pub":
		// api/packages/<name> lists the versions; .../versions/<v> is one
		// published version.
		segments := strings.Split(lower, "/")
		if len(segments) < 3 || segments[0] != "api" || segments[1] != "packages" || segments[2] == "" {
			return false
		}
		return len(segments) == 3 || (len(segments) == 4 && segments[3] == "advisories")

	case "swift":
		// SE-0292: /{scope}/{name} lists releases and /{scope}/{name}/{version}
		// is release metadata; the .zip and Package.swift are fixed.
		segments := strings.Split(lower, "/")
		switch len(segments) {
		case 2:
			return segments[0] != "" && segments[1] != ""
		case 3:
			// ".zip" and its ".zip.sig" signature are fixed.
			return !strings.Contains(segments[2], ".zip")
		}
		return false

	case "cocoapods":
		// The CDN's shard listings and version files are rewritten on every
		// trunk push; Specs/.../<version>/<pod>.podspec.json is fixed.
		name := baseName(lower)
		return (strings.HasPrefix(name, "all_pods_versions_") && strings.HasSuffix(name, ".txt")) ||
			name == "cocoapods-version.yml" || name == "deprecated_podspecs.txt"

	case "huggingface":
		// api/models|datasets/... is live repo metadata. A resolve/raw URL
		// at a branch or tag moves with it; at a 40-hex commit it is fixed.
		if strings.HasPrefix(lower, "api/models/") || strings.HasPrefix(lower, "api/datasets/") {
			return true
		}
		segments := strings.Split(lower, "/")
		for i := 1; i <= 3 && i+1 < len(segments); i++ {
			if segments[i] == "resolve" || segments[i] == "raw" {
				rev := segments[i+1]
				if len(rev) == 40 && isHexString(rev) {
					return false
				}
				// Weight files at a branch stay cached as before:
				// revalidating a multi-GB checkpoint every TTL would
				// re-download it unless the Hub's redirect chain answers
				// 304. Small config/tokenizer/README files do refresh.
				return !isHFWeightFile(segments[len(segments)-1])
			}
		}
		return false

	case "rubygems":
		// The specs indexes and the compact index (versions, names,
		// info/<gem>) change on every push; gems/ and quick/ are fixed.
		switch lower {
		case "specs.4.8.gz", "latest_specs.4.8.gz", "prerelease_specs.4.8.gz", "versions", "names":
			return true
		}
		return strings.HasPrefix(lower, "info/") && !strings.Contains(lower[len("info/"):], "/")

	default:
		return false
	}
}

// isCargoIndexPath reports whether p is a sparse-index file for the crate
// it names: 1/{n}, 2/{n}, 3/{c}/{n} or {n[0:2]}/{n[2:4]}/{n}.
func isCargoIndexPath(p string) bool {
	s := strings.Split(p, "/")
	switch {
	case len(s) == 2:
		return (s[0] == "1" && len(s[1]) == 1) || (s[0] == "2" && len(s[1]) == 2)
	case len(s) == 3 && s[0] == "3":
		return len(s[2]) == 3 && len(s[1]) == 1 && s[2][:1] == s[1]
	case len(s) == 3:
		return len(s[2]) >= 4 && len(s[0]) == 2 && len(s[1]) == 2 && s[2][:2] == s[0] && s[2][2:4] == s[1]
	}
	return false
}

func baseName(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func isHexString(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return s != ""
}

// isHFWeightFile reports whether a Hugging Face file name is a model
// weight / checkpoint (large, binary) rather than small metadata.
func isHFWeightFile(name string) bool {
	switch path.Ext(name) {
	case ".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".gguf", ".h5", ".onnx",
		".msgpack", ".tflite", ".ot", ".npz", ".npy", ".pkl", ".joblib", ".nemo", ".pb", ".zip", ".tar", ".gz":
		return true
	}
	return false
}

// metadataExpired reports whether a cached entry has outlived the
// positive metadata TTL and should be revalidated.
//
// It does NOT decide whether the entry may be treated as a cache miss —
// that also requires a reachable upstream. See upstreamReachable.
func (f *facet) metadataExpired(logicalPath string, meta storage.ContentMetadata) bool {
	// An upload has no upstream copy to revalidate against; "expiring" it
	// would replace it with the public namesake (see ContentMetadata.Uploaded).
	if f == nil || f.metadataTTL <= 0 || meta.Uploaded {
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
