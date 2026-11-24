package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sync/singleflight"

	"github.com/chain305/chainsaw-core/cache"
	"github.com/chain305/chainsaw-core/formats/common"
	"github.com/chain305/chainsaw-core/index"
	"github.com/chain305/chainsaw-core/storage"
)

// MaxTransformBodySize caps an index/metadata document the facet rewrites
// (pypi.org/simple/ is ~46 MiB). Above it the document is refused, never
// served untransformed or cached partial. Detection accuracy wins over
// bandwidth, so the cap sits well above today's largest index; anything
// else that buffers the same document (release hold, composer re-point)
// uses this value so it cannot drop out earlier.
const MaxTransformBodySize = 256 << 20 // 256 MiB

const maxTransformBodySize = MaxTransformBodySize

var errBodyTooLarge = errors.New("response body exceeds transform size limit")

// transformInitialAlloc caps the up-front buffer: an upstream's
// Content-Length is a claim, and one org's upstream claiming 256 MiB over a
// tiny body must not get a 256 MiB buffer in the shared process.
const transformInitialAlloc = 8 << 20

// transformBudget bounds, in MiB, the bytes every whole-document read in the
// process (facet transforms, release hold, version gate) holds at once. A
// read waits for room with its request context, bounded by
// transformBudgetWait so readers that each hold part of the budget and wait
// for more cannot stall forever; a read that gets no room is refused.
// ponytail: counts the read buffer only, not the transformer's output copy.
var (
	transformBudget     = semaphore.NewWeighted(1024)
	transformBudgetWait = 30 * time.Second
)

var errTransformBudget = errors.New("transform memory budget exhausted")

// upstreamErrorRecorder is a package-level callback the observability
// wiring installs via SetUpstreamErrorRecorder. It is invoked once per
// USER-VISIBLE upstream failure with the proxy facet's ecosystem/format
// label (e.g. "npm", "pypi"). Not called for transient retries — the
// facet only records at the outermost error return after retry
// exhaustion. nil is a no-op so tests and metrics-disabled builds are
// unaffected.
var upstreamErrorRecorder func(ecosystem string)

// SetUpstreamErrorRecorder installs (or clears) the package-level
// upstream-error recorder. Called once at startup from
// cmd/chainsaw-proxy/init_server.go after the Prometheus Metrics
// struct is constructed. Pass nil to disable.
func SetUpstreamErrorRecorder(rec func(ecosystem string)) {
	upstreamErrorRecorder = rec
}

// knownEcosystemLabels mirrors the FacetConfig.Format enum
// (internal/repository.Format) — the full set of repository FORMAT
// strings, including proxy aliases (bun/yarn/gradle) and raw, since the
// label is the per-repo f.format value, not the alias-folded ecosystem.
// Mirroring rather than importing avoids a proxy→repository cycle. Keep
// in sync — adding a new format requires adding it here too, or new
// ecosystems will silently land in {ecosystem="other"} until updated.
//
// label values: known enum + "other" (cardinality bound = N+1).
var knownEcosystemLabels = map[string]struct{}{
	"apt": {}, "bun": {}, "cargo": {}, "cocoapods": {}, "composer": {},
	"dnf": {}, "docker": {}, "go": {}, "gradle": {}, "homebrew": {}, "huggingface": {},
	"maven": {}, "npm": {}, "nuget": {}, "pip": {}, "pub": {}, "raw": {},
	"rubygems": {}, "swift": {}, "yarn": {}, "yum": {},
}

// normalizeEcosystemLabel collapses any unknown ecosystem string to
// "other" so the chainsaw_upstream_errors_total CounterVec keeps a
// hard cardinality bound even if a future caller wires an unvalidated
// format string into recordUpstreamError. Defense-in-depth — today's
// callers all pass repository.Format (validated enum), but the
// package-level recorder seam accepts any string. A sustained rise in
// {ecosystem="other"} signals an allow-list update is needed.
func normalizeEcosystemLabel(ecosystem string) string {
	if _, ok := knownEcosystemLabels[ecosystem]; ok {
		return ecosystem
	}
	return "other"
}

// recordUpstreamError forwards a single ecosystem label to the
// installed recorder. Safe for nil. The ecosystem label is normalized
// against an allow-list so the metric stays cardinality-bounded even
// if a future caller passes an unvalidated string.
func recordUpstreamError(ecosystem string) {
	rec := upstreamErrorRecorder
	if rec == nil {
		return
	}
	rec(normalizeEcosystemLabel(ecosystem))
}

// UpstreamUserAgent is the User-Agent on every repository fetch.
//
// Without it, internal fetches (scanner artifact and POM reads) went out
// as Go's default "Go-http-client/1.1" and client fetches forwarded the
// client's UA. Maven Central throttles the Go default: measured
// 2026-10-21, the same POM answered 200 to curl's UA and 429
// (Retry-After 662) to Go's, which then held the Sonatype stand-off open.
// The binary stamps its version over the default at startup.
var UpstreamUserAgent = "chainsaw-proxy/dev (+https://chain305.com)"

// Request mirrors the arguments expected by ProxyFacetSupport.get(...)
type Request struct {
	LogicalPath string
	Method      string
	Header      http.Header
	// RawQuery is the client's query string. The facet forwards only what
	// it knows to be safe (docker tags/list pagination); everything else
	// keys on the path alone.
	RawQuery string
}

// Response contains the resolved content plus HTTP metadata.
type Response struct {
	StatusCode int
	Headers    http.Header
	Content    *storage.CachedContent
	FromCache  bool
}

// Facet mimics the Nexus ProxyFacet contract.
type Facet interface {
	Get(ctx context.Context, req *Request) (*Response, error)
	UpdateRemote(remote RemoteDefinition)
	UpdateNegative(cache *cache.NegativeCache)
	RemoteDefinition() RemoteDefinition
}

// RemoteDefinition contains the remote base URL and HTTP client.
type RemoteDefinition struct {
	BaseURL *url.URL
	Client  *http.Client
	Headers map[string]string
}

// InternalPackageChecker checks whether a package version is internally published.
// When set on the facet, upstream content is never stored over internal packages.
type InternalPackageChecker interface {
	IsInternalVersion(orgID, repoName, packageName, version string) bool
}

// InternalPackageErrChecker is an InternalPackageChecker that can also report
// a failed lookup. The facet prefers it: a lookup that errors is refused
// rather than read as "not internal", which would fetch and store the public
// namesake of a private package (dependency confusion on a DB error).
type InternalPackageErrChecker interface {
	IsInternalVersionErr(orgID, repoName, packageName, version string) (bool, error)
}

// FacetConfig holds dependencies for building a proxy facet.
type FacetConfig struct {
	RepoName string
	Format   string
	Storage  storage.StorageFacet
	Remote   RemoteDefinition
	Index    *index.Index
	Resolver common.CoordinateResolver
	Negative *cache.NegativeCache
	Mapper   RemoteURLMapper
	Rewrite  ResponseTransformer
	Logger   *slog.Logger
	// AllowMissingRemote returns 404 on cache misses when no upstream is configured.
	AllowMissingRemote bool
	// InternalChecker, when set, prevents upstream from overwriting internal packages.
	InternalChecker InternalPackageChecker
	// CircuitBreaker, when set, short-circuits upstream fetches when the remote
	// is known to be unavailable. This prevents request pile-up behind a slow or
	// down upstream, falling through to stale cache instead.
	CircuitBreaker *CircuitBreaker
	// UpstreamTracker, when set, records per-upstream request metrics for
	// the observability endpoint /api/upstream/status.
	UpstreamTracker *UpstreamTracker
	// MetadataTTL bounds how long a MUTABLE registry document (npm
	// packument, pip simple-index page) may be served from cache without
	// revalidating upstream. Zero disables expiry, which is the
	// pre-existing behaviour: every cached document, mutable or not, was
	// served forever. Immutable artifacts are never expired by this
	// regardless of value — see isMutableDocument.
	MetadataTTL time.Duration
}

type facet struct {
	repoName           string
	format             string
	storage            storage.StorageFacet
	remote             RemoteDefinition
	index              *index.Index
	resolver           common.CoordinateResolver
	negative           *cache.NegativeCache
	mapper             RemoteURLMapper
	rewriter           ResponseTransformer
	logger             *slog.Logger
	allowMissingRemote bool
	internalChecker    InternalPackageChecker
	mu                 sync.RWMutex
	fetchGroup         singleflight.Group
	circuitBreaker     *CircuitBreaker
	upstreamTracker    *UpstreamTracker
	metadataTTL        time.Duration
}

// NewFacet wires a proxy facet similar to ProxyFacetSupport.
func NewFacet(cfg FacetConfig) Facet {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &facet{
		repoName:           cfg.RepoName,
		format:             cfg.Format,
		storage:            cfg.Storage,
		remote:             guardRemoteHeaders(cfg.Remote),
		index:              cfg.Index,
		resolver:           cfg.Resolver,
		negative:           cfg.Negative,
		mapper:             cfg.Mapper,
		rewriter:           cfg.Rewrite,
		logger:             logger,
		allowMissingRemote: cfg.AllowMissingRemote,
		internalChecker:    cfg.InternalChecker,
		circuitBreaker:     cfg.CircuitBreaker,
		upstreamTracker:    cfg.UpstreamTracker,
		metadataTTL:        cfg.MetadataTTL,
	}
}

// Get is the core pull-through cache flow.
func (f *facet) Get(ctx context.Context, req *Request) (*Response, error) {
	if req.Method != http.MethodGet {
		return &Response{StatusCode: http.StatusMethodNotAllowed}, nil
	}
	logicalPath := strings.TrimPrefix(req.LogicalPath, "/")
	if logicalPath == "" {
		return &Response{StatusCode: http.StatusBadRequest}, nil
	}
	// A docker tags/list page is keyed by its query and never stored: the
	// path-only entry is the unpaginated list, and caching page 2 there
	// served page 1 for every later page (or the reverse).
	if query := tagsListPageQuery(f.format, logicalPath, req.RawQuery); query != "" {
		return f.fetchTagsPage(ctx, req, logicalPath, query)
	}
	cacheKey := cache.ScopedKey(OrgIDFromContext(ctx), logicalPath)
	if negative := f.currentNegative(); negative != nil && negative.Hit(cacheKey) {
		return &Response{StatusCode: http.StatusNotFound, Headers: make(http.Header)}, nil
	}

	cacheResp, err := f.tryCacheHit(ctx, logicalPath)
	if err != nil {
		return nil, err
	}
	if cacheResp != nil {
		return cacheResp, nil
	}

	remote := f.currentRemote()
	if remote.BaseURL == nil || remote.Client == nil {
		if f.allowMissingRemote {
			return &Response{StatusCode: http.StatusNotFound, Headers: make(http.Header)}, nil
		}
		recordUpstreamError(f.format)
		return nil, errors.New("repository upstream unavailable")
	}

	return f.awaitFetch(ctx, req, remote, logicalPath, cacheKey)
}

// tryCacheHit attempts to serve the artifact from the local cache.
// Returns (response, nil) on a usable hit, (nil, nil) on miss or
// encoding-repair fall-through, and (nil, err) on storage failure other
// than NotFound.
//
// The freshness check lives HERE, not at the call sites, because there
// are two of them — Get and fetchAndStore's singleflight re-check — and
// a guard on only one would let concurrent callers disagree about
// whether the same entry is expired: the leader would fetch while a
// coalesced waiter served the stale body, or vice versa.
func (f *facet) tryCacheHit(ctx context.Context, logicalPath string) (*Response, error) {
	content, err := f.storage.Get(ctx, logicalPath)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	f.applyCoordinateMetadata(logicalPath, content)
	if needsEncodingRepair(content.Metadata) {
		return nil, nil
	}

	stale := false
	if f.metadataExpired(logicalPath, content.Metadata) {
		if f.upstreamReachable() {
			// Expired with a live upstream: treat as a miss so the
			// fetch path revalidates (conditionally — see
			// addRevalidationHeaders).
			return nil, nil
		}
		// THE AIR-GAP GUARD. No upstream is reachable, so a "miss"
		// would route into a fetch that cannot succeed and would only
		// fail the request. An air-gapped box with a warm cache must
		// keep serving without ever touching the network.
		stale = true
		recordMetadataRevalidation(f.format, revalidationStaleServed)
		if f.logger != nil {
			f.logger.Warn("metadata cache entry expired but no upstream is reachable; serving stale",
				"path", logicalPath, "cached_at", content.Metadata.CachedAt)
		}
	}

	return f.respondFromCache(ctx, logicalPath, content, stale)
}

// applyCoordinateMetadata refreshes the package coordinate fields on a
// cached entry from the resolver, so entries stored before a resolver
// change still report the right name/version/subtype.
func (f *facet) applyCoordinateMetadata(logicalPath string, content *storage.CachedContent) {
	coord, ok := f.describe(logicalPath)
	if !ok {
		return
	}
	if content.Metadata.PackageName != coord.Name || content.Metadata.PackageVersion != coord.Version {
		content.Metadata.PackageName = coord.Name
		content.Metadata.PackageVersion = coord.Version
	}
	if content.Metadata.PackageSubtype != coord.Subtype {
		content.Metadata.PackageSubtype = coord.Subtype
	}
}

// respondFromCache finishes a cache hit: applies the response
// transformer when one is installed, then assembles headers. When stale
// is true the RFC 7234 Warning: 110 header is added, matching what
// tryStaleCache serves on the upstream-failure path.
func (f *facet) respondFromCache(ctx context.Context, logicalPath string, content *storage.CachedContent, stale bool) (*Response, error) {
	if f.rewriter != nil {
		rewritten, rewriteErr := f.rewriteCachedContent(ctx, logicalPath, content)
		if rewriteErr != nil {
			return nil, rewriteErr
		}
		if rewritten != nil {
			content = rewritten
		}
	}
	headers := headersFromMetadata(content.Metadata)
	if stale {
		headers.Set("Warning", staleWarning)
	}
	// An entry nobody has verified yet is not a cache hit to the caller:
	// it must verify it (see ContentMetadata.Unverified).
	return &Response{
		StatusCode: http.StatusOK,
		Headers:    headers,
		Content:    content,
		FromCache:  !content.Metadata.Unverified,
	}, nil
}

// awaitFetch dispatches the upstream fetch through singleflight and
// waits on the caller's context. Coalesces concurrent requests for the
// same artifact: only one goroutine fetches from upstream while others
// wait for the result. Uses DoChan with a detached context so that if
// the first caller disconnects (e.g. Ctrl+C during npm install), the
// upstream fetch continues for all other coalesced waiters.
func (f *facet) awaitFetch(ctx context.Context, req *Request, remote RemoteDefinition, logicalPath, cacheKey string) (*Response, error) {
	ch := f.fetchGroup.DoChan(cacheKey, func() (interface{}, error) {
		// Use a context that is not cancelled when the original caller
		// disconnects. The upstream fetch must complete to populate the
		// cache for all waiting clients.
		fetchCtx := context.WithoutCancel(ctx)
		return f.fetchAndStore(fetchCtx, req, remote, logicalPath, cacheKey)
	})

	// Each caller waits on its own context. If this caller's context is
	// cancelled, it returns immediately — but the upstream fetch continues
	// for the remaining waiters.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case result := <-ch:
		if result.Err != nil {
			// Outermost user-visible error — retries inside
			// fetchWithRetry have already been exhausted and stale-cache
			// fallback (if any) was not available. Record exactly once
			// per failure per ecosystem so the counter tracks real
			// customer-facing events, not transient blips.
			recordUpstreamError(f.format)
			return nil, result.Err
		}
		// Every coalesced waiter receives the SAME *Response, and the server
		// writes per-request headers into it (applyCacheHeaders, release
		// hold). Shared, that map took concurrent writes from two installs of
		// the same package and the runtime killed the whole process ("fatal
		// error: concurrent map writes", 2026-10-21, 8 parallel npm packs).
		return ownCopy(result.Val.(*Response)), nil
	}
}

// ownCopy gives one singleflight waiter its own Response: headers, the
// content struct and its ExtraHeaders map. The blob itself is not copied;
// CachedContent.Open hands each caller a fresh reader.
func ownCopy(shared *Response) *Response {
	if shared == nil {
		return nil
	}
	resp := *shared
	resp.Headers = shared.Headers.Clone()
	if shared.Content != nil {
		content := *shared.Content
		content.Metadata.ExtraHeaders = maps.Clone(shared.Content.Metadata.ExtraHeaders)
		resp.Content = &content
	}
	return &resp
}

// fetchAndStore is the singleflight-protected body: re-check cache,
// consult the circuit breaker, perform the upstream fetch, then route
// the response into the appropriate handler (stale, negative cache,
// internal override, store).
func (f *facet) fetchAndStore(fetchCtx context.Context, req *Request, remote RemoteDefinition, logicalPath, cacheKey string) (*Response, error) {
	// Re-check cache inside singleflight: a prior caller may have
	// populated it while we waited for the group lock.
	if cached, err := f.tryCacheHit(fetchCtx, logicalPath); err != nil {
		return nil, err
	} else if cached != nil {
		return cached, nil
	}

	// A non-literal path is refused before the breaker and the retry loop:
	// it is the client's fault, not the upstream's, and must not trip the
	// breaker for everyone else.
	if _, err := f.remoteURL(remote, logicalPath); err != nil {
		return nil, err
	}

	// Circuit breaker: fail fast when upstream is known to be down.
	if f.circuitBreaker != nil && !f.circuitBreaker.Allow() {
		if stale := f.tryStaleCache(fetchCtx, logicalPath); stale != nil {
			f.logger.Warn("circuit breaker open, serving stale cache",
				"path", logicalPath, "state", f.circuitBreaker.State())
			return stale, nil
		}
		return nil, ErrCircuitOpen
	}

	header := cloneHeader(req.Header)
	// The CLIENT's conditional headers are always stripped: it is
	// validating against ITS copy, whose validators mean nothing to our
	// upstream, and a 304 answered to them would starve the cache. What
	// follows adds the PROXY's OWN conditional, derived from the entry
	// we hold. The two must not be confused — hence strip, then add.
	stripConditionalHeaders(header)
	// The facet stores whole objects, so it fetches whole objects. A
	// forwarded client Range made upstream answer 206, and the slice was
	// cached as the artifact. The server serves the client's range from
	// the whole, enforced body.
	header.Del("Range")
	revalidating := f.addRevalidationHeaders(fetchCtx, logicalPath, header)

	remoteResp, fetchErr := f.fetchWithRetry(fetchCtx, remote, logicalPath, header)
	if fetchErr != nil {
		if f.circuitBreaker != nil {
			// DNS failures are classified separately — a local
			// resolver flap should not be treated as "upstream
			// is down" and trip full cache-only fallback.
			f.circuitBreaker.RecordNetworkFailure(fetchErr)
		}
		// Upstream network error — try serving stale cache if available.
		if stale := f.tryStaleCache(fetchCtx, logicalPath); stale != nil {
			f.logger.Warn("upstream fetch failed, serving stale cache",
				"path", logicalPath, "error", fetchErr)
			return stale, nil
		}
		return nil, fetchErr
	}
	defer remoteResp.Body.Close()

	f.recordCircuitOutcome(remoteResp.StatusCode)

	if revalidating {
		switch {
		case remoteResp.StatusCode == http.StatusNotModified:
			recordMetadataRevalidation(f.format, revalidationFresh)
		case remoteResp.StatusCode < 400:
			recordMetadataRevalidation(f.format, revalidationChanged)
		}
	}

	// Upstream confirmed OUR copy, but our copy could not be served (the
	// blob read failed or the entry went). The client sent no conditional,
	// so a bare 304 is an empty body it cannot use: npm read it as
	// "invalid json response body" (prod, 2026-10-30, Contabo S3 GETs
	// timing out). Fetch the whole document instead.
	if revalidating && remoteResp.StatusCode == http.StatusNotModified {
		if fresh := f.serveRevalidated(fetchCtx, logicalPath); fresh != nil {
			return fresh, nil
		}
		_ = remoteResp.Body.Close()
		stripConditionalHeaders(header)
		var refetchErr error
		remoteResp, refetchErr = f.fetchWithRetry(fetchCtx, remote, logicalPath, header)
		if refetchErr != nil {
			return nil, refetchErr
		}
		defer remoteResp.Body.Close()
		f.recordCircuitOutcome(remoteResp.StatusCode)
	}

	if handled, resp := f.handleUpstreamStatus(fetchCtx, logicalPath, cacheKey, remoteResp); handled {
		return resp, nil
	}

	return f.storeUpstream(fetchCtx, remote, logicalPath, remoteResp)
}

// recordCircuitOutcome feeds upstream status codes back into the
// circuit breaker: 5xx is a failure, anything else but 429 a success.
//
// A 4xx counts as success because the breaker asks one question — is
// the upstream up — and an upstream that answers 404 or 403 is up. It
// used to count as nothing, which is how half-open probes got stranded:
// on a proxy whose traffic is mostly misses, the probe after a 5xx burst
// is often a 404, and a probe with no outcome kept the breaker
// half-open with no slots left (see CircuitBreaker.Allow). 429 alone is
// left unrecorded: the upstream is alive but asking us to stop, and
// closing the circuit on it would invite the traffic it refused.
func (f *facet) recordCircuitOutcome(status int) {
	if f.circuitBreaker == nil {
		return
	}
	switch {
	case status >= 500:
		f.circuitBreaker.RecordFailure()
	case status != http.StatusTooManyRequests:
		f.circuitBreaker.RecordSuccess()
	}
}

// handleUpstreamStatus inspects the upstream response status code and
// returns (true, resp) when the caller should short-circuit with that
// response (404 negative-cached, 5xx served from stale cache, or any
// other 4xx/5xx passthrough). Returns (false, nil) when the response
// is a success that still needs to be stored.
func (f *facet) handleUpstreamStatus(fetchCtx context.Context, logicalPath, cacheKey string, remoteResp *http.Response) (bool, *Response) {
	if remoteResp.StatusCode == http.StatusNotFound {
		if negative := f.currentNegative(); negative != nil {
			negative.Remember(cacheKey)
		}
		return true, &Response{StatusCode: http.StatusNotFound, Headers: cloneHeader(remoteResp.Header)}
	}

	// 304 Not Modified carries an EMPTY body. It must never reach
	// storeUpstream, which would write those zero bytes over a perfectly
	// good cached packument.
	//
	// This branch is now LIVE. It was written while unreachable — the
	// client's conditionals are stripped and the proxy sent none of its
	// own — as a guard against exactly the change that has since landed:
	// addRevalidationHeaders now sends If-None-Match / If-Modified-Since
	// from the stored validators, so upstream has something to answer
	// 304 to.
	//
	// Serving from cache is the correct handling: 304 means "what you
	// have is current". Falling back to a passthrough when the cache has
	// since gone means the caller gets an honest empty 304 rather than a
	// silently blanked entry.
	if remoteResp.StatusCode == http.StatusNotModified {
		if fresh := f.serveRevalidated(fetchCtx, logicalPath); fresh != nil {
			return true, fresh
		}
		return true, &Response{
			StatusCode: http.StatusNotModified,
			Headers:    cloneHeader(remoteResp.Header),
		}
	}

	// A 206 is a slice, never the object. The facet sends no Range, so
	// this is an upstream misbehaving; storing it would cache the slice
	// as the artifact.
	if remoteResp.StatusCode == http.StatusPartialContent {
		return true, &Response{StatusCode: http.StatusBadGateway, Headers: make(http.Header)}
	}

	if remoteResp.StatusCode >= 500 {
		// Upstream server error — try serving stale cache if available.
		if stale := f.tryStaleCache(fetchCtx, logicalPath); stale != nil {
			f.logger.Warn("upstream returned server error, serving stale cache",
				"path", logicalPath, "status", remoteResp.StatusCode)
			return true, stale
		}
	}

	if remoteResp.StatusCode >= 400 {
		return true, &Response{StatusCode: remoteResp.StatusCode, Headers: cloneHeader(remoteResp.Header)}
	}

	return false, nil
}

// storeUpstream is the happy-path store-and-respond flow for a
// successful (<400) upstream response. Builds metadata, honors the
// internal-package override, prepares the body reader (decoding /
// rewriting when a transformer is installed), and writes the cache.
func (f *facet) storeUpstream(fetchCtx context.Context, remote RemoteDefinition, logicalPath string, remoteResp *http.Response) (*Response, error) {
	originURL, _ := f.remoteURL(remote, logicalPath) // the fetch already proved it literal
	meta := storage.ContentMetadata{
		ContentType:     remoteResp.Header.Get("Content-Type"),
		ContentEncoding: recordedContentEncoding(remoteResp.Header.Get("Content-Encoding")),
		ETag:            remoteResp.Header.Get("ETag"),
		OriginURL:       originURL,
		ReleasedAt:      releaseTimestamp(remoteResp),
		CachedAt:        time.Now().UTC(),
		ExtraHeaders:    captureExtraHeaders(remoteResp.Header),
	}
	if isTagsListPath(f.format, logicalPath) {
		rewriteTagsListLink(meta.ExtraHeaders)
	}
	if coord, ok := f.describe(logicalPath); ok {
		meta.PackageName = coord.Name
		meta.PackageVersion = coord.Version
		meta.PackageSubtype = coord.Subtype
		meta.Unverified = true
		if f.index != nil {
			_ = f.index.Record(f.repoName, index.PackageCoordinate{
				Package: coord.Name,
				Version: coord.Version,
				Format:  string(coord.Format),
			}, logicalPath)
		}
	}

	if resp, err := f.serveInternalOverride(fetchCtx, logicalPath, meta); err != nil {
		return nil, err
	} else if resp != nil {
		return resp, nil
	}

	bodyReader, prepErr := f.prepareBodyReader(fetchCtx, logicalPath, remoteResp)
	if prepErr != nil {
		return nil, prepErr
	}

	// An upload can land while the fill was in flight; the public body
	// must not replace it. A failed lookup proceeds: tryCacheHit already
	// saw this path absent, unexpired or not uploaded.
	if existing, err := f.storage.Get(fetchCtx, logicalPath); err == nil && existing.Metadata.Uploaded {
		f.applyCoordinateMetadata(logicalPath, existing)
		return f.respondFromCache(fetchCtx, logicalPath, existing, false)
	}

	var saved *storage.CachedContent
	var putErr error
	if sp, ok := f.storage.(spoolingStore); ok {
		var stored bool
		saved, stored, putErr = sp.PutOrSpool(fetchCtx, logicalPath, bodyReader, meta)
		if putErr == nil && !stored {
			f.logger.Warn("blob store write failed; serving the fill from the local disk tier, not cached",
				"repository", f.repoName, "logical_path", logicalPath)
		}
	} else {
		saved, putErr = f.storage.Put(fetchCtx, logicalPath, bodyReader, meta)
	}
	if putErr != nil {
		return nil, fmt.Errorf("write cache: %w", putErr)
	}
	return &Response{
		StatusCode: http.StatusOK,
		Headers:    headersFromMetadata(saved.Metadata),
		Content:    saved,
		FromCache:  false,
	}, nil
}

// spoolingStore is a storage that can serve a proxy fill from local disk
// when the blob store write fails (storage.LocalStorage.PutOrSpool).
type spoolingStore interface {
	PutOrSpool(ctx context.Context, logicalPath string, src io.Reader, meta storage.ContentMetadata) (*storage.CachedContent, bool, error)
}

// serveInternalOverride returns the cached internal copy when the
// upstream response would otherwise overwrite an internally published
// package, preventing upstream content from clobbering internal
// publishes. Returns (nil, nil) when no override applies (no checker,
// missing coords, not internal).
//
// It returns an error, and nothing is stored, when the version is internal
// but its bytes cannot be read, or when the checker cannot tell whether it is
// internal. Falling through in either case stored and served the upstream
// namesake of a private package.
func (f *facet) serveInternalOverride(fetchCtx context.Context, logicalPath string, meta storage.ContentMetadata) (*Response, error) {
	if f.internalChecker == nil || meta.PackageName == "" || meta.PackageVersion == "" {
		return nil, nil
	}
	orgID := OrgIDFromContext(fetchCtx)
	var internal bool
	if ec, ok := f.internalChecker.(InternalPackageErrChecker); ok {
		var err error
		internal, err = ec.IsInternalVersionErr(orgID, f.repoName, meta.PackageName, meta.PackageVersion)
		if err != nil {
			return nil, fmt.Errorf("internal package check for %s@%s: %w", meta.PackageName, meta.PackageVersion, err)
		}
	} else {
		internal = f.internalChecker.IsInternalVersion(orgID, f.repoName, meta.PackageName, meta.PackageVersion)
	}
	if !internal {
		return nil, nil
	}
	f.logger.Info("skipping upstream store for internal package",
		"package", meta.PackageName, "version", meta.PackageVersion)
	// Serve from existing internal storage.
	cached, intErr := f.storage.Get(fetchCtx, logicalPath)
	if intErr != nil {
		return nil, fmt.Errorf("internal package %s@%s is published but its stored copy could not be read: %w",
			meta.PackageName, meta.PackageVersion, intErr)
	}
	return &Response{
		StatusCode: http.StatusOK,
		Headers:    headersFromMetadata(cached.Metadata),
		Content:    cached,
		FromCache:  true,
	}, nil
}

func (f *facet) describe(logicalPath string) (common.PackageCoordinate, bool) {
	if f.resolver == nil {
		return common.PackageCoordinate{}, false
	}
	coord, ok := f.resolver.Describe(logicalPath)
	if !ok {
		return common.PackageCoordinate{}, false
	}
	if coord.Format == "" {
		coord.Format = f.format
	}
	return coord, true
}

// fetchWithRetry wraps fetchFromRemote with retry logic for transient failures.
// It retries on network errors and HTTP 502/503/429 with short exponential
// backoff (100ms, 500ms). Non-retryable: 4xx (except 429), context cancelled,
// circuit breaker open, and any response whose Retry-After outlasts the next
// backoff step.
func (f *facet) fetchWithRetry(ctx context.Context, remote RemoteDefinition, logicalPath string, header http.Header) (*http.Response, error) {
	const maxRetries = 2
	backoff := [...]time.Duration{100 * time.Millisecond, 500 * time.Millisecond}

	started := time.Now().UTC()
	resp, err := f.fetchFromRemote(ctx, remote, logicalPath, header)
	if f.upstreamTracker != nil {
		isErr := err != nil || (resp != nil && resp.StatusCode >= 500)
		f.upstreamTracker.RecordRequest(time.Since(started), isErr)
	}
	if err == nil && !isRetryableStatus(resp.StatusCode) {
		return resp, nil
	}

	for attempt := 0; attempt < maxRetries; attempt++ {
		// Don't retry if the context is already done.
		if ctx.Err() != nil {
			if resp != nil {
				return resp, nil
			}
			return nil, ctx.Err()
		}

		// Check if the error or status is retryable.
		if err == nil && !isRetryableStatus(resp.StatusCode) {
			return resp, nil
		}

		// Wait with jitter before retrying.
		delay := backoff[attempt]
		jitter := time.Duration(int64(delay) / 10) // 10% jitter
		if jitter > 0 {
			delay += time.Duration(time.Now().UnixNano() % int64(jitter))
		}

		// The upstream said when to come back. A retry inside that window
		// is refused by construction and only spends the rate budget that
		// produced the 429, so hand the response back instead.
		if resp != nil {
			if wait, ok := retryAfter(resp.Header.Get("Retry-After"), time.Now()); ok && wait > delay {
				return resp, nil
			}
		}

		// Close the previous response body before retrying.
		if resp != nil {
			resp.Body.Close()
		}

		if f.upstreamTracker != nil {
			f.upstreamTracker.RecordRetry()
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}

		f.logger.Debug("retrying upstream fetch",
			"path", logicalPath, "attempt", attempt+1, "prev_error", err)

		started = time.Now().UTC()
		resp, err = f.fetchFromRemote(ctx, remote, logicalPath, header)
		if f.upstreamTracker != nil {
			isErr := err != nil || (resp != nil && resp.StatusCode >= 500)
			f.upstreamTracker.RecordRequest(time.Since(started), isErr)
		}
	}

	return resp, err
}

// retryAfter parses a Retry-After header in either RFC 9110 form: delay
// seconds or an HTTP-date. ok is false when the header is absent, malformed
// or already in the past. Mirrors upstreamhttp's parser; importing that
// package would pull policy and config into the proxy.
func retryAfter(header string, now time.Time) (time.Duration, bool) {
	s := strings.TrimSpace(header)
	if s == "" {
		return 0, false
	}
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second, n > 0
	}
	if t, err := http.ParseTime(s); err == nil && t.After(now) {
		return t.Sub(now), true
	}
	return 0, false
}

func isRetryableStatus(status int) bool {
	return status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout ||
		status == http.StatusTooManyRequests
}

func (f *facet) fetchFromRemote(ctx context.Context, remote RemoteDefinition, logicalPath string, header http.Header) (*http.Response, error) {
	remoteURL, err := f.remoteURL(remote, logicalPath)
	if err != nil {
		return nil, err
	}
	if q, _ := ctx.Value(upstreamQueryKey{}).(string); q != "" {
		remoteURL += "?" + q
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, remoteURL, nil)
	if err != nil {
		return nil, err
	}
	forceHTML := f.shouldForceHTML(logicalPath)
	needsTransform := f.rewriter != nil
	for k, v := range remote.Headers {
		if v == "" {
			continue
		}
		req.Header.Add(k, v)
	}
	for k, values := range header {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Authorization") ||
			strings.EqualFold(k, "User-Agent") {
			continue
		}
		if forceHTML && strings.EqualFold(k, "Accept") {
			continue
		}
		// Never the client's Accept-Encoding: one fill serves every client and
		// the checksum gate, so what is cached must not be a transfer coding
		// the first client happened to accept (it is set below).
		if strings.EqualFold(k, "Accept-Encoding") {
			continue
		}
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	if forceHTML {
		req.Header.Set("Accept", "text/html")
	}
	if needsTransform {
		req.Header.Set("Accept-Encoding", "gzip, zstd, identity")
	} else {
		// The file itself. Not left unset: Go would then ask for gzip and
		// transparently gunzip, turning an Apache mirror's `.tgz` (served
		// as Content-Encoding: gzip) into a .tar. Forwarding the client's
		// header made Maven Central answer Brotli, which Go never decodes,
		// so the facet cached the br body as the .pom and the checksum gate
		// refused it (CHW-2305 on genuine poms, prod 2026-11-23/24).
		req.Header.Set("Accept-Encoding", "identity")
	}
	// One fetch fills the cache for every client, so the variant asked for
	// must not be whichever client came first.
	if accept := sharedUpstreamAccept(f.format, logicalPath); accept != "" {
		req.Header.Set("Accept", accept)
	}
	// The proxy fetches as itself: a singleflight fetch serves every
	// waiting client, so no one client's UA is the right one. A UA the
	// operator configures in the remote headers still wins.
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", UpstreamUserAgent)
	}
	if charge := upstreamCharger; charge != nil {
		charge(req.URL.Hostname())
	}
	return remote.Client.Do(req)
}

// upstreamCharger, when set, is told the host of every upstream fetch the
// proxy makes for a client. It must not block: installs never wait on it.
var upstreamCharger func(host string)

// SetUpstreamCharger installs the hook that counts install fetches against
// the process-wide upstream budget (upstreamhttp.InProcessHostLimiter.Charge).
// Pass nil to disable.
func SetUpstreamCharger(f func(host string)) { upstreamCharger = f }

func (f *facet) remoteURL(remote RemoteDefinition, logicalPath string) (string, error) {
	base := remote.BaseURL
	query := ""
	if f.mapper != nil {
		if mapping := f.mapper(logicalPath, base); mapping != nil {
			if mapping.Base != nil {
				base = mapping.Base
			}
			if mapping.LogicalPath != "" {
				logicalPath = mapping.LogicalPath
			}
			if mapping.Query != "" {
				query = mapping.Query
			}
		}
	}
	return LiteralRemoteURL(base, logicalPath, query)
}

// ErrNonLiteralUpstreamPath: resolving the logical path against the base would
// fetch a different path than the one the policy judged.
var ErrNonLiteralUpstreamPath = errors.New("proxy: logical path does not resolve literally under the upstream base")

// LiteralRemoteURL resolves logicalPath against base (RFC 3986, as
// ResolveReference does) and refuses when the result is not exactly the
// base's directory plus logicalPath — a dot segment removed, or a leading
// slash that replaced the base path. The decision judges logicalPath as
// written, so the fetch may only go there (pentest #9/#23/#29). base is the
// post-mapper base: a mapper's own rewrite is not a mismatch.
func LiteralRemoteURL(base *url.URL, logicalPath, rawQuery string) (string, error) {
	ref := &url.URL{Path: strings.TrimPrefix(logicalPath, "/"), RawQuery: rawQuery}
	u := base.ResolveReference(ref)
	if ref.Path != "" {
		bp := base.EscapedPath()
		want := bp[:strings.LastIndex(bp, "/")+1] + ref.EscapedPath()
		if !strings.HasPrefix(want, "/") {
			want = "/" + want
		}
		if u.EscapedPath() != want {
			return "", ErrNonLiteralUpstreamPath
		}
	}
	return u.String(), nil
}

// encodingIdentity marks "upstream sent no Content-Encoding", as distinct
// from "we never recorded one".
//
// needsEncodingRepair keys on an EMPTY ContentEncoding to force a
// re-fetch of pip simple-index pages cached before the encoding was
// captured. But storeUpstream wrote the upstream header back verbatim,
// so when upstream served the page identity-encoded the stored value was
// empty again and the very next request missed again — a permanent
// re-fetch loop with no caching at all for those paths, which is the
// exact opposite of the freeze the same file suffers elsewhere.
//
// Recording "identity" terminates the repair after one pass while still
// letting a genuinely unrecorded legacy entry be repaired once.
const encodingIdentity = "identity"

func recordedContentEncoding(upstream string) string {
	if strings.TrimSpace(upstream) == "" {
		return encodingIdentity
	}
	return upstream
}

func needsEncodingRepair(meta storage.ContentMetadata) bool {
	// The repair is an upstream refetch; an upload has no upstream copy.
	if meta.Uploaded || meta.ContentEncoding != "" {
		return false
	}
	if !strings.HasPrefix(meta.LogicalPath, "simple") {
		return false
	}
	ct := strings.ToLower(meta.ContentType)
	if strings.Contains(ct, "application/vnd.pypi.simple") {
		return true
	}
	if strings.Contains(ct, "text/html") {
		return true
	}
	return false
}

// extraHeaderKeys lists upstream response headers that are captured into
// ContentMetadata.ExtraHeaders so they survive cache round-trips.
var extraHeaderKeys = []string{
	"X-Linked-Etag",
	"X-Linked-Size",
	"X-Repo-Commit",
	"Accept-Ranges",
	"Last-Modified",
	// Swift Package Registry (SE-0292 / SE-0391): integrity + signing
	// envelopes and version-negotiation headers must be preserved so SPM
	// clients can verify archives and content-negotiate correctly.
	"Digest",
	"Content-Version",
	"X-Swift-Package-Signature",
	"X-Swift-Package-Signature-Format",
	"Link",
	// Integrity headers clients check against the body: a cached hit used
	// to drop them. Neither format has a transformer, so they still match.
	"Docker-Content-Digest",
	"X-Checksum-Sha1",
	"X-Checksum-Md5",
	"X-Checksum-Sha256",
}

func captureExtraHeaders(upstream http.Header) map[string]string {
	if upstream == nil {
		return nil
	}
	var extra map[string]string
	for _, key := range extraHeaderKeys {
		if v := upstream.Get(key); v != "" {
			if extra == nil {
				extra = make(map[string]string, len(extraHeaderKeys))
			}
			extra[key] = v
		}
	}
	return extra
}

func headersFromMetadata(meta storage.ContentMetadata) http.Header {
	h := make(http.Header)
	if meta.ContentType != "" {
		h.Set("Content-Type", meta.ContentType)
	}
	// "identity" is our internal marker for "upstream sent none", and
	// RFC 7231 §3.1.2.2 says identity must not appear in a
	// Content-Encoding header — so it is recorded but never served.
	if meta.ContentEncoding != "" && !strings.EqualFold(meta.ContentEncoding, encodingIdentity) {
		h.Set("Content-Encoding", meta.ContentEncoding)
	}
	if meta.ETag != "" {
		h.Set("ETag", meta.ETag)
	}
	if meta.Size > 0 {
		h.Set("Content-Length", fmt.Sprintf("%d", meta.Size))
	}
	for k, v := range meta.ExtraHeaders {
		if v != "" {
			h.Set(k, v)
		}
	}
	return h
}

func releaseTimestamp(resp *http.Response) time.Time {
	if resp == nil {
		return time.Time{}
	}
	// NOTE: do not fall back to the HTTP "Date" response header — that is the
	// time the upstream served the artifact, not the time the artifact was
	// published. Using it causes the "released within N days" policy to
	// quarantine arbitrarily old packages the first time they are fetched.
	for _, key := range []string{
		"X-Artifact-Released-At",
		"X-Release-Date",
		"Last-Modified",
	} {
		value := strings.TrimSpace(resp.Header.Get(key))
		if value == "" {
			continue
		}
		if ts, err := http.ParseTime(value); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

func cloneHeader(src http.Header) http.Header {
	dst := make(http.Header, len(src))
	for k, values := range src {
		for _, v := range values {
			dst.Add(k, v)
		}
	}
	return dst
}

func stripConditionalHeaders(header http.Header) {
	if header == nil {
		return
	}
	conditional := []string{
		"If-None-Match",
		"If-Modified-Since",
		"If-Match",
		"If-Unmodified-Since",
		"If-Range",
	}
	for _, key := range conditional {
		header.Del(key)
	}
}

// addRevalidationHeaders attaches the PROXY's own conditional request
// headers, derived from the validators stored on the cached entry, and
// reports whether it added any.
//
// This is what turns an expired packument from a ~190KB re-fetch into a
// 304 with an empty body. Production metadata already carries what is
// needed: undici.meta holds an ETag (W/"616f...") and a Last-Modified in
// extra_headers, written by storeUpstream and — until now — never read.
//
// It is deliberately scoped to the same documents the TTL expires. On a
// genuine first-time miss there is no cached entry, so nothing is added
// and the fetch is unconditional; sending a conditional there could only
// produce a 304 with no cache to serve from.
func (f *facet) addRevalidationHeaders(ctx context.Context, logicalPath string, header http.Header) bool {
	if f == nil || f.storage == nil || header == nil || f.metadataTTL <= 0 {
		return false
	}
	if !isMutableDocument(f.format, logicalPath) {
		return false
	}
	content, err := f.storage.Get(ctx, logicalPath)
	if err != nil || content == nil {
		return false
	}
	added := false
	if etag := strings.TrimSpace(content.Metadata.ETag); etag != "" {
		header.Set("If-None-Match", etag)
		added = true
	}
	if lastModified := strings.TrimSpace(content.Metadata.ExtraHeaders["Last-Modified"]); lastModified != "" {
		header.Set("If-Modified-Since", lastModified)
		added = true
	}
	return added
}

// serveRevalidated answers a 304 from the cached copy, having first
// refreshed its CachedAt stamp.
//
// The refresh is not optional. Without it the entry's age is still past
// the TTL the instant this response is sent, so the very next request
// expires it again and revalidates again — a revalidation loop that
// costs one upstream round trip per hit forever. Refreshing the stamp is
// what makes the 304 worth anything.
//
// Unlike tryStaleCache this serves NO Warning: 110. A 304 is upstream
// stating the cached body is current, which is the opposite of stale.
//
// Returns nil when the entry has gone (evicted between the fetch and
// here), leaving the caller to pass the bare 304 through.
func (f *facet) serveRevalidated(ctx context.Context, logicalPath string) *Response {
	if f == nil || f.storage == nil {
		return nil
	}
	content, err := f.storage.Get(ctx, logicalPath)
	if err != nil || content == nil {
		f.logRevalidatedUnservable(logicalPath, err)
		return nil
	}
	meta := content.Metadata
	meta.CachedAt = time.Now().UTC()
	if updated, updErr := f.storage.UpdateMetadata(ctx, logicalPath, meta); updErr != nil {
		// Not fatal — the body we hold is confirmed current, so the
		// response is still correct. But the stamp did not move, so
		// this entry will revalidate again next request. Say so.
		if f.logger != nil {
			f.logger.Warn("revalidated entry but could not refresh its cache timestamp; it will revalidate again",
				"path", logicalPath, "error", updErr)
		}
	} else if updated != nil {
		content = updated
	}
	f.applyCoordinateMetadata(logicalPath, content)
	// Deliberately does NOT re-run the expiry check: if UpdateMetadata
	// failed above, tryCacheHit would call this entry expired, return a
	// miss, and leave the caller emitting a bare 304 to a client that
	// sent no conditional. Build the response directly.
	resp, respErr := f.respondFromCache(ctx, logicalPath, content, false)
	if respErr != nil || resp == nil {
		f.logRevalidatedUnservable(logicalPath, respErr)
		return nil
	}
	return resp
}

// logRevalidatedUnservable records why a 304-confirmed entry could not be
// served; the caller then fetches the whole document again.
func (f *facet) logRevalidatedUnservable(logicalPath string, err error) {
	if f.logger != nil {
		f.logger.Warn("revalidated entry could not be served from cache; refetching it whole",
			"path", logicalPath, "error", err)
	}
}

// tryStaleCache attempts to serve a previously cached copy of the artifact.
// Used as a fallback when the upstream is unreachable or returns a server error.
func (f *facet) tryStaleCache(ctx context.Context, logicalPath string) *Response {
	// A facet with no storage is a real configuration (and a real test
	// fixture); this is a fallback path, so a missing cache is "no stale
	// copy available", never a panic.
	if f == nil || f.storage == nil {
		return nil
	}
	content, err := f.storage.Get(ctx, logicalPath)
	if err != nil {
		return nil
	}
	headers := headersFromMetadata(content.Metadata)
	headers.Set("Warning", staleWarning)
	return &Response{
		StatusCode: http.StatusOK,
		Headers:    headers,
		Content:    content,
		FromCache:  !content.Metadata.Unverified,
	}
}

func (f *facet) UpdateRemote(remote RemoteDefinition) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remote = guardRemoteHeaders(sanitizeRemoteDefinition(remote))
}

func (f *facet) UpdateNegative(cache *cache.NegativeCache) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.negative = cache
}

func (f *facet) RemoteDefinition() RemoteDefinition {
	return f.currentRemote()
}

// RemoteURL is the upstream URL a fill of logicalPath fetches, after the
// format's URL mapper; "" when no upstream is configured. The publish gate
// probes upstream name existence through it, so the probe asks the host and
// path a client fill would (a hand-built URL missed the nuget flat container
// and the crates.io sparse index). It errors, like a fill would, when the
// resolved URL is not literal (pentest #9/#23/#29).
func (f *facet) RemoteURL(logicalPath string) (string, error) {
	remote := f.currentRemote()
	if remote.BaseURL == nil {
		return "", nil
	}
	return f.remoteURL(remote, logicalPath)
}

func (f *facet) currentRemote() RemoteDefinition {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return cloneRemoteDefinition(f.remote)
}

func (f *facet) currentNegative() *cache.NegativeCache {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.negative
}

func sanitizeRemoteDefinition(remote RemoteDefinition) RemoteDefinition {
	if remote.BaseURL != nil {
		copyURL := *remote.BaseURL
		remote.BaseURL = &copyURL
	}
	return remote
}

// guardRemoteHeaders gives remote a client that drops remote.Headers (the
// upstream's credentials) from any redirect hop whose scheme or host:port
// differs from the first request's. Go's client strips only Authorization,
// Cookie and WWW-Authenticate, and only on a domain change: a custom
// credential header (X-NuGet-ApiKey, X-JFrog-Art-Api) followed every
// redirect to any host, plain http included. The client's own redirect
// policy, or Go's default 10-hop limit, still applies after the strip.
func guardRemoteHeaders(remote RemoteDefinition) RemoteDefinition {
	if remote.Client == nil || len(remote.Headers) == 0 {
		return remote
	}
	names := make([]string, 0, len(remote.Headers))
	for k := range remote.Headers {
		names = append(names, k)
	}
	c := *remote.Client
	next := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && !SameOrigin(req.URL, via[0].URL) {
			for _, k := range names {
				req.Header.Del(k)
			}
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	remote.Client = &c
	return remote
}

// SameOrigin reports whether a and b share scheme and host:port, the port
// made explicit from the scheme's default: https://feed:443 is
// https://feed.
func SameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil || !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		switch strings.ToLower(u.Scheme) {
		case "https":
			return "443"
		case "http":
			return "80"
		}
		return ""
	}
	return port(a) == port(b)
}

func cloneRemoteDefinition(remote RemoteDefinition) RemoteDefinition {
	return sanitizeRemoteDefinition(remote)
}

// RemoteURLMapping captures overrides for remote fetches.
type RemoteURLMapping struct {
	Base        *url.URL
	LogicalPath string
	Query       string
}

// RemoteURLMapper allows formats to rewrite the remote host or path dynamically.
type RemoteURLMapper func(logicalPath string, base *url.URL) *RemoteURLMapping

type ResponseTransformer interface {
	ShouldTransform(logicalPath string, resp *http.Response) bool
	Transform(ctx context.Context, logicalPath string, body []byte) ([]byte, error)
}

func (f *facet) shouldForceHTML(logicalPath string) bool {
	if !strings.EqualFold(f.format, "pip") {
		return false
	}
	path := strings.TrimPrefix(strings.ToLower(logicalPath), "/")
	return strings.HasPrefix(path, "simple/")
}

func (f *facet) prepareBodyReader(ctx context.Context, logicalPath string, resp *http.Response) (io.Reader, error) {
	if f.rewriter == nil || !f.rewriter.ShouldTransform(logicalPath, resp) {
		return resp.Body, nil
	}
	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
	payload, release, err := readBodyWithEncoding(ctx, resp.Body, encoding, resp.ContentLength)
	defer release()
	// Too large to transform is refused, not served untransformed: the
	// first MaxTransformBodySize bytes are already consumed, so "the rest
	// of resp.Body" was a truncated document that got cached, and an
	// untransformed index points clients at the upstream around the proxy.
	if err != nil {
		return nil, err
	}
	transformed, err := f.rewriter.Transform(ctx, logicalPath, payload)
	if err != nil {
		return nil, fmt.Errorf("transform response: %w", err)
	}
	reader, err := encodeTransformedPayload(transformed, encoding)
	if err != nil {
		return nil, err
	}
	return reader, nil
}

// rewriteCachedContent applies the response transformer to a cache hit. The
// result is served from memory and memoised (rewriteMemo); it is never written
// back to the blob store, which used to happen on every hit from a host
// different from the last one, and let a concurrent request read the other
// host's rewrite. Returns (nil, nil) when the stored copy is served as is.
func (f *facet) rewriteCachedContent(ctx context.Context, logicalPath string, content *storage.CachedContent) (*storage.CachedContent, error) {
	if f.rewriter == nil || content == nil {
		return nil, nil
	}
	resp := &http.Response{Header: headersFromMetadata(content.Metadata)}
	if !f.rewriter.ShouldTransform(logicalPath, resp) {
		return nil, nil
	}
	memo := rewriteMemo()
	key := strings.Join([]string{
		f.repoName, storage.OrgFromContext(ctx), logicalPath,
		strconv.FormatInt(content.Metadata.CachedAt.UnixNano(), 10), content.Metadata.ETag,
		strconv.FormatInt(content.Metadata.Size, 10),
		BaseURLFromContext(ctx), OrgSlugFromContext(ctx),
	}, "\x00")
	if e, ok := memo.get(key); ok {
		if e.unchanged {
			return nil, nil
		}
		return storage.NewInMemoryContent(e.meta, e.data), nil
	}

	reader, err := content.Open()
	if err != nil {
		return nil, fmt.Errorf("open cached content: %w", err)
	}
	defer reader.Close()

	encoding := strings.ToLower(content.Metadata.ContentEncoding)
	payload, release, err := readBodyWithEncoding(ctx, reader, encoding, content.Metadata.Size)
	defer release()
	if errors.Is(err, errBodyTooLarge) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	transformed, err := f.rewriter.Transform(ctx, logicalPath, payload)
	if err != nil {
		return nil, fmt.Errorf("transform cached response: %w", err)
	}
	if bytes.Equal(payload, transformed) {
		memo.put(rewriteMemoEntry{key: key, unchanged: true})
		return nil, nil
	}
	encodedReader, err := encodeTransformedPayload(transformed, encoding)
	if err != nil {
		return nil, err
	}
	encoded, err := io.ReadAll(encodedReader)
	if err != nil {
		return nil, fmt.Errorf("encode cached response: %w", err)
	}
	out := storage.NewInMemoryContent(content.Metadata, encoded)
	memo.put(rewriteMemoEntry{key: key, meta: out.Metadata, data: encoded})
	return out, nil
}

func readBodyWithEncoding(ctx context.Context, body io.Reader, encoding string, sizeHint int64) ([]byte, func(), error) {
	switch encoding {
	case "gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			return nil, func() {}, fmt.Errorf("decode gzip response: %w", err)
		}
		defer zr.Close()
		payload, release, err := readTransformBody(ctx, zr, 0)
		if err != nil {
			return nil, release, fmt.Errorf("read gzip response: %w", err)
		}
		return payload, release, nil
	case "zstd":
		zr, err := zstd.NewReader(body)
		if err != nil {
			return nil, func() {}, fmt.Errorf("decode zstd response: %w", err)
		}
		defer zr.Close()
		payload, release, err := readTransformBody(ctx, zr, 0)
		if err != nil {
			return nil, release, fmt.Errorf("read zstd response: %w", err)
		}
		return payload, release, nil
	default:
		payload, release, err := readTransformBody(ctx, body, sizeHint)
		if err != nil {
			return nil, release, fmt.Errorf("read remote response: %w", err)
		}
		return payload, release, nil
	}
}

// ReadTransformBody reads a whole document of at most MaxTransformBodySize
// bytes, charged to the process-wide transform budget. Call release once
// the bytes are no longer needed; it is never nil and safe to call twice.
func ReadTransformBody(ctx context.Context, r io.Reader, sizeHint int64) ([]byte, func(), error) {
	return readTransformBody(ctx, r, sizeHint)
}

// readTransformBody reads at most maxTransformBodySize bytes, refusing
// more with errBodyTooLarge. The buffer starts at min(sizeHint,
// transformInitialAlloc) and grows by doubling; sizeHint is trusted once a
// quarter of it has arrived, so an honest length is not grown past and a
// lying one buys at most 4x the bytes really sent.
func readTransformBody(ctx context.Context, r io.Reader, sizeHint int64) ([]byte, func(), error) {
	lease := &transformLease{}
	r = io.LimitReader(r, maxTransformBodySize+1)
	size := 32 << 10
	if sizeHint > 0 {
		size = int(min(sizeHint+1, transformInitialAlloc))
	}
	if err := lease.reserve(ctx, size); err != nil {
		return nil, lease.release, err
	}
	buf := make([]byte, 0, size)
	for {
		if len(buf) == cap(buf) {
			if len(buf) > maxTransformBodySize {
				lease.release()
				return nil, lease.release, errBodyTooLarge
			}
			next := 2 * cap(buf)
			if sizeHint > int64(cap(buf)) && sizeHint <= 4*int64(len(buf)) {
				next = int(sizeHint) + 1
			}
			next = min(next, maxTransformBodySize+1)
			if err := lease.reserve(ctx, next); err != nil {
				lease.release()
				return nil, lease.release, err
			}
			grown := make([]byte, len(buf), next)
			copy(grown, buf)
			buf = grown
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			break
		}
		if err != nil {
			lease.release()
			return nil, lease.release, err
		}
	}
	if len(buf) > maxTransformBodySize {
		lease.release()
		return nil, lease.release, errBodyTooLarge
	}
	return buf, lease.release, nil
}

// transformLease is one read's share of transformBudget, in MiB.
type transformLease struct {
	sem  *semaphore.Weighted
	held int64
}

// reserve grows the lease to cover a buffer of n bytes.
func (l *transformLease) reserve(ctx context.Context, n int) error {
	if l.sem == nil {
		l.sem = transformBudget
	}
	need := (int64(n) + 1<<20 - 1) >> 20
	if need <= l.held {
		return nil
	}
	wctx, cancel := context.WithTimeout(ctx, transformBudgetWait)
	defer cancel()
	if err := l.sem.Acquire(wctx, need-l.held); err != nil {
		return fmt.Errorf("%w: %v", errTransformBudget, err)
	}
	l.held = need
	return nil
}

func (l *transformLease) release() {
	if l.held > 0 {
		l.sem.Release(l.held)
		l.held = 0
	}
}

func encodeTransformedPayload(data []byte, encoding string) (io.Reader, error) {
	switch encoding {
	case "gzip":
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(data); err != nil {
			return nil, fmt.Errorf("encode gzip response: %w", err)
		}
		if err := zw.Close(); err != nil {
			return nil, fmt.Errorf("finalize gzip response: %w", err)
		}
		return bytes.NewReader(buf.Bytes()), nil
	case "zstd":
		var buf bytes.Buffer
		zw, err := zstd.NewWriter(&buf)
		if err != nil {
			return nil, fmt.Errorf("init zstd writer: %w", err)
		}
		if _, err := zw.Write(data); err != nil {
			zw.Close()
			return nil, fmt.Errorf("encode zstd response: %w", err)
		}
		if err := zw.Close(); err != nil {
			return nil, fmt.Errorf("finalize zstd response: %w", err)
		}
		return bytes.NewReader(buf.Bytes()), nil
	default:
		return bytes.NewReader(data), nil
	}
}

// upstreamQueryKey carries a sanitised query string to fetchFromRemote.
type upstreamQueryKey struct{}

// dockerManifestAccept is every manifest media type, schema1 last. A tag
// fetched with a narrow client's Accept cached a single-platform manifest
// (or a 404) for every client after it.
const dockerManifestAccept = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.docker.distribution.manifest.v2+json, " +
	"application/vnd.docker.distribution.manifest.v1+prettyjws"

// sharedUpstreamAccept is the Accept the facet sends for a document whose
// upstream variant depends on it, or "" to forward the client's.
func sharedUpstreamAccept(format, logicalPath string) string {
	switch strings.ToLower(format) {
	case "docker", "homebrew":
		if s := registryV2Segments(logicalPath); s != nil && s[len(s)-2] == "manifests" {
			return dockerManifestAccept
		}
	case "npm", "yarn", "bun":
		// The full packument: an abbreviated one cached by the first npm
		// client lacks fields (time, ...) other clients and policy read.
		if isMutableDocument(format, logicalPath) {
			return "application/json"
		}
	}
	return ""
}

// registryV2Segments returns the lowercased segments of a registry-v2 path
// ("v2/<name...>/<kind>/<ref>"), or nil.
func registryV2Segments(logicalPath string) []string {
	segments := strings.Split(strings.ToLower(strings.TrimPrefix(logicalPath, "/")), "/")
	if len(segments) < 4 || segments[0] != "v2" {
		return nil
	}
	return segments
}

func isTagsListPath(format, logicalPath string) bool {
	switch strings.ToLower(format) {
	case "docker", "homebrew":
	default:
		return false
	}
	s := registryV2Segments(logicalPath)
	return s != nil && s[len(s)-2] == "tags" && s[len(s)-1] == "list"
}

// tagsListPageQuery returns the pagination query (n and last only,
// encoded) of a tags/list request, or "" for anything else.
func tagsListPageQuery(format, logicalPath, rawQuery string) string {
	if rawQuery == "" || !isTagsListPath(format, logicalPath) {
		return ""
	}
	return paginationQuery(rawQuery)
}

func paginationQuery(rawQuery string) string {
	parsed, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}
	keep := url.Values{}
	for _, k := range []string{"n", "last"} {
		if v := parsed.Get(k); v != "" {
			keep.Set(k, v)
		}
	}
	return keep.Encode()
}

// rewriteTagsListLink points an upstream tags/list "next" Link back at this
// proxy path: a relative "?query" reference resolves against whatever URL
// the client used. A Link it cannot rewrite is dropped, never passed on.
func rewriteTagsListLink(extra map[string]string) {
	link, ok := extra["Link"]
	if !ok {
		return
	}
	delete(extra, "Link")
	start, end := strings.IndexByte(link, '<'), strings.IndexByte(link, '>')
	if start < 0 || end < start {
		return
	}
	target, err := url.Parse(link[start+1 : end])
	if err != nil {
		return
	}
	if q := paginationQuery(target.RawQuery); q != "" {
		extra["Link"] = "<?" + q + ">" + link[end+1:]
	}
}

// fetchTagsPage fetches one tags/list page upstream and serves it from
// memory without storing it.
func (f *facet) fetchTagsPage(ctx context.Context, req *Request, logicalPath, query string) (*Response, error) {
	remote := f.currentRemote()
	if remote.BaseURL == nil || remote.Client == nil {
		return &Response{StatusCode: http.StatusNotFound, Headers: make(http.Header)}, nil
	}
	if f.circuitBreaker != nil && !f.circuitBreaker.Allow() {
		return nil, ErrCircuitOpen
	}
	header := cloneHeader(req.Header)
	stripConditionalHeaders(header)
	header.Del("Range")
	resp, err := f.fetchWithRetry(context.WithValue(ctx, upstreamQueryKey{}, query), remote, logicalPath, header)
	if err != nil {
		if f.circuitBreaker != nil {
			f.circuitBreaker.RecordNetworkFailure(err)
		}
		recordUpstreamError(f.format)
		return nil, err
	}
	defer resp.Body.Close()
	f.recordCircuitOutcome(resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return &Response{StatusCode: resp.StatusCode, Headers: cloneHeader(resp.Header)}, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTransformBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("read tags page: %w", err)
	}
	if len(body) > maxTransformBodySize {
		return nil, fmt.Errorf("tags page: %w", errBodyTooLarge)
	}
	meta := storage.ContentMetadata{
		LogicalPath:  logicalPath,
		ContentType:  resp.Header.Get("Content-Type"),
		ETag:         resp.Header.Get("ETag"),
		CachedAt:     time.Now().UTC(),
		ExtraHeaders: captureExtraHeaders(resp.Header),
	}
	rewriteTagsListLink(meta.ExtraHeaders)
	content := storage.NewInMemoryContent(meta, body)
	return &Response{StatusCode: http.StatusOK, Headers: headersFromMetadata(content.Metadata), Content: content}, nil
}
