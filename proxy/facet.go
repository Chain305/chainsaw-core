package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sync/singleflight"

	"github.com/chain305/chainsaw-core/cache"
	"github.com/chain305/chainsaw-core/formats/common"
	"github.com/chain305/chainsaw-core/index"
	"github.com/chain305/chainsaw-core/storage"
)

const maxTransformBodySize = 50 << 20 // 50 MiB

var errBodyTooLarge = errors.New("response body exceeds transform size limit")

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
	"dnf": {}, "docker": {}, "go": {}, "gradle": {}, "huggingface": {},
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

// Request mirrors the arguments expected by ProxyFacetSupport.get(...)
type Request struct {
	LogicalPath string
	Method      string
	Header      http.Header
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
		remote:             cfg.Remote,
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
	return &Response{
		StatusCode: http.StatusOK,
		Headers:    headers,
		Content:    content,
		FromCache:  true,
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
		return result.Val.(*Response), nil
	}
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

	if handled, resp := f.handleUpstreamStatus(fetchCtx, logicalPath, cacheKey, remoteResp); handled {
		return resp, nil
	}

	return f.storeUpstream(fetchCtx, remote, logicalPath, remoteResp)
}

// recordCircuitOutcome feeds upstream status codes back into the
// circuit breaker: 5xx bumps the failure counter, <400 bumps success.
// 4xx status codes are intentionally ignored — they're client errors,
// not upstream health signals.
func (f *facet) recordCircuitOutcome(status int) {
	if f.circuitBreaker == nil {
		return
	}
	if status >= 500 {
		f.circuitBreaker.RecordFailure()
	} else if status < 400 {
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
	meta := storage.ContentMetadata{
		ContentType:     remoteResp.Header.Get("Content-Type"),
		ContentEncoding: recordedContentEncoding(remoteResp.Header.Get("Content-Encoding")),
		ETag:            remoteResp.Header.Get("ETag"),
		OriginURL:       f.remoteURL(remote, logicalPath),
		ReleasedAt:      releaseTimestamp(remoteResp),
		CachedAt:        time.Now().UTC(),
		ExtraHeaders:    captureExtraHeaders(remoteResp.Header),
	}
	if coord, ok := f.describe(logicalPath); ok {
		meta.PackageName = coord.Name
		meta.PackageVersion = coord.Version
		meta.PackageSubtype = coord.Subtype
		if f.index != nil {
			_ = f.index.Record(f.repoName, index.PackageCoordinate{
				Package: coord.Name,
				Version: coord.Version,
				Format:  string(coord.Format),
			}, logicalPath)
		}
	}

	if resp := f.serveInternalOverride(fetchCtx, logicalPath, meta); resp != nil {
		return resp, nil
	}

	bodyReader, prepErr := f.prepareBodyReader(fetchCtx, logicalPath, remoteResp)
	if prepErr != nil {
		return nil, prepErr
	}

	saved, putErr := f.storage.Put(fetchCtx, logicalPath, bodyReader, meta)
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

// serveInternalOverride returns the cached internal copy when the
// upstream response would otherwise overwrite an internally published
// package, preventing upstream content from clobbering internal
// publishes. Returns nil when no override applies (no checker, missing
// coords, not internal, or internal version is in DB but missing from
// storage — in which case we fall through to the normal store path).
func (f *facet) serveInternalOverride(fetchCtx context.Context, logicalPath string, meta storage.ContentMetadata) *Response {
	if f.internalChecker == nil || meta.PackageName == "" || meta.PackageVersion == "" {
		return nil
	}
	orgID := OrgIDFromContext(fetchCtx)
	if !f.internalChecker.IsInternalVersion(orgID, f.repoName, meta.PackageName, meta.PackageVersion) {
		return nil
	}
	f.logger.Info("skipping upstream store for internal package",
		"package", meta.PackageName, "version", meta.PackageVersion)
	// Serve from existing internal storage.
	internal, intErr := f.storage.Get(fetchCtx, logicalPath)
	if intErr != nil {
		// Internal version exists in DB but not in storage — unusual. Fall through.
		return nil
	}
	return &Response{
		StatusCode: http.StatusOK,
		Headers:    headersFromMetadata(internal.Metadata),
		Content:    internal,
		FromCache:  true,
	}
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
// circuit breaker open.
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

		// Close the previous response body before retrying.
		if resp != nil {
			resp.Body.Close()
		}

		if f.upstreamTracker != nil {
			f.upstreamTracker.RecordRetry()
		}

		// Wait with jitter before retrying.
		delay := backoff[attempt]
		jitter := time.Duration(int64(delay) / 10) // 10% jitter
		if jitter > 0 {
			delay += time.Duration(time.Now().UnixNano() % int64(jitter))
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

func isRetryableStatus(status int) bool {
	return status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout ||
		status == http.StatusTooManyRequests
}

func (f *facet) fetchFromRemote(ctx context.Context, remote RemoteDefinition, logicalPath string, header http.Header) (*http.Response, error) {
	remoteURL := f.remoteURL(remote, logicalPath)
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
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Authorization") {
			continue
		}
		if forceHTML && strings.EqualFold(k, "Accept") {
			continue
		}
		if needsTransform && strings.EqualFold(k, "Accept-Encoding") {
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
	}
	return remote.Client.Do(req)
}

func (f *facet) remoteURL(remote RemoteDefinition, logicalPath string) string {
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
	ref := &url.URL{
		Path: strings.TrimPrefix(logicalPath, "/"),
	}
	if query != "" {
		ref.RawQuery = query
	}
	return base.ResolveReference(ref).String()
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
	if meta.ContentEncoding != "" {
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
		return nil
	}
	return resp
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
		FromCache:  true,
	}
}

func (f *facet) UpdateRemote(remote RemoteDefinition) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.remote = sanitizeRemoteDefinition(remote)
}

func (f *facet) UpdateNegative(cache *cache.NegativeCache) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.negative = cache
}

func (f *facet) RemoteDefinition() RemoteDefinition {
	return f.currentRemote()
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
	payload, err := readBodyWithEncoding(resp.Body, encoding)
	if errors.Is(err, errBodyTooLarge) {
		f.logger.Debug("skipping transformation: response body too large", "path", logicalPath)
		return resp.Body, nil
	}
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

func (f *facet) rewriteCachedContent(ctx context.Context, logicalPath string, content *storage.CachedContent) (*storage.CachedContent, error) {
	if f.rewriter == nil || content == nil {
		return nil, nil
	}
	resp := &http.Response{Header: headersFromMetadata(content.Metadata)}
	if !f.rewriter.ShouldTransform(logicalPath, resp) {
		return nil, nil
	}
	reader, err := content.Open()
	if err != nil {
		return nil, fmt.Errorf("open cached content: %w", err)
	}
	defer reader.Close()

	encoding := strings.ToLower(content.Metadata.ContentEncoding)
	payload, err := readBodyWithEncoding(reader, encoding)
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
		return nil, nil
	}
	encoded, err := encodeTransformedPayload(transformed, encoding)
	if err != nil {
		return nil, err
	}
	meta := content.Metadata
	meta.CachedAt = content.Metadata.CachedAt
	updated, err := f.storage.Put(ctx, logicalPath, encoded, meta)
	if err != nil {
		return nil, fmt.Errorf("rewrite cached content: %w", err)
	}
	return updated, nil
}

func readBodyWithEncoding(body io.Reader, encoding string) ([]byte, error) {
	limit := int64(maxTransformBodySize + 1)
	switch encoding {
	case "gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("decode gzip response: %w", err)
		}
		defer zr.Close()
		payload, err := io.ReadAll(io.LimitReader(zr, limit))
		if err != nil {
			return nil, fmt.Errorf("read gzip response: %w", err)
		}
		if len(payload) > maxTransformBodySize {
			return nil, errBodyTooLarge
		}
		return payload, nil
	case "zstd":
		zr, err := zstd.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("decode zstd response: %w", err)
		}
		defer zr.Close()
		payload, err := io.ReadAll(io.LimitReader(zr, limit))
		if err != nil {
			return nil, fmt.Errorf("read zstd response: %w", err)
		}
		if len(payload) > maxTransformBodySize {
			return nil, errBodyTooLarge
		}
		return payload, nil
	default:
		payload, err := io.ReadAll(io.LimitReader(body, limit))
		if err != nil {
			return nil, fmt.Errorf("read remote response: %w", err)
		}
		if len(payload) > maxTransformBodySize {
			return nil, errBodyTooLarge
		}
		return payload, nil
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
