package intelligence

// Asynchronous transitive-dependency Scan enqueuer.
//
// When the scanner finishes a parent package the new Wave-5 dependency
// section is already populated by registrymetadata. This file walks
// that list, resolves each dep to a concrete latest version via the
// upstream registry, and fires a detached `Scan` goroutine for every
// dep we haven't seen yet. Each child Scan re-enters the same enqueuer
// when it completes, so the dep tree fans out automatically — the
// recursion is depth-bounded via a context value to keep runaway fan-
// out off popular packages with hundreds of leaves.
//
// Children scan with `req.Artifact` populated when the upstream tarball
// is small enough, so the same Tier-1 + Tier-2 + risk-evaluation
// pipeline that runs for the user-installed parent runs for every
// transitive too. The whole walk happens in detached goroutines —
// the user's install response is never waiting on this.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
)

// maxAutoDepDepth bounds the recursion. With depth 0 == the parent,
// 1 = direct deps, 2 = grand-deps. Enough to surface "your tree has a
// vulnerable dep two hops away" without spawning thousands of scans
// for popular libraries.
const maxAutoDepDepth = 2

// autoDepFanoutCap is the per-Scan limit on how many child enqueues
// we'll fire. Protects against degenerate manifests with thousands of
// listed deps. The hot 95th-percentile package has ~30.
const autoDepFanoutCap = 64

// autoDepArtifactCap caps how big a transitive tarball we'll spool
// into RAM for the artifact follow-up. Same value as the proxy hot-
// path follow-up so memory pressure is bounded.
const autoDepArtifactCap = 32 * 1024 * 1024

// autoDepResolveTimeout is the upper bound on each "resolve latest"
// upstream call. The scan happens detached, but the resolve step
// blocks the enqueuer's goroutine briefly — keep it tight.
const autoDepResolveTimeout = 6 * time.Second

// autoDepScanDeadline is the per-child Scan deadline, generous enough
// to cover the synchronous Scan call (Tier-1 fan-out) plus the async
// follow-up Scan with the fetched artifact.
const autoDepScanDeadline = 90 * time.Second

type depDepthKey struct{}

func depthFromCtx(ctx context.Context) int {
	if ctx == nil {
		return 0
	}
	v, _ := ctx.Value(depDepthKey{}).(int)
	return v
}

func withDepDepth(ctx context.Context, depth int) context.Context {
	return context.WithValue(ctx, depDepthKey{}, depth)
}

// enqueueDependencyScans walks Report.Dependencies and fires a detached
// Scan for each previously-unseen dep. Bounded by maxAutoDepDepth +
// autoDepFanoutCap. No-op when the report has no deps, the scanner has
// no store, or we're already at max depth.
func (s *DefaultService) enqueueDependencyScans(parentCtx context.Context, parent *Report) {
	if s == nil || parent == nil || s.store == nil {
		return
	}
	depth := depthFromCtx(parentCtx)
	if depth >= maxAutoDepDepth {
		return
	}

	// Combine Direct + Peer (peer deps are a runtime requirement) but
	// skip Dev (test-only) and Optional (rarely installed) so we don't
	// burn fan-out on rarely-loaded code.
	candidates := make([]DependencyRef, 0,
		len(parent.Dependencies.Direct)+len(parent.Dependencies.Peer))
	candidates = append(candidates, parent.Dependencies.Direct...)
	candidates = append(candidates, parent.Dependencies.Peer...)
	if len(candidates) == 0 {
		return
	}
	if len(candidates) > autoDepFanoutCap {
		candidates = candidates[:autoDepFanoutCap]
	}

	parentEcosystem := parent.Identity.Ecosystem

	// Per-Scan dedup so the same dep appearing under multiple buckets
	// doesn't double-fire.
	seen := make(map[string]struct{}, len(candidates))
	var wg sync.WaitGroup
	for _, dep := range candidates {
		eco := strings.TrimSpace(dep.Ecosystem)
		if eco == "" {
			eco = parentEcosystem
		}
		name := strings.TrimSpace(dep.Name)
		if name == "" {
			continue
		}
		// Latest is a useful sentinel but useless as a cache key —
		// resolve to a concrete version below before scanning. Skip
		// ecosystems we know we can't resolve.
		if !canAutoResolve(eco) {
			continue
		}
		key := strings.ToLower(eco) + "|" + name
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		wg.Add(1)
		go func(eco, name string) {
			defer wg.Done()
			s.scanTransitiveDep(eco, name, depth+1)
		}(eco, name)
	}
	// Don't block the parent on the children — fire-and-forget. The
	// wg is here for tests that want to await completion via
	// AwaitTransitiveDeps. Production callers don't wait.
}

// scanTransitiveDep is the per-dep worker fired by enqueueDependencyScans.
// It resolves the latest version, optionally fetches the tarball, and
// invokes Scan against the same DefaultService instance — so the cache,
// singleflight, and recursive enqueue chain all engage automatically.
func (s *DefaultService) scanTransitiveDep(eco, name string, depth int) {
	parent := s.bg
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, autoDepScanDeadline)
	defer cancel()
	ctx = withDepDepth(ctx, depth)

	version := s.resolveLatestVersion(ctx, eco, name)
	if version == "" {
		return
	}

	// Bail fast when a fresh cache entry already exists. We let stale
	// cache fall through so they get refreshed via the normal Scan
	// path, which is consistent with how stale-while-revalidate works.
	if s.store != nil {
		if cached, err := s.store.Get(ctx, "", Key{Ecosystem: eco, Package: name, Version: version}); err == nil && cached != nil {
			age := s.now().Sub(cached.Observation.CollectedAt)
			if age < DefaultMaxStaleness {
				// Still propagate the recursion when grand-children
				// haven't been seen yet — the cached parent might be
				// older than the latest dep section.
				s.enqueueDependencyScans(ctx, cached)
				return
			}
		}
	}

	req := Request{
		Key:   Key{Ecosystem: eco, Package: name, Version: version},
		OrgID: "",
		Options: Options{
			RefreshReason: "transitive_auto",
			AllowStale:    false,
		},
	}
	if handle := s.tryFetchArtifact(ctx, eco, name, version); handle != nil {
		req.Artifact = handle
	}

	if _, err := s.Scan(ctx, req); err != nil && s.logger != nil {
		s.logger.Debug("transitive dep scan failed",
			"ecosystem", eco, "package", name, "version", version, "depth", depth, "err", err)
	}
}

// canAutoResolve gates which ecosystems we'll auto-fetch latest
// versions for. Mirrors the registrymetadata coverage list — packages
// outside this set wouldn't pick up a useful Report from a Scan
// anyway.
func canAutoResolve(eco string) bool {
	switch strings.ToLower(eco) {
	case "npm", "yarn", "bun", "pypi", "pip", "cargo", "rubygems":
		return true
	}
	// Maven / NuGet / Composer require version search APIs that don't
	// have a stable "latest" endpoint we can hit cheaply. Skip until
	// we add per-ecosystem version-resolver support.
	return false
}

// resolveLatestVersion makes a single registry call to discover the
// latest published version of a package. Returns empty string when
// the registry is unreachable, the package doesn't exist, or the
// ecosystem is unsupported.
func (s *DefaultService) resolveLatestVersion(ctx context.Context, eco, name string) string {
	resolveCtx, cancel := context.WithTimeout(ctx, autoDepResolveTimeout)
	defer cancel()
	switch strings.ToLower(eco) {
	case "npm", "yarn", "bun":
		return resolveNpmLatest(resolveCtx, name)
	case "pypi", "pip":
		return resolvePyPILatest(resolveCtx, name)
	case "cargo":
		return resolveCargoLatest(resolveCtx, name)
	case "rubygems":
		return resolveRubyGemsLatest(resolveCtx, name)
	}
	return ""
}

// tryFetchArtifact pulls the upstream tarball into RAM so the child
// Scan's Tier-2 providers run. Returns nil on any failure or when the
// artifact exceeds the cap — a nil handle just means Tier-2 stays
// empty for this dep.
func (s *DefaultService) tryFetchArtifact(ctx context.Context, eco, name, version string) *ArtifactHandle {
	url, mediaType := artifactURLFor(eco, name, version)
	if url == "" {
		return nil
	}
	fetchCtx, cancel := context.WithTimeout(ctx, autoDepResolveTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "chainsaw-intelligence-deps/1")
	resp, err := autoDepHTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, autoDepArtifactCap+1))
	if err != nil {
		return nil
	}
	if int64(len(body)) > autoDepArtifactCap {
		return nil
	}
	return &ArtifactHandle{Bytes: body, MediaType: mediaType}
}

var autoDepHTTPClient = httpclient.New(httpclient.WithTimeout(autoDepResolveTimeout))

// artifactURLFor returns the canonical tarball URL + Content-Type for
// the given coordinate. Empty url means we don't know how to fetch
// this ecosystem's artifact.
func artifactURLFor(eco, name, version string) (string, string) {
	switch strings.ToLower(eco) {
	case "npm", "yarn", "bun":
		// npm pattern: registry.npmjs.org/{pkg}/-/{basename}-{ver}.tgz
		// Scoped packages (@scope/name) drop the @scope/ prefix from the
		// tarball basename: @babel/core → core-7.0.0.tgz.
		basename := name
		if i := strings.Index(name, "/"); i >= 0 {
			basename = name[i+1:]
		}
		path := fmt.Sprintf("%s/-/%s-%s.tgz", encodeNPMPackage(name), basename, version)
		return "https://registry.npmjs.org/" + path, "application/x-tar"
	case "pypi", "pip":
		// PyPI's flat layout requires hitting /pypi/{pkg}/{ver}/json to
		// find the file URL. Skip in this MVP — Tier-2 will simply not
		// run for transitive PyPI deps until we cache the file URL
		// during resolveLatest.
		return "", ""
	case "cargo":
		return fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s/download", url.PathEscape(name), url.PathEscape(version)), "application/x-tar"
	case "rubygems":
		return fmt.Sprintf("https://rubygems.org/gems/%s-%s.gem", url.PathEscape(name), url.PathEscape(version)), "application/octet-stream"
	}
	return "", ""
}

// -- per-ecosystem latest-version resolvers ---------------------------

func resolveNpmLatest(ctx context.Context, name string) string {
	endpoint := "https://registry.npmjs.org/" + encodeNPMPackage(name)
	var pack struct {
		DistTags map[string]string `json:"dist-tags"`
	}
	if err := autoDepGetJSON(ctx, endpoint, &pack); err != nil {
		return ""
	}
	return strings.TrimSpace(pack.DistTags["latest"])
}

func resolvePyPILatest(ctx context.Context, name string) string {
	endpoint := "https://pypi.org/pypi/" + url.PathEscape(name) + "/json"
	var pack struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := autoDepGetJSON(ctx, endpoint, &pack); err != nil {
		return ""
	}
	return strings.TrimSpace(pack.Info.Version)
}

func resolveCargoLatest(ctx context.Context, name string) string {
	endpoint := "https://crates.io/api/v1/crates/" + url.PathEscape(name)
	var pack struct {
		Crate struct {
			MaxStableVersion string `json:"max_stable_version"`
			MaxVersion       string `json:"max_version"`
			NewestVersion    string `json:"newest_version"`
		} `json:"crate"`
	}
	if err := autoDepGetJSON(ctx, endpoint, &pack); err != nil {
		return ""
	}
	for _, candidate := range []string{pack.Crate.MaxStableVersion, pack.Crate.NewestVersion, pack.Crate.MaxVersion} {
		if v := strings.TrimSpace(candidate); v != "" {
			return v
		}
	}
	return ""
}

func resolveRubyGemsLatest(ctx context.Context, name string) string {
	endpoint := "https://rubygems.org/api/v1/gems/" + url.PathEscape(name) + ".json"
	var pack struct {
		Version string `json:"version"`
	}
	if err := autoDepGetJSON(ctx, endpoint, &pack); err != nil {
		return ""
	}
	return strings.TrimSpace(pack.Version)
}

// autoDepGetJSON is a tight HTTP+JSON fetcher local to the enqueuer so
// it doesn't share state with the registrymetadata provider's client
// (different timeout regime; we want resolution to fail fast).
func autoDepGetJSON(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "chainsaw-intelligence-deps/1")
	resp, err := autoDepHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("not found")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, 8<<20)
	return json.NewDecoder(limited).Decode(out)
}
