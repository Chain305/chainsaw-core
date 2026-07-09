package typosquat

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// goTopSeed is the embedded fallback popular-modules list for Go. Used when
// no live deps.dev top-modules API is reachable (today there is no stable
// public top-N endpoint — see seeds/go_top.txt). Refreshed manually per the
// header comment in that file.
//
//go:embed seeds/go_top.txt
var goTopSeed []byte

// cocoapodsTopSeed is the embedded fallback popular-pods list for Cocoapods.
// CocoaPods trunk has no public top-N endpoint; we ship a curated list and
// refresh it out-of-band. See seeds/cocoapods_top.txt.
//
//go:embed seeds/cocoapods_top.txt
var cocoapodsTopSeed []byte

// pubTopSeed is the embedded fallback popular-packages list for Dart/pub.dev.
// pub.dev exposes per-package score endpoints but no stable public top-N
// list, so we ship a curated list and refresh it out-of-band. See
// seeds/pub_top.txt.
//
//go:embed seeds/pub_top.txt
var pubTopSeed []byte

// cargoTopSeed is the embedded fallback popular-crates list for Cargo.
// fetchCargo prefers crates.io's live download-ranked API, but falls back
// to this curated seed when the network is unreachable or returns empty
// (air-gapped deployments, the install hot path). See seeds/cargo_top.txt.
//
//go:embed seeds/cargo_top.txt
var cargoTopSeed []byte

// rubygemsTopSeed is the embedded fallback popular-gems list for RubyGems.
// fetchRubyGems prefers rubygems.org's live search API, but falls back to
// this curated seed when the network is unreachable or returns empty. See
// seeds/rubygems_top.txt.
//
//go:embed seeds/rubygems_top.txt
var rubygemsTopSeed []byte

// Fetcher retrieves popular packages from upstream registry APIs.
type Fetcher struct {
	client *http.Client
	logger *slog.Logger
}

// maxPaginatedRequests limits the number of HTTP requests per ecosystem fetch.
const maxPaginatedRequests = 100

// maxFetchLimit caps the popular package fetch limit to prevent unbounded requests.
const maxFetchLimit = 10000

// minPlausiblePopularPackages is a sanity floor on the size of a single
// registry response body's package count. A tampered upstream that strips
// the feed down to a handful of entries would otherwise poison the typosquat
// index by making real popular packages look unpopular (and therefore not
// flagged when a close-distance name is published). Responses below this
// floor are treated as a fetch failure so the index retains the last-good
// state rather than degrading silently. The value is deliberately small —
// every registry we hit returns thousands of results on the first page.
const minPlausiblePopularPackages = 25

// ErrSuspiciousRegistryResponse is returned when a registry response fails a
// post-TLS integrity guard (unexpected host after redirect, scheme downgrade,
// implausibly small package count). Callers log and keep the previous index.
var ErrSuspiciousRegistryResponse = errors.New("typosquat: suspicious registry response")

// allowedRegistryHosts is the closed set of upstream hosts the popular-package
// fetcher is allowed to talk to. Any redirect off this list is treated as a
// tampering signal and the response is rejected.
//
// Integrity model (see MIGRATIONS.md §"Vendored data files"): the popular-
// package feeds are live, high-volume, and change daily, so a SHA256 pin is
// not workable here — a legitimate refresh invalidates the pin every time.
// Instead we harden the transport:
//
//  1. Require TLS 1.2+ on every hop.
//  2. Enforce an HTTPS-only scheme (the base URLs below are HTTPS; redirects
//     to plain HTTP are rejected by enforceRequestSafety in CheckRedirect).
//  3. Pin the set of hosts we'll follow redirects to (this map). A DNS or
//     middlebox attacker that rewrites a response to a lookalike host is
//     caught here.
//  4. Sanity-floor the decoded result count (minPlausiblePopularPackages).
//     A tampered response that shrinks the feed to "just the attacker's
//     typosquats plus a handful of real names" no longer poisons the index;
//     the fetch fails and the previous in-memory index is retained.
var allowedRegistryHosts = map[string]struct{}{
	"registry.npmjs.org": {},
	// PyPI popular-packages JSON moved from hugovk.github.io to the
	// maintainer's personal domain hugovk.dev (github.io now 301-redirects
	// there). We keep the github.io entry in the allowlist so an upstream
	// revert is handled gracefully, but the primary URL in fetchPyPI targets
	// hugovk.dev to avoid the redirect hop + its associated post-redirect
	// allowlist re-check.
	"hugovk.dev":                 {},
	"hugovk.github.io":           {},
	"crates.io":                  {},
	"packagist.org":              {},
	"rubygems.org":               {},
	"azuresearch-usnc.nuget.org": {},
	"huggingface.co":             {},
	"search.maven.org":           {},
}

// FetcherOption customises Fetcher construction. Options are additive
// and may be combined — the zero-option call preserves the pre-existing
// behaviour so every existing call site compiles unchanged.
type FetcherOption func(*Fetcher)

// WithHTTPClient injects a pre-built *http.Client that Fetcher will
// use for every outbound registry request. Useful for threading in a
// shared internal/upstreamhttp.Client so every registry fetch across
// the process picks up the shared per-host rate limiter + 429 retry
// behaviour. Callers are responsible for preserving the redirect
// allowlist when they bring their own client — the default client
// constructed below installs the CheckRedirect guard for you.
func WithHTTPClient(client *http.Client) FetcherOption {
	return func(f *Fetcher) {
		if client != nil {
			f.client = client
		}
	}
}

// NewFetcher creates a popular package fetcher. Callers that want to
// route through a shared upstreamhttp.Client pass WithHTTPClient; the
// no-option path constructs the same TLS-hardened + redirect-guarded
// client it did before so existing call sites don't change behaviour.
func NewFetcher(logger *slog.Logger, opts ...FetcherOption) *Fetcher {
	if logger == nil {
		logger = slog.Default()
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Require modern TLS. The registries we talk to all support 1.3; 1.2 is
	// kept as a floor to avoid surprise breakage if one endpoint lags.
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	f := &Fetcher{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				// Reject scheme downgrade and off-allowlist hops. A rogue
				// redirect is one of the cheaper MITM primitives against a
				// fetcher that only validates the initial URL.
				return enforceRequestSafety(req.URL)
			},
		},
		logger: logger,
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// enforceRequestSafety validates a URL about to be fetched. It rejects
// non-HTTPS schemes and any host outside allowedRegistryHosts. Called both
// on the original request and on every redirect hop. Wraps
// ErrSuspiciousRegistryResponse so callers can distinguish tampering from
// ordinary network errors.
func enforceRequestSafety(u *url.URL) error {
	if u == nil {
		return fmt.Errorf("%w: nil URL", ErrSuspiciousRegistryResponse)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%w: non-HTTPS scheme %q", ErrSuspiciousRegistryResponse, u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if _, ok := allowedRegistryHosts[host]; !ok {
		return fmt.Errorf("%w: host %q is not in allowlist", ErrSuspiciousRegistryResponse, host)
	}
	return nil
}

// FetchPopularPackages retrieves the top-N popular packages for an ecosystem.
// Returns nil if the ecosystem doesn't have a supported popularity API.
//
// Integrity posture: responses are transport-hardened (HTTPS, allowlisted
// hosts, TLS 1.2+, redirect allowlist) and the final package count is
// sanity-floored against minPlausiblePopularPackages to reject tampered
// feeds. See the package doc comment and MIGRATIONS.md §"Vendored data files"
// for the full model.
func (f *Fetcher) FetchPopularPackages(ctx context.Context, ecosystem string, limit int) ([]PopularPackage, error) {
	if limit > maxFetchLimit {
		limit = maxFetchLimit
	}
	if limit <= 0 {
		return nil, nil
	}
	ecosystem = strings.ToLower(ecosystem)
	var (
		pkgs []PopularPackage
		err  error
	)
	switch ecosystem {
	case "npm":
		pkgs, err = f.fetchNPM(ctx, limit)
	case "pip", "pypi":
		pkgs, err = f.fetchPyPI(ctx, limit)
	case "cargo":
		pkgs, err = f.fetchCargo(ctx, limit)
	case "composer":
		pkgs, err = f.fetchComposer(ctx, limit)
	case "rubygems":
		pkgs, err = f.fetchRubyGems(ctx, limit)
	case "nuget":
		pkgs, err = f.fetchNuGet(ctx, limit)
	case "huggingface":
		pkgs, err = f.fetchHuggingFace(ctx, limit)
	case "maven", "gradle":
		// Gradle artifacts are published to Maven repositories and share
		// the group:artifact coordinate space, so the Maven popular-package
		// list is the correct source for both ecosystems.
		pkgs, err = f.fetchMaven(ctx, limit)
	case "go", "gomod":
		// deps.dev exposes per-module queries but no public top-N list as
		// of PR 4. Read the embedded curated seed file; see goTopSeed's
		// doc comment for the refresh cadence. This keeps the detector
		// bootstrap deterministic in air-gapped deployments while leaving
		// the door open to swap in a live fetcher later.
		pkgs, err = f.fetchSeed(ctx, goTopSeed, limit)
	case "cocoapods":
		// CocoaPods trunk has no documented top-N endpoint; rely on the
		// embedded seed for now.
		pkgs, err = f.fetchSeed(ctx, cocoapodsTopSeed, limit)
	case "pub":
		// pub.dev has no documented top-N endpoint; rely on the embedded
		// seed for now (same posture as Go/CocoaPods).
		pkgs, err = f.fetchSeed(ctx, pubTopSeed, limit)
	default:
		return nil, nil // no API available
	}
	if err != nil {
		return nil, err
	}
	// Only sanity-check when the caller asked for more than the floor; if
	// the requested limit was below the floor, the floor cannot apply.
	if limit >= minPlausiblePopularPackages {
		if err := sanityCheckPopularCount(ecosystem, len(pkgs)); err != nil {
			return nil, err
		}
	}
	return pkgs, nil
}

// fetchSeed reads an embedded newline-delimited popular-package list. It
// skips blank lines and '#' comment lines so the source file can carry a
// provenance header. The context is honoured on each line so a cancelled
// bootstrap doesn't continue to scan; in practice the seed list is small
// enough that this is cosmetic.
func (f *Fetcher) fetchSeed(ctx context.Context, data []byte, limit int) ([]PopularPackage, error) {
	if len(data) == 0 {
		return nil, nil
	}
	out := make([]PopularPackage, 0, 256)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Seed files are small; default 64 KiB buffer is fine. A module path
	// couldn't legitimately exceed that.
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, PopularPackage{Name: line, Rank: len(out)})
		if len(out) >= limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read popular-package seed: %w", err)
	}
	return out, nil
}

// npmSeedKeywords is the curated set of broad keyword probes we use to
// surface npm's popular-package landscape.
//
// Why multiple queries? As of 2026-04, npm's /-/v1/search API requires a
// `text` parameter (calls with `popularity=1.0` alone return HTTP 400
// "'text' query parameter is required"). No single keyword covers the
// popular-npm landscape — "keywords:javascript" overweights low-level
// runtime deps (tslib, es-object-atoms) while "keywords:framework" surfaces
// user-installed libraries (express, next, vite). We query each keyword,
// weight by popularity, and union the results; per-package popularity from
// npm's own scoring decides final rank after dedup. This trades ~20 small
// HTTPS calls for a broader, more stable corpus.
//
// Keep this list stable across releases — adding/removing a keyword shifts
// the corpus and can flip typosquat decisions at the edges. When expanding,
// prefer keywords that cover a distinct tool/framework population rather
// than synonyms of an existing entry.
var npmSeedKeywords = []string{
	"keywords:javascript",
	"keywords:nodejs",
	"keywords:npm",
	"keywords:cli",
	"keywords:framework",
	"keywords:react",
	"keywords:vue",
	"keywords:angular",
	"keywords:typescript",
	"keywords:express",
	"keywords:webpack",
	"keywords:eslint",
	"keywords:jest",
	"keywords:testing",
	"keywords:http",
	"keywords:util",
	"keywords:parser",
	"keywords:build",
	"keywords:bundler",
	"keywords:lint",
}

// npmCorpusDenylist removes names that npm's keyword search surfaces as
// "popular" but which are NOT installable npm packages, or which act as
// confusable namespaces that draw false-positive typosquat matches against
// short real names. The original symptom was `jose` (4 chars, a real npm
// package with ~10M weekly downloads) firing sc.typosquat_medium with
// SimilarTo="jsr" — `jsr` is the JSR namespace (jsr.io), not an installable
// npm dependency, but appears in npm search results because the JSR launch
// announcement saturated keyword:javascript / keyword:typescript queries.
// Keep this list minimal and add only entries verified to either (a) not
// resolve under `npm install <name>` or (b) be a registry-namespace label
// that legitimate users would never type as a bare dep.
var npmCorpusDenylist = map[string]struct{}{
	"jsr": {}, // JSR namespace label — not an installable npm package.
}

// npmStaticPopularSeed lists obviously-popular npm packages that must
// always be in the typosquat-safe set, regardless of what the live keyword
// search surfaces on a given day. Two failure modes this guards against:
//
//  1. The keyword corpus has a long-tail cutoff. A real ~10M weekly
//     downloads package (e.g. `jose`) can land outside the top-N when
//     keyword coverage drifts. If it's not in the popular index, the
//     detector treats it as a candidate typosquat and starts firing on
//     every short distant name (jose ↔ jsr was the original symptom).
//  2. New broadly-popular short names appear faster than the weekly
//     refresh cycle, so we want a defensive baseline.
//
// Keep entries to packages that are (a) real, (b) installable, and (c)
// short enough to be at risk of false-positive edit-distance matches.
// Long names (≥11 chars) get the long threshold and are less affected.
var npmStaticPopularSeed = []string{
	"jose", // ~10M weekly downloads, 4 chars — high risk of false-positive matches.
}

func (f *Fetcher) fetchNPM(ctx context.Context, limit int) ([]PopularPackage, error) {
	// perQuery balances coverage (more per keyword = deeper tail) against
	// HTTP cost. 250 is npm's max page size; 50 is the floor below which
	// the per-keyword corpus becomes too shallow to matter.
	perQuery := limit / len(npmSeedKeywords)
	if perQuery < 50 {
		perQuery = 50
	}
	if perQuery > 250 {
		perQuery = 250
	}

	// Track the best popularity score we've seen for each name. Popularity
	// is npm's own 0..1 ranking within its scoring model; we merge by
	// taking the maximum across queries (a package that ranks highly under
	// any relevant keyword deserves its best score).
	type seenEntry struct {
		popularity float64
		firstSeen  int // stable tie-breaker when scores match exactly
	}
	seen := make(map[string]seenEntry, perQuery*len(npmSeedKeywords))
	seqCounter := 0

	// Preseed with the static popular list so obviously-popular short
	// names are guaranteed in the index even when keyword coverage drifts.
	// We assign popularity=1.0 (max) so the static entries land at the top
	// of the final ranking and are kept inside any limit cutoff. They
	// flow through the same denylist filter as live results below.
	for _, name := range npmStaticPopularSeed {
		if _, deny := npmCorpusDenylist[strings.ToLower(name)]; deny {
			continue
		}
		seen[name] = seenEntry{popularity: 1.0, firstSeen: seqCounter}
		seqCounter++
	}

	var lastErr error
	okQueries := 0
	// Rate-limiting + 429 retry is handled upstream by
	// internal/upstreamhttp when wired via NewFetcher(WithHTTPClient(...)).
	// The earlier hard-coded 1500ms throttle here has been removed in
	// favour of that shared middleware so every chainsaw-proxy fetch
	// path shares one npm budget instead of each goroutine re-deriving
	// its own. The default (no-option) Fetcher client does not have
	// rate limiting, but the only production caller (supplychain
	// Bootstrap via cmd/chainsaw-proxy) passes WithHTTPClient.
	for _, kw := range npmSeedKeywords {
		searchURL := fmt.Sprintf(
			"https://registry.npmjs.org/-/v1/search?text=%s&size=%d&popularity=1.0",
			url.QueryEscape(kw), perQuery,
		)
		result, err := f.fetchJSON(ctx, searchURL)
		if err != nil {
			// Soft-fail per keyword — surface only if every query fails.
			f.logger.Warn("npm keyword fetch failed",
				"keyword", kw, "error", err)
			lastErr = err
			continue
		}
		okQueries++

		objects, ok := result["objects"].([]any)
		if !ok {
			continue
		}
		for _, obj := range objects {
			m, ok := obj.(map[string]any)
			if !ok {
				continue
			}
			pkg, ok := m["package"].(map[string]any)
			if !ok {
				continue
			}
			name, _ := pkg["name"].(string)
			if name == "" {
				continue
			}
			// Drop denylisted names (registry-namespace labels and other
			// non-installable surface that npm's keyword search returns).
			if _, deny := npmCorpusDenylist[strings.ToLower(name)]; deny {
				continue
			}
			// Extract popularity from score.detail.popularity (present on
			// npm's live responses; absent on registries that don't emit
			// the score envelope).
			var pop float64
			if score, ok := m["score"].(map[string]any); ok {
				if detail, ok := score["detail"].(map[string]any); ok {
					pop, _ = detail["popularity"].(float64)
				}
			}
			prev, had := seen[name]
			if !had {
				seen[name] = seenEntry{popularity: pop, firstSeen: seqCounter}
				seqCounter++
			} else if pop > prev.popularity {
				seen[name] = seenEntry{popularity: pop, firstSeen: prev.firstSeen}
			}
		}
	}

	if okQueries == 0 {
		return nil, fmt.Errorf("fetch npm popular packages: all keyword queries failed: %w", lastErr)
	}

	// Rank: popularity desc, then first-seen asc for deterministic ordering
	// across runs that hit the same data.
	type ranked struct {
		name       string
		popularity float64
		firstSeen  int
	}
	ranking := make([]ranked, 0, len(seen))
	for name, e := range seen {
		ranking = append(ranking, ranked{name, e.popularity, e.firstSeen})
	}
	sort.Slice(ranking, func(i, j int) bool {
		if ranking[i].popularity != ranking[j].popularity {
			return ranking[i].popularity > ranking[j].popularity
		}
		return ranking[i].firstSeen < ranking[j].firstSeen
	})

	if limit > len(ranking) {
		limit = len(ranking)
	}
	packages := make([]PopularPackage, 0, limit)
	for i := 0; i < limit; i++ {
		packages = append(packages, PopularPackage{
			Name: ranking[i].name,
			Rank: i,
		})
	}
	return packages, nil
}

func (f *Fetcher) fetchPyPI(ctx context.Context, limit int) ([]PopularPackage, error) {
	// Use the PyPI top packages JSON endpoint (hugovk/top-pypi-packages).
	// The canonical URL is hugovk.dev; the legacy hugovk.github.io path now
	// 301-redirects here, and following that redirect would otherwise fail
	// the post-redirect allowlist check.
	url := "https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.min.json"
	result, err := f.fetchJSON(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("fetch pypi popular packages: %w", err)
	}

	rows, ok := result["rows"].([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected pypi response format")
	}

	var packages []PopularPackage
	for i, row := range rows {
		if i >= limit {
			break
		}
		m, ok := row.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["project"].(string)
		if name != "" {
			packages = append(packages, PopularPackage{Name: name, Rank: i})
		}
	}
	return packages, nil
}

func (f *Fetcher) fetchCargo(ctx context.Context, limit int) ([]PopularPackage, error) {
	var packages []PopularPackage
	pageSize := 100

	for page := 1; len(packages) < limit; page++ {
		url := fmt.Sprintf("https://crates.io/api/v1/crates?sort=downloads&per_page=%d&page=%d", pageSize, page)
		result, err := f.fetchJSON(ctx, url)
		if err != nil {
			if len(packages) > 0 {
				break
			}
			// Network unreachable (air-gapped, install hot path). Fall back
			// to the embedded curated seed so offline deployments still get
			// a non-empty corpus, mirroring Go/CocoaPods/pub.
			f.logger.Warn("cargo live fetch failed; falling back to embedded seed", "error", err)
			return f.fetchSeed(ctx, cargoTopSeed, limit)
		}

		crates, ok := result["crates"].([]any)
		if !ok || len(crates) == 0 {
			break
		}
		for _, c := range crates {
			if len(packages) >= limit {
				break
			}
			m, ok := c.(map[string]any)
			if !ok {
				continue
			}
			name, _ := m["name"].(string)
			if name != "" {
				packages = append(packages, PopularPackage{Name: name, Rank: len(packages)})
			}
		}

		// Rate limit: 1 req/sec for crates.io.
		select {
		case <-ctx.Done():
			return packages, ctx.Err()
		case <-time.After(1100 * time.Millisecond):
		}
	}

	// Empty network result (reachable but no usable entries) — fall back to
	// the embedded seed rather than poison the index with an empty corpus.
	if len(packages) == 0 {
		return f.fetchSeed(ctx, cargoTopSeed, limit)
	}
	return packages, nil
}

func (f *Fetcher) fetchComposer(ctx context.Context, limit int) ([]PopularPackage, error) {
	var packages []PopularPackage
	pageSize := 100

	for page := 1; len(packages) < limit; page++ {
		url := fmt.Sprintf("https://packagist.org/explore/popular.json?per_page=%d&page=%d", pageSize, page)
		result, err := f.fetchJSON(ctx, url)
		if err != nil {
			if len(packages) > 0 {
				break
			}
			return nil, fmt.Errorf("fetch composer popular packages: %w", err)
		}

		pkgs, ok := result["packages"].([]any)
		if !ok || len(pkgs) == 0 {
			break
		}
		for _, p := range pkgs {
			if len(packages) >= limit {
				break
			}
			m, ok := p.(map[string]any)
			if !ok {
				continue
			}
			name, _ := m["name"].(string)
			if name != "" {
				packages = append(packages, PopularPackage{Name: name, Rank: len(packages)})
			}
		}
	}

	return packages, nil
}

func (f *Fetcher) fetchRubyGems(ctx context.Context, limit int) ([]PopularPackage, error) {
	var packages []PopularPackage
	pageSize := 100

	for page := 1; len(packages) < limit; page++ {
		url := fmt.Sprintf("https://rubygems.org/api/v1/search.json?query=*&page=%d&sort=downloads", page)
		body, err := f.fetchRaw(ctx, url)
		if err != nil {
			if len(packages) > 0 {
				break
			}
			// Network unreachable (air-gapped, install hot path). Fall back
			// to the embedded curated seed so offline deployments still get
			// a non-empty corpus, mirroring Go/CocoaPods/pub.
			f.logger.Warn("rubygems live fetch failed; falling back to embedded seed", "error", err)
			return f.fetchSeed(ctx, rubygemsTopSeed, limit)
		}

		var gems []map[string]any
		if err := json.Unmarshal(body, &gems); err != nil {
			break
		}
		if len(gems) == 0 {
			break
		}
		for _, g := range gems {
			if len(packages) >= limit {
				break
			}
			name, _ := g["name"].(string)
			if name != "" {
				packages = append(packages, PopularPackage{Name: name, Rank: len(packages)})
			}
		}
		_ = pageSize // suppress unused
	}

	// Empty network result (reachable but no usable entries) — fall back to
	// the embedded seed rather than poison the index with an empty corpus.
	if len(packages) == 0 {
		return f.fetchSeed(ctx, rubygemsTopSeed, limit)
	}
	return packages, nil
}

func (f *Fetcher) fetchNuGet(ctx context.Context, limit int) ([]PopularPackage, error) {
	var packages []PopularPackage
	pageSize := 100

	for skip := 0; len(packages) < limit; skip += pageSize {
		url := fmt.Sprintf("https://azuresearch-usnc.nuget.org/query?q=&skip=%d&take=%d&sortBy=totalDownloads-desc", skip, pageSize)
		result, err := f.fetchJSON(ctx, url)
		if err != nil {
			if len(packages) > 0 {
				break
			}
			return nil, fmt.Errorf("fetch nuget popular packages: %w", err)
		}

		data, ok := result["data"].([]any)
		if !ok || len(data) == 0 {
			break
		}
		for _, d := range data {
			if len(packages) >= limit {
				break
			}
			m, ok := d.(map[string]any)
			if !ok {
				continue
			}
			id, _ := m["id"].(string)
			if id != "" {
				packages = append(packages, PopularPackage{Name: id, Rank: len(packages)})
			}
		}
	}

	return packages, nil
}

func (f *Fetcher) fetchHuggingFace(ctx context.Context, limit int) ([]PopularPackage, error) {
	var packages []PopularPackage
	pageSize := 100

	for offset := 0; len(packages) < limit; offset += pageSize {
		url := fmt.Sprintf("https://huggingface.co/api/models?sort=downloads&limit=%d&offset=%d", pageSize, offset)
		body, err := f.fetchRaw(ctx, url)
		if err != nil {
			if len(packages) > 0 {
				break
			}
			return nil, fmt.Errorf("fetch huggingface popular models: %w", err)
		}

		var models []map[string]any
		if err := json.Unmarshal(body, &models); err != nil {
			break
		}
		if len(models) == 0 {
			break
		}
		for _, m := range models {
			if len(packages) >= limit {
				break
			}
			id, _ := m["modelId"].(string)
			if id == "" {
				id, _ = m["id"].(string)
			}
			if id != "" {
				packages = append(packages, PopularPackage{Name: id, Rank: len(packages)})
			}
		}
	}

	return packages, nil
}

func (f *Fetcher) fetchMaven(ctx context.Context, limit int) ([]PopularPackage, error) {
	var packages []PopularPackage
	pageSize := 200

	for start := 0; len(packages) < limit; start += pageSize {
		url := fmt.Sprintf("https://search.maven.org/solrsearch/select?q=*:*&rows=%d&start=%d&wt=json", pageSize, start)
		result, err := f.fetchJSON(ctx, url)
		if err != nil {
			if len(packages) > 0 {
				break
			}
			return nil, fmt.Errorf("fetch maven popular packages: %w", err)
		}

		response, ok := result["response"].(map[string]any)
		if !ok {
			break
		}
		docs, ok := response["docs"].([]any)
		if !ok || len(docs) == 0 {
			break
		}
		for _, d := range docs {
			if len(packages) >= limit {
				break
			}
			m, ok := d.(map[string]any)
			if !ok {
				continue
			}
			artifactID, _ := m["a"].(string)
			groupID, _ := m["g"].(string)
			if artifactID != "" {
				name := artifactID
				if groupID != "" {
					name = groupID + ":" + artifactID
				}
				packages = append(packages, PopularPackage{Name: name, Rank: len(packages)})
			}
		}
	}

	return packages, nil
}

func (f *Fetcher) fetchJSON(ctx context.Context, url string) (map[string]any, error) {
	body, err := f.fetchRaw(ctx, url)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode JSON from %s: %w", url, err)
	}
	return result, nil
}

func (f *Fetcher) fetchRaw(ctx context.Context, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	// Front-of-the-line integrity check — this catches a caller that hand-
	// rolls a URL outside the allowlist without relying on CheckRedirect.
	if err := enforceRequestSafety(req.URL); err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "chainsaw-proxy/1.0 (typosquat-index)")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}
	// Re-validate the final URL after any redirect chain resolved. Defence-
	// in-depth: CheckRedirect also enforces this, but a misconfigured client
	// (e.g. CheckRedirect replaced in tests) would otherwise silently bypass
	// the allowlist.
	if resp.Request != nil {
		if err := enforceRequestSafety(resp.Request.URL); err != nil {
			return nil, err
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5 MiB limit
	if err != nil {
		return nil, fmt.Errorf("read response from %s: %w", rawURL, err)
	}
	return body, nil
}

// sanityCheckPopularCount guards against a registry response that returned
// far fewer packages than plausible — a strong signal that the feed was
// tampered with (MITM, DNS hijack, account takeover of the feed publisher)
// or that the upstream API changed shape in a way we didn't anticipate. In
// either case the safe default is to fail the fetch and keep the previous
// in-memory index rather than load a poisoned one.
func sanityCheckPopularCount(ecosystem string, got int) error {
	if got >= minPlausiblePopularPackages {
		return nil
	}
	return fmt.Errorf("%w: %s popular-package feed returned %d entries, want >=%d",
		ErrSuspiciousRegistryResponse, ecosystem, got, minPlausiblePopularPackages)
}
