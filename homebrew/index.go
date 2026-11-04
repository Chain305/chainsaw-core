package homebrew

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Doer is the HTTP surface the index needs. *http.Client and the upstreamhttp
// client both satisfy it; production callers pass a rate-limited, SSRF-guarded
// client.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// ErrNotFound is returned when the API answers 404 for a formula or cask.
var ErrNotFound = errors.New("homebrew: not found")

// maxFormulaListBytes bounds the full formula.json download (32 MB on
// 2026-11-04). The cap leaves headroom for growth without letting a hostile
// mirror stream unbounded data into memory.
const maxFormulaListBytes = 128 << 20

// maxDocBytes bounds a single formula or cask document.
const maxDocBytes = 4 << 20

// maxPerName caps the per-formula fallback cache. The fallback only runs for
// names the loaded index knows (or before the first load), so ~9k formulae
// plus aliases is the steady-state ceiling; the cap keeps a degraded index
// (load failing) from growing it without bound on made-up names.
const maxPerName = 16384

// retiredDigestGrace is how long a bottle digest stays declared after an
// index reload replaced it. brew can lag the index: the proxy serves its
// cached api/ JWS for up to 600s and brew keeps its own for 450s, so for a
// few minutes after a formula bump brew still asks for the previous bottle.
// That digest was declared by Homebrew's API minutes ago and resolves to the
// PREVIOUS pkg_version, which policy judges as such.
const retiredDigestGrace = 30 * time.Minute

// BottleRef is what a bottle digest resolves to.
type BottleRef struct {
	Formula    string // canonical formula name (e.g. "openssl@3")
	PkgVersion string // e.g. "3.4.1" or "2.9.3_1"
	Platform   string // bottle tag, e.g. "arm64_sequoia"
}

// IndexConfig configures an Index.
type IndexConfig struct {
	// APIBase is the API root; DefaultAPIBase when empty.
	APIBase string
	// Client performs the fetches. Required.
	Client Doer
	// Refresh is how long a loaded full index is trusted before the next
	// conditional refetch. Homebrew's API is cache-control max-age=600 and
	// brew auto-updates every 450s, so 10 minutes is the natural cadence.
	Refresh time.Duration
	// FormulaTTL bounds the per-formula fallback cache.
	FormulaTTL time.Duration
	// Now is injectable for tests.
	Now func() time.Time
}

type retiredRef struct {
	ref   BottleRef
	until time.Time
}

type cachedFormula struct {
	f       *Formula
	fetched time.Time
	missing bool
}

// Index resolves bottle digests, ghcr image names and formula names against
// Homebrew's API. It loads the full formula.json lazily and refreshes it on a
// cadence; between refreshes a digest or name it has never seen falls back to
// one per-formula fetch, so a formula bumped minutes ago still resolves.
type Index struct {
	cfg IndexConfig

	mu        sync.RWMutex
	byName    map[string]*Formula
	byImage   map[string]string
	byDigest  map[string]BottleRef
	etag      string
	loadedAt  time.Time
	loadErr   error
	loading   sync.Mutex
	perName   map[string]cachedFormula
	perNameMu sync.Mutex
	// retired holds digests a reload dropped, each until its grace ends.
	retired map[string]retiredRef
	flight  singleflight.Group
}

// NewIndex builds an Index. Nothing is fetched until first use.
func NewIndex(cfg IndexConfig) *Index {
	if strings.TrimSpace(cfg.APIBase) == "" {
		cfg.APIBase = DefaultAPIBase
	}
	cfg.APIBase = strings.TrimRight(cfg.APIBase, "/")
	if cfg.Refresh <= 0 {
		cfg.Refresh = 10 * time.Minute
	}
	if cfg.FormulaTTL <= 0 {
		cfg.FormulaTTL = 10 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Index{
		cfg:     cfg,
		perName: make(map[string]cachedFormula),
		retired: make(map[string]retiredRef),
	}
}

// APIBase returns the configured API root.
func (ix *Index) APIBase() string { return ix.cfg.APIBase }

// Formula returns the formula named name (canonical, alias or old name),
// preferring the full index and falling back to a per-formula fetch.
func (ix *Index) Formula(ctx context.Context, name string) (*Formula, error) {
	name = NormalizeName(name)
	if name == "" {
		return nil, ErrNotFound
	}
	ix.ensureLoaded(ctx)
	ix.mu.RLock()
	f := ix.byName[name]
	authoritative := ix.authoritativeLocked()
	ix.mu.RUnlock()
	if f != nil {
		return f, nil
	}
	if authoritative {
		// A loaded index that does not hold the name is the answer: going
		// upstream for every unknown name would let anyone turn made-up
		// names into formulae.brew.sh requests.
		return nil, ErrNotFound
	}
	return ix.fetchOne(ctx, name)
}

// authoritativeLocked reports a successfully loaded full index. Callers hold
// ix.mu. A formula added upstream since the last load is unknown until the
// next refresh (at most cfg.Refresh), the same window brew's own API cache
// has.
func (ix *Index) authoritativeLocked() bool {
	return ix.loadErr == nil && len(ix.byName) > 0
}

// FormulaForImage resolves a ghcr.io image name ("openssl/3", "libxmlxx") to
// its formula. image may carry the "homebrew/core/" prefix.
func (ix *Index) FormulaForImage(ctx context.Context, image string) (*Formula, error) {
	image = strings.ToLower(strings.Trim(strings.TrimSpace(image), "/"))
	image = strings.TrimPrefix(image, CoreImagePrefix)
	if image == "" {
		return nil, ErrNotFound
	}
	ix.ensureLoaded(ctx)
	ix.mu.RLock()
	name := ix.byImage[image]
	var f *Formula
	if name != "" {
		f = ix.byName[name]
	}
	authoritative := ix.authoritativeLocked()
	ix.mu.RUnlock()
	if f != nil {
		return f, nil
	}
	if authoritative {
		return nil, ErrNotFound
	}
	return ix.fetchOne(ctx, GuessFormulaFromImage(image))
}

// ResolveBottle maps an image + blob digest to the formula version that
// declares it. err is nil when a formula declares the digest, ErrNotFound
// when none does (the caller must treat the blob as undeclared, never as
// unknown-but-fine), and any other error when the lookup itself failed (the
// caller cannot tell, and must refuse as unverifiable).
func (ix *Index) ResolveBottle(ctx context.Context, image, digest string) (BottleRef, error) {
	digest = normalizeDigest(digest)
	if digest == "" {
		return BottleRef{}, ErrNotFound
	}
	ix.ensureLoaded(ctx)
	now := ix.cfg.Now()
	ix.mu.RLock()
	ref, ok := ix.byDigest[digest]
	if !ok {
		if r, hit := ix.retired[digest]; hit && now.Before(r.until) {
			ref, ok = r.ref, true
		}
	}
	ix.mu.RUnlock()
	if ok {
		return ref, nil
	}
	// Index miss: the formula may have been bumped since the last load, so
	// read its live per-formula document rather than the (stale) index copy.
	known, err := ix.FormulaForImage(ctx, image)
	if err != nil {
		return BottleRef{}, err
	}
	if known == nil {
		return BottleRef{}, ErrNotFound
	}
	f, err := ix.fetchOne(ctx, known.Name)
	if err != nil {
		return BottleRef{}, err
	}
	if f == nil {
		return BottleRef{}, ErrNotFound
	}
	for plat, bf := range f.Bottle.Stable.Files {
		if normalizeDigest(bf.SHA256) == digest {
			return BottleRef{Formula: f.Name, PkgVersion: f.PkgVersion(), Platform: plat}, nil
		}
	}
	return BottleRef{}, ErrNotFound
}

// Names returns every formula name in the loaded index (nil before the first
// successful load).
func (ix *Index) Names(ctx context.Context) []string {
	ix.ensureLoaded(ctx)
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	out := make([]string, 0, len(ix.byName))
	for n, f := range ix.byName {
		if f != nil && f.Name == n {
			out = append(out, n)
		}
	}
	return out
}

// LoadErr reports the last full-index load error (nil when healthy).
func (ix *Index) LoadErr() error {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.loadErr
}

func normalizeDigest(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "sha256:")
	d = strings.TrimPrefix(d, "sha256-")
	if len(d) != 64 {
		return ""
	}
	for _, c := range d {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return d
}

func (ix *Index) ensureLoaded(ctx context.Context) {
	now := ix.cfg.Now()
	ix.mu.RLock()
	fresh := !ix.loadedAt.IsZero() && now.Sub(ix.loadedAt) < ix.cfg.Refresh
	ix.mu.RUnlock()
	if fresh {
		return
	}
	// One loader at a time; others serve the (possibly stale) index.
	if !ix.loading.TryLock() {
		return
	}
	defer ix.loading.Unlock()
	if err := ix.load(ctx); err != nil {
		ix.mu.Lock()
		ix.loadErr = err
		// Back off a full refresh interval before retrying a failed load,
		// but keep serving whatever was loaded before.
		ix.loadedAt = now
		ix.mu.Unlock()
	}
}

func (ix *Index) load(ctx context.Context) error {
	if ix.cfg.Client == nil {
		return errors.New("homebrew: index has no HTTP client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ix.cfg.APIBase+"/formula.json", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	ix.mu.RLock()
	if ix.etag != "" && len(ix.byName) > 0 {
		req.Header.Set("If-None-Match", ix.etag)
	}
	ix.mu.RUnlock()
	resp, err := ix.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		ix.mu.Lock()
		ix.loadedAt = ix.cfg.Now()
		ix.loadErr = nil
		ix.mu.Unlock()
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("homebrew: formula.json HTTP %d", resp.StatusCode)
	}
	var list []*Formula
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxFormulaListBytes))
	if err := dec.Decode(&list); err != nil {
		return fmt.Errorf("homebrew: decode formula.json: %w", err)
	}
	byName, byImage, byDigest := buildMaps(list)
	now := ix.cfg.Now()
	ix.mu.Lock()
	for d, until := range ix.retired {
		if !now.Before(until.until) {
			delete(ix.retired, d)
		}
	}
	for d, ref := range ix.byDigest {
		if _, still := byDigest[d]; !still {
			ix.retired[d] = retiredRef{ref: ref, until: now.Add(retiredDigestGrace)}
		}
	}
	ix.byName, ix.byImage, ix.byDigest = byName, byImage, byDigest
	ix.etag = resp.Header.Get("ETag")
	ix.loadedAt = ix.cfg.Now()
	ix.loadErr = nil
	ix.mu.Unlock()
	return nil
}

func buildMaps(list []*Formula) (map[string]*Formula, map[string]string, map[string]BottleRef) {
	byName := make(map[string]*Formula, len(list)*2)
	byImage := make(map[string]string, len(list))
	byDigest := make(map[string]BottleRef, len(list)*8)
	for _, f := range list {
		if f == nil || strings.TrimSpace(f.Name) == "" {
			continue
		}
		name := NormalizeName(f.Name)
		f.Name = name
		byName[name] = f
		for _, alt := range append(append([]string{}, f.Aliases...), f.OldNames...) {
			if a := NormalizeName(alt); a != "" {
				if _, taken := byName[a]; !taken {
					byName[a] = f
				}
			}
		}
		byImage[ImageName(name)] = name
		pv := f.PkgVersion()
		for plat, bf := range f.Bottle.Stable.Files {
			if d := normalizeDigest(bf.SHA256); d != "" {
				byDigest[d] = BottleRef{Formula: name, PkgVersion: pv, Platform: plat}
			}
		}
	}
	return byName, byImage, byDigest
}

func (ix *Index) fetchOne(ctx context.Context, name string) (*Formula, error) {
	if !ValidName(name) {
		// Never put a string that is not a formula token into an upstream URL.
		return nil, ErrNotFound
	}
	now := ix.cfg.Now()
	ix.perNameMu.Lock()
	if c, ok := ix.perName[name]; ok && now.Sub(c.fetched) < ix.cfg.FormulaTTL {
		ix.perNameMu.Unlock()
		if c.missing {
			return nil, ErrNotFound
		}
		return c.f, nil
	}
	ix.perNameMu.Unlock()

	// Concurrent misses on one name share one upstream request.
	v, err, _ := ix.flight.Do(name, func() (any, error) {
		var f Formula
		err := fetchJSON(ctx, ix.cfg.Client, ix.cfg.APIBase+"/formula/"+url.PathEscape(name)+".json", &f)
		if errors.Is(err, ErrNotFound) {
			ix.storePerName(name, cachedFormula{fetched: now, missing: true})
			return nil, ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		f.Name = NormalizeName(f.Name)
		ix.storePerName(name, cachedFormula{f: &f, fetched: now})
		return &f, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*Formula), nil
}

// storePerName caches one per-formula result, keeping the cache under
// maxPerName: expired entries go first, and if it is still full the whole
// cache is dropped (it only saves upstream requests; correctness never
// depends on it).
func (ix *Index) storePerName(name string, c cachedFormula) {
	now := ix.cfg.Now()
	ix.perNameMu.Lock()
	defer ix.perNameMu.Unlock()
	if len(ix.perName) >= maxPerName {
		for k, v := range ix.perName {
			if now.Sub(v.fetched) >= ix.cfg.FormulaTTL {
				delete(ix.perName, k)
			}
		}
		if len(ix.perName) >= maxPerName {
			ix.perName = make(map[string]cachedFormula)
		}
	}
	ix.perName[name] = c
}

// FetchCask fetches one cask document. Casks are not indexed in bulk: the
// guard and the brew.env compiler look them up by token on demand.
func FetchCask(ctx context.Context, client Doer, apiBase, token string) (*Cask, error) {
	if strings.TrimSpace(apiBase) == "" {
		apiBase = DefaultAPIBase
	}
	token = NormalizeName(token)
	if token == "" {
		return nil, ErrNotFound
	}
	var c Cask
	if err := fetchJSON(ctx, client, strings.TrimRight(apiBase, "/")+"/cask/"+url.PathEscape(token)+".json", &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// FetchFormula fetches one formula document without an index.
func FetchFormula(ctx context.Context, client Doer, apiBase, name string) (*Formula, error) {
	if strings.TrimSpace(apiBase) == "" {
		apiBase = DefaultAPIBase
	}
	name = NormalizeName(name)
	if name == "" {
		return nil, ErrNotFound
	}
	var f Formula
	if err := fetchJSON(ctx, client, strings.TrimRight(apiBase, "/")+"/formula/"+url.PathEscape(name)+".json", &f); err != nil {
		return nil, err
	}
	f.Name = NormalizeName(f.Name)
	return &f, nil
}

func fetchJSON(ctx context.Context, client Doer, endpoint string, out any) error {
	if client == nil {
		return errors.New("homebrew: no HTTP client")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("homebrew: %s HTTP %d", endpoint, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxDocBytes)).Decode(out)
}
