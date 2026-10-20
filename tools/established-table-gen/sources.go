package main

// sources.go — candidate universes and registry fetchers. Every fetch is
// cached as one JSON record per line under -cache; a rerun loads the cache,
// fetches only what is missing, and appends, so an interrupted run (or a rail
// iteration) never pays for the same doc twice.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const userAgent = "chain305 established-table-gen (github.com/chain305/chainsaw)"

var errNotFound = errors.New("not found (404)")

// ---------------------------------------------------------------------------
// universe construction

// readSeedList reads a popular-*.txt seed: one name per line, # comments.
func readSeedList(path string) ([]string, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		names = append(names, l)
	}
	return names, nil
}

func readLines(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(raw), "\n"), nil
}

// readPackagesCSV reads ecosystem,name,version rows and returns the distinct
// names for one ecosystem. Registry names cannot contain commas, so a
// three-way split is exact; malformed rows are refused, not skipped — a shape
// change in the SBOM export must not silently shrink the universe.
func readPackagesCSV(path, eco string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	seen := map[string]bool{}
	var names []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if lineNo == 1 {
			if line != "ecosystem,name,version" {
				return nil, fmt.Errorf("%s: unexpected header %q", path, line)
			}
			continue
		}
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 3 {
			return nil, fmt.Errorf("%s:%d: malformed row %q", path, lineNo, line)
		}
		if parts[0] != eco {
			continue // other ecosystems' rows are well-formed, just not ours
		}
		if parts[1] == "" {
			return nil, fmt.Errorf("%s:%d: empty %s name %q", path, lineNo, eco, line)
		}
		n := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	return names, sc.Err()
}

// readNpmDocsNames reads the cached abbreviated npm docs (one JSON object per
// line, {"name": ..., "versions": {...}}) and keeps only the names: the size
// payload is irrelevant here, the file widens the candidate universe.
func readNpmDocsNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var names []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<22), 1<<22)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var doc struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			return nil, fmt.Errorf("%s: bad JSONL line: %w", path, err)
		}
		if doc.Name != "" && !seen[doc.Name] {
			seen[doc.Name] = true
			names = append(names, doc.Name)
		}
	}
	return names, sc.Err()
}

// unionNames merges name sources deterministically (sorted output) and
// reports the per-source sizes for the header.
func unionNames(sources map[string][]string) ([]string, map[string]int) {
	seen := map[string]bool{}
	var all []string
	for _, names := range sources {
		for _, n := range names {
			if !seen[n] {
				seen[n] = true
				all = append(all, n)
			}
		}
	}
	sort.Strings(all)
	counts := make(map[string]int, len(sources))
	for label, names := range sources {
		counts[label] = len(names)
	}
	return all, counts
}

// ---------------------------------------------------------------------------
// fetch plumbing

// fetcher wraps an http.Client with retries and an optional global rate
// limit. The npm downloads API 429s hard against concurrency, so all calls
// to api.npmjs.org share one fetcher with a minimum interval.
type fetcher struct {
	hc          *http.Client
	mu          sync.Mutex
	nextAllowed time.Time
	minInterval time.Duration
}

func newFetcher() *fetcher {
	return &fetcher{hc: &http.Client{Timeout: 90 * time.Second}}
}

// newRateLimitedFetcher spaces requests at least minInterval apart across
// all goroutines sharing it.
func newRateLimitedFetcher(minInterval time.Duration) *fetcher {
	return &fetcher{hc: &http.Client{Timeout: 90 * time.Second}, minInterval: minInterval}
}

func (f *fetcher) throttle() {
	if f.minInterval == 0 {
		return
	}
	f.mu.Lock()
	now := time.Now()
	start := f.nextAllowed
	if start.Before(now) {
		start = now
	}
	f.nextAllowed = start.Add(f.minInterval)
	f.mu.Unlock()
	if wait := time.Until(start); wait > 0 {
		time.Sleep(wait)
	}
}

// getJSON GETs url into out with retries and a descriptive User-Agent
// (crates.io demands one). 404 is returned as errNotFound and is NOT retried;
// 429/5xx back off with growing delays (up to 8 attempts, honoring
// Retry-After when sent), and truncated-but-200 transfers fail as parse
// errors and retry too. Bodies are capped.
func (f *fetcher) getJSON(u string, out any, maxBytes int64) error {
	var lastErr error
	backoff := 500 * time.Millisecond
	for attempt := 0; attempt < 12; attempt++ {
		if attempt > 0 {
			delay := backoff
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			time.Sleep(delay)
		}
		f.throttle()
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")
		resp, err := f.hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		switch {
		case resp.StatusCode == http.StatusNotFound:
			return errNotFound
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := strconv.Atoi(ra); err == nil && secs > 0 && secs < 60 {
					backoff = time.Duration(secs) * time.Second
				}
			}
			lastErr = fmt.Errorf("GET %s: %s", u, resp.Status)
			continue
		case resp.StatusCode != http.StatusOK:
			return fmt.Errorf("GET %s: %s", u, resp.Status)
		}
		if err := json.Unmarshal(body, out); err != nil {
			// A truncated transfer (huge docs cut mid-stream) parses like a
			// malformed one; retry before giving up.
			lastErr = fmt.Errorf("parse %s: %w", u, err)
			continue
		}
		return nil
	}
	return lastErr
}

// workerPool runs fn over items with a fixed modest concurrency, collecting
// per-item errors. Items are handed out in order; workers pull as they free up.
func workerPool[T any](items []T, conc int, fn func(T) error) []error {
	if conc < 1 {
		conc = 1
	}
	errs := make([]error, len(items))
	jobs := make(chan int)
	go func() {
		defer close(jobs)
		for i := range items {
			jobs <- i
		}
	}()
	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				errs[i] = fn(items[i])
			}
		}()
	}
	wg.Wait()
	return errs
}

// checkErrs returns the first non-nil error in errs.
func checkErrs(errs []error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// jsonlCache is an append-only JSONL cache. Records are written as they
// arrive so an interrupted run keeps everything already fetched.
type jsonlCache struct {
	path string
	mu   sync.Mutex
	w    *bufio.Writer
	f    *os.File
}

func openJSONLCache(dir, name string) (*jsonlCache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	return &jsonlCache{path: path, f: f, w: bufio.NewWriter(f)}, nil
}

func (c *jsonlCache) append(rec any) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.w.Write(b)
	c.w.WriteByte('\n')
	return c.w.Flush()
}

func (c *jsonlCache) close() {
	c.w.Flush()
	c.f.Close()
}

// loadJSONLCache reads every record into a map keyed by the record's cacheKey
// fn. Tolerates a torn final line from a killed previous run — the refetch
// simply overwrites it.
func loadJSONLCache[T any](dir, name string, key func(T) string) (map[string]T, error) {
	path := filepath.Join(dir, name)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]T{}, nil
		}
		return nil, err
	}
	defer f.Close()
	out := map[string]T{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<22), 1<<22)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec T
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		out[key(rec)] = rec
	}
	return out, sc.Err()
}

// ---------------------------------------------------------------------------
// npm: full registry docs

// npmDocRec is the distilled FULL registry doc for one package: the doc is
// fetched once and only these fields are cached (a full-doc JSONL would be
// gigabytes; this distillation is everything the clear lines read).
type npmDocRec struct {
	Name         string `json:"name"`
	OK           bool   `json:"ok"` // false = 404/unpublished: known-absent, never qualifies
	Created      string `json:"created,omitempty"`
	Last         string `json:"last,omitempty"`
	Versions     int    `json:"versions,omitempty"`
	SecurityOnly bool   `json:"security_only,omitempty"` // every version is npm's "-security" holding placeholder
}

func (r npmDocRec) key() string { return r.Name }

// npmNameRE accepts the shapes npm names can take (scope included, exactly as
// the registry spells and serves them); anything else is refused loudly.
var npmNameRE = regexp.MustCompile(`^(@[A-Za-z0-9-._]+/)?[A-Za-z0-9._-]+$`)

func fetchNPMDocs(cacheDir string, names []string, conc int, progress *progress) (map[string]npmDocRec, error) {
	cached, err := loadJSONLCache(cacheDir, "npm_docs.jsonl", func(r npmDocRec) string { return r.Name })
	if err != nil {
		return nil, err
	}
	cache, err := openJSONLCache(cacheDir, "npm_docs.jsonl")
	if err != nil {
		return nil, err
	}
	defer cache.close()

	var missing []string
	for _, n := range names {
		if _, ok := cached[n]; !ok {
			missing = append(missing, n)
		}
	}
	fmt.Fprintf(os.Stderr, "npm docs: %d cached, %d to fetch\n", len(cached), len(missing))

	f := newFetcher()
	var mu sync.Mutex
	errs := workerPool(missing, conc, func(n string) error {
		if !npmNameRE.MatchString(n) {
			return fmt.Errorf("npm docs: refusing invalid package name %q", n)
		}
		rec, err := fetchOneNPMDoc(f, n)
		if err != nil {
			return fmt.Errorf("doc %s: %w", n, err)
		}
		if err := cache.append(rec); err != nil {
			return err
		}
		mu.Lock()
		cached[n] = rec
		mu.Unlock()
		progress.done(len(missing), "npm docs")
		return nil
	})
	return cached, checkErrs(errs)
}

func fetchOneNPMDoc(f *fetcher, name string) (npmDocRec, error) {
	// The registry accepts the scope unencoded; keep the plain spelling so
	// the URL and the row key are the same string.
	u := strings.ReplaceAll("https://registry.npmjs.org/"+url.PathEscape(name), "%2F", "/")
	var doc struct {
		Name     string                     `json:"name"`
		Time     map[string]json.RawMessage `json:"time"`     // values are timestamps, except junk like the "unpublished" record
		Versions map[string]json.RawMessage `json:"versions"` // RawMessage: len() and keys without materialising manifests
	}
	// A handful of docs exceed 64MB (@prisma/client is ~70MB), so the cap
	// sits well above that; anything past 256MB is an upstream change.
	if err := f.getJSON(u, &doc, 256<<20); err != nil {
		if errors.Is(err, errNotFound) {
			return npmDocRec{Name: name, OK: false}, nil
		}
		return npmDocRec{}, err
	}
	rec := npmDocRec{Name: name, OK: true, Versions: len(doc.Versions)}
	securityOnly := len(doc.Versions) > 0
	for v := range doc.Versions {
		if !strings.HasSuffix(v, "-security") {
			securityOnly = false
			break
		}
	}
	rec.SecurityOnly = securityOnly

	// time.created is the doc creation (first publish); last is the newest
	// per-version time, excluding the bookkeeping created/modified keys and
	// non-string records like "unpublished" (which prove nothing).
	first, last := "", ""
	for k, raw := range doc.Time {
		if k == "modified" {
			continue
		}
		var ts string
		if err := json.Unmarshal(raw, &ts); err != nil {
			continue
		}
		d := ts
		if len(d) > 10 {
			d = d[:10]
		}
		if d == "" {
			continue
		}
		if k == "created" {
			if first == "" || d < first {
				first = d
			}
			continue
		}
		if last == "" || d > last {
			last = d
		}
	}
	rec.Created = minStr(first, last) // created, or the oldest version time when created is absent
	rec.Last = last
	return rec, nil
}

func minStr(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	case a < b:
		return a
	default:
		return b
	}
}

// ---------------------------------------------------------------------------
// npm: weekly downloads

type npmDlRec struct {
	Name   string `json:"name"`
	Weekly int64  `json:"weekly"` // 0 = no data in the downloads DB (unknown)
}

func (r npmDlRec) key() string { return r.Name }

// fetchNPMWeekly fills weekly download counts for every name. The point API
// accepts ~128 comma-joined unscoped names per request; scoped names carry a
// slash the path cannot hold, so they are fetched individually. A 404 from
// the downloads DB means zero/unknown, recorded as 0.
func fetchNPMWeekly(cacheDir string, names []string, conc int, progress *progress) (map[string]int64, error) {
	cached, err := loadJSONLCache(cacheDir, "npm_downloads.jsonl", func(r npmDlRec) string { return r.Name })
	if err != nil {
		return nil, err
	}
	cache, err := openJSONLCache(cacheDir, "npm_downloads.jsonl")
	if err != nil {
		return nil, err
	}
	defer cache.close()

	out := map[string]int64{}
	for n, rec := range cached {
		out[n] = rec.Weekly
	}
	var need []string
	for _, n := range names {
		if _, ok := cached[n]; !ok {
			need = append(need, n)
		}
	}
	fmt.Fprintf(os.Stderr, "npm downloads: %d cached, %d to fetch\n", len(cached), len(need))

	var unscoped, scoped []string
	for _, n := range need {
		if strings.ContainsRune(n, '/') {
			scoped = append(scoped, n)
		} else {
			unscoped = append(unscoped, n)
		}
	}

	// api.npmjs.org 429s hard against concurrency: one shared rate-limited
	// fetcher spaces every request (batches and scoped point calls alike).
	f := newRateLimitedFetcher(900 * time.Millisecond)
	var mu sync.Mutex

	// Unscoped names FIRST: batches of 128 through the same endpoint — one
	// successful request covers 128 packages, the best possible use of a
	// scarce rate budget. The response is {"name":{"downloads":N,...}}
	// with null entries for unknown names.
	const batch = 128
	var batches [][]string
	for i := 0; i < len(unscoped); i += batch {
		end := i + batch
		if end > len(unscoped) {
			end = len(unscoped)
		}
		batches = append(batches, unscoped[i:end])
	}
	fmt.Fprintf(os.Stderr, "npm downloads: %d unscoped in %d bulk batches, then %d scoped point calls (bulk rejects scoped names)\n",
		len(unscoped), len(batches), len(scoped))
	errs := workerPool(batches, 2, func(names []string) error {
		u := "https://api.npmjs.org/downloads/point/last-week/" + strings.Join(names, ",")
		var doc map[string]*struct {
			Downloads int64 `json:"downloads"`
		}
		if err := f.getJSON(u, &doc, 8<<20); err != nil && !errors.Is(err, errNotFound) {
			return fmt.Errorf("downloads batch (%d names): %w", len(names), err)
		}
		recs := make([]npmDlRec, len(names))
		for i, n := range names {
			weekly := int64(0)
			if e, ok := doc[n]; ok && e != nil {
				weekly = e.Downloads
			}
			recs[i] = npmDlRec{Name: n, Weekly: weekly}
		}
		for _, rec := range recs {
			if err := cache.append(rec); err != nil {
				return err
			}
		}
		mu.Lock()
		for _, rec := range recs {
			out[rec.Name] = rec.Weekly
		}
		mu.Unlock()
		progress.done(1, "npm downloads")
		return nil
	})
	if err := checkErrs(errs); err != nil {
		return nil, err
	}

	// Scoped names: the bulk endpoint rejects them outright ("scoped
	// packages are not currently supported in bulk lookups"), so one point
	// call each. Sequential on purpose: with parallel workers, whichever
	// request gets a 429 starves while its siblings keep draining the
	// refill budget; one stream spaces requests naturally and retries are
	// guaranteed their turn.
	errs = workerPool(scoped, 1, func(n string) error {
		u := "https://api.npmjs.org/downloads/point/last-week/" + url.PathEscape(n)
		var doc struct {
			Downloads int64 `json:"downloads"`
		}
		if err := f.getJSON(u, &doc, 1<<20); err != nil && !errors.Is(err, errNotFound) {
			return fmt.Errorf("downloads %s: %w", n, err)
		}
		if err := cache.append(npmDlRec{Name: n, Weekly: doc.Downloads}); err != nil {
			return err
		}
		mu.Lock()
		out[n] = doc.Downloads
		mu.Unlock()
		progress.done(1, "npm downloads")
		return nil
	})
	return out, checkErrs(errs)
}

// ---------------------------------------------------------------------------
// pypi

type pypiRec struct {
	Name     string `json:"name"` // canonical spelling from info.name
	OK       bool   `json:"ok"`
	First    string `json:"first,omitempty"`
	Last     string `json:"last,omitempty"`
	Versions int    `json:"versions,omitempty"`
}

func (r pypiRec) key() string { return r.Name }

// pep503 lowercases and collapses [-_.] runs to a single "-", the form the
// JSON API serves. Rows are keyed by info.name — the registry's own spelling.
func pep503(name string) string {
	s := strings.ToLower(name)
	s = strings.ReplaceAll(s, "_", "-")
	s = strings.ReplaceAll(s, ".", "-")
	return pep503Collapse.ReplaceAllString(s, "-")
}

var pep503Collapse = regexp.MustCompile(`-{2,}`)

func fetchPyPI(cacheDir string, names []string, conc int, progress *progress) (map[string]pypiRec, error) {
	cached, err := loadJSONLCache(cacheDir, "pypi_docs.jsonl", func(r pypiRec) string { return r.Name })
	if err != nil {
		return nil, err
	}
	cache, err := openJSONLCache(cacheDir, "pypi_docs.jsonl")
	if err != nil {
		return nil, err
	}
	defer cache.close()

	// The cache is keyed by the registry spelling, but lookups arrive in the
	// seed/csv spelling, so resolve through the PEP503 form.
	byNorm := map[string]pypiRec{}
	for _, rec := range cached {
		byNorm[pep503(rec.Name)] = rec
	}
	var missing []string
	for _, n := range names {
		if _, ok := byNorm[pep503(n)]; !ok {
			missing = append(missing, n)
		}
	}
	fmt.Fprintf(os.Stderr, "pypi docs: %d cached, %d to fetch\n", len(byNorm), len(missing))

	f := newFetcher()
	var mu sync.Mutex
	errs := workerPool(missing, conc, func(n string) error {
		u := "https://pypi.org/pypi/" + pep503(n) + "/json"
		var doc struct {
			Info struct {
				Name string `json:"name"`
			} `json:"info"`
			Releases map[string][]struct {
				UploadTime string `json:"upload_time"`
			} `json:"releases"`
		}
		if err := f.getJSON(u, &doc, 64<<20); err != nil {
			if errors.Is(err, errNotFound) {
				rec := pypiRec{Name: n, OK: false}
				if err := cache.append(rec); err != nil {
					return err
				}
				mu.Lock()
				byNorm[pep503(n)] = rec
				mu.Unlock()
				return nil
			}
			return fmt.Errorf("pypi %s: %w", n, err)
		}
		rec := pypiRec{Name: doc.Info.Name, OK: true}
		if rec.Name == "" {
			rec.Name = n
		}
		first, last := "", ""
		for _, files := range doc.Releases {
			if len(files) == 0 {
				continue // a version with no files never shipped
			}
			rec.Versions++
			for _, file := range files {
				d := file.UploadTime
				if len(d) > 10 {
					d = d[:10]
				}
				if d == "" {
					continue
				}
				if first == "" || d < first {
					first = d
				}
				if last == "" || d > last {
					last = d
				}
			}
		}
		rec.First, rec.Last = first, last
		if err := cache.append(rec); err != nil {
			return err
		}
		mu.Lock()
		byNorm[pep503(rec.Name)] = rec
		byNorm[pep503(n)] = rec
		mu.Unlock()
		progress.done(len(missing), "pypi docs")
		return nil
	})
	return byNorm, checkErrs(errs)
}

// ---------------------------------------------------------------------------
// cargo

type cargoRec struct {
	Name        string `json:"name"`
	Created     string `json:"created"` // YYYY-MM-DD from created_at
	Updated     string `json:"updated"` // YYYY-MM-DD from updated_at
	Downloads   int64  `json:"downloads"`
	NumVersions int    `json:"num_versions"`
}

func (r cargoRec) key() string { return r.Name }

// fetchCargoListing pages the crates.io sort=downloads listing. The listing
// already carries created_at, updated_at, total downloads and num_versions,
// so no per-crate second call is needed (v1 covers the top pages fully —
// 30 pages = top 3,000 crates). crates.io asks for a descriptive User-Agent
// and modest rates: sequential pages with a pause.
func fetchCargoListing(cacheDir string, pages int) ([]cargoRec, error) {
	cached, err := loadJSONLCache(cacheDir, "cargo_crates.jsonl", func(r cargoRec) string { return r.Name })
	if err != nil {
		return nil, err
	}
	f := newFetcher()
	for page := 1; page <= pages; page++ {
		if page > 1 {
			time.Sleep(700 * time.Millisecond)
		}
		u := fmt.Sprintf("https://crates.io/api/v1/crates?sort=downloads&per_page=100&page=%d", page)
		var doc struct {
			Crates []struct {
				Name        string `json:"name"`
				CreatedAt   string `json:"created_at"`
				UpdatedAt   string `json:"updated_at"`
				Downloads   int64  `json:"downloads"`
				NumVersions int    `json:"num_versions"`
			} `json:"crates"`
			Meta struct {
				NextPage *string `json:"next_page"` // URL of the next page, or null on the last page
			} `json:"meta"`
		}
		if err := f.getJSON(u, &doc, 16<<20); err != nil {
			return nil, fmt.Errorf("cargo page %d: %w", page, err)
		}
		if len(doc.Crates) == 0 {
			break
		}
		for _, c := range doc.Crates {
			cached[c.Name] = cargoRec{
				Name:        c.Name,
				Created:     day(c.CreatedAt),
				Updated:     day(c.UpdatedAt),
				Downloads:   c.Downloads,
				NumVersions: c.NumVersions,
			}
		}
		fmt.Fprintf(os.Stderr, "cargo listing: page %d -> %d crates (total known %d)\n", page, len(doc.Crates), len(cached))
		if doc.Meta.NextPage == nil {
			break
		}
	}
	// The listing is rank-ordered; the cache from a previous run may hold
	// more pages than this run asks for, so keep only what this run covers.
	// (Cheap and keeps reruns with a smaller -cargo-pages honest.)
	if err := writeCargoCache(cacheDir, cached); err != nil {
		return nil, err
	}
	out := make([]cargoRec, 0, len(cached))
	for _, rec := range cached {
		out = append(out, rec)
	}
	// Deterministic: by downloads desc, then name.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Downloads != out[j].Downloads {
			return out[i].Downloads > out[j].Downloads
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > pages*100 {
		out = out[:pages*100]
	}
	return out, nil
}

// writeCargoCache rewrites the cargo cache for this run's page depth. The
// cargo source is a single listing (not 8k individual docs), so a compact
// rewrite on each run is simpler than append-only and keeps the cache
// exactly in step with the last run's -cargo-pages.
func writeCargoCache(cacheDir string, recs map[string]cargoRec) error {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(cacheDir, "cargo_crates.jsonl"))
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	names := make([]string, 0, len(recs))
	for n := range recs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b, err := json.Marshal(recs[n])
		if err != nil {
			return err
		}
		w.Write(b)
		w.WriteByte('\n')
	}
	return w.Flush()
}

// day truncates an RFC3339 timestamp to its YYYY-MM-DD date.
func day(ts string) string {
	if len(ts) >= 10 {
		return ts[:10]
	}
	return ""
}

// progress prints a heartbeat every 250 completed items so long runs are
// observable without drowning the log.
type progress struct {
	mu    sync.Mutex
	total int
	doneN int
}

func (p *progress) done(total int, label string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if total > 0 {
		p.total = total
	}
	p.doneN++
	if p.doneN%250 == 0 {
		fmt.Fprintf(os.Stderr, "%s: %d/%d\n", label, p.doneN, p.total)
	}
}
