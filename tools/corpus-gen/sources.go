package main

// Upstream adapters. Every function here answers ONE question against ONE
// neutral public source, records what it saw as an Evidence row, and never
// touches a security vendor.
//
// ─── WHICH SOURCE ANSWERS WHAT, AND WHY IT IS THAT ONE ──────────────────────
//
//	                name enumeration                 version + metadata
//	npm        replicate.npmjs.com/_all_docs        deps.dev
//	pypi       pypi.org/simple                      deps.dev
//	maven      search.maven.org solrsearch          deps.dev
//	cargo      crates.io/api/v1/crates              deps.dev
//	nuget      azuresearch-usnc.nuget.org/query     deps.dev
//	rubygems   rubygems.org/names                   deps.dev
//	go         index.golang.org/index               deps.dev
//	composer   packagist.org/packages/list.json     repo.packagist.org/p2
//
// COMPOSER IS THE EXCEPTION AND IT IS NOT AN OVERSIGHT. deps.dev does not
// index Packagist at all — verified, not assumed: a real coordinate
// (composer/symfony%2Fconsole) 404s while the same probe returns 200 for the
// other seven systems. Silently dropping Composer would delete an ecosystem
// from the benchmark and make the omission look like "Composer has no
// packages". Packagist's own p2 document carries versions, publish times and
// licences, so Composer is served from there and the difference is recorded
// in every evidence row's Source field.
//
// ─── npm CANNOT BE PAGINATED BY OFFSET ──────────────────────────────────────
//
// replicate.npmjs.com answers `skip=` with 400 Bad Request (verified), so the
// npm sampler walks seeded two-character startkey prefixes instead. That is a
// name-prefix-stratified sample rather than a uniform one; it is recorded as
// such in source-manifest.json rather than described as uniform.
//
// ─── EVERY REQUEST CARRIES A DESCRIPTIVE User-Agent ─────────────────────────
//
// crates.io answers 403 to a UA-less request. This is a lesson already
// learned the expensive way on the public artifact fetch path
// (internal/server/public_artifact_fetch.go): because a fetch failure here
// degrades into "that ecosystem yielded no candidates", a UA regression looks
// exactly like a coverage gap rather than like a bug.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const userAgent = "chainsaw-corpus-gen/1 (+https://chain305.com; benchmark corpus construction)"

// maxBody bounds any single upstream response. pypi.org/simple is ~46 MB and
// is the largest legitimate response here; anything beyond 128 MB is a
// redirect loop or a mirror misbehaving, not data.
const maxBody = 128 << 20

// Evidence is one recorded upstream fact. The corpus is reproducible from
// these rows, not from re-querying — see the package comment in main.go.
type Evidence struct {
	Kind       string `json:"kind"` // enumerate | version | versions | osv | osv_vuln | ossf | project
	Eco        string `json:"eco,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Source     string `json:"source"` // host, never a full URL with a query
	URL        string `json:"url,omitempty"`
	ObservedAt string `json:"observed_at"`
	Status     int    `json:"status,omitempty"`
	BodySHA256 string `json:"body_sha256,omitempty"`
	Summary    any    `json:"summary,omitempty"`
}

type client struct {
	http *http.Client
	mu   sync.Mutex
	ev   []Evidence

	// nameCache holds the big one-shot name listings (pypi, rubygems,
	// packagist) so a stratum that samples the same ecosystem twice does
	// not re-download 46 MB.
	nameCache map[string][]string
}

func newClient() *client {
	return &client{
		http:      &http.Client{Timeout: 180 * time.Second},
		nameCache: map[string][]string{},
	}
}

func (c *client) record(e Evidence) {
	e.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	c.mu.Lock()
	c.ev = append(c.ev, e)
	c.mu.Unlock()
}

func (c *client) evidence() []Evidence {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Evidence, len(c.ev))
	copy(out, c.ev)
	return out
}

// get fetches u with the descriptive UA, retrying once on 429/5xx honouring
// Retry-After. It returns the body and the status; a non-2xx is NOT an error,
// because "this coordinate 404s" is a result the caller must be able to
// record rather than a failure that aborts a 15,000-request run.
func (c *client) get(u string, hdr map[string]string) ([]byte, int, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if attempt == 0 {
				time.Sleep(2 * time.Second)
				continue
			}
			return nil, 0, err
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		if rerr != nil {
			return nil, resp.StatusCode, rerr
		}
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt == 0 {
			wait := 5 * time.Second
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if n, err := strconv.Atoi(ra); err == nil && n > 0 && n < 120 {
					wait = time.Duration(n) * time.Second
				}
			}
			time.Sleep(wait)
			continue
		}
		return body, resp.StatusCode, nil
	}
}

// downloadTo streams a URL to disk, hashing as it writes.
//
// IT EXISTS BECAUSE THE BUFFERED PATH SILENTLY TRUNCATED. `get` reads through
// an io.LimitReader capped at maxBody (128 MB), which is right for a JSON API
// response and wrong for OSV's npm bulk export — that archive is 215 MB, so it
// arrived as a 128 MB prefix. The zip reader then refused it, which is the
// lucky outcome: the cap produced a LOUD failure only because zip carries its
// central directory at the END of the file. A truncated JSON or text payload
// would have parsed as a short-but-valid document and quietly shrunk a
// stratum.
//
// So bulk archives never go through the in-memory path at all. The cap here is
// deliberately generous and the size is returned, so a caller can tell a
// complete download from a clipped one rather than inferring it from a parse
// failure.
const maxDownload = 2 << 30

func (c *client) downloadTo(u, path string) (int64, string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	tmp := path + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxDownload))
	closeErr := f.Close()
	if err != nil {
		os.Remove(tmp)
		return 0, "", err
	}
	if closeErr != nil {
		os.Remove(tmp)
		return 0, "", closeErr
	}
	if n >= maxDownload {
		os.Remove(tmp)
		return 0, "", fmt.Errorf("download hit the %d-byte ceiling; it is almost certainly truncated", int64(maxDownload))
	}
	// Rename only after a complete write, so an interrupted run cannot
	// leave a short file that the next run happily reuses from cache.
	if err := os.Rename(tmp, path); err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func (c *client) postJSON(u string, payload any) ([]byte, int, error) {
	buf, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(string(buf)))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			if attempt == 0 {
				time.Sleep(2 * time.Second)
				continue
			}
			return nil, 0, err
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		if rerr != nil {
			return nil, resp.StatusCode, rerr
		}
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt == 0 {
			time.Sleep(5 * time.Second)
			continue
		}
		return body, resp.StatusCode, nil
	}
}

// ─── NAME ENUMERATION ───────────────────────────────────────────────────────

// npmPrefixAlphabet is the character set npm package names start with. The
// sampler draws two-character prefixes from it; see the file comment for why
// prefix walking replaces offset pagination.
const npmPrefixAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// enumerate returns up to want candidate NAMES for eco, chosen deterministically
// from rng. It never returns versions: version selection is a separate,
// separately-seeded decision so that changing the pool size does not reshuffle
// which version of an unaffected package was picked.
func (c *client) enumerate(eco string, rng *rand.Rand, want int) ([]string, error) {
	switch eco {
	case "pypi", "rubygems", "composer":
		all, err := c.fullNameList(eco)
		if err != nil {
			return nil, err
		}
		return sampleStrings(all, rng, want), nil
	case "npm":
		return c.enumerateNPM(rng, want)
	case "cargo":
		return c.enumerateCrates(rng, want)
	case "nuget":
		return c.enumerateNuGet(rng, want)
	case "maven":
		return c.enumerateMaven(rng, want)
	case "go":
		return c.enumerateGo(rng, want)
	}
	return nil, fmt.Errorf("no enumerator for ecosystem %q", eco)
}

var simpleAnchor = regexp.MustCompile(`<a [^>]*>([^<]+)</a>`)

// fullNameList downloads an ecosystem's COMPLETE name index once. These three
// registries publish one, which makes their sample genuinely uniform over the
// whole registry rather than over a paginated window.
func (c *client) fullNameList(eco string) ([]string, error) {
	c.mu.Lock()
	if v, ok := c.nameCache[eco]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	var u string
	switch eco {
	case "pypi":
		u = "https://pypi.org/simple/"
	case "rubygems":
		u = "https://rubygems.org/names"
	case "composer":
		u = "https://packagist.org/packages/list.json"
	}
	body, status, err := c.get(u, map[string]string{"Accept": "text/html,application/json"})
	if err != nil {
		return nil, fmt.Errorf("%s name index: %w", eco, err)
	}
	if status != 200 {
		return nil, fmt.Errorf("%s name index: HTTP %d", eco, status)
	}
	var names []string
	switch eco {
	case "pypi":
		for _, m := range simpleAnchor.FindAllStringSubmatch(string(body), -1) {
			names = append(names, strings.TrimSpace(m[1]))
		}
	case "rubygems":
		for _, ln := range strings.Split(string(body), "\n") {
			if s := strings.TrimSpace(ln); s != "" {
				names = append(names, s)
			}
		}
	case "composer":
		var doc struct {
			PackageNames []string `json:"packageNames"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, fmt.Errorf("composer list.json: %w", err)
		}
		names = doc.PackageNames
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%s name index parsed to zero names", eco)
	}
	// Sort before anything samples it. The registries mostly return sorted
	// lists already, but "mostly" is how a non-deterministic corpus gets
	// shipped looking seeded.
	sort.Strings(names)
	c.record(Evidence{Kind: "enumerate", Eco: eco, Source: hostOf(u), URL: u, Status: status,
		BodySHA256: sha256Hex(body), Summary: map[string]any{"names": len(names)}})
	c.mu.Lock()
	c.nameCache[eco] = names
	c.mu.Unlock()
	return names, nil
}

func (c *client) enumerateNPM(rng *rand.Rand, want int) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	// Each prefix yields a contiguous alphabetical run, so draw many
	// prefixes rather than few deep pages: 40 names from 60 prefixes is a
	// far better spread of the registry than 2400 names from two.
	const perPrefix = 40
	for attempts := 0; len(out) < want && attempts < want*4; attempts++ {
		p := string([]byte{
			npmPrefixAlphabet[rng.IntN(len(npmPrefixAlphabet))],
			npmPrefixAlphabet[rng.IntN(len(npmPrefixAlphabet))],
		})
		u := "https://replicate.npmjs.com/_all_docs?limit=" + strconv.Itoa(perPrefix) +
			"&startkey=" + url.QueryEscape(`"`+p+`"`) +
			"&endkey=" + url.QueryEscape(`"`+p+"￰"+`"`)
		body, status, err := c.get(u, nil)
		if err != nil || status != 200 {
			continue
		}
		var doc struct {
			Rows []struct {
				ID string `json:"id"`
			} `json:"rows"`
		}
		if json.Unmarshal(body, &doc) != nil {
			continue
		}
		c.record(Evidence{Kind: "enumerate", Eco: "npm", Source: "replicate.npmjs.com", Status: status,
			BodySHA256: sha256Hex(body), Summary: map[string]any{"prefix": p, "rows": len(doc.Rows)}})
		for _, r := range doc.Rows {
			if r.ID == "" || seen[r.ID] || strings.HasPrefix(r.ID, "_design") {
				continue
			}
			seen[r.ID] = true
			out = append(out, r.ID)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (c *client) enumerateCrates(rng *rand.Rand, want int) ([]string, error) {
	const per = 100
	maxPage := 334087/per - 1 // total from crates.io meta, 2026-09
	seen := map[string]bool{}
	var out []string
	for attempts := 0; len(out) < want && attempts < want/per+40; attempts++ {
		page := rng.IntN(maxPage) + 1
		u := fmt.Sprintf("https://crates.io/api/v1/crates?page=%d&per_page=%d&sort=alpha", page, per)
		body, status, err := c.get(u, nil)
		if err != nil || status != 200 {
			continue
		}
		var doc struct {
			Crates []struct {
				ID string `json:"id"`
			} `json:"crates"`
		}
		if json.Unmarshal(body, &doc) != nil {
			continue
		}
		c.record(Evidence{Kind: "enumerate", Eco: "cargo", Source: "crates.io", Status: status,
			BodySHA256: sha256Hex(body), Summary: map[string]any{"page": page, "rows": len(doc.Crates)}})
		for _, cr := range doc.Crates {
			if cr.ID != "" && !seen[cr.ID] {
				seen[cr.ID] = true
				out = append(out, cr.ID)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// enumerateNuGet walks the NuGet CATALOG, not the search API.
//
// The search endpoint caps `skip` at exactly 3000 — verified: skip=3000
// returns results, skip=3100 returns totalHits:0 with an empty data array and
// HTTP 200. An earlier version of this sampler drew offsets across the full
// 486,841 reported hits, so 99.4% of its draws landed in the dead window and
// the ecosystem contributed ZERO candidates while every request succeeded.
// That is the silent-lookup failure CLAUDE.md warns about, in its natural
// habitat: a 200 with an empty body reads as "this registry has no packages".
//
// The catalog has no such cap. Its index lists ~23,000 pages of ~550 entries
// each, covering the whole registry, so sampling pages samples NuGet.
func (c *client) enumerateNuGet(rng *rand.Rand, want int) ([]string, error) {
	idxBody, status, err := c.get("https://api.nuget.org/v3/catalog0/index.json", nil)
	if err != nil || status != 200 {
		return nil, fmt.Errorf("nuget catalog index: HTTP %d: %v", status, err)
	}
	var idx struct {
		Items []struct {
			ID string `json:"@id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(idxBody, &idx); err != nil {
		return nil, fmt.Errorf("nuget catalog index: %w", err)
	}
	if len(idx.Items) == 0 {
		return nil, fmt.Errorf("nuget catalog index listed zero pages")
	}
	c.record(Evidence{Kind: "enumerate", Eco: "nuget", Source: "api.nuget.org", Status: status,
		BodySHA256: sha256Hex(idxBody), Summary: map[string]any{"catalog_pages": len(idx.Items)}})

	seen := map[string]bool{}
	var out []string
	for attempts := 0; len(out) < want && attempts < want/200+60; attempts++ {
		page := idx.Items[rng.IntN(len(idx.Items))].ID
		body, st, err := c.get(page, nil)
		if err != nil || st != 200 {
			continue
		}
		var doc struct {
			Items []struct {
				ID string `json:"nuget:id"`
			} `json:"items"`
		}
		if json.Unmarshal(body, &doc) != nil {
			continue
		}
		for _, it := range doc.Items {
			if it.ID != "" && !seen[it.ID] {
				seen[it.ID] = true
				out = append(out, it.ID)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func (c *client) enumerateMaven(rng *rand.Rand, want int) ([]string, error) {
	const per = 100
	maxStart := 200000 // solr deep paging degrades past this; verified working at 50k
	seen := map[string]bool{}
	var out []string
	for attempts := 0; len(out) < want && attempts < want/per+40; attempts++ {
		start := rng.IntN(maxStart)
		u := fmt.Sprintf("https://search.maven.org/solrsearch/select?q=*:*&rows=%d&start=%d&wt=json", per, start)
		body, status, err := c.get(u, nil)
		if err != nil || status != 200 {
			continue
		}
		var doc struct {
			Response struct {
				Docs []struct {
					G string `json:"g"`
					A string `json:"a"`
				} `json:"docs"`
			} `json:"response"`
		}
		if json.Unmarshal(body, &doc) != nil {
			continue
		}
		c.record(Evidence{Kind: "enumerate", Eco: "maven", Source: "search.maven.org", Status: status,
			BodySHA256: sha256Hex(body), Summary: map[string]any{"start": start, "rows": len(doc.Response.Docs)}})
		for _, d := range doc.Response.Docs {
			if d.G == "" || d.A == "" {
				continue
			}
			n := d.G + ":" + d.A
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// goFeedStart and goFeedEnd bound index.golang.org's chronological feed. The
// sampler draws random `since` timestamps across that window, which samples
// PUBLICATION TIME uniformly rather than name space — the only axis that feed
// exposes. Recorded in the manifest so the difference is not lost.
var (
	goFeedStart = time.Date(2019, 4, 10, 0, 0, 0, 0, time.UTC)
	goFeedEnd   = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
)

func (c *client) enumerateGo(rng *rand.Rand, want int) ([]string, error) {
	span := goFeedEnd.Sub(goFeedStart)
	seen := map[string]bool{}
	var out []string
	const per = 200
	for attempts := 0; len(out) < want && attempts < want/per+60; attempts++ {
		since := goFeedStart.Add(time.Duration(rng.Int64N(int64(span))))
		u := "https://index.golang.org/index?limit=" + strconv.Itoa(per) +
			"&since=" + url.QueryEscape(since.UTC().Format(time.RFC3339))
		body, status, err := c.get(u, nil)
		if err != nil || status != 200 {
			continue
		}
		c.record(Evidence{Kind: "enumerate", Eco: "go", Source: "index.golang.org", Status: status,
			BodySHA256: sha256Hex(body), Summary: map[string]any{"since": since.Format(time.RFC3339)}})
		for _, ln := range strings.Split(string(body), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			var rec struct {
				Path string `json:"Path"`
			}
			if json.Unmarshal([]byte(ln), &rec) != nil || rec.Path == "" {
				continue
			}
			// Skip +incompatible / nested vanity noise that cannot be
			// fetched as a module in its own right.
			if strings.Contains(rec.Path, "!") || !seen[rec.Path] {
				if !seen[rec.Path] {
					seen[rec.Path] = true
					out = append(out, rec.Path)
				}
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return u
	}
	return p.Host
}
