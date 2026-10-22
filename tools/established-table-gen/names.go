package main

// names.go — the registry's own full name list, the census universe.
//
// The table used to be built from a candidate universe that included a
// customer SBOM export, which made every measurement on that customer
// in-sample and sent the export's pseudonymised internal-<hash> names to the
// registries. The census reads public registry name lists ONLY, and never
// keeps one after a successful generation.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// censusNames returns every package name the registry lists for eco, from
// the cache file when present.
//
// npm's list (~4.5M names, ~100 MB) is never written to disk: it is paged
// straight into memory. The smaller lists are cached so a failed later step
// does not re-list (crates.io takes ~3,600 requests at 1/s); generate removes
// the cache file after a successful write.
func censusNames(eco, cacheDir string) ([]string, error) {
	path := namesCachePath(eco, cacheDir)
	if names, err := readLines(path); err == nil && len(names) > 0 {
		names = dropEmptyAndPseudonyms(eco, names)
		fmt.Fprintf(os.Stderr, "%s names: %d from cache %s\n", eco, len(names), path)
		return names, nil
	}
	var (
		names []string
		err   error
	)
	switch eco {
	case "npm":
		names, err = npmAllNames()
	case "pypi":
		names, err = pypiAllNames()
	case "pub":
		names, err = pubAllNames()
	case "cargo":
		names, err = cargoAllNames(cacheDir)
	default:
		return nil, fmt.Errorf("census: no name list for %q", eco)
	}
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	if eco == "npm" {
		names = dropEmptyAndPseudonyms(eco, names)
		fmt.Fprintf(os.Stderr, "%s names: %d fetched (memory only)\n", eco, len(names))
		return names, nil
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(names, "\n")+"\n"), 0o644); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	names = dropEmptyAndPseudonyms(eco, names)
	fmt.Fprintf(os.Stderr, "%s names: %d fetched -> %s\n", eco, len(names), path)
	return names, nil
}

// namesCachePath is where a non-npm name list is cached during a run.
func namesCachePath(eco, cacheDir string) string {
	return filepath.Join(cacheDir, eco+"_names.txt")
}

// dropEmptyAndPseudonyms is the second guard behind "public lists only": a
// pseudonym shape can never be a registry name worth a lookup.
func dropEmptyAndPseudonyms(eco string, names []string) []string {
	out := names[:0]
	dropped := 0
	for _, n := range names {
		n = strings.TrimSpace(n)
		switch {
		case n == "":
		case pseudonymRE.MatchString(n):
			dropped++
		default:
			out = append(out, n)
		}
	}
	if dropped > 0 {
		fmt.Fprintf(os.Stderr, "%s names: dropped %d internal-<hash> name(s)\n", eco, dropped)
	}
	return out
}

// npmAllNames pages replicate.npmjs.com/_all_docs (ids only, ~4.5M rows).
func npmAllNames() ([]string, error) {
	f := newRateLimitedFetcher(500 * time.Millisecond)
	var names []string
	start := ""
	for page := 0; ; page++ {
		u := "https://replicate.npmjs.com/_all_docs?limit=10000"
		if start != "" {
			key, _ := json.Marshal(start)
			// The replicate endpoint refuses skip=; startkey is inclusive, so
			// the first row repeats the previous page's last and is dropped.
			u += "&startkey=" + url.QueryEscape(string(key))
		}
		var resp struct {
			Rows []struct {
				ID string `json:"id"`
			} `json:"rows"`
		}
		if err := f.getJSON(u, &resp, 64<<20); err != nil {
			return nil, fmt.Errorf("npm _all_docs page %d: %w", page, err)
		}
		rows := resp.Rows
		if start != "" && len(rows) > 0 && rows[0].ID == start {
			rows = rows[1:]
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			if !strings.HasPrefix(r.ID, "_") {
				names = append(names, r.ID)
			}
		}
		start = rows[len(rows)-1].ID
		if page%50 == 0 {
			fmt.Fprintf(os.Stderr, "npm names: page %d, %d names, at %q\n", page, len(names), start)
		}
	}
	return names, nil
}

// pypiAllNames reads the PEP 691 JSON simple index.
func pypiAllNames() ([]string, error) {
	var resp struct {
		Projects []struct {
			Name string `json:"name"`
		} `json:"projects"`
	}
	f := newFetcher()
	f.accept = "application/vnd.pypi.simple.v1+json"
	if err := f.getJSON("https://pypi.org/simple/", &resp, 512<<20); err != nil {
		return nil, fmt.Errorf("pypi simple index: %w", err)
	}
	names := make([]string, 0, len(resp.Projects))
	for _, p := range resp.Projects {
		names = append(names, p.Name)
	}
	return names, nil
}

// pubAllNames reads pub.dev's package-names list (one response today; the
// nextUrl field is followed if it ever paginates).
func pubAllNames() ([]string, error) {
	f := newRateLimitedFetcher(time.Second)
	var names []string
	for u := "https://pub.dev/api/package-names"; u != ""; {
		var resp struct {
			Packages []string `json:"packages"`
			NextURL  string   `json:"nextUrl"`
		}
		if err := f.getJSON(u, &resp, 64<<20); err != nil {
			return nil, fmt.Errorf("pub package-names: %w", err)
		}
		names = append(names, resp.Packages...)
		u = resp.NextURL
	}
	return names, nil
}

// cargoAllNames seek-pages the crates.io listing at 1 request/second, the
// crawler rate crates.io asks for (~3,600 pages). The 2 GB db dump is the
// documented alternative; it does not fit the release machine's disk.
//
// The listing already carries each crate's creation date, 90-day downloads
// and version count, so they are cached as crate records here and the census
// makes no per-crate API call at all (fetchCrates finds them cached).
func cargoAllNames(cacheDir string) ([]string, error) {
	cache, err := openJSONLCache(cacheDir, "cargo_crates_census.jsonl")
	if err != nil {
		return nil, err
	}
	defer cache.close()
	f := newRateLimitedFetcher(time.Second)
	var names []string
	next := "?per_page=100&sort=alpha"
	for page := 0; next != ""; page++ {
		var resp struct {
			Crates []struct {
				Name            string `json:"name"`
				CreatedAt       string `json:"created_at"`
				UpdatedAt       string `json:"updated_at"`
				RecentDownloads int64  `json:"recent_downloads"`
				NumVersions     int    `json:"num_versions"`
			} `json:"crates"`
			Meta struct {
				NextPage string `json:"next_page"`
			} `json:"meta"`
		}
		if err := f.getJSON("https://crates.io/api/v1/crates"+next, &resp, 16<<20); err != nil {
			return nil, fmt.Errorf("crates.io listing page %d: %w", page, err)
		}
		for _, c := range resp.Crates {
			names = append(names, c.Name)
			if err := cache.append(crateRec{Name: c.Name, OK: true, Created: day(c.CreatedAt), Updated: day(c.UpdatedAt),
				Recent: c.RecentDownloads, Versions: c.NumVersions}); err != nil {
				return nil, err
			}
		}
		next = resp.Meta.NextPage
		if page%250 == 0 {
			fmt.Fprintf(os.Stderr, "cargo names: page %d, %d names\n", page, len(names))
		}
	}
	return names, nil
}
