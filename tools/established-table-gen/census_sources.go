package main

// census_sources.go — the per-candidate metadata the census needs beyond the
// registry docs: weekly-equivalent downloads for PyPI and pub, and the
// crates.io crate record. Every source is cached as JSONL in the -cache dir
// and spaced by a shared limiter; 429/5xx back off and honour Retry-After
// (fetcher.get).

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"
)

type weeklyRec struct {
	Name   string `json:"name"`
	Weekly int64  `json:"weekly"`
}

// fetchPyPIWeekly reads pypistats.org's last_week figure, keyed by PEP 503
// name. A 404 (pypistats never saw the project) is 0 downloads.
func fetchPyPIWeekly(cacheDir string, names []string) (map[string]int64, error) {
	cached, err := loadJSONLCache(cacheDir, "pypi_weekly.jsonl", func(r weeklyRec) string { return r.Name })
	if err != nil {
		return nil, err
	}
	cache, err := openJSONLCache(cacheDir, "pypi_weekly.jsonl")
	if err != nil {
		return nil, err
	}
	defer cache.close()
	f := newRateLimitedFetcher(1100 * time.Millisecond)
	out := map[string]int64{}
	for _, n := range names {
		k := pep503(n)
		rec, ok := cached[k]
		if !ok {
			var resp struct {
				Data struct {
					LastWeek int64 `json:"last_week"`
				} `json:"data"`
			}
			switch err := f.getJSON("https://pypistats.org/api/packages/"+url.PathEscape(k)+"/recent", &resp, 1<<20); {
			case errors.Is(err, errNotFound):
			case err != nil:
				return nil, fmt.Errorf("pypistats %s: %w", k, err)
			}
			rec = weeklyRec{Name: k, Weekly: resp.Data.LastWeek}
			if err := cache.append(rec); err != nil {
				return nil, err
			}
		}
		out[k] = rec.Weekly
	}
	fmt.Fprintf(os.Stderr, "pypistats: %d names\n", len(out))
	return out, nil
}

// topPyPIURL is the public monthly-download ranking of the top 15,000 PyPI
// projects (hugovk/top-pypi-packages, from the PyPI BigQuery/ClickHouse
// dataset).
const topPyPIURL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"

// fetchTopPyPI returns PEP 503 name -> 30-day downloads for the top 15,000
// projects, and the smallest count in the list (the cutoff). The census uses
// it only to skip pypistats calls for projects that cannot reach the
// downloads line: if the cutoff is not far below the line, the list cannot
// prove that and the run refuses.
func fetchTopPyPI() (map[string]int64, int64, error) {
	var resp struct {
		Rows []struct {
			Count   int64  `json:"download_count"`
			Project string `json:"project"`
		} `json:"rows"`
	}
	if err := newFetcher().getJSON(topPyPIURL, &resp, 64<<20); err != nil {
		return nil, 0, fmt.Errorf("top-pypi-packages: %w", err)
	}
	out := map[string]int64{}
	var cutoff int64 = -1
	for _, r := range resp.Rows {
		out[pep503(r.Project)] = r.Count
		if cutoff < 0 || r.Count < cutoff {
			cutoff = r.Count
		}
	}
	if len(out) < 10_000 || cutoff < 0 || cutoff*7/30 >= weeklyDownloadsLine/4 {
		return nil, 0, fmt.Errorf("top-pypi-packages: %d rows, cutoff %d/month — cannot rule out the downloads line, refusing", len(out), cutoff)
	}
	fmt.Fprintf(os.Stderr, "top-pypi-packages: %d projects, cutoff %d/month\n", len(out), cutoff)
	return out, cutoff, nil
}

// fetchPubDownloads reads pub.dev's 30-day download count from the score
// endpoint.
func fetchPubDownloads(cacheDir string, names []string) (map[string]int64, error) {
	cached, err := loadJSONLCache(cacheDir, "pub_downloads.jsonl", func(r weeklyRec) string { return r.Name })
	if err != nil {
		return nil, err
	}
	cache, err := openJSONLCache(cacheDir, "pub_downloads.jsonl")
	if err != nil {
		return nil, err
	}
	defer cache.close()
	f := newRateLimitedFetcher(500 * time.Millisecond)
	out := map[string]int64{}
	for _, n := range names {
		rec, ok := cached[n]
		if !ok {
			if !pubNameRE.MatchString(n) {
				return nil, fmt.Errorf("pub score: refusing invalid package name %q", n)
			}
			var resp struct {
				DownloadCount30Days int64 `json:"downloadCount30Days"`
			}
			if err := f.getJSON("https://pub.dev/api/packages/"+n+"/score", &resp, 1<<20); err != nil && !errors.Is(err, errNotFound) {
				return nil, fmt.Errorf("pub score %s: %w", n, err)
			}
			// The cached Weekly field holds the raw 30-day figure here.
			rec = weeklyRec{Name: n, Weekly: resp.DownloadCount30Days}
			if err := cache.append(rec); err != nil {
				return nil, err
			}
		}
		out[n] = rec.Weekly
	}
	return out, nil
}

type crateRec struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Created  string `json:"created,omitempty"`
	Updated  string `json:"updated,omitempty"`
	Recent   int64  `json:"recent"` // 90-day downloads
	Versions int    `json:"versions"`
}

// fetchCrates reads one crates.io crate record per candidate, at the 1/s
// crawler rate crates.io asks for.
func fetchCrates(cacheDir string, names []string) (map[string]crateRec, error) {
	cached, err := loadJSONLCache(cacheDir, "cargo_crates_census.jsonl", func(r crateRec) string { return r.Name })
	if err != nil {
		return nil, err
	}
	cache, err := openJSONLCache(cacheDir, "cargo_crates_census.jsonl")
	if err != nil {
		return nil, err
	}
	defer cache.close()
	f := newRateLimitedFetcher(time.Second)
	for _, n := range names {
		if _, ok := cached[n]; ok {
			continue
		}
		var resp struct {
			Crate struct {
				CreatedAt       string `json:"created_at"`
				UpdatedAt       string `json:"updated_at"`
				RecentDownloads int64  `json:"recent_downloads"`
			} `json:"crate"`
			Versions []struct{} `json:"versions"`
		}
		rec := crateRec{Name: n}
		switch err := f.getJSON("https://crates.io/api/v1/crates/"+url.PathEscape(n), &resp, 16<<20); {
		case errors.Is(err, errNotFound):
		case err != nil:
			return nil, fmt.Errorf("crates.io %s: %w", n, err)
		default:
			rec = crateRec{Name: n, OK: true, Created: day(resp.Crate.CreatedAt), Updated: day(resp.Crate.UpdatedAt),
				Recent: resp.Crate.RecentDownloads, Versions: len(resp.Versions)}
		}
		if err := cache.append(rec); err != nil {
			return nil, err
		}
		cached[n] = rec
	}
	return cached, nil
}
