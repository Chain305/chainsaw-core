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
	"strconv"
	"strings"
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

// pypiDownloadsSQL is ClickHouse's public copy of the PyPI download logs (the
// dataset behind clickpy.clickhouse.com), read as its read-only demo user.
// The census sends it two aggregate queries and no package name. The demo
// user is capped at 60,000 result rows an hour, so the per-project answer
// comes back as ONE row (groupArray joined into a string, TSVRaw). It also
// stops reading at 1B rows and by default returns what it has read so far:
// the daily table (1.1B rows, not pruned by date) came back with a different
// subset on every run, which dropped fastapi-sso and 141 other existing rows.
// So the census reads the monthly table (~50M rows) and sets
// read_overflow_mode='throw' — a truncated scan is an error, never an answer.
const pypiDownloadsSQL = "https://sql-clickhouse.clickhouse.com/?user=demo&query="

// fetchPyPIRecent returns PEP 503 name -> downloads a week (the last complete
// month x 7/30) for every project at or above floor a week. It decides only
// who is worth a pypistats call — admission reads pypistats — and refuses
// when the dataset is stale or too small to rule a name out.
func fetchPyPIRecent(now time.Time, floor int64) (map[string]int64, error) {
	f := newFetcher()
	f.accept = "text/tab-separated-values"
	query := func(q string, line func([]string) error) error {
		q += " SETTINGS read_overflow_mode = 'throw' FORMAT TSVRaw"
		return f.get(pypiDownloadsSQL+url.QueryEscape(q), 64<<20, func(b []byte) error {
			for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				if err := line(strings.Split(l, "\t")); err != nil {
					return err
				}
			}
			return nil
		})
	}
	var current time.Time
	if err := query("SELECT max(month) FROM pypi.pypi_downloads_per_month", func(c []string) (err error) {
		current, err = time.Parse("2006-01-02", c[0])
		return err
	}); err != nil {
		return nil, fmt.Errorf("pypi downloads (clickhouse): %w", err)
	}
	// The newest month is still loading: read the one before it.
	month := current.AddDate(0, -1, 0)
	if now.Sub(month) > 70*24*time.Hour {
		return nil, fmt.Errorf("pypi downloads (clickhouse): last complete month %s is stale, refusing", month.Format("2006-01"))
	}
	out := map[string]int64{}
	if err := query(fmt.Sprintf("SELECT arrayStringConcat(groupArray(concat(project, '\\t', toString(c))), '\\n') FROM "+
		"(SELECT project, sum(count) AS c FROM pypi.pypi_downloads_per_month WHERE month = '%s' GROUP BY project HAVING c >= %d)",
		month.Format("2006-01-02"), floor*30/7), func(c []string) error {
		if len(c) != 2 {
			return fmt.Errorf("malformed row %q", c)
		}
		n, err := strconv.ParseInt(c[1], 10, 64)
		if err != nil {
			return err
		}
		out[pep503(c[0])] = n * 7 / 30
		return nil
	}); err != nil {
		return nil, fmt.Errorf("pypi downloads (clickhouse): %w", err)
	}
	if len(out) < 10_000 {
		return nil, fmt.Errorf("pypi downloads (clickhouse): only %d projects >= %d/week in %s, refusing", len(out), floor, month.Format("2006-01"))
	}
	fmt.Fprintf(os.Stderr, "pypi downloads (clickhouse): %d projects >= %d/week in %s (x 7/30)\n", len(out), floor, month.Format("2006-01"))
	return out, nil
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
