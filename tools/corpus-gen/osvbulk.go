package main

// OSV's per-ecosystem bulk export, which is where the paired V1/V2 stratum
// comes from.
//
// ─── WHY V1 IS NOT DRAWN FROM THE RANDOM REGISTRY POOL ──────────────────────
//
// It was, in the first version of this tool, and it produced 0 of 350 rows.
// Measured on a real run: of 1,086 randomly sampled coordinates across eight
// ecosystems, SEVEN carried any advisory at all. Vulnerability density in the
// registry at large is well under 1%, so filling 175 pairs by random sampling
// would need a pool of roughly 20,000-35,000 verified coordinates — 40,000 to
// 70,000 upstream requests to collect a stratum that OSV publishes directly.
//
// The bulk export is also the only source that carries the FIXED version. The
// querybatch API returns advisory ids and nothing else, so a pool-derived V1
// would still need one detail fetch per advisory to find its control.
//
// ─── WHAT MAKES A USABLE PAIR ───────────────────────────────────────────────
//
// An affected entry must carry BOTH an explicit `versions[]` list (a real
// vulnerable coordinate, not a range expression we would have to resolve
// ourselves) AND a `ranges[].events[].fixed` (the control). Density is high:
// NuGet's 1,890 advisories yield 6,316 qualifying entries.
//
// Withdrawn advisories are skipped. So are entries whose fixed version equals
// the vulnerable one, which would make the pair a tautology.

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// osvBulkEcosystem maps our token to the export's directory name. These differ
// from the query API's spellings in one place — crates.io — and a wrong name
// yields a 404 that would look like "this ecosystem has no vulnerabilities".
var osvBulkEcosystem = map[string]string{
	"npm": "npm", "pypi": "PyPI", "maven": "Maven", "cargo": "crates.io",
	"nuget": "NuGet", "rubygems": "RubyGems", "go": "Go", "composer": "Packagist",
}

// VulnPair is one vulnerable coordinate and the control that fixes it.
type VulnPair struct {
	Eco          string
	Name         string
	VulnVersion  string
	FixedVersion string
	AdvisoryID   string
}

func (p VulnPair) key() string { return p.Eco + "\x00" + p.Name + "\x00" + p.VulnVersion }

// osvBulkPairs downloads (or reuses) an ecosystem's export and returns every
// qualifying pair, sorted. The archive is cached rather than re-fetched: npm's
// is 215 MB and a corpus rebuild should not re-download a quarter of a
// gigabyte to change a seed.
func (c *client) osvBulkPairs(eco, cacheDir string) ([]VulnPair, error) {
	bulkEco, ok := osvBulkEcosystem[eco]
	if !ok {
		return nil, fmt.Errorf("no OSV bulk export for %q", eco)
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(cacheDir, strings.ReplaceAll(bulkEco, ".", "_")+"-all.zip")
	if st, err := os.Stat(path); err != nil || st.Size() == 0 {
		u := "https://osv-vulnerabilities.storage.googleapis.com/" + bulkEco + "/all.zip"
		// Streamed, NOT buffered: npm's export is 215 MB and the buffered
		// path caps at 128 MB. See downloadTo in sources.go.
		n, sum, err := c.downloadTo(u, path)
		if err != nil {
			return nil, fmt.Errorf("osv bulk %s: %w", eco, err)
		}
		c.record(Evidence{Kind: "osv_bulk", Eco: eco, Source: "osv-vulnerabilities.storage.googleapis.com",
			URL: u, Status: 200, BodySHA256: sum,
			Summary: map[string]any{"bytes": n}})
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		// A CACHED FILE THAT DOES NOT OPEN IS NOT A HARD FAILURE, IT IS A
		// BAD CACHE. This happened for real: an earlier build fetched the
		// npm export through the buffered path and stored a 134,217,728-byte
		// prefix of a 215 MB archive. Every later run then reused the
		// truncated file from cache and failed identically, because "the
		// file exists and is non-empty" is not the same question as "the
		// file is the archive we wanted". Discard and re-fetch ONCE; a
		// second failure is real.
		os.Remove(path)
		u := "https://osv-vulnerabilities.storage.googleapis.com/" + bulkEco + "/all.zip"
		n, sum, derr := c.downloadTo(u, path)
		if derr != nil {
			return nil, fmt.Errorf("osv bulk %s: cached archive was unreadable (%v) and the refetch failed: %w", eco, err, derr)
		}
		c.record(Evidence{Kind: "osv_bulk", Eco: eco, Source: "osv-vulnerabilities.storage.googleapis.com",
			URL: u, Status: 200, BodySHA256: sum,
			Summary: map[string]any{"bytes": n, "refetched_after_bad_cache": true}})
		if zr, err = zip.OpenReader(path); err != nil {
			return nil, fmt.Errorf("osv bulk %s: %w", eco, err)
		}
	}
	defer zr.Close()

	var pairs []VulnPair
	seen := map[string]bool{}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(rc, 8<<20))
		rc.Close()
		if err != nil {
			continue
		}
		var doc struct {
			ID        string `json:"id"`
			Withdrawn string `json:"withdrawn"`
			Affected  []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Versions []string `json:"versions"`
				Ranges   []struct {
					Events []struct {
						Fixed string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
		}
		if json.Unmarshal(raw, &doc) != nil || doc.Withdrawn != "" {
			continue
		}
		for _, a := range doc.Affected {
			if a.Package.Name == "" || len(a.Versions) == 0 {
				continue
			}
			// The export mixes ecosystem variants (npm vs npm:...);
			// accept only the exact match so a Maven advisory carried in
			// the Go export cannot leak into the Go stratum.
			if a.Package.Ecosystem != bulkEco {
				continue
			}
			var fixed []string
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						fixed = append(fixed, e.Fixed)
					}
				}
			}
			if len(fixed) == 0 {
				continue
			}
			sort.Strings(fixed)
			fix := fixed[len(fixed)-1]
			vers := append([]string(nil), a.Versions...)
			sort.Strings(vers)
			for _, v := range vers {
				if v == "" || v == fix {
					continue // a pair whose control IS the vulnerable version proves nothing
				}
				p := VulnPair{Eco: eco, Name: a.Package.Name, VulnVersion: v,
					FixedVersion: fix, AdvisoryID: doc.ID}
				if seen[p.key()] {
					continue
				}
				seen[p.key()] = true
				pairs = append(pairs, p)
			}
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Name != pairs[j].Name {
			return pairs[i].Name < pairs[j].Name
		}
		if pairs[i].VulnVersion != pairs[j].VulnVersion {
			return pairs[i].VulnVersion < pairs[j].VulnVersion
		}
		return pairs[i].AdvisoryID < pairs[j].AdvisoryID
	})
	return pairs, nil
}
