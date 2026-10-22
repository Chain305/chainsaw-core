package main

// releases.go — the table's sixth column (the build-time release set) and the
// malware-feed exclusion, both added 2026-10-21.
//
// The guard's established clear used to skip the typosquat lane for any
// version, so a dormant lookalike that qualified years ago and then shipped a
// malicious release was cleared on its history. The guard now stays silent
// only for an exact pin inside the row's release set and WARNS otherwise, so
// the table has to carry that set. It is written only for rows the typosquat
// detector can flag: every other row never reaches the clear, and carrying
// thousands of release lists for them would bloat the binary for nothing. A
// flagged row the generator missed (a corpus that moved after the build)
// simply has no set and warns — the safe direction.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

// feedEcosystems maps the OSV ecosystem label onto the generator's.
var feedEcosystems = map[string]string{"npm": "npm", "pypi": "pypi", "crates.io": "cargo", "pub": "pub"}

// loadFeedNames reads the known-malicious feed (the `chainsaw guard update`
// cache, OSV array or NDJSON) plus the embedded floor, and returns
// ecosystem -> normalized names. A feed that cannot be read refuses the run:
// a table built without it could clear a name the feed knows is malicious.
func loadFeedNames(path string) (map[string]map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("malware feed %s: %w (pass -malware-feed; run `chainsaw guard update` to create it)", path, err)
	}
	extra := malware.ParseOSVBlob(data)
	if len(extra) == 0 {
		return nil, fmt.Errorf("malware feed %s: parsed 0 entries — refusing to build without it", path)
	}
	out := map[string]map[string]bool{}
	for _, e := range append(malware.Floor(), extra...) {
		if e == nil || e.Withdrawn != nil {
			continue
		}
		for _, a := range e.Affected {
			eco, ok := feedEcosystems[strings.ToLower(a.Package.Ecosystem)]
			if !ok || a.Package.Name == "" {
				continue
			}
			if out[eco] == nil {
				out[eco] = map[string]bool{}
			}
			out[eco][typosquat.NormalizerForFormat(eco)(a.Package.Name)] = true
		}
	}
	fmt.Fprintf(os.Stderr, "malware feed: %d entries from %s (+ embedded floor)\n", len(extra), path)
	return out, nil
}

// offlineTransport fails every request, so the typosquat fetcher falls back to
// its embedded seed — the same corpus the offline guard loads for cargo/pub.
type offlineTransport struct{}

func (offlineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("offline")
}

// guardCorpusLimit mirrors cli.popularCorpusLimit for the fetcher-seeded
// ecosystems.
const guardCorpusLimit = 500

// detectorCorpus returns the popular corpus the guard's detector loads for an
// ecosystem: the ranked seed file for npm/pypi, the embedded fetcher seed for
// the rest.
func detectorCorpus(eco string, seedNames []string) ([]typosquat.PopularPackage, error) {
	if len(seedNames) > 0 {
		pkgs := make([]typosquat.PopularPackage, len(seedNames))
		for i, n := range seedNames {
			pkgs[i] = typosquat.PopularPackage{Name: n, Rank: i + 1}
		}
		return pkgs, nil
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	f := typosquat.NewFetcher(quiet, typosquat.WithHTTPClient(&http.Client{Transport: offlineTransport{}}))
	pkgs, _ := f.FetchPopularPackages(context.Background(), eco, guardCorpusLimit)
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("%s: no embedded popular corpus — cannot tell which rows need a release set", eco)
	}
	return pkgs, nil
}

// ---------------------------------------------------------------------------
// cargo: versions from the sparse index, fetched for lookalike rows only

type cargoVersionsRec struct {
	Name     string   `json:"name"`
	OK       bool     `json:"ok"`
	Versions []string `json:"versions,omitempty"`
}

// cargoIndexPath is the sparse-index path for a crate name.
func cargoIndexPath(name string) string {
	n := strings.ToLower(name)
	switch len(n) {
	case 1:
		return "1/" + n
	case 2:
		return "2/" + n
	case 3:
		return "3/" + n[:1] + "/" + n
	default:
		return n[:2] + "/" + n[2:4] + "/" + n
	}
}

func fetchCargoVersions(cacheDir string, names []string) (map[string][]string, error) {
	cached, err := loadJSONLCache(cacheDir, "cargo_versions.jsonl", func(r cargoVersionsRec) string { return r.Name })
	if err != nil {
		return nil, err
	}
	cache, err := openJSONLCache(cacheDir, "cargo_versions.jsonl")
	if err != nil {
		return nil, err
	}
	defer cache.close()
	f := newFetcher()
	out := map[string][]string{}
	for _, n := range names {
		rec, ok := cached[n]
		if !ok {
			rec = cargoVersionsRec{Name: n, OK: true}
			err := f.get("https://index.crates.io/"+cargoIndexPath(n), 64<<20, func(b []byte) error {
				rec.Versions = rec.Versions[:0]
				for _, line := range strings.Split(string(b), "\n") {
					if strings.TrimSpace(line) == "" {
						continue
					}
					var v struct {
						Vers string `json:"vers"`
					}
					if err := json.Unmarshal([]byte(line), &v); err != nil {
						return err
					}
					rec.Versions = append(rec.Versions, v.Vers)
				}
				return nil
			})
			if errors.Is(err, errNotFound) {
				rec = cargoVersionsRec{Name: n}
			} else if err != nil {
				return nil, fmt.Errorf("cargo versions %s: %w", n, err)
			}
			if err := cache.append(rec); err != nil {
				return nil, err
			}
		}
		out[n] = rec.Versions
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// pub

type pubRec struct {
	Name        string   `json:"name"`
	OK          bool     `json:"ok"`
	First       string   `json:"first,omitempty"`
	Last        string   `json:"last,omitempty"`
	VersionList []string `json:"version_list,omitempty"`
}

// pubNameRE is pub.dev's package-name shape; anything else is refused.
var pubNameRE = regexp.MustCompile(`^[a-z0-9_]+$`)

// fetchPub reads https://pub.dev/api/packages/<name>: every version with its
// publish time. pub.dev publishes no weekly download figure, so pub rows
// qualify only through the release-history and long-lived lines.
func fetchPub(cacheDir string, names []string, conc int, prog *progress) (map[string]pubRec, error) {
	cached, err := loadJSONLCache(cacheDir, "pub_docs.jsonl", func(r pubRec) string { return r.Name })
	if err != nil {
		return nil, err
	}
	cache, err := openJSONLCache(cacheDir, "pub_docs.jsonl")
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
	fmt.Fprintf(os.Stderr, "pub docs: %d cached, %d to fetch\n", len(cached), len(missing))
	f := newFetcher()
	var mu sync.Mutex
	errs := workerPool(missing, conc, func(n string) error {
		if !pubNameRE.MatchString(n) {
			return fmt.Errorf("pub docs: refusing invalid package name %q", n)
		}
		var doc struct {
			Versions []struct {
				Version   string `json:"version"`
				Published string `json:"published"`
			} `json:"versions"`
		}
		rec := pubRec{Name: n}
		switch err := f.getJSON("https://pub.dev/api/packages/"+n, &doc, 64<<20); {
		case errors.Is(err, errNotFound):
		case err != nil:
			return fmt.Errorf("pub %s: %w", n, err)
		default:
			rec.OK = true
			for _, v := range doc.Versions {
				rec.VersionList = append(rec.VersionList, v.Version)
				d := day(v.Published)
				if d == "" {
					continue
				}
				if rec.First == "" || d < rec.First {
					rec.First = d
				}
				if d > rec.Last {
					rec.Last = d
				}
			}
		}
		if err := cache.append(rec); err != nil {
			return err
		}
		mu.Lock()
		cached[n] = rec
		mu.Unlock()
		prog.done(len(missing), "pub docs")
		return nil
	})
	return cached, checkErrs(errs)
}

// sortedReleases renders a release set as the sixth TSV column.
func sortedReleases(vs []string) string {
	out := make([]string, 0, len(vs))
	seen := map[string]bool{}
	for _, v := range vs {
		// A comma or tab would split the column; no registry allows either in
		// a version, so a version carrying one is dropped rather than escaped.
		if v == "" || seen[v] || strings.ContainsAny(v, ",\t\n") {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
