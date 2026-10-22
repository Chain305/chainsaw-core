// Command established-table-gen builds the install guard's embedded
// established tables (core/cli/seeds/established_<eco>.tsv) as a CENSUS: from
// the registry's full public name list, every name one edit from a
// block-eligible typosquat target that the registry shows is long-standing
// AND heavily used — first published >= 2 years before the build and >= 100k
// downloads a week (or the ecosystem's equivalent). Each row carries its
// exact build-time release set; the guard is silent only for an exact pin in
// it and warns on every other install of the name.
//
// Sources (public only — never a customer inventory; see README.md):
//
//	npm:   replicate.npmjs.com/_all_docs ids; registry docs; api.npmjs.org last-week
//	pypi:  pypi.org/simple (PEP 691); pypi.org/pypi/<name>/json; pypistats.org last_week
//	cargo: crates.io listing (seek pages, 1/s); /api/v1/crates/<name>; index.crates.io
//	pub:   pub.dev/api/package-names; /api/packages/<name>; /score downloadCount30Days
//
// Never admitted: known-malicious feed names, npm security placeholders,
// names with no registry data. Rails: a self-test of the admission lines,
// sentinel names that must be admitted, and a churn limit against the previous
// census. Any hard failure refuses the write and exits non-zero.
//
// Usage (from core/):
//
//	go run ./tools/established-table-gen -ecosystem npm -cache /tmp/etg-cache -out cli/seeds/established_npm.tsv
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	eco := flag.String("ecosystem", "", "npm | pypi | cargo | pub")
	out := flag.String("out", "", "output TSV path (refused on any hard rail failure)")
	// Not ./cache: run from core/, that is the core/cache Go package.
	cacheDir := flag.String("cache", filepath.Join(os.TempDir(), "established-table-gen-cache"), "cache dir (name lists + JSONL fetch caches); keep it outside the repo, reruns resume from it")
	npmSeed := flag.String("npm-popular-seed", "cli/seeds/npm_popular.txt", "popular npm seed (ranked corpus)")
	pypiSeed := flag.String("pypi-popular-seed", "cli/seeds/pypi_popular.txt", "popular pypi seed (ranked corpus)")
	malwareFeed := flag.String("malware-feed", defaultMalwareFeed(),
		"known-malicious OSV feed (the `chainsaw guard update` cache); every name in it is excluded. Required: an unreadable feed refuses the run")
	candidatesOnly := flag.Bool("candidates-only", false, "list names and count candidates, then stop (no per-candidate requests)")
	conc := flag.Int("concurrency", 6, "concurrent registry fetches (kept modest on purpose)")
	flag.Parse()

	if *eco == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: established-table-gen -ecosystem npm|pypi|cargo|pub -out <tsv> [-cache dir] [-malware-feed path] [-concurrency N]")
		os.Exit(2)
	}
	started := time.Now()
	gen, err := generate(generateArgs{
		eco:         *eco,
		out:         *out,
		cacheDir:    *cacheDir,
		npmSeed:     *npmSeed,
		pypiSeed:    *pypiSeed,
		malwareFeed: *malwareFeed,
		conc:        *conc,

		candidatesOnly: *candidatesOnly,
		now:            time.Now().UTC(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "established-table-gen: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "established-table-gen: %s done in %s (%d rows -> %s)\n",
		*eco, time.Since(started).Round(time.Second), gen, *out)
}

// defaultMalwareFeed is where `chainsaw guard update` writes the full OpenSSF
// known-malicious set (cli.guardDBPath).
func defaultMalwareFeed() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "chainsaw", "known_malicious.json")
}
