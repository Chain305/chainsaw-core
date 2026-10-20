// Command established-table-gen regenerates the install guard's embedded
// established-package tables (core/cli/seeds/established_<eco>.tsv): every
// registry package in the candidate universe that meets ANY clear line, as
// real per-package registry data — not a popularity ranking.
//
// This replaces a rejected corpus-row design. The adversarial finding: a
// package with 20k weekly downloads, 8 years of history and 60 versions must
// CLEAR a typosquat verdict, yet it will never appear in a top-10k popularity
// corpus. The table therefore keys establishment (the clear lines mirrored
// from core/risk/established.go and core/intelligence/typosquat_established.go)
// instead of rank, and every row carries the numbers that qualified it so the
// consumer re-adjudicates offline with zero network.
//
// Sources (see README.md for the trust channel — reviewed data PR or signed
// bundle, never live at install time):
//
//	npm:   universe = cli/seeds/npm_popular.txt ∪ packages.csv(npm) ∪
//	       npm_docs.jsonl names ∪ canary pins. Per name: the FULL registry
//	       doc (time.created, per-version times, len(versions)) plus
//	       api.npmjs.org last-week downloads (bulk batches for unscoped
//	       names, point calls for scoped).
//	pypi:  universe = cli/seeds/pypi_popular.txt ∪ packages.csv(pypi).
//	       pypi.org/pypi/<PEP503>/json releases (version_count = releases
//	       with files; first/last from upload_time). Downloads unknown -> 0.
//	cargo: crates.io/api/v1/crates?sort=downloads top pages; the listing
//	       carries created_at/updated_at/downloads/num_versions.
//
// Anti-poisoning rails (refuse-don't-report-zero, after the corpus floor
// discipline in popular-corpus-gen): canary adjudication for every measured
// false-block, a multi-signal floor for downloads-only rows, a d1-of-popular
// ratio watch, churn limits against the previous table, and a patient-attacker
// self-test. Any hard rail failure refuses the write and exits non-zero.
//
// Usage (from core/):
//
//	go run ./tools/established-table-gen -ecosystem npm \
//	  -packages-csv "/path/to/packages.csv" \
//	  -npm-docs-jsonl "/path/to/npm_docs.jsonl" \
//	  -cache ./cache -out cli/seeds/established_npm.tsv
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// canaries are the measured false-blocks of the typosquat gate (npm). Every
// one must be adjudicated on real registry data each run: in the table, or
// listed with the reason it does not qualify. A canary we cannot fetch is a
// hard failure — the table would silently lose its regression coverage.
var canaries = []string{
	"pug", "jsdoc", "uglify-es", "flatten", "lodash.set", "charset",
	"parseuri", "clui", "as-number", "hable", "crypto-es", "crypto-ts",
	"has-own", "js-logger",
}

func main() {
	eco := flag.String("ecosystem", "", "npm | pypi | cargo")
	out := flag.String("out", "", "output TSV path (refused on any hard rail failure)")
	cacheDir := flag.String("cache", "./cache", "JSONL fetch-cache dir; reruns resume from it")
	packagesCSV := flag.String("packages-csv",
		"/Users/zeeshan/Desktop/Chain305 Research/publish/sbom/packages.csv",
		"SBOM packages.csv (ecosystem,name,version); the non-seed half of the universe")
	npmDocsJSONL := flag.String("npm-docs-jsonl",
		"/Users/zeeshan/Desktop/Chain305 Research/analysis/sizes/npm_docs.jsonl",
		"cached abbreviated npm docs; names only, used to widen the universe")
	npmSeed := flag.String("npm-popular-seed", "cli/seeds/npm_popular.txt", "popular npm seed (ranked corpus)")
	pypiSeed := flag.String("pypi-popular-seed", "cli/seeds/pypi_popular.txt", "popular pypi seed (ranked corpus)")
	cargoPages := flag.Int("cargo-pages", 30, "crates.io listing pages to fetch (100 crates each)")
	conc := flag.Int("concurrency", 6, "concurrent registry fetches (kept modest on purpose)")
	flag.Parse()

	if *eco == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "usage: established-table-gen -ecosystem npm|pypi|cargo -out <tsv> [-cache dir] [-concurrency N]")
		os.Exit(2)
	}
	started := time.Now()
	gen, err := generate(generateArgs{
		eco:         *eco,
		out:         *out,
		cacheDir:    *cacheDir,
		packagesCSV: *packagesCSV,
		npmDocs:     *npmDocsJSONL,
		npmSeed:     *npmSeed,
		pypiSeed:    *pypiSeed,
		cargoPages:  *cargoPages,
		conc:        *conc,
		now:         time.Now().UTC(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "established-table-gen: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "established-table-gen: %s done in %s (%d rows -> %s)\n",
		*eco, time.Since(started).Round(time.Second), gen, *out)
}
