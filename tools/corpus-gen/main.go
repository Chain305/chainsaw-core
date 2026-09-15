// Command corpus-gen builds a REPRODUCIBLE, competitor-neutral package corpus
// for the detection-comparison benchmark, and validates one.
//
//	corpus-gen build    --seed PIB-2026-v1 --out ./corpus-v1
//	corpus-gen validate ./corpus-v1
//
// ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
//
// scripts/detection-eval/corpus-seed.tsv is 179 hand-curated rows. Every row
// cites a source, so it is honest, but it is not reproducible and it is not
// scalable: nobody can re-derive it, and "why is THAT package in the corpus"
// has no mechanical answer. A benchmark whose sample was chosen by hand can
// always be accused of having been chosen to flatter the result.
//
// This tool removes the hand from the loop. Candidate discovery, version
// selection, ground-truth ingestion, sampling, deduplication and freezing are
// all deterministic given (seed, upstream snapshot). Human judgement is
// reserved for adjudicating disagreements AFTER collection, never for
// deciding what is measured.
//
// ─── THE RULE THAT MAKES IT A BENCHMARK AND NOT A DEMO ──────────────────────
//
// NO VENDOR IS QUERIED DURING CONSTRUCTION. Not socket.dev, not Chainsaw, not
// even to ask whether a coordinate exists. A corpus filtered by what a vendor
// can answer measures agreement, not capability. `corpus-gen validate` fails
// if any evidence record carries a vendor host, so this is enforced rather
// than promised.
//
// A COROLLARY THAT LOOKS LIKE A BUG AND IS NOT: the corpus deliberately
// retains coordinates in ecosystems a given vendor does not support. The
// 2026-09-14 study found 48 coordinates where socket.dev had an opinion and
// Chainsaw did not; filtering to "supported by both" would have erased
// exactly that measurement. "No opinion" is an outcome to be scored, not a
// row to be dropped.
//
// ─── GROUND TRUTH IS LABELLED BY CONFIDENCE, NOT ASSERTED ───────────────────
//
// No upstream is infallible, and OpenSSF says so about its own malicious
// dataset. So:
//
//   - A package absent from OSV and from the OpenSSF feed is
//     `presumed_benign`, never `benign`. Silence from a feed is not evidence
//     of safety, and recording it as such would manufacture a false-positive
//     denominator we cannot defend.
//   - An OpenSSF coordinate the registry no longer serves is
//     `historically_reported_registry_absent`, never `tombstoned`. Absence
//     does not prove the registry removed it FOR being malicious.
//
// These two namings are the difference between a measurement and a press
// release. Do not "simplify" them.
//
// ─── DETERMINISM ────────────────────────────────────────────────────────────
//
// Go map iteration order is RANDOMISED BY THE RUNTIME. Every candidate pool
// is therefore sorted with sortCoords before the PRNG is allowed to touch it;
// sampling a map's range order would produce a different corpus on every run
// while looking perfectly seeded. The generator uses math/rand/v2's PCG,
// whose output stream is specified and stable across Go releases (unlike
// top-level math/rand, which is deliberately unspecified in v2).
//
// ─── REPRODUCIBILITY COMES FROM evidence.jsonl, NOT FROM RE-QUERYING ────────
//
// The OpenSSF repository is pinned by git commit, so its half re-derives
// exactly. deps.dev and OSV have no snapshot mechanism and their answers
// change daily: re-running this tool next month against the same seed will
// NOT reproduce the same corpus, and pretending otherwise is the trap. What
// reproduces is the archived evidence — every upstream fact the selection
// used is written to evidence.jsonl, and `validate` re-checks the corpus
// against it offline.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ecosystems is the fixed ecosystem set, matching corpus-seed.tsv's eight.
// Order is load-bearing: it seeds the per-ecosystem sub-streams, so inserting
// an ecosystem in the middle reshuffles every other ecosystem's sample.
// APPEND ONLY.
var ecosystems = []string{"npm", "pypi", "maven", "cargo", "nuget", "rubygems", "composer", "go"}

// Stratum quotas.
//
// V1/V2 are a PAIRED design (175 pairs, 350 rows), not two independent
// samples. Pairing a vulnerable version with the nearest fixed version of the
// SAME package controls for everything except the vulnerability itself, which
// is worth far more than 350 unrelated coordinates: a vendor that flags both
// halves is not detecting the CVE, it is detecting the package.
//
// Every stratum is split EQUALLY across the eight ecosystems rather than
// weighted by registry size or downloads. That is deliberate. A
// download-weighted corpus is ~80% npm, so a download-weighted benchmark
// reports an npm result wearing a cross-ecosystem headline. Equal weighting
// measures per-ecosystem capability, which is the thing that actually differs
// between vendors.
var quotas = []Quota{
	{Stratum: "B1", Target: 600, Truth: "presumed_benign", Label: "benign"},
	{Stratum: "B2", Target: 200, Truth: "presumed_benign", Label: "benign"},
	{Stratum: "M1", Target: 250, Truth: "malicious", Label: "malicious"},
	{Stratum: "M2", Target: 150, Truth: "historically_reported_registry_absent", Label: "malicious"},
	{Stratum: "M3", Target: 100, Truth: "malicious", Label: "malicious"},
	{Stratum: "V1", Target: 175, Truth: "vulnerable", Label: "vulnerable"},
	{Stratum: "V2", Target: 175, Truth: "patched", Label: "benign"},
	{Stratum: "T1", Target: 100, Truth: "malicious", Label: "malicious"},
	{Stratum: "R1", Target: 100, Truth: "presumed_benign", Label: "suspicious"},
	{Stratum: "L1", Target: 100, Truth: "presumed_benign", Label: "benign"},
}

// Quota is one stratum's target and the ground-truth it carries.
type Quota struct {
	Stratum string
	Target  int
	Truth   string
	Label   string // the corpus.tsv label column, for the existing harnesses
}

func totalTarget() int {
	n := 0
	for _, q := range quotas {
		n += q.Target
	}
	return n
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "build":
		os.Exit(cmdBuild(os.Args[2:]))
	case "validate":
		os.Exit(cmdValidate(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `corpus-gen — reproducible benchmark corpus builder (%d coordinates)

  corpus-gen build    --seed PIB-2026-v1 --out ./corpus-v1 [--pool-multiplier 8]
  corpus-gen validate ./corpus-v1

build writes corpus.tsv, ground-truth.csv, evidence.jsonl, exclusions.csv,
source-manifest.json, statistics.json and SHA256SUMS.

validate re-checks the emitted corpus OFFLINE against its own evidence and
exits 2 — DID NOT RUN — if it cannot reach a verdict, never 0.
`, totalTarget())
}

type buildOpts struct {
	seed        string
	out         string
	poolMult    int
	ossfDir     string
	osvCache    string
	concurrency int
	keepRaw     bool
	dryRun      bool
}

func cmdBuild(args []string) int {
	fs := flag.NewFlagSet("build", flag.ExitOnError)
	var o buildOpts
	fs.StringVar(&o.seed, "seed", "PIB-2026-v1", "sampling seed; the same seed against the same upstream snapshot yields the same corpus")
	fs.StringVar(&o.out, "out", "./corpus-v1", "output directory")
	fs.IntVar(&o.poolMult, "pool-multiplier", 8, "candidate pool size as a multiple of each stratum target; oversampling lets the exclusion engine discard without biasing selection")
	fs.StringVar(&o.ossfDir, "ossf", "", "path to a clone of ossf/malicious-packages (required; pinned by its git commit)")
	fs.StringVar(&o.osvCache, "osv-cache", "", "directory for OSV bulk exports; cached because npm's is 215 MB and a reseed should not re-download it (default: <out>/.osv-cache)")
	fs.IntVar(&o.concurrency, "concurrency", 8, "concurrent upstream requests")
	fs.BoolVar(&o.keepRaw, "keep-raw", false, "also archive raw upstream response bodies (large)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "report pool sizes and exit without emitting a corpus")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(o.seed) == "" {
		fmt.Fprintln(os.Stderr, "DID NOT RUN: --seed is required; an unseeded corpus is not reproducible")
		return 2
	}
	if o.ossfDir == "" {
		fmt.Fprintln(os.Stderr, "DID NOT RUN: --ossf is required (git clone https://github.com/ossf/malicious-packages)")
		return 2
	}
	if o.osvCache == "" {
		o.osvCache = filepath.Join(o.out, ".osv-cache")
	}
	if err := runBuild(o); err != nil {
		fmt.Fprintf(os.Stderr, "DID NOT RUN: %v\n", err)
		return 2
	}
	return 0
}
