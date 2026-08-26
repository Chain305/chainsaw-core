package typosquat

// corpus_fp_eval_test.go — measures the SERVER-side typosquat false-positive
// rate per ecosystem on a held-out corpus of real package names.
//
// ─── WHY A SECOND FP HARNESS ───────────────────────────────────────────────
//
// core/cli/guard_typosquat_fp_eval_test.go measures the OFFLINE INSTALL
// GUARD: a different detector instance, loaded from core/cli/seeds/*.txt,
// npm and PyPI only, behind guard_typosquat_gate.go's block-lane predicates.
// None of that is on the server path and none of it covers docker, swift or
// github_actions.
//
// The server path is: supplychain.Bootstrap → FetchPopularPackages →
// Detector.LoadEcosystem → typosquatProvider.Run → SupplyChain.Typosquat* →
// core/risk. There is NO gate between Detector.Check and the risk signal —
// the confidence string IS the verdict:
//
//	high    → sc.typosquat_high    SevCritical  -40  MaxImpact 30  → QUARANTINE
//	medium  → sc.typosquat_medium  SevMedium    -20                → WARN
//	low     → sc.typosquat_low     SevLow        -8                → advisory
//
// sc.typosquat_high acquired SevCritical this cycle, so a "high" is now a
// blocking verdict where it previously could only warn. That is why supplying
// a corpus to three ecosystems that had never fired had to be measured before
// it was shipped, not after: this is the shape of the 742-false-positive
// incident (docs/launch/fp-rate-measurement-2026-08.md).
//
// ─── THE CORPUS MUST BE HELD OUT ───────────────────────────────────────────
//
// Detector.Check clears an exact corpus member before any distance check
// runs, so a benign corpus drawn from the detector's own index can never
// produce a false positive. Every name measured here is verified absent from
// the loaded index, and the harness fails if any leaked in.
//
// ─── THIS TEST NEVER FAILS ON A RATE ───────────────────────────────────────
//
// Same contract as the guard harness: it is a measurement, not a gate. A
// threshold here would be bumped the first time it went red. The budget that
// DOES gate lives in TestDockerTyposquatCannotQuarantine and its siblings.
//
// ─── RUN ───────────────────────────────────────────────────────────────────
//
//	CHAINSAW_TYPOSQUAT_EVAL_CORPUS=scripts/detection-eval/corpus-heldout-names \
//	  go test ./core/typosquat/ -run TestHeldOutFalsePositiveRateByEcosystem -v
//
// Skips when unset, so CI stays hermetic and offline.

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const fpCorpusEnv = "CHAINSAW_TYPOSQUAT_EVAL_CORPUS"

// fpSources pairs an ecosystem with its held-out name list. npm and pypi are
// present as the CALIBRATION BASELINE — the question this harness has to
// answer is not "is docker's rate low" in the abstract but "is it worse than
// the ecosystems already shipping", and that comparison only means anything
// when both numbers come out of the same code path in the same run.
//
// docker appears TWICE on purpose. Every non-official name on Docker Hub is
// `org/name`, so a corpus drawn from Hub can only measure the org-scoped
// population — and org-scoped names are long and structurally unlike the
// bare official names in the index, which flatters the result. The second
// row re-measures the SAME index against the bare `name` halves of those
// same coordinates: `bitnami/redis` contributes `redis`, `cimg/postgres`
// contributes `postgres`. That is the short, official-shaped population an
// edit-distance detector is actually dangerous to, and it is what a pull
// from a non-Hub registry looks like. Read the two docker rows together.
var fpSources = []struct {
	Ecosystem string // the ecosystem string the detector is called with
	Label     string // report label; differs from Ecosystem for a second population
	File      string
}{
	{"npm", "npm", "npm_heldout.tsv"},
	{"pypi", "pypi", "pypi_heldout.tsv"},
	{"docker", "docker (org/name)", "docker_heldout.tsv"},
	{"docker", "docker (bare name)", "docker-barename_heldout.tsv"},
	{"swift", "swift", "swift_heldout.tsv"},
	{"github_actions", "github_actions", "github_actions_heldout.tsv"},
}

type fpName struct {
	Name string
	Rank int
}

type fpTally struct {
	total int
	// Keyed by confidence; the risk registry keys the signal the same way.
	high, medium, low int
	byMethod          map[string]int
	samples           map[string][]string
}

func newFPTally() *fpTally {
	return &fpTally{byMethod: map[string]int{}, samples: map[string][]string{}}
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(n) / float64(total)
}

// fpLoad reads "<rank>\t<name>" lines, tolerating a bare-name file.
func fpLoad(path string) ([]fpName, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	var out []fpName
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rank := 0
		name := line
		if tab := strings.IndexByte(line, '\t'); tab > 0 {
			if r, err := strconv.Atoi(strings.TrimSpace(line[:tab])); err == nil {
				rank = r
				name = strings.TrimSpace(line[tab+1:])
			}
		}
		if name != "" {
			out = append(out, fpName{Name: name, Rank: rank})
		}
	}
	return out, sc.Err()
}

// fpLoadedDetector builds a detector for one ecosystem through the SAME
// sequence bootstrap.go uses — FetchPopularPackages with the network down,
// then LoadEcosystem — so the corpus under measurement is byte-for-byte the
// corpus production loads, not a test fixture that could drift from it.
//
// npm and PyPI have no embedded seed (they fetch live), so their index comes
// from a <eco>_corpus.txt dropped in the corpus directory by the builder —
// a copy of the same core/cli/seeds list the held-out band was cut against.
// Without that the baseline column is unmeasurable and every docker number
// would have nothing to be compared to.
func fpLoadedDetector(t *testing.T, dir, eco string) (*Detector, map[string]bool, string) {
	t.Helper()
	det := NewDetector(slog.New(slog.DiscardHandler))

	var pkgs []PopularPackage
	source := "embedded seed (production path)"
	if raw, err := os.ReadFile(filepath.Join(dir, eco+"_corpus.txt")); err == nil {
		lines, lerr := fpLoadLines(raw)
		if lerr != nil {
			t.Fatalf("%s: read supplied corpus: %v", eco, lerr)
		}
		pkgs = lines
		source = "supplied corpus file"
	} else {
		p, ferr := offlineFetcher().FetchPopularPackages(context.Background(), eco, 5000)
		if ferr != nil {
			t.Fatalf("%s: no <eco>_corpus.txt in %s and the offline fetch failed (%v) — "+
				"this ecosystem cannot be measured", eco, dir, ferr)
		}
		pkgs = p
	}
	if len(pkgs) == 0 {
		t.Fatalf("%s: empty corpus — the ecosystem is enrolled but unsourced", eco)
	}
	det.LoadEcosystem(eco, pkgs)

	norm := NormalizerForFormat(eco)
	seeded := make(map[string]bool, len(pkgs))
	for _, p := range pkgs {
		if n := norm(p.Name); n != "" {
			seeded[n] = true
		}
	}
	return det, seeded, fmt.Sprintf("%s, %d entries", source, len(pkgs))
}

// fpLoadLines parses a '#'-commented newline list into rank-ordered packages,
// the same rule fetchSeed applies to the embedded seeds.
func fpLoadLines(raw []byte) ([]PopularPackage, error) {
	var out []PopularPackage
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.ContainsAny(line, " \t") {
			continue
		}
		out = append(out, PopularPackage{Name: line, Rank: len(out) + 1})
	}
	return out, nil
}

func TestHeldOutFalsePositiveRateByEcosystem(t *testing.T) {
	dir := strings.TrimSpace(os.Getenv(fpCorpusEnv))
	if dir == "" {
		t.Skipf("set %s=<dir> holding the held-out per-ecosystem name lists", fpCorpusEnv)
	}

	ctx := context.Background()
	type row struct {
		eco string
		t   *fpTally
	}
	var rows []row

	for _, src := range fpSources {
		path := filepath.Join(dir, src.File)
		names, err := fpLoad(path)
		if err != nil || len(names) == 0 {
			t.Logf("SKIP %-20s no corpus at %s (%v)", src.Label, path, err)
			continue
		}

		det, seeded, corpusDesc := fpLoadedDetector(t, dir, src.Ecosystem)
		t.Logf("%-20s corpus: %s; held-out names: %d", src.Label, corpusDesc, len(names))
		norm := NormalizerForFormat(src.Ecosystem)

		tally := newFPTally()
		var contaminated []string
		for _, n := range names {
			if seeded[norm(n.Name)] {
				contaminated = append(contaminated, n.Name)
				continue
			}
			tally.total++
			res := det.Check(ctx, src.Ecosystem, n.Name)
			if !res.IsSuspected {
				continue
			}
			tally.byMethod[res.Method]++
			key := res.Confidence + "/" + res.Method
			if len(tally.samples[key]) < 12 {
				tally.samples[key] = append(tally.samples[key],
					fmt.Sprintf("%s → %q d=%d", n.Name, res.SimilarTo, res.Distance))
			}
			switch res.Confidence {
			case "high":
				tally.high++
			case "medium":
				tally.medium++
			default:
				tally.low++
			}
		}
		if len(contaminated) > 0 {
			t.Errorf("%s: %d held-out names are ALSO in the loaded corpus and were cleared by the "+
				"exact-match exemption before any distance check — the corpus is not held out (e.g. %v)",
				src.Ecosystem, len(contaminated), contaminated[:min(5, len(contaminated))])
		}
		rows = append(rows, row{src.Label, tally})
	}

	if len(rows) == 0 {
		t.Fatalf("no held-out corpus found under %s", dir)
	}

	t.Log("")
	t.Log("HELD-OUT FALSE-POSITIVE RATE, server path (Detector.Check → risk signal)")
	t.Log("")
	t.Logf("%-20s %8s  %18s  %18s  %18s", "ecosystem", "names",
		"QUARANTINE(high)", "WARN(medium)", "advisory(low)")
	for _, r := range rows {
		t.Logf("%-20s %8d  %8d %8.3f%%  %8d %8.3f%%  %8d %8.3f%%",
			r.eco, r.t.total,
			r.t.high, pct(r.t.high, r.t.total),
			r.t.medium, pct(r.t.medium, r.t.total),
			r.t.low, pct(r.t.low, r.t.total))
	}

	t.Log("")
	t.Log("by detection method")
	for _, r := range rows {
		methods := make([]string, 0, len(r.t.byMethod))
		for m := range r.t.byMethod {
			methods = append(methods, m)
		}
		sort.Strings(methods)
		var parts []string
		for _, m := range methods {
			parts = append(parts, fmt.Sprintf("%s=%d (%.2f%%)", m, r.t.byMethod[m], pct(r.t.byMethod[m], r.t.total)))
		}
		t.Logf("%-20s %s", r.eco, strings.Join(parts, "  "))
	}

	t.Log("")
	t.Log("samples")
	for _, r := range rows {
		keys := make([]string, 0, len(r.t.samples))
		for k := range r.t.samples {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			t.Logf("%-20s %-22s %s", r.eco, k, strings.Join(r.t.samples[k], " | "))
		}
	}
}
