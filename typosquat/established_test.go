package typosquat

// established_test.go — the acceptance measurement for the popularity-direction
// check.
//
// Every case below is a REAL ROW from a read-only export of production
// `intelligence_reports` (7,099 rows), not a constructed example. The export
// carries exactly 15 rows with supplyChain.typosquatConfidence="high": the six
// false positives asserted by TestDirectionCheckClearsProductionFalsePositives
// and the nine true positives asserted by
// TestDirectionCheckKeepsProductionTruePositives. There are no other
// high-confidence rows, so between them these two tests cover 100% of the
// evidence.
//
// The index the tests load is deliberately SERVER-SHAPED, not seed-shaped: it
// carries the target of each pair and omits the query, which is the exact
// condition the live npm keyword corpus produced (see established.go). Loading
// the reviewed seed instead would clear every query on the exact-match branch
// and measure nothing — which is itself asserted, as the dead-code proof, by
// TestDirectionCheckIsInertWhenIndexIsTheReference.

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// prodNPMKeywordIndex reproduces the membership of the server's live npm
// keyword corpus for the names that matter here: every TARGET of a
// high-confidence production row is present, and every QUERY is absent. Rank
// is slice position, as LoadEcosystem backfills it.
//
// The five FP targets (msw, json3, tsutils, is-typedarray, li) really are in
// the server corpus while ms, json5, esutils, lie and is-typed-array really
// are not; that asymmetry is the defect and reproducing it is the point.
var prodNPMKeywordIndex = []PopularPackage{
	{Name: "express"},
	{Name: "lodash"},
	{Name: "chalk"},
	{Name: "msw"},
	{Name: "json3"},
	{Name: "tsutils"},
	{Name: "is-typedarray"},
	{Name: "li"},
}

var prodPyPIKeywordIndex = []PopularPackage{
	{Name: "requests"},
	{Name: "colorama"},
}

func prodShapedDetector(t *testing.T) *Detector {
	t.Helper()
	d := NewDetector(slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.LoadEcosystem("npm", prodNPMKeywordIndex)
	d.LoadEcosystem("pip", prodPyPIKeywordIndex)
	return d
}

// prodRow is one production intelligence_reports row. Version is carried so
// the table reads as the inventory it came from; Check is a pure function of
// the name and never sees it.
type prodRow struct {
	Ecosystem string
	Name      string
	Version   string
	SimilarTo string
}

// prodHighFalsePositives are the six rows — five distinct pairs — where the
// impersonation claim points the wrong way round. Each query is a
// substantially more-installed package than the target it was accused of
// squatting. All six are `warn` today and all six became hard `quarantine`
// when sc.typosquat_high was promoted to SevCritical.
var prodHighFalsePositives = []prodRow{
	{"npm", "ms", "2.1.3", "msw"},
	{"npm", "json5", "1.0.2", "json3"},
	{"npm", "json5", "2.2.3", "json3"},
	{"npm", "esutils", "2.0.3", "tsutils"},
	{"npm", "lie", "3.3.0", "li"},
	{"npm", "is-typed-array", "1.1.15", "is-typedarray"},
}

// prodHighTruePositives are the other nine high-confidence production rows.
// Every one is a genuine squat of a household name and must keep reaching
// high confidence — a fix that clears the six above by also clearing these is
// worthless.
var prodHighTruePositives = []prodRow{
	{"npm", "chalkk", "0.0.1-security", "chalk"},
	{"npm", "chalkk", "latest", "chalk"},
	{"npm", "expres", "latest", "express"},
	{"npm", "lodashs", "latest", "lodash"},
	{"npm", "lodahs", "0.0.1-securitY", "lodash"},
	{"npm", "lodahs", "latest", "lodash"},
	{"pip", "reqeusts", "0.0.1", "requests"},
	{"pip", "reqeusts", "latest", "requests"},
	{"pip", "colourama", "latest", "colorama"},
}

func TestDirectionCheckClearsProductionFalsePositives(t *testing.T) {
	d := prodShapedDetector(t)
	for _, row := range prodHighFalsePositives {
		t.Run(row.Ecosystem+"/"+row.Name+"@"+row.Version, func(t *testing.T) {
			got := d.Check(context.Background(), row.Ecosystem, row.Name)

			// The pair must still be FOUND — this is a demotion, not a
			// silencing. If the detector stopped matching at all, the
			// measurement below would pass for the wrong reason.
			if !got.IsSuspected {
				t.Fatalf("%s: expected the similarity to still be reported (demote, never silence), got a clean result",
					row.Name)
			}
			if got.SimilarTo != row.SimilarTo {
				t.Fatalf("%s: SimilarTo = %q, want %q — the production row is not being reproduced",
					row.Name, got.SimilarTo, row.SimilarTo)
			}
			if got.Confidence != "low" {
				t.Errorf("%s → %q: confidence = %q, want \"low\". %q is the more-installed of the two, so the typosquat claim points the wrong way and must not reach the blocking lane",
					row.Name, row.SimilarTo, got.Confidence, row.Name)
			}
		})
	}
}

func TestDirectionCheckKeepsProductionTruePositives(t *testing.T) {
	d := prodShapedDetector(t)
	for _, row := range prodHighTruePositives {
		t.Run(row.Ecosystem+"/"+row.Name+"@"+row.Version, func(t *testing.T) {
			got := d.Check(context.Background(), row.Ecosystem, row.Name)
			if !got.IsSuspected {
				t.Fatalf("%s: real typosquat of %q no longer detected at all", row.Name, row.SimilarTo)
			}
			if got.SimilarTo != row.SimilarTo {
				t.Fatalf("%s: SimilarTo = %q, want %q", row.Name, got.SimilarTo, row.SimilarTo)
			}
			if got.Confidence != "high" {
				t.Errorf("%s → %q: confidence = %q, want \"high\" — the direction check has cost a true positive",
					row.Name, row.SimilarTo, got.Confidence)
			}
		})
	}
}

// TestDirectionCheckIsDirectional proves the demotion is not "the candidate is
// on the reviewed list, therefore exempt". Reverse the same pair — ask about
// `msw` against an index carrying `ms` — and the claim now points the RIGHT
// way (msw is rank #2888 on the reviewed list, ms is #8), so it must survive
// at full confidence.
//
// Without this, an attacker whose name happened onto the reference list would
// get a blanket exemption in both directions.
func TestDirectionCheckIsDirectional(t *testing.T) {
	d := NewDetector(slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.LoadEcosystem("npm", []PopularPackage{{Name: "ms"}})

	got := d.Check(context.Background(), "npm", "msw")
	if !got.IsSuspected || got.SimilarTo != "ms" {
		t.Fatalf("msw → ms not detected: %+v", got)
	}
	if got.Confidence != "high" {
		t.Errorf("msw → ms: confidence = %q, want \"high\" — this direction is the plausible one and must not be demoted", got.Confidence)
	}
}

// TestDirectionCheckIgnoresEcosystemsWithNoReference pins the blast radius.
// The docker, swift and github_actions corpora added earlier in this wave
// measured 0.000%/0.780%, 0.000% and 0.000%; none of those ecosystems has a
// reviewed download-ranked reference, so the demotion can never consult one
// and those numbers cannot move.
func TestDirectionCheckIgnoresEcosystemsWithNoReference(t *testing.T) {
	for _, ecosystem := range []string{"docker", "swift", "github_actions", "go", "maven", "cargo", "rubygems", "nuget", "composer", "huggingface", "cocoapods", "pub", "gradle"} {
		if _, ok := establishedSources[ecosystem]; ok {
			t.Errorf("%s: unexpectedly has a direction reference; its measured rates were taken without one", ecosystem)
		}
		if _, ok := establishedRank(ecosystem, "anything"); ok {
			t.Errorf("%s: establishedRank returned a rank for an ecosystem with no reference", ecosystem)
		}
		if moreEstablishedThanTarget(ecosystem, "chekout", "checkout") {
			t.Errorf("%s: demotion fired for an ecosystem with no reference", ecosystem)
		}
	}
}

// TestDirectionCheckIsInertWhenIndexIsTheReference is the dead-code proof that
// the published FP and recall budgets cannot move.
//
// The install guard loads core/cli/seeds/npm_popular.txt as its MATCH INDEX,
// and this reference is a byte-identical mirror of it. So on that path every
// name the demotion could possibly apply to is already in the index, and an
// index hit returns clean from Check's exact-match branch before the demotion
// is consulted. Assert exactly that, over the whole list: no name on the
// reference is ever suspected when the reference is also the index.
//
// guard_typosquat_fp_eval_test.go (BASELINE 453 / 1.87%, production gate
// 247 / 1.02%, recovering 206) draws its queries from a corpus built to have
// an empty intersection with this list, and guard_typosquat_recall_eval_test.go
// (BASELINE 1,122, production gate 1,030, 8.2% given up) draws its queries
// from the OpenSSF malicious feed, whose overlap with this list is 49 npm +
// 4 PyPI account-takeover compromises — every one of which this test proves
// returns clean regardless.
func TestDirectionCheckIsInertWhenIndexIsTheReference(t *testing.T) {
	for _, tc := range []struct {
		ecosystem string
		seed      []byte
	}{
		{"npm", npmEstablishedSeed},
		{"pip", pypiEstablishedSeed},
	} {
		names := parseEstablishedSeedForTest(t, tc.seed)
		if len(names) < 1000 {
			t.Fatalf("%s: reference has only %d names, refusing to draw a conclusion from it", tc.ecosystem, len(names))
		}
		pkgs := make([]PopularPackage, len(names))
		for i, n := range names {
			pkgs[i] = PopularPackage{Name: n, Rank: i + 1}
		}
		d := NewDetector(slog.New(slog.NewTextHandler(io.Discard, nil)))
		d.LoadEcosystem(tc.ecosystem, pkgs)

		for _, n := range names {
			if got := d.Check(context.Background(), tc.ecosystem, n); got.IsSuspected {
				t.Fatalf("%s/%s: reference name was suspected (of %q) while the reference IS the index — the demotion is reachable on the guard's path after all, and its published FP/recall numbers are no longer safe",
					tc.ecosystem, n, got.SimilarTo)
			}
		}
	}
}

// TestEstablishedReferenceMirrorsGuardSeed pins the two copies of one list
// together. The dead-code argument in established.go depends on this file
// being the SAME list the install guard loads as its match index; if they
// drift, that argument silently stops holding.
func TestEstablishedReferenceMirrorsGuardSeed(t *testing.T) {
	for _, tc := range []struct {
		mirror        string // the copy this package embeds
		embedded      []byte
		guard         string // filesystem path, relative to this test
		guardRepoPath string // repo-relative path, for the failure message
		genArgs       string
	}{
		{
			mirror:        "core/typosquat/seeds/npm_established.txt",
			embedded:      npmEstablishedSeed,
			guard:         "../cli/seeds/npm_popular.txt",
			guardRepoPath: "core/cli/seeds/npm_popular.txt",
			genArgs:       "-ecosystem npm -limit 5000",
		},
		{
			mirror:        "core/typosquat/seeds/pypi_established.txt",
			embedded:      pypiEstablishedSeed,
			guard:         "../cli/seeds/pypi_popular.txt",
			guardRepoPath: "core/cli/seeds/pypi_popular.txt",
			genArgs:       "-ecosystem pypi -limit 3000",
		},
	} {
		want, err := os.ReadFile(tc.guard)
		if err != nil {
			t.Fatalf("read %s: %v", tc.guard, err)
		}
		if !bytes.Equal(want, tc.embedded) {
			t.Errorf(`popular-package seed drift.

  CANONICAL (edit or regenerate THIS one): %s
  MIRROR    (never hand-edit; copy over it): %s

  The canonical file is the install guard's typosquat match INDEX and is what
  core/tools/popular-corpus-gen writes. The mirror exists only because
  core/cli imports core/typosquat and not the reverse, so go:embed cannot
  reach across.

  TO FIX, in this order:
    1. go run ./tools/popular-corpus-gen %s -out %s
    2. cp %s %s

  Do NOT "fix" this by editing the mirror or by regenerating only one of the
  two. They must stay byte-identical: established.go's proof that the
  direction check cannot move the guard's published FP (453/1.87%%, 247/1.02%%)
  and recall (1,030, 8.2%%) numbers depends on the mirror being exactly the
  list the guard loads as its index.`,
				tc.guardRepoPath, tc.mirror, tc.genArgs, tc.guardRepoPath, tc.guardRepoPath, tc.mirror)
		}
	}
}

// TestEstablishedRankIsLineOrder pins the ranking convention the reference
// files declare in their own header ("LINE ORDER IS RANK ... do not sort").
// Comment and blank lines must not consume a rank, or every rank below the
// header would be off by the header's height.
func TestEstablishedRankIsLineOrder(t *testing.T) {
	for _, tc := range []struct {
		ecosystem string
		name      string
		wantRank  int
	}{
		// Ranks read off core/cli/seeds/*.txt, counting non-comment lines.
		{"npm", "ms", 8},
		{"npm", "json5", 74},
		{"npm", "esutils", 208},
		{"npm", "is-typed-array", 427},
		{"npm", "lie", 837},
		{"npm", "msw", 2888},
		{"npm", "tsutils", 1816},
		{"npm", "is-typedarray", 1405},
		{"pip", "requests", 6},
		{"pip", "colorama", 89},
	} {
		got, ok := establishedRank(tc.ecosystem, tc.name)
		if !ok {
			t.Errorf("%s/%s: not on the reference list", tc.ecosystem, tc.name)
			continue
		}
		if got != tc.wantRank {
			t.Errorf("%s/%s: rank = %d, want %d — line order is no longer rank", tc.ecosystem, tc.name, got, tc.wantRank)
		}
	}

	// Targets that are absent entirely. The absent-target arm of
	// moreEstablishedThanTarget is what clears json5→json3 and lie→li.
	for _, tc := range []struct{ ecosystem, name string }{
		{"npm", "json3"},
		{"npm", "li"},
		{"npm", "chalkk"},
		{"npm", "expres"},
		{"npm", "lodashs"},
		{"npm", "lodahs"},
		{"pip", "reqeusts"},
		{"pip", "colourama"},
	} {
		if _, ok := establishedRank(tc.ecosystem, tc.name); ok {
			t.Errorf("%s/%s: unexpectedly on the reference list — the direction check's reading of this name changes", tc.ecosystem, tc.name)
		}
	}
}

func parseEstablishedSeedForTest(t *testing.T, data []byte) []string {
	t.Helper()
	var out []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan reference: %v", err)
	}
	return out
}

// ─── MEDIUM TIER ────────────────────────────────────────────────────────────
//
// The direction argument is semantic, not a tuned threshold: a package more
// established than its claimed target is not squatting it at ANY confidence
// tier. Check therefore demotes on the same branch for "medium", and this
// section pins that by name.
//
// Production population: 30 distinct pairs / 135 rows, zero true positives
// among them. Verdict cost, measured by re-running the real risk engine over
// all 172 medium rows in the export: 112 of the 135 change their overall
// score and ZERO change verdict. The three non-allow demoted rows
// (@posthog/core@1.28.0, eslint-config-next@16.0.4 and @16.1.6) stay `warn`
// because another signal's MaxImpact ceiling is binding, not the typosquat
// weight. So the loosening half of this extension is 135 corrected display
// signals and no verdict movement at all.

// prodMediumFalsePositives is every wrong-direction MEDIUM pair in the
// production export, largest group first, with one real version per pair.
// Each was read individually; none is a squat.
var prodMediumFalsePositives = []prodRow{
	{"npm", "@posthog/core", "1.30.14", "@pothos/core"}, // 68 rows
	{"npm", "radix-ui", "1.6.7", "radix-vue"},           // 9
	{"npm", "@types/react", "19.2.15", "@cypress/react"},
	{"npm", "@emnapi/core", "1.10.0", "@enact/core"},
	{"npm", "acorn", "8.16.0", "cors"},
	{"npm", "@floating-ui/dom", "1.8.0", "@floating-ui/vue"},
	{"npm", "@floating-ui/core", "1.7.5", "@floating-ui/vue"},
	{"npm", "@babel/core", "7.28.5", "@tabler/core"},
	{"npm", "which", "7.0.0", "watch"},
	{"npm", "@babel/core", "8.0.0", "@abp/core"},
	{"npm", "isexe", "4.0.0", "isite"},
	{"npm", "fflate", "0.8.3", "slate"},
	{"npm", "eslint-config-next", "16.0.4", "eslint-config-xo"},
	{"npm", "body-parser", "2.3.0", "oxc-parser"},
	{"npm", "zod-to-json-schema", "3.25.2", "json-schema-to-zod"},
	{"npm", "reusify", "1.1.0", "restify"},
	{"npm", "socks", "2.8.9", "stacks"},
	{"npm", "jose", "6.2.2", "foso"},
	{"npm", "path-browserify", "1.0.1", "http-browserify"},
	{"npm", "toidentifier", "1.0.1", "is-identifier"},
	{"npm", "extend", "3.0.2", "exenv"},
	{"npm", "is-plain-obj", "4.1.0", "is-plain-object"},
	{"npm", "zwitch", "2.0.4", "watch"},
	{"npm", "remark-stringify", "11.0.0", "recma-stringify"},
	{"npm", "has-symbols", "1.1.0", "log-symbols"},
	{"npm", "process", "0.11.10", "progress"},
	{"npm", "d3-path", "3.1.0", "doc-path"},
	{"npm", "is-set", "2.0.3", "is-ssh"},
	{"npm", "devlop", "1.1.0", "evlog"},
	{"npm", "remark-parse", "11.0.0", "recma-parse"},
}

// TestDirectionCheckClearsProductionMediumFalsePositives asserts every
// wrong-direction medium pair by name. The predicate is asserted for all 30;
// the end-to-end demotion is asserted for every pair the detector reproduces
// from a single-target index (pairs whose production hit came from the
// reorder or combosquat lanes need more corpus than one name).
func TestDirectionCheckClearsProductionMediumFalsePositives(t *testing.T) {
	if len(prodMediumFalsePositives) != 30 {
		t.Fatalf("table has %d pairs, the production export has 30 — the measurement and the table have diverged",
			len(prodMediumFalsePositives))
	}
	var reproduced int
	for _, row := range prodMediumFalsePositives {
		t.Run(row.Ecosystem+"/"+row.Name+"→"+row.SimilarTo, func(t *testing.T) {
			if !moreEstablishedThanTarget(row.Ecosystem, row.Name, row.SimilarTo) {
				t.Fatalf("%s → %q is not wrong-direction on the reviewed reference; this pair does not belong in the table",
					row.Name, row.SimilarTo)
			}
			d := NewDetector(slog.New(slog.NewTextHandler(io.Discard, nil)))
			d.LoadEcosystem(row.Ecosystem, []PopularPackage{{Name: row.SimilarTo, Rank: 1}})
			got := d.Check(context.Background(), row.Ecosystem, row.Name)
			if !got.IsSuspected {
				return // not reproducible from a one-name index; predicate asserted above
			}
			reproduced++
			if got.Confidence != "low" {
				t.Errorf("%s → %q: confidence = %q, want \"low\" — %q is the more-installed of the two",
					row.Name, row.SimilarTo, got.Confidence, row.Name)
			}
		})
	}
	if reproduced < 20 {
		t.Errorf("only %d of 30 pairs reproduced end-to-end; the table is drifting away from what the detector actually does", reproduced)
	}
}

// TestDirectionCheckDemotesEveryTierAboveLow pins the tier coverage itself.
// Correcting "high" and knowingly leaving "medium" wrong would be arbitrary:
// the claim is false at both.
func TestDirectionCheckDemotesEveryTierAboveLow(t *testing.T) {
	d := NewDetector(slog.New(slog.NewTextHandler(io.Discard, nil)))
	// json5 → json3 is d=1 (high). acorn → cors is d=2 (medium). Both
	// wrong-direction; both must land on "low".
	d.LoadEcosystem("npm", []PopularPackage{{Name: "json3", Rank: 1}, {Name: "cors", Rank: 2}})
	for _, tc := range []struct{ name, target, wasTier string }{
		{"json5", "json3", "high"},
		{"acorn", "cors", "medium"},
	} {
		got := d.Check(context.Background(), "npm", tc.name)
		if !got.IsSuspected || got.SimilarTo != tc.target {
			t.Fatalf("%s → %s not reproduced: %+v", tc.name, tc.target, got)
		}
		if got.Confidence != "low" {
			t.Errorf("%s → %q (was %s): confidence = %q, want \"low\" — the demotion must cover every tier above low",
				tc.name, tc.target, tc.wasTier, got.Confidence)
		}
	}
}

// TestDirectionCheckLeavesTheCombosquatFloorAlone records the SCOPE of this
// fix against two rows that look like they belong to it and do not.
//
// `prettier` reported as similar to `ret`, and `tailwindcss` to `css`, are
// real and visibly false — but they are COMBOSQUAT hits, already graded
// "low" (-8, advisory) by the lane's own deliberate breadth (checkCombosquat:
// 13.0% of benign packages embed some popular name). Check's demotion is
// guarded on `Confidence != "low"`, so this fix does not touch them and must
// not be credited with fixing them. Correcting the combosquat lane's own
// false-claim rate is separate work.
func TestDirectionCheckLeavesTheCombosquatFloorAlone(t *testing.T) {
	d := NewDetector(slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.LoadEcosystem("npm", []PopularPackage{{Name: "ret", Rank: 1}, {Name: "css", Rank: 2}})
	var live int
	for _, name := range []string{"prettier", "tailwindcss"} {
		got := d.Check(context.Background(), "npm", name)
		if !got.IsSuspected {
			// `prettier` → `ret` needs a fuller corpus than two names to
			// reproduce; `tailwindcss` → `css` reproduces here. Counted
			// below so this test cannot quietly become vacuous.
			continue
		}
		live++
		if got.Confidence != "low" {
			t.Errorf("%s → %q (%s): confidence = %q; this lane is expected to sit at the advisory floor, so the direction check has changed something it does not claim to fix",
				name, got.SimilarTo, got.Method, got.Confidence)
		}
	}
	if live == 0 {
		t.Fatal("neither combosquat hit reproduced — this test is asserting nothing")
	}

	// And the wrong-direction predicate DOES hold for both, which is the
	// point: they are excluded by the `Confidence != "low"` guard in Check,
	// not because the direction check considers them fine.
	for _, tc := range []struct{ cand, target string }{{"prettier", "ret"}, {"tailwindcss", "css"}} {
		if !moreEstablishedThanTarget("npm", tc.cand, tc.target) {
			t.Errorf("%s → %q: expected wrong-direction on the reference; the scope note in this test is then wrong", tc.cand, tc.target)
		}
	}
}

// TestDirectionCheckDoesNotClaimTheCoincidentalCollisionClass records the
// LIMIT of the fix, by name, so the next reader does not assume the medium
// tier is now clean.
//
// `immer` → `mime` is 10 production rows and is plainly a false positive —
// but `mime` really is the more-downloaded of the two (rank #197 vs #807), so
// the direction claim is not what is wrong with it. It is a coincidental
// short-name collision, a different class, and this check correctly declines
// to speak to it. 25 medium rows across 12 pairs are in that class.
func TestDirectionCheckDoesNotClaimTheCoincidentalCollisionClass(t *testing.T) {
	for _, tc := range []struct{ eco, cand, target string }{
		{"npm", "immer", "mime"},
		{"npm", "recast", "react"},
		{"npm", "cssesc", "jsesc"},
		{"npm", "vfile", "vite"},
		{"npm", "string.prototype.trim", "string.prototype.trimend"},
	} {
		if moreEstablishedThanTarget(tc.eco, tc.cand, tc.target) {
			t.Errorf("%s → %q was treated as wrong-direction; on the reviewed reference the target is the more established of the two, so this pair is the coincidental-collision class and the direction check must not claim it",
				tc.cand, tc.target)
		}
	}
}
