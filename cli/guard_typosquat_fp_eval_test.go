package cli

// guard_typosquat_fp_eval_test.go — measures the install guard's NAME-LEVEL
// false-block rate on a HELD-OUT corpus of real package names, and attributes
// the effect of each block-lane gate predicate separately.
//
// ─── WHY THIS EXISTS: the published FP rate cannot see this defect ──────────
//
// docs/launch/fp-rate-measurement.md publishes a false-block rate measured by
// TestBenignFalseBlockRate over the corpus build-benign-corpus.sh builds. That
// number is structurally incapable of producing a typosquat false block, for
// two independent reasons — write them down once so the next person does not
// rebuild the same blind spot:
//
//  1. SEED OVERLAP. build-benign-corpus.sh draws its benign packages from
//     `head -600` / `head -260` of core/cli/seeds/npm_popular.txt and
//     pypi_popular.txt — the SAME seed lists localGuard.detector() loads as
//     the typosquat TARGET INDEX. typosquat.Detector.Check returns an empty
//     result on an exact corpus match BEFORE any distance check runs
//     ("Exact match with popular package → not a typosquat"), so every member
//     of that corpus is cleared by the exemption. A benign corpus drawn from
//     the detector's own allowlist can never trip the detector.
//
//  2. WRONG ENTRY POINT. TestBenignFalseBlockRate calls analyzeArtifact — the
//     byte scanner. The typosquat verdict lives in guard_eval.go's evaluate()
//     ladder and is never reached on that path.
//
// The false-block class (docs/proposal_typosquat_fp_class.md) lives OUTSIDE
// the seed: a legitimate package absent from the corpus that sits one edit
// from a top-guardTyposquatBlockRankCutoff corpus member — `nano`→`nan`,
// `args`→`arg`. So the corpus for THIS measurement has to be held out from
// the index. scripts/detection-eval/build-heldout-name-corpus.sh builds it
// from the same upstreams the seeds are generated from, keeps only ranks past
// the shipped seed, and verifies the intersection with the seed is empty.
//
// ─── WHY IT IS CHEAP ────────────────────────────────────────────────────────
//
// The typosquat verdict is a pure function of the package NAME, so this
// harness needs no tarballs: two text files, ~24k names, about a minute.
// TestBenignFalseBlockRate's corpus is 565 MB and needs the network.
//
// ─── WHAT IT REPORTS ────────────────────────────────────────────────────────
//
// Five block-lane configurations, measured in one pass so the false-positive
// win and the recall cost can be attributed to each predicate on its own:
//
//	BASELINE       rank cutoff only — the pre-fix behaviour that blocks nano/args
//	P2             + target length, scoped by shape (typosquatTargetLongEnough)
//	P1             + edge edits demote            (typosquatEditIsTypoShaped)
//	P2+P1 no-rescue  both, popular-target rescue disabled
//	P2+P1          both + the rescue — the production gate
//
// The last two differ only in guardTyposquatPopularRescueRank, so the price of
// re-admitting appends on household names reads straight off the pair. The
// recall side of that same trade is measured by
// TestTyposquatMalwareFeedBlockRecall in guard_typosquat_recall_eval_test.go —
// read the two together or neither number means anything.
//
// Each is decided by the REAL predicates in guard_typosquat_gate.go, and each
// d=1 decision is independently re-derived from the proposal by this file
// (tsfpModelAllowsD1Block / tsfpEditShape) using a different algorithm — a
// prefix/suffix scan rather than an alignment enumeration. The two are
// compared name by name. That cross-check exists to DISAGREE: where the two
// readings of "typo-shaped" diverge, the harness prints the packages, and one
// of the two readings has to be wrong.
//
// It also runs the FULL evaluate() ladder over every name that any
// configuration flags, to prove the gate is on the install path rather than
// merely present in the tree.
//
// ─── THIS TEST NEVER FAILS ON A RATE ────────────────────────────────────────
//
// It is a measurement, not a gate. A threshold assertion here would be bumped
// the first time it went red and would tell us nothing. It fails only when the
// corpus itself is unusable. Recall regressions are pinned by the squat-recall
// suite and by guard_typosquat_test.go; this file exists to produce a number.
//
// ─── RUN ────────────────────────────────────────────────────────────────────
//
//	scripts/detection-eval/build-heldout-name-corpus.sh
//	CHAINSAW_TYPOSQUAT_EVAL_CORPUS=scripts/detection-eval/corpus-heldout-names \
//	  go test ./core/cli/ -run TestTyposquatHeldOutFalseBlockRate -v
//
// Skips when the env var is unset, so CI stays hermetic and offline — the same
// convention CHAINSAW_DETECTION_EVAL_CORPUS uses in benign_fp_eval_test.go.

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/typosquat"
)

// tsfpCorpusEnv points at the directory built by
// scripts/detection-eval/build-heldout-name-corpus.sh.
const tsfpCorpusEnv = "CHAINSAW_TYPOSQUAT_EVAL_CORPUS"

// tsfpSources is one held-out name list per ecosystem. The ecosystem string is
// the one the guard is called with, so detector() and NormalizerForFormat
// resolve exactly as they do on the install path.
var tsfpSources = []struct {
	Ecosystem string
	File      string
}{
	{"npm", "npm_heldout.tsv"},
	{"pypi", "pypi_heldout.tsv"},
}

// tsfpName is one held-out package name plus its upstream popularity rank.
// Rank is the position in the upstream download-ranked list, which is what
// lets the report bucket blocks by popularity band — the question "does the
// tail get worse?" is the whole reason the rank is carried.
type tsfpName struct {
	Ecosystem string
	Name      string
	Rank      int
}

// tsfpOutcome is the guard's user-visible decision for one name.
type tsfpOutcome int

const (
	tsfpAllow tsfpOutcome = iota
	tsfpWarn
	tsfpBlock
)

func tsfpOutcomeName(o tsfpOutcome) string {
	switch o {
	case tsfpBlock:
		return "BLOCK"
	case tsfpWarn:
		return "WARN"
	default:
		return "ALLOW"
	}
}

// tsfpMode is one block-lane configuration under measurement.
type tsfpMode struct {
	Label string
	Slug  string
	Gate  typosquatBlockGate
}

// tsfpModes are ordered weakest gate first, so each row of the summary table
// reads as "the row above, minus what this predicate demotes".
var tsfpModes = []tsfpMode{
	{"BASELINE (rank cutoff only)", "baseline", typosquatBlockGate{}},
	{"P2 (target length, by shape)", "p2", typosquatBlockGate{RequireMinTargetLen: true}},
	{"P1 (edge edits demote)", "p1", typosquatBlockGate{
		RequireTypoShape: true, PopularTargetRescueRank: guardTyposquatPopularRescueRank}},
	{"P2+P1, rescue OFF", "p2p1-norescue", typosquatBlockGate{
		RequireMinTargetLen: true, RequireTypoShape: true}},
	{"P2+P1 (production gate)", "p2p1", typosquatBlockGate{
		RequireMinTargetLen: true, RequireTypoShape: true,
		PopularTargetRescueRank: guardTyposquatPopularRescueRank}},
}

// tsfpProdMode is the index of the configuration that matches
// guardTyposquatBlockGate, i.e. what a user actually gets today. The row above
// it is the same gate with the popular-target rescue disabled, so the price of
// the rescue reads straight off the difference between the two.
const tsfpProdMode = 4

// tsfpHit is one non-ALLOW verdict, carrying every field a reader needs to
// judge it without re-running anything. The BLOCK list assembled from these IS
// the product artifact: it is the list of packages real users cannot install.
type tsfpHit struct {
	Ecosystem  string
	Name       string
	Rank       int
	Target     string
	Distance   int
	Method     string
	TargetRank int
	Shape      string
	Ties       int // corpus names at distance 1 — >1 means the target is a coin flip
}

func (h tsfpHit) line() string {
	tie := ""
	if h.Ties > 1 {
		tie = fmt.Sprintf("  AMBIGUOUS(%d targets at d=1)", h.Ties)
	}
	return fmt.Sprintf("%-6s %-40s rank #%-6d → %-26q d=%d %-13s target-rank #%-5d %-16s%s",
		h.Ecosystem, h.Name, h.Rank, h.Target, h.Distance, h.Method, h.TargetRank, h.Shape, tie)
}

func (h tsfpHit) tsv() string {
	return strings.Join([]string{
		h.Ecosystem, h.Name, strconv.Itoa(h.Rank), h.Target,
		strconv.Itoa(h.Distance), h.Method, strconv.Itoa(h.TargetRank),
		h.Shape, strconv.Itoa(h.Ties),
	}, "\t")
}

// tsfpTally accumulates one configuration's results.
type tsfpTally struct {
	blocked   []tsfpHit
	warned    []tsfpHit
	blockEco  map[string]int
	blockBand map[string]int
}

func newTSFPTally() *tsfpTally {
	return &tsfpTally{blockEco: map[string]int{}, blockBand: map[string]int{}}
}

func (a *tsfpTally) add(out tsfpOutcome, h tsfpHit) {
	switch out {
	case tsfpBlock:
		a.blocked = append(a.blocked, h)
		a.blockEco[h.Ecosystem]++
		a.blockBand[tsfpBand(h.Rank)]++
	case tsfpWarn:
		a.warned = append(a.warned, h)
	}
}

// tsfpBands are popularity buckets over the UPSTREAM rank. Held-out npm names
// start at rank 5,001 and pypi at 3,001, so the first bucket is npm-empty and
// holds pypi's 3,001–5,000 band.
var tsfpBands = []string{"<=5k", "5k-10k", "10k-25k", ">25k"}

func tsfpBand(rank int) string {
	switch {
	case rank <= 5000:
		return "<=5k"
	case rank <= 10000:
		return "5k-10k"
	case rank <= 25000:
		return "10k-25k"
	default:
		return ">25k"
	}
}

// ─── the verdict ladder, reproduced ────────────────────────────────────────

// tsfpLadder reproduces guard_eval.go evaluate()'s typosquat arm for one
// candidate under a chosen gate. It is a reproduction rather than a call into
// evaluate() because evaluate() consults exactly one gate — the production var
// — and this harness has to price four of them from a single detector result.
//
// The reproduction is not taken on trust: the measurement loop runs the real
// evaluate() over every flagged name and reports any verdict that disagrees
// with this ladder under the production gate.
func tsfpLadder(gate typosquatBlockGate, ecosystem, name string, res typosquat.DetectionResult) tsfpOutcome {
	if !res.IsSuspected {
		return tsfpAllow
	}
	// Homoglyph is a separate arm and is never gated: a byte-level confusable
	// collision has no legitimate explanation regardless of rank or shape.
	if res.Method == "homoglyph" && res.Confidence == "high" {
		return tsfpBlock
	}
	if res.Method == "edit-distance" && res.Distance == 1 &&
		res.TargetRank > 0 && res.TargetRank <= guardTyposquatBlockRankCutoff &&
		gate.allowsD1Block(ecosystem, name, res) {
		return tsfpBlock
	}
	// Gated out of the BLOCK lane, or never eligible for it: the hit is
	// DEMOTED, not silenced.
	if res.Confidence == "high" || res.Confidence == "medium" {
		return tsfpWarn
	}
	// Low confidence (combosquat) is deliberately silent — see the long note in
	// evaluate() and TestGuardNeverWarnsOnLowConfidenceCombosquat.
	return tsfpAllow
}

// ─── independent model, written from the proposal not the implementation ───

// tsfpMinTargetLen is this file's own reading of P2 ("require the matched
// target to be ≥ 5 characters"), written as a literal rather than reusing
// guardTyposquatBlockMinTargetLen so a change to that constant surfaces here
// as a disagreement instead of being silently absorbed.
const tsfpMinTargetLen = 5

// tsfpModelAllowsD1Block is the independent re-derivation of the block lane.
// Any disagreement with typosquatBlockGate.allowsD1Block is reported by name.
//
// It models the SAME three rules the gate implements, from the proposal rather
// than from the code:
//
//	P2 — an EDGE edit (append/prepend/truncate) or a SUBSTITUTION needs a
//	     target of ≥ tsfpMinTargetLen runes. Other shapes do not.
//	P1 — an EDGE edit demotes …
//	P3 — … unless it ADDS a rune (append/prepend) and the target is inside
//	     gate.PopularTargetRescueRank and long enough.
func tsfpModelAllowsD1Block(gate typosquatBlockGate, ecosystem, candidate string, res typosquat.DetectionResult) bool {
	norm := typosquat.NormalizerForFormat(ecosystem)
	shape := tsfpEditShape([]rune(norm(candidate)), []rune(norm(res.SimilarTo)))
	short := len([]rune(res.SimilarTo)) < tsfpMinTargetLen

	if gate.RequireMinTargetLen && short && tsfpShapeNeedsLongTarget(shape) {
		return false
	}
	if gate.RequireTypoShape && tsfpEdgeShape(shape) {
		rescuable := shape == "append" || shape == "prepend"
		return rescuable && !short && gate.PopularTargetRescueRank > 0 &&
			res.TargetRank > 0 && res.TargetRank <= gate.PopularTargetRescueRank
	}
	return true
}

// tsfpEdgeShape is the naming family: one rune added to or dropped from an END
// of the target. Everything else — substitution, transposition, interior
// insert/delete, doubled end — is typo-shaped, and an alignment we cannot read
// ("unknown") fails SAFE by not being an edge shape, i.e. stays block-eligible.
func tsfpEdgeShape(shape string) bool {
	switch shape {
	case "append", "prepend", "drop-plural-or-version", "truncate-start":
		return true
	default:
		return false
	}
}

// tsfpShapeNeedsLongTarget models P2's shape scoping: only the shapes in which
// two INDEPENDENT legitimate short names collide are length-gated.
func tsfpShapeNeedsLongTarget(shape string) bool {
	return tsfpEdgeShape(shape) || shape == "substitution"
}

// tsfpEditShape names the shape of the single edit between two normalized
// names by scanning the common prefix and suffix — a deliberately different
// method from classifyTyposquatEdit's alignment enumeration, so that agreement
// between the two is evidence rather than a shared bug.
//
// A doubled end rune is reported as a doubling, not an append: `expresss`
// against `express` is a key held one beat too long, which is a typo.
func tsfpEditShape(cand, targ []rune) string {
	p := 0
	for p < len(cand) && p < len(targ) && cand[p] == targ[p] {
		p++
	}
	s := 0
	for s < len(cand)-p && s < len(targ)-p && cand[len(cand)-1-s] == targ[len(targ)-1-s] {
		s++
	}
	extraC := len(cand) - p - s // runes of cand not covered by the common ends
	extraT := len(targ) - p - s

	switch {
	case extraC == 1 && extraT == 1:
		return "substitution"
	case extraC == 2 && extraT == 2 && cand[p] == targ[p+1] && cand[p+1] == targ[p]:
		return "transposition"
	case extraC == 1 && extraT == 0: // one rune inserted into cand
		switch {
		case p == 0 && len(targ) > 0 && cand[0] == targ[0]:
			return "double-start"
		case p == 0:
			return "prepend"
		case s == 0 && len(targ) > 0 && cand[len(cand)-1] == targ[len(targ)-1]:
			return "double-end"
		case s == 0:
			return "append"
		default:
			return "insert-interior"
		}
	case extraC == 0 && extraT == 1: // one rune dropped from cand
		switch {
		case p == 0:
			return "truncate-start"
		case s == 0:
			// A name missing one of a DOUBLED pair at the end (`expres`
			// against `express`) also aligns as an interior delete, and that
			// is the reading a human would give it: a key that failed to
			// repeat is a typo, not a shortened sibling name.
			last := targ[len(targ)-1]
			if len(targ) > 1 && last == targ[len(targ)-2] {
				return "delete-interior"
			}
			// A dropped plural 's' or version digit is the sibling-naming
			// pattern (braces→brace, listr2→listr); any other dropped last
			// rune is a keystroke that did not land (debug→debu).
			if last == 's' || (last >= '0' && last <= '9') {
				return "drop-plural-or-version"
			}
			return "truncate-end"
		default:
			return "delete-interior"
		}
	}
	return "unknown"
}

// ─── equidistant-target ambiguity ──────────────────────────────────────────

// tsfpD1Index builds a BK-tree over the same embedded seed the detector loads,
// used only to count how many corpus names sit at distance 1 from a candidate.
//
// WHY IT MATTERS. BKTree.Search walks children via `range node.children` — a
// Go map, so its result order is randomized per run. Detector.Check used to
// keep the first minimum-distance match out of that slice (`best :=
// matches[0]`, replaced only on a strictly SMALLER distance), so a candidate
// with two or more corpus names at distance 1 reported EITHER of them, and the
// reported target decides the rank cutoff, the length gate and the shape gate.
// Those names' verdicts were a coin flip between runs — `args` blocked on
// roughly a third of real CLI runs (matching `yargs` #70) and warned on the
// rest (matching `arg` #263).
//
// Check now resolves equidistant matches by a TOTAL order (nearest distance,
// then most popular target, then lexicographic — betterEditMatch in
// core/typosquat/detector.go), so the verdict is a pure function of the
// corpus. This count stays in the report because ambiguity is still worth
// knowing about: it says how many names' verdicts hinge on a tie-break rule
// rather than on a single unambiguous nearest neighbour.
func tsfpD1Index(eco string) *typosquat.BKTree {
	var seed []byte
	switch strings.ToLower(eco) {
	case "npm":
		seed = npmPopularSeed
	case "pypi", "pip":
		seed = pypiPopularSeed
	default:
		return nil
	}
	norm := typosquat.NormalizerForFormat(eco)
	tree := typosquat.NewBKTree()
	for _, p := range parsePopularSeed(seed) {
		if nm := norm(p.Name); nm != "" {
			tree.Insert(nm)
		}
	}
	return tree
}

// tsfpD1Ties counts corpus names at exactly distance 1 from `normalized`.
// Distance 0 (an exact corpus member) is excluded: those never reach the
// distance check at all.
func tsfpD1Ties(tree *typosquat.BKTree, normalized string) int {
	if tree == nil {
		return 0
	}
	n := 0
	for _, m := range tree.Search(normalized, 1) {
		if m.Distance == 1 {
			n++
		}
	}
	return n
}

// ─── the measurement ───────────────────────────────────────────────────────

func TestTyposquatHeldOutFalseBlockRate(t *testing.T) {
	dir := strings.TrimSpace(os.Getenv(tsfpCorpusEnv))
	if dir == "" {
		t.Skipf("set %s=<dir> built by scripts/detection-eval/build-heldout-name-corpus.sh", tsfpCorpusEnv)
	}

	// Hermetic verdicts: the number must come from the EMBEDDED seed and the
	// EMBEDDED malicious floor, never from a signal bundle or a
	// `chainsaw guard update` cache that happens to sit on the measuring box.
	t.Setenv(intelligence.BundleEnvVar, "")
	t.Setenv(guardDBEnv, filepath.Join(t.TempDir(), "no-such-known-malicious.json"))
	t.Setenv(guardArtifactDirEnv, "")
	t.Setenv(guardDeepFetchEnv, "")

	names, perEco, err := tsfpLoadCorpus(dir)
	if err != nil {
		t.Fatalf("load held-out corpus: %v", err)
	}
	if len(names) == 0 {
		t.Fatalf("held-out corpus in %s is empty — rebuild it with scripts/detection-eval/build-heldout-name-corpus.sh", dir)
	}

	ctx := context.Background()
	guard := newLocalGuard()

	// Corpus integrity: a held-out name that is ALSO in the shipped seed gets
	// the exact-match exemption and is cleared before any distance check —
	// exactly the flaw this harness exists to escape. The builder verifies the
	// intersection is empty; re-verify here against the seeds the binary
	// actually embeds, because those are what the detector loads.
	seeded := tsfpSeedMembers()
	var contaminated []string

	tallies := make([]*tsfpTally, len(tsfpModes))
	for i := range tallies {
		tallies[i] = newTSFPTally()
	}
	ties := map[string]*typosquat.BKTree{}

	var (
		suspected   int
		ambiguous   int
		ambigBlocks int
		modelDiffs  []string
		wiringDiffs []string
		tieFlips    []string
		otherSignal []string
		evaluated   int
	)

	for _, n := range names {
		norm := typosquat.NormalizerForFormat(n.Ecosystem)
		if seeded[n.Ecosystem+"\x00"+norm(n.Name)] {
			contaminated = append(contaminated, n.Ecosystem+":"+n.Name)
		}

		det := guard.detector(n.Ecosystem)
		if det == nil {
			t.Fatalf("no typosquat detector for ecosystem %q — the corpus cannot be measured", n.Ecosystem)
		}
		if _, ok := ties[n.Ecosystem]; !ok {
			ties[n.Ecosystem] = tsfpD1Index(n.Ecosystem)
		}
		nTies := tsfpD1Ties(ties[n.Ecosystem], norm(n.Name))
		if nTies > 1 {
			ambiguous++
		}

		res := det.Check(ctx, n.Ecosystem, n.Name)
		if !res.IsSuspected {
			continue
		}
		suspected++

		hit := tsfpHit{
			Ecosystem:  n.Ecosystem,
			Name:       n.Name,
			Rank:       n.Rank,
			Target:     res.SimilarTo,
			Distance:   res.Distance,
			Method:     res.Method,
			TargetRank: res.TargetRank,
			Shape:      tsfpEditShape([]rune(norm(n.Name)), []rune(norm(res.SimilarTo))),
			Ties:       nTies,
		}

		// d1Gated is the population that can actually reach the gate — the only
		// place the shipped predicates and the independent model can differ.
		d1Gated := res.Method == "edit-distance" && res.Distance == 1 &&
			res.TargetRank > 0 && res.TargetRank <= guardTyposquatBlockRankCutoff

		anyNonAllow := false
		for i, m := range tsfpModes {
			out := tsfpLadder(m.Gate, n.Ecosystem, n.Name, res)
			tallies[i].add(out, hit)
			if out != tsfpAllow {
				anyNonAllow = true
			}
			if d1Gated {
				got := m.Gate.allowsD1Block(n.Ecosystem, n.Name, res)
				want := tsfpModelAllowsD1Block(m.Gate, n.Ecosystem, n.Name, res)
				if got != want {
					modelDiffs = append(modelDiffs, fmt.Sprintf(
						"%-8s %s:%s → %q  gate=%-5v model=%-5v shape=%s",
						m.Slug, n.Ecosystem, n.Name, res.SimilarTo, got, want, hit.Shape))
				}
			}
		}
		if d1Gated && nTies > 1 && tsfpLadder(guardTyposquatBlockGate, n.Ecosystem, n.Name, res) == tsfpBlock {
			ambigBlocks++
		}
		if !anyNonAllow {
			continue
		}

		// Wiring check: the REAL evaluate() must reach the same verdict as the
		// reproduced ladder under the production gate.
		evaluated++
		v := guard.evaluate(ctx, packageSpec{Ecosystem: n.Ecosystem, Name: n.Name})
		got := tsfpAllow
		switch {
		case v.Block:
			got = tsfpBlock
		case v.Severity != "":
			got = tsfpWarn
		}
		want := tsfpLadder(guardTyposquatBlockGate, n.Ecosystem, n.Name, res)
		switch {
		case got == want:
			// agreed
		case v.Severity != "" && !strings.HasPrefix(v.Severity, "typosquat"):
			// A different signal (known-malicious floor, supplemental advisory,
			// behavioral) claimed the verdict. Not a ladder defect.
			otherSignal = append(otherSignal, fmt.Sprintf("%s:%s → %s (%s) %q",
				n.Ecosystem, n.Name, tsfpOutcomeName(got), v.Severity, v.Reason))
		case !strings.Contains(v.Reason, strconv.Quote(res.SimilarTo)):
			// evaluate() ran its own Check and landed on a DIFFERENT target for
			// the same name — the equidistant-target coin flip described on
			// tsfpD1Index. Noise, not a ladder defect, but it is exactly the
			// noise that makes the rate above non-reproducible.
			tieFlips = append(tieFlips, fmt.Sprintf("%s:%s → ladder saw %q (%s), evaluate() saw %q",
				n.Ecosystem, n.Name, res.SimilarTo, tsfpOutcomeName(want), tsfpReasonTarget(v.Reason)))
		default:
			wiringDiffs = append(wiringDiffs, fmt.Sprintf("%s:%s → evaluate()=%s severity=%q, ladder=%s (%s)",
				n.Ecosystem, n.Name, tsfpOutcomeName(got), v.Severity, tsfpOutcomeName(want), v.Reason))
		}
	}

	// ─── report ────────────────────────────────────────────────────────────

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("")
	w("TYPOSQUAT FALSE-BLOCK RATE — HELD-OUT NAME CORPUS")
	w("corpus: %s", dir)
	w("Drawn from OUTSIDE the shipped popularity seeds, so unlike")
	w("TestBenignFalseBlockRate it can actually reach the typosquat verdict.")
	w("")
	ecos := make([]string, 0, len(perEco))
	for e := range perEco {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	w("  %-10s  %10s", "ecosystem", "names")
	w("  %-10s  %10s", strings.Repeat("-", 10), strings.Repeat("-", 10))
	for _, e := range ecos {
		w("  %-10s  %10d", e, perEco[e])
	}
	w("  %-10s  %10d", "TOTAL", len(names))
	w("")
	w("  detector fired (IsSuspected) on %d / %d names (%.2f%%)", suspected, len(names), pct(suspected, len(names)))
	if len(contaminated) == 0 {
		w("  corpus integrity: 0 held-out names are members of the embedded seed (good)")
	} else {
		w("  corpus integrity: WARNING — %d held-out names ARE embedded-seed members and were", len(contaminated))
		w("  cleared by the exact-match exemption before any distance check ran. Every rate")
		w("  below is understated by that much. Rebuild the corpus. First few: %s",
			strings.Join(tsfpHead(contaminated, 10), ", "))
	}

	w("")
	w("BLOCK / WARN BY GATE CONFIGURATION  (denominator = %d held-out names)", len(names))
	w("")
	w("  %-30s %8s %9s %8s %9s", "configuration", "BLOCK", "rate", "WARN", "rate")
	w("  %-30s %8s %9s %8s %9s", strings.Repeat("-", 30), strings.Repeat("-", 8),
		strings.Repeat("-", 9), strings.Repeat("-", 8), strings.Repeat("-", 9))
	for i, m := range tsfpModes {
		a := tallies[i]
		w("  %-30s %8d %8.2f%% %8d %8.2f%%",
			m.Label, len(a.blocked), pct(len(a.blocked), len(names)),
			len(a.warned), pct(len(a.warned), len(names)))
	}
	w("")
	w("  Read down the BLOCK column: each row is the row above minus what that")
	w("  predicate demotes. Demoted hits become WARNs — they still print and still")
	w("  record; they stop refusing the install.")
	w("")
	w("  Production gate recovers %d of BASELINE's %d blocks (%.1f%% of them).",
		len(tallies[0].blocked)-len(tallies[tsfpProdMode].blocked), len(tallies[0].blocked),
		pct(len(tallies[0].blocked)-len(tallies[tsfpProdMode].blocked), len(tallies[0].blocked)))

	w("")
	w("BLOCK RATE BY ECOSYSTEM")
	w("")
	w("  %-30s %s", "configuration", strings.Join(tsfpPad(ecos, 18), ""))
	for i, m := range tsfpModes {
		a := tallies[i]
		cells := make([]string, 0, len(ecos))
		for _, e := range ecos {
			cells = append(cells, fmt.Sprintf("%6d %8.2f%%   ", a.blockEco[e], pct(a.blockEco[e], perEco[e])))
		}
		w("  %-30s %s", m.Label, strings.Join(cells, ""))
	}

	w("")
	w("BLOCK RATE BY POPULARITY BAND  (upstream download rank; does the tail get worse?)")
	w("")
	bandTotals := map[string]int{}
	for _, n := range names {
		bandTotals[tsfpBand(n.Rank)]++
	}
	bandHeader := make([]string, 0, len(tsfpBands))
	for _, bd := range tsfpBands {
		bandHeader = append(bandHeader, fmt.Sprintf("%-18s", fmt.Sprintf("%s (n=%d)", bd, bandTotals[bd])))
	}
	w("  %-30s %s", "configuration", strings.Join(bandHeader, ""))
	for i, m := range tsfpModes {
		a := tallies[i]
		cells := make([]string, 0, len(tsfpBands))
		for _, bd := range tsfpBands {
			cells = append(cells, fmt.Sprintf("%5d %8.2f%%   ", a.blockBand[bd], pct(a.blockBand[bd], bandTotals[bd])))
		}
		w("  %-30s %s", m.Label, strings.Join(cells, ""))
	}

	w("")
	w("EDIT SHAPE OF BASELINE BLOCKS  (which shapes each predicate removes)")
	w("")
	baseShapes, prodShapes := map[string]int{}, map[string]int{}
	for _, h := range tallies[0].blocked {
		baseShapes[h.Shape]++
	}
	for _, h := range tallies[tsfpProdMode].blocked {
		prodShapes[h.Shape]++
	}
	w("  %-20s %8s %8s %10s", "shape", "BASELINE", "P2+P1", "recovered")
	for _, kv := range sortedCounts(baseShapes) {
		w("  %-20s %8d %8d %10d", kv.k, kv.v, prodShapes[kv.k], kv.v-prodShapes[kv.k])
	}

	w("")
	w("REPRODUCIBILITY")
	w("")
	w("  %d / %d held-out names have TWO OR MORE corpus targets at distance 1;", ambiguous, len(names))
	w("  %d of the production gate's %d blocks sit on such a name.",
		ambigBlocks, len(tallies[tsfpProdMode].blocked))
	w("  Those verdicts are decided by Detector.Check's tie-break, which is now a")
	w("  TOTAL order (nearest, then most popular target, then lexicographic —")
	w("  betterEditMatch in core/typosquat/detector.go). Before that fix the tie")
	w("  was resolved by Go map-iteration order and the numbers above wobbled")
	w("  run to run; they should now reproduce exactly. If two runs of this")
	w("  harness disagree by even one name, the tie-break has regressed.")
	if len(tieFlips) > 0 {
		w("  Observed live in this run: %d names where evaluate()'s own Check landed on", len(tieFlips))
		w("  a different equidistant target than the one measured microseconds earlier.")
		for _, d := range tsfpHead(tieFlips, 15) {
			w("    %s", d)
		}
	}

	// The full lists. This is the deliverable: every name a real user cannot
	// install under each configuration.
	for i, m := range tsfpModes {
		a := tallies[i]
		w("")
		w("BLOCKED — %s  (%d names, %.2f%%)", m.Label, len(a.blocked), pct(len(a.blocked), len(names)))
		if len(a.blocked) == 0 {
			w("  (none)")
			continue
		}
		sorted := append([]tsfpHit(nil), a.blocked...)
		sort.Slice(sorted, func(x, y int) bool {
			if sorted[x].Ecosystem != sorted[y].Ecosystem {
				return sorted[x].Ecosystem < sorted[y].Ecosystem
			}
			return sorted[x].Rank < sorted[y].Rank
		})
		for _, h := range sorted {
			w("  %s", h.line())
		}
		tsfpWriteTSV(t, dir, "blocked-"+m.Slug+".tsv", sorted)
	}

	w("")
	if len(modelDiffs) == 0 {
		w("CROSS-CHECK: the shipped predicates and this file's independent model agree")
		w("on every d=1 in-cutoff hit in the corpus (0 disagreements).")
	} else {
		w("CROSS-CHECK: %d disagreements between guard_typosquat_gate.go and this file's", len(modelDiffs))
		w("independent model of the proposal. Each one is a package where the two")
		w("readings of \"typo-shaped\" differ — resolve them before publishing a number.")
		w("")
		for _, d := range tsfpHead(modelDiffs, 60) {
			w("  %s", d)
		}
	}

	w("")
	if len(wiringDiffs) == 0 {
		w("WIRING: evaluate() agrees with the reproduced ladder under the production")
		w("gate on all %d flagged names — the predicates are genuinely on the install path.", evaluated)
	} else {
		w("WIRING: WARNING — %d names where evaluate() disagrees with the reproduced", len(wiringDiffs))
		w("ladder under the production gate, and the disagreement is NOT explained by")
		w("equidistant-target noise or by another signal claiming the verdict:")
		for _, d := range tsfpHead(wiringDiffs, 40) {
			w("  %s", d)
		}
	}
	if len(otherSignal) > 0 {
		w("")
		w("  %d flagged names were claimed by a non-typosquat signal (known-malicious", len(otherSignal))
		w("  floor / supplemental advisory / behavioral) rather than by the ladder:")
		for _, d := range tsfpHead(otherSignal, 20) {
			w("    %s", d)
		}
	}

	w("")
	w("CAVEAT: npm-high-impact and top-pypi-packages are themselves popularity")
	w("lists. npm has ~3M packages, so this corpus samples the NEAR tail. `nano`,")
	w("one of the two reproduced false blocks, is absent from the upstream list")
	w("entirely and so cannot appear here at all. Treat every rate above as a")
	w("LOWER BOUND on the real false-block rate.")

	t.Log(b.String())
}

// tsfpReasonTarget pulls the quoted target back out of a guard reason string
// ("looks like a typosquat of \"lodash\" (distance 1, …)"). Best-effort: it is
// only used to describe a disagreement, never to decide one.
func tsfpReasonTarget(reason string) string {
	i := strings.Index(reason, `"`)
	if i < 0 {
		return "(none)"
	}
	j := strings.Index(reason[i+1:], `"`)
	if j < 0 {
		return "(none)"
	}
	return reason[i+1 : i+1+j]
}

// tsfpLoadCorpus reads the "<rank>\t<name>" files the builder writes.
func tsfpLoadCorpus(dir string) ([]tsfpName, map[string]int, error) {
	var names []tsfpName
	perEco := map[string]int{}
	for _, src := range tsfpSources {
		path := filepath.Join(dir, src.File)
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("open %s: %w (run scripts/detection-eval/build-heldout-name-corpus.sh)", path, err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			rankStr, name, ok := strings.Cut(line, "\t")
			if !ok {
				// Tolerate a bare name list; rank 0 lands in the first band.
				name, rankStr = line, "0"
			}
			rank, convErr := strconv.Atoi(strings.TrimSpace(rankStr))
			if convErr != nil {
				continue
			}
			if name = strings.TrimSpace(name); name == "" {
				continue
			}
			names = append(names, tsfpName{Ecosystem: src.Ecosystem, Name: name, Rank: rank})
			perEco[src.Ecosystem]++
		}
		scanErr := sc.Err()
		f.Close()
		if scanErr != nil {
			return nil, nil, fmt.Errorf("read %s: %w", path, scanErr)
		}
	}
	return names, perEco, nil
}

// tsfpSeedMembers returns the normalized names the binary EMBEDS, keyed
// "<ecosystem>\x00<normalized name>". These are the names that get the
// detector's exact-match exemption — a held-out corpus must contain none.
func tsfpSeedMembers() map[string]bool {
	out := map[string]bool{}
	for eco, seed := range map[string][]byte{"npm": npmPopularSeed, "pypi": pypiPopularSeed} {
		norm := typosquat.NormalizerForFormat(eco)
		for _, p := range parsePopularSeed(seed) {
			out[eco+"\x00"+norm(p.Name)] = true
		}
	}
	return out
}

// tsfpWriteTSV drops a machine-readable copy of a blocked list next to the
// corpus. Best-effort: a read-only corpus dir must not fail a measurement.
func tsfpWriteTSV(t *testing.T, dir, name string, hits []tsfpHit) {
	t.Helper()
	var b strings.Builder
	b.WriteString("# ecosystem\tname\tupstream_rank\ttarget\tdistance\tmethod\ttarget_rank\tedit_shape\td1_ties\n")
	for _, h := range hits {
		b.WriteString(h.tsv())
		b.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(b.String()), 0o644); err != nil {
		t.Logf("note: could not write %s: %v", name, err)
	}
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d) * 100
}

func tsfpHead(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(append([]string(nil), s[:n]...), fmt.Sprintf("… and %d more", len(s)-n))
}

func tsfpPad(cols []string, width int) []string {
	out := make([]string, 0, len(cols))
	for _, c := range cols {
		out = append(out, fmt.Sprintf("%-*s", width, c))
	}
	return out
}

type tsfpCount struct {
	k string
	v int
}

func sortedCounts(m map[string]int) []tsfpCount {
	out := make([]tsfpCount, 0, len(m))
	for k, v := range m {
		out = append(out, tsfpCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].v != out[j].v {
			return out[i].v > out[j].v
		}
		return out[i].k < out[j].k
	})
	return out
}
