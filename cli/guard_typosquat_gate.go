package cli

// Block-lane gate for d=1 edit-distance typosquat hits.
//
// The rank cutoff alone (guardTyposquatBlockRankCutoff) asks only "is the
// TARGET popular?". It never asks "does the edit look like a typo?", so it
// blocks every legitimate package outside the corpus that happens to sit one
// edit from a top-2500 name. Two real false blocks motivated this file:
//
//	chainsaw npm install nano   → blocked as a typosquat of `nan`  (rank #1476)
//	chainsaw npm install args   → blocked as a typosquat of `arg`  (rank #263)
//	                              or of `yargs` (rank #70), see EDGE EDITS
//
// `nano` is the Apache CouchDB client; `args` is a widely-used CLI parser.
// Neither is a typo of anything — they differ from a popular name by a rune
// added or dropped at an END of the name, which is how sibling packages get
// NAMED (nan→nano, listr→listr2, attr→attrs), not how names get MISTYPED.
//
// ─── THE MODEL ─────────────────────────────────────────────────────────────
//
// Two predicates, deliberately separate and independently toggleable (see
// typosquatBlockGate) so a measurement pass can attribute the false-positive
// win and the recall cost to each on its own rather than to an
// undifferentiated blob:
//
//	P2 — typosquatTargetLongEnough:  the target must be long enough that a
//	     single edit is plausibly a slip rather than a different word. How
//	     long depends on the SHAPE (see typosquatEditShape.needsLongTarget).
//	P1 — typosquatEditIsTypoShaped:  the single edit must have a typo shape,
//	     with one rank-scoped rescue (see EDGE EDITS below).
//
// Both are pure functions of (ecosystem, candidate name, DetectionResult), so
// they unit-test without constructing a guard, a corpus, or a detector.
//
// Failing either predicate DEMOTES to the warn lane, and a demoted hit is
// printed even under --quiet (severity guardSeverityTyposquatDemoted, see
// guard_eval.go) precisely because the gate — not the evidence — is what
// downgraded it. Homoglyph hits are a different arm entirely and never
// consult this file: a byte-level confusable collision has no legitimate
// explanation regardless of rank, target length, or edit shape.
//
// ─── EDGE EDITS: the false-block class, and its limit ──────────────────────
//
// The EDGE shapes are the naming family: a rune added to, or dropped from, an
// END of a popular name — `nano`/`nan`, `args`/`arg`, `args`/`yargs`,
// `attr`/`attrs`, `listr`/`listr2`, `websocket`/`websockets`. They demote.
//
// Two carve-outs, both measured, both asymmetric on purpose:
//
//  1. APPEND/PREPEND on a household name still blocks (rank ≤
//     guardTyposquatPopularRescueRank). Attackers use that half heavily:
//     `hdebug` (debug #3), `pydantics` (pydantic #20), `python-dateutil2`
//     (#15), `typescript3` (#205), `lodashn` (lodash #101), `ptorch` (torch
//     #359) are all in the OpenSSF feed. Held-out cost: 18 false blocks.
//     Feed benefit: 32 recovered malicious names.
//
//  2. A TRUNCATE demotes only when the dropped rune is a plural 's' or a
//     version digit (typosquatEditDropSiblingSuffix), or when it is the
//     LEADING rune. Dropping an arbitrary LAST rune is a keystroke that did
//     not land, and the feed is full of those: debu, nump, chal, tsli,
//     psuti, openpyx, requests-toolbel. Those keep blocking.
//
// The leading-rune truncate is the one place a real cost is accepted rather
// than engineered away: it demotes `odash`/`halk`/`equests` along with
// `args`/`yargs` (#70), `echarts`/`recharts`, `error`/`verror`,
// `path`/`dpath`. Nothing in either corpus separates those two populations —
// both sit against top-ranked targets — and `args` is one of the two false
// blocks this branch exists to close, so the demotion stands and the cost is
// published. See TestTyposquatHeldOutFalseBlockRate (false blocks) and
// TestTyposquatMalwareFeedBlockRecall (recall); read them together.
//
// ─── THE MEASURED TRADE (quote both halves or neither) ─────────────────────
//
// Held-out false blocks, 24,206 real package names outside the shipped seed
// (TestTyposquatHeldOutFalseBlockRate):
//
//	BASELINE, rank cutoff only  453 blocks  1.87%
//	production gate             247 blocks  1.02%   → 206 false blocks recovered
//
// Block recall on real attacker names, 227,525 npm/PyPI coordinates from the
// OpenSSF malicious-packages feed (TestTyposquatMalwareFeedBlockRecall). Only
// the 1,122 that are d=1 against an in-cutoff target can reach this gate:
//
//	BASELINE                   1,122 blocks
//	production gate            1,030 blocks          → 92 given up, 8.2%
//
// So the gate trades 92 typosquat-lane blocks on known-malicious names for 206
// recovered false blocks. Both numbers are lower bounds on their own side, and
// the 92 are all names the shipped known-malicious floor refuses by coordinate
// anyway — what is actually given up is the block on the NEXT, unlisted squat
// of the same shape, which now warns instead (loudly: see
// guardSeverityTyposquatDemoted, printed even under --quiet).
//
// ─── SCOPE: what stays demoted on purpose ──────────────────────────────────
//
// Three ACCEPTED RISKS, each measured rather than assumed. All three still
// WARN, and the warning prints under --quiet.
//
//  1. A SUBSTITUTION against a ≤4-rune target (P2). That band is where two
//     legitimate short names collide by coincidence — blob/glob, jsbi/jsbn,
//     tape/type, chat/chai, gsap/asap, mqtt/mitt, i18n/y18n, pix/pip. Cost:
//     30 of the 92 demoted malicious names, including cffy/cffi, zipf/zipp,
//     yamm/yaml. Transpositions, interior inserts/deletes and doubled-end
//     fat-fingers on the SAME short targets do keep the block lane, because
//     two independent legitimate names essentially never collide in those
//     shapes (uudi, ajvv, ritch all still block).
//
//  2. A LEADING-RUNE truncate, at any rank. Required by `args`/`yargs` (#70).
//     Cost: 24 of the 92, including odash/lodash, halk/chalk,
//     equests/requests, olorama/colorama.
//
//  3. An APPEND/PREPEND against a target deeper than
//     guardTyposquatPopularRescueRank. Cost: 31 of the 92, mostly against
//     rank #500–2500 targets.

import (
	"unicode/utf8"

	"github.com/chain305/chainsaw-core/typosquat"
)

// guardTyposquatBlockMinTargetLen is the minimum length, in RUNES, of a
// typosquat TARGET for a d=1 hit whose shape needs the length check (edge
// edits and substitutions — see typosquatEditShape.needsLongTarget) to BLOCK
// rather than warn. One edit on a 3-4 character name carries little signal: at
// that length a single added, dropped or swapped rune is not a slip of the
// finger, it is a different word.
//
// 5 is data-derived from two corpora, in both directions:
//
//   - RECALL: every historically-squatted target the recall suite gates on
//     clears it with margin — react(5) and chalk(5) sit exactly on the
//     boundary, colors(6) and lodash(6) one above, express(7), requests(8)
//     and cross-env(9) further still. Nothing in the recall suite is demoted.
//     Raising it to 6 would start costing real coverage (react, chalk).
//
//   - FALSE BLOCKS: the held-out corpus (24,206 real names outside the seed,
//     scripts/detection-eval/corpus-heldout-names) produces 70 baseline blocks
//     against 3-rune targets and 71 against 4-rune targets. Lowering the floor
//     to 4 would therefore readmit MORE false blocks than the 3-rune band
//     contributes, all of them substitutions: jsbi→jsbn, gsap→asap, yazl→yaml,
//     mqtt→mitt, blob→glob, tape→type, chat→chai, i18n→y18n, swrv→sirv.
//     (An earlier revision of this comment claimed "the false-block class
//     lives at 3" — blocked-baseline.tsv says otherwise.)
//
// The check is on RUNES, not bytes, so a non-ASCII target is measured the way
// a human reads it.
const guardTyposquatBlockMinTargetLen = 5

// guardTyposquatPopularRescueRank is the popularity rank at or above which an
// edge INSERTION (append/prepend) keeps the block lane despite being a naming
// shape. Appending a rune to a household name is what the malicious-packages
// feed is full of; appending one to a rank-#2000 name is what real siblings
// do. 500 is where the two populations separate in the measured corpora: it
// recovers the feed's append/prepend squats of top-500 targets while leaving
// the held-out false blocks (whose targets are overwhelmingly deeper than
// #500) demoted. Set to 0 to disable the rescue entirely — the measurement
// harness prices it that way.
const guardTyposquatPopularRescueRank = 500

// typosquatEditShape names the shape of the single edit that separates a
// candidate name from the popular target it matched.
type typosquatEditShape string

const (
	// Typo shapes — a hand slipping on a keyboard produces these.
	typosquatEditSubstitution   typosquatEditShape = "substitution"    // serfe → serde
	typosquatEditTransposition  typosquatEditShape = "transposition"   // lodahs → lodash
	typosquatEditDeleteInterior typosquatEditShape = "delete-interior" // crossenv → cross-env
	typosquatEditInsertInterior typosquatEditShape = "insert-interior" // loadash → lodash
	// Doubled-letter fat-fingers: holding a key one beat too long at either
	// end of the name. expresss → express, actionpackk → actionpack.
	typosquatEditDoubleEnd   typosquatEditShape = "insert-doubled-end"
	typosquatEditDoubleStart typosquatEditShape = "insert-doubled-start"

	// Naming shapes — a human deliberately choosing a related name produces
	// these: one rune added to, or dropped from, an END of the target. A
	// suffix append on a short stem is the canonical sibling-package pattern
	// (nan → nano, arg → args), not a mistype; a truncate is its mirror
	// (yargs → args, braces → brace, listr2 → listr).
	typosquatEditAppend        typosquatEditShape = "append"         // nan → nano
	typosquatEditPrepend       typosquatEditShape = "prepend"        // arg → xarg
	typosquatEditTruncateStart typosquatEditShape = "truncate-start" // yargs → args
	// A dropped PLURAL 's' or version DIGIT at the end is the sibling-naming
	// half of the truncate family: braces→brace, attrs→attr, listr2→listr,
	// cbor2→cbor, beautifulsoup4→beautifulsoup. Measured: this is where
	// essentially all the legitimate truncate collisions live.
	typosquatEditDropSiblingSuffix typosquatEditShape = "drop-plural-or-version"

	// typosquatEditTruncateEnd is the OTHER half: an arbitrary last rune
	// missing (`debu` for debug, `nump` for numpy, `chal` for chalk). That is
	// a keystroke that did not land, so it is a TYPO shape and keeps the
	// block lane. The OpenSSF feed is full of them.
	typosquatEditTruncateEnd typosquatEditShape = "truncate-end"

	// typosquatEditUnknown means no single-edit alignment could be
	// reconstructed. It counts as typo-shaped: an alignment we cannot read
	// must never open a hole. See classifyTyposquatEdit.
	typosquatEditUnknown typosquatEditShape = "unknown"
)

// typoShaped reports whether this shape is consistent with a mistype.
// Everything except the four EDGE shapes is; unknown fails SAFE (true).
func (s typosquatEditShape) typoShaped() bool {
	return !s.edgeEdit()
}

// edgeEdit reports whether the shape is a rune added to or dropped from an
// END of the target — the naming family.
func (s typosquatEditShape) edgeEdit() bool {
	switch s {
	case typosquatEditAppend, typosquatEditPrepend,
		typosquatEditDropSiblingSuffix, typosquatEditTruncateStart:
		return true
	default:
		return false
	}
}

// edgeInsertion reports whether the shape ADDS a rune at an end (as opposed to
// dropping one). Only this half is eligible for the popular-target rescue —
// see the EDGE EDITS section of the file header for the measurement behind the
// asymmetry.
func (s typosquatEditShape) edgeInsertion() bool {
	return s == typosquatEditAppend || s == typosquatEditPrepend
}

// needsLongTarget reports whether this shape must clear
// guardTyposquatBlockMinTargetLen to keep the block lane.
//
// Edge edits and substitutions do: those are the two shapes in which two
// INDEPENDENT legitimate short names collide (blob/glob, tape/type, nano/nan,
// attr/attrs). Transpositions, interior inserts/deletes and doubled-end
// fat-fingers do not: `uudi` is not a package that happens to look like
// `uuid`, and demoting those on a length rule alone stripped the block lane
// from every popular name of 4 runes or fewer — 118 npm and 147 PyPI corpus
// names inside the rank cutoff, including pip, six, idna, glob, ajv, uuid,
// rich and tqdm.
func (s typosquatEditShape) needsLongTarget() bool {
	return s.edgeEdit() || s == typosquatEditSubstitution
}

// typosquatTargetLongEnough is predicate P2: the matched target must be at
// least guardTyposquatBlockMinTargetLen runes long WHEN the edit shape needs
// that check.
func typosquatTargetLongEnough(ecosystem, candidate string, res typosquat.DetectionResult) bool {
	if utf8.RuneCountInString(res.SimilarTo) >= guardTyposquatBlockMinTargetLen {
		return true
	}
	return !classifyTyposquatEdit(ecosystem, candidate, res).needsLongTarget()
}

// typosquatEditIsTypoShaped is predicate P1: the single edit separating the
// candidate from res.SimilarTo must look like a mistype rather than a
// deliberate sibling name.
func typosquatEditIsTypoShaped(ecosystem, candidate string, res typosquat.DetectionResult) bool {
	return classifyTyposquatEdit(ecosystem, candidate, res).typoShaped()
}

// classifyTyposquatEdit names the shape of the d=1 edit between `candidate`
// and res.SimilarTo.
//
// NORMALIZATION — which case we are in.
//
//	The detector computes res.Distance on NORMALIZED forms: detector.Check
//	compares norm(packageName) against the BK-tree key, which LoadEcosystem
//	built as norm(popularName). res.SimilarTo, however, is handed back as the
//	RAW popular name (names[best.Word]). So the two strings available here are
//	in DIFFERENT spaces, and comparing them directly would misclassify every
//	name whose normalizer does real work — crossenv vs cross-env is a
//	delimiter deletion under NormalizeNPM but would look like a two-edit
//	mismatch to a naive raw comparison on a delimiter-stripping ecosystem.
//
//	We therefore re-apply the SAME normalizer the detector used
//	(NormalizerForFormat on the ecosystem, which is what LoadEcosystem keyed
//	the index with) to BOTH strings before aligning. Normalizers are
//	idempotent, so norm(res.SimilarTo) reproduces best.Word exactly and the
//	alignment we reconstruct is the one the distance was measured on.
//
//	That is the reconstructible case, and it is the case every ecosystem in
//	EcosystemsWithTyposquatRisk lands in today. The unreconstructible case is
//	still handled: if the normalized forms do not differ by exactly one edit
//	we can read, we return typosquatEditUnknown, which is typo-shaped — an
//	alignment failure DEMOTES NOTHING and never opens a hole.
//
// ALIGNMENT AMBIGUITY. An edit inside a run of repeated runes has several
// valid alignments (express + s can be read as an interior insert OR as an
// append; braces − s as a truncate OR as an interior delete). Every valid
// alignment is enumerated and the most typo-shaped one wins, so an ambiguous
// alignment can never silently demote a real squat.
func classifyTyposquatEdit(ecosystem, candidate string, res typosquat.DetectionResult) typosquatEditShape {
	if res.SimilarTo == "" || candidate == "" {
		return typosquatEditUnknown
	}
	norm := typosquat.NormalizerForFormat(ecosystem)
	cand := []rune(norm(candidate))
	targ := []rune(norm(res.SimilarTo))
	if len(cand) == 0 || len(targ) == 0 {
		return typosquatEditUnknown
	}

	switch len(cand) - len(targ) {
	case 0:
		return classifySameLengthEdit(cand, targ)
	case -1:
		return classifyDeletionEdit(cand, targ)
	case 1:
		return classifyInsertionEdit(cand, targ)
	default:
		return typosquatEditUnknown
	}
}

// classifySameLengthEdit handles equal-length candidates: exactly one rune
// differs (substitution) or exactly two adjacent runes are swapped
// (transposition). Both are typo shapes.
func classifySameLengthEdit(cand, targ []rune) typosquatEditShape {
	diff := make([]int, 0, 3)
	for i := range cand {
		if cand[i] != targ[i] {
			diff = append(diff, i)
			if len(diff) > 2 {
				return typosquatEditUnknown
			}
		}
	}
	switch len(diff) {
	case 1:
		return typosquatEditSubstitution
	case 2:
		i, j := diff[0], diff[1]
		if j == i+1 && cand[i] == targ[j] && cand[j] == targ[i] {
			return typosquatEditTransposition
		}
	}
	return typosquatEditUnknown
}

// classifyDeletionEdit handles a candidate one rune SHORTER than the target —
// the mirror of classifyInsertionEdit. len(cand)+1 == len(targ) is the
// caller's precondition.
//
// Position decides the shape, symmetrically with an insertion:
//   - interior (a rune dropped strictly between two surviving runes) →
//     typo-shaped (crossenv → cross-env, reqests → requests);
//   - at either END → a truncate, which is a NAMING shape (yargs → args,
//     braces → brace, listr2 → listr).
//
// EVERY valid alignment is enumerated and the most typo-shaped one wins, so a
// name missing one of a DOUBLED pair at the end (`expres` against `express`)
// classifies as the interior delete it also is, not as a truncate.
func classifyDeletionEdit(cand, targ []rune) typosquatEditShape {
	best := typosquatEditUnknown
	for p := range targ {
		if !runesEqualSkipping(targ, p, cand) {
			continue
		}
		var shape typosquatEditShape
		switch {
		case p > 0 && p < len(targ)-1:
			shape = typosquatEditDeleteInterior
		case p == 0:
			shape = typosquatEditTruncateStart
		case isSiblingSuffixRune(targ[p]):
			shape = typosquatEditDropSiblingSuffix
		default: // p == len(targ)-1: an arbitrary last rune is missing.
			shape = typosquatEditTruncateEnd
		}
		if deletionShapeRank(shape) > deletionShapeRank(best) {
			best = shape
		}
	}
	return best
}

// isSiblingSuffixRune reports whether a dropped FINAL rune is the plural 's'
// or a version digit — the two suffixes that distinguish sibling packages from
// each other (braces/brace, attrs/attr, listr2/listr, cbor2/cbor,
// beautifulsoup4/beautifulsoup, pyasn1/pyasn, types-boto3/types-boto).
//
// Measured on the held-out corpus, that is where essentially the whole
// legitimate truncate class lives; measured on the OpenSSF feed, the malicious
// truncates drop an arbitrary letter instead (debu, nump, chal, tsli, psuti,
// openpyx, aiohtt, typing-extension). Splitting the family here keeps both.
func isSiblingSuffixRune(r rune) bool {
	return r == 's' || (r >= '0' && r <= '9')
}

// deletionShapeRank orders the readings of an ambiguous deletion. Higher wins:
// an interior delete and an arbitrary end-truncate are typo-shaped; a dropped
// plural/version suffix and a leading-rune truncate are naming shapes; unknown
// means no alignment was found at all.
func deletionShapeRank(s typosquatEditShape) int {
	switch s {
	case typosquatEditDeleteInterior:
		return 3
	case typosquatEditTruncateEnd:
		return 2
	case typosquatEditDropSiblingSuffix, typosquatEditTruncateStart:
		return 1
	default:
		return 0
	}
}

// classifyInsertionEdit handles a candidate one rune LONGER than the target.
// len(cand) == len(targ)+1 is the caller's precondition.
//
// Position decides the shape:
//   - interior (strictly between two target runes) → typo-shaped;
//   - at the end → typo-shaped ONLY if the inserted rune repeats the target's
//     last rune (the doubled-letter fat-finger);
//   - at the start → typo-shaped ONLY if the inserted rune repeats the
//     target's first rune.
//
// EVERY valid alignment is enumerated and the strongest one wins, so an
// ambiguous alignment can never demote a name that has a typo-shaped reading.
// Doubling a rune at either end always ALSO admits an interior reading (the
// two copies are interchangeable), which is why the ranking prefers the
// doubled label: both are typo-shaped, and the doubled one is the shape a
// human would name.
func classifyInsertionEdit(cand, targ []rune) typosquatEditShape {
	best := typosquatEditUnknown
	for p := 0; p <= len(targ); p++ {
		if !runesEqualSkipping(cand, p, targ) {
			continue
		}
		var shape typosquatEditShape
		switch {
		case p == len(targ) && cand[p] == targ[len(targ)-1]:
			shape = typosquatEditDoubleEnd
		case p == 0 && cand[0] == targ[0]:
			shape = typosquatEditDoubleStart
		case p > 0 && p < len(targ):
			shape = typosquatEditInsertInterior
		case p == 0:
			shape = typosquatEditPrepend
		default: // p == len(targ): appended after the last target rune.
			shape = typosquatEditAppend
		}
		if insertionShapeRank(shape) > insertionShapeRank(best) {
			best = shape
		}
	}
	return best
}

// insertionShapeRank orders the readings of an ambiguous insertion. Higher
// wins. Both doubled forms and the interior form are typo-shaped; append and
// prepend are not; unknown means no alignment was found at all.
func insertionShapeRank(s typosquatEditShape) int {
	switch s {
	case typosquatEditDoubleEnd, typosquatEditDoubleStart:
		return 3
	case typosquatEditInsertInterior:
		return 2
	case typosquatEditAppend, typosquatEditPrepend:
		return 1
	default:
		return 0
	}
}

// runesEqualSkipping reports whether `long` with the rune at index `skip`
// removed equals `short`. Requires len(long) == len(short)+1.
func runesEqualSkipping(long []rune, skip int, short []rune) bool {
	if len(long) != len(short)+1 || skip < 0 || skip >= len(long) {
		return false
	}
	j := 0
	for i := range long {
		if i == skip {
			continue
		}
		if long[i] != short[j] {
			return false
		}
		j++
	}
	return true
}

// typosquatBlockGate selects which of the block-lane predicates are enforced.
// Production is guardTyposquatBlockGate below; the fields exist so a
// measurement pass can turn exactly one off and attribute its contribution,
// and so the regression suite can pin the pre-fix behaviour it replaces.
type typosquatBlockGate struct {
	RequireMinTargetLen bool // P2
	RequireTypoShape    bool // P1
	// PopularTargetRescueRank re-admits an edge INSERTION whose target sits at
	// or above this rank. 0 disables the rescue. Only consulted when
	// RequireTypoShape is on — it is a carve-out of P1, not a rule of its own.
	PopularTargetRescueRank int
}

// guardTyposquatBlockGate is the production configuration. A var, not a
// const, purely so tests can substitute a gate and restore it; nothing on the
// install path mutates it.
var guardTyposquatBlockGate = typosquatBlockGate{
	RequireMinTargetLen:     true,
	RequireTypoShape:        true,
	PopularTargetRescueRank: guardTyposquatPopularRescueRank,
}

// allowsD1Block reports whether a d=1 edit-distance hit against an
// in-cutoff-rank target still earns the block lane. False demotes it to WARN
// (severity guardSeverityTyposquatDemoted — printed, never silenced).
func (g typosquatBlockGate) allowsD1Block(ecosystem, candidate string, res typosquat.DetectionResult) bool {
	if g.RequireMinTargetLen && !typosquatTargetLongEnough(ecosystem, candidate, res) {
		return false
	}
	if g.RequireTypoShape && !typosquatEditIsTypoShaped(ecosystem, candidate, res) {
		return g.rescuesPopularTarget(ecosystem, candidate, res)
	}
	return true
}

// rescuesPopularTarget is the one carve-out of P1: an edge INSERTION on a
// long-enough, household-rank target keeps the block lane. See the EDGE EDITS
// section of the file header for why truncates are excluded.
func (g typosquatBlockGate) rescuesPopularTarget(ecosystem, candidate string, res typosquat.DetectionResult) bool {
	if g.PopularTargetRescueRank <= 0 {
		return false
	}
	if res.TargetRank <= 0 || res.TargetRank > g.PopularTargetRescueRank {
		return false
	}
	if utf8.RuneCountInString(res.SimilarTo) < guardTyposquatBlockMinTargetLen {
		return false
	}
	return classifyTyposquatEdit(ecosystem, candidate, res).edgeInsertion()
}
