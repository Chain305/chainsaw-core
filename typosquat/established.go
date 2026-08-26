package typosquat

import (
	"bufio"
	"bytes"
	_ "embed"
	"strings"
	"sync"
)

// established.go — the popularity-DIRECTION check for the edit-distance lane.
//
// ─── THE DEFECT ─────────────────────────────────────────────────────────────
//
// A typosquat is, by definition, a LESS established package wearing the face
// of a MORE established one. The direction is half the claim. Detector.Check
// never checked it: it found the nearest neighbour in whatever popular corpus
// happened to be loaded and reported the QUERY as a squat of that neighbour,
// regardless of which of the two is the bigger, older, more-installed package.
//
// Measured against a read-only export of production `intelligence_reports`
// (7,099 rows, 15 of them carrying typosquatConfidence="high"), that produced
// five wrong-direction pairs — SIX rows, 40% of every high-confidence verdict
// the fleet has ever emitted:
//
//	npm  ms@2.1.3               "similar to" msw
//	npm  json5@1.0.2, @2.2.3    "similar to" json3
//	npm  esutils@2.0.3          "similar to" tsutils
//	npm  lie@3.3.0              "similar to" li
//	npm  is-typed-array@1.1.15  "similar to" is-typedarray
//
// `ms` is one of the most-depended-on packages in existence and was reported
// as a squat of `msw`. `is-typed-array` and `json5` are transitive
// dependencies of much of npm. These merely WARNed while sc.typosquat_high
// was SevHigh; once it was promoted to SevCritical so that a real
// high-confidence squat could finally quarantine (epoch 6), all six became
// hard BLOCKS. The promotion is right; shipping it on top of a detector with
// no direction check is not.
//
// The remaining nine high-confidence rows — chalkk/chalk, expres/express,
// lodashs/lodash, lodahs/lodash, reqeusts/requests, colourama/colorama — are
// true positives and must keep blocking. See TestDirectionCheck* .
//
// ─── WHY THE LOADED CORPUS CANNOT ANSWER THE QUESTION ───────────────────────
//
// The obvious check — "is the QUERY itself in the popular corpus at a rank at
// or above the target?" — is UNREACHABLE. Detector.check returns an empty
// result on an exact corpus match before any distance work runs ("Exact match
// with popular package → not a typosquat"), so by the time there is a
// SimilarTo to compare against, the query is known to be absent from the
// index. Corpus rank is retained through to Check (d.ranks, surfaced as
// DetectionResult.TargetRank) — it is the TARGET's rank, and there is no
// query rank to put beside it.
//
// Nor is "absent from the corpus" evidence of anything. The corpus is a
// top-N cut, and on the server it is npm's live keyword search (fetcher.go,
// fetchNPM) — a third-party relevance ranking, not a download ranking. That
// is precisely how the six above happened: the keyword corpus carries `msw`,
// `json3`, `tsutils`, `is-typedarray` and `li` while omitting `ms`, `json5`,
// `esutils`, `lie` and `is-typed-array`. official.go's header already writes
// this down for the combosquat lane — "a corpus that upstream ranking can
// move is not a trust boundary" — and it is the same corpus and the same
// argument here.
//
// So the direction question needs a popularity oracle the match index does
// not supply: a REVIEWED, download-ranked reference, below.
//
// ─── WHY NOT A TARGET-RANK CUTOFF ───────────────────────────────────────────
//
// "Demote when the target sits deep in the corpus tail" would separate these
// six from the nine true positives too, and the install guard already has one
// (guardTyposquatBlockRankCutoff). It was rejected here for two reasons.
// First, it answers a different question — "is the target worth squatting?" —
// and buys precision by trading recall on every genuine squat of a mid-rank
// package. Second, and decisively, it is NOT MEASURABLE against the evidence:
// TargetRank is additive and was not persisted at the epoch the production
// rows were written, so every one of the 15 high-confidence rows carries no
// target rank at all. A gate whose effect on the only real corpus cannot be
// computed is not a gate, it is a guess.
//
// ─── WHAT THIS KEYS ON ──────────────────────────────────────────────────────
//
// Exact, whole package names on a REVIEWED, DOWNLOAD-RANKED list, checked in
// both directions. Same trust shape as officialSiblings (exact reviewed
// names, no patterns) and the same demotion shape as sameOwnerSibling (a
// structural fact, DEMOTE never silence).
//
// An attacker cannot forge a place on it. The list is generated from an
// upstream DOWNLOAD ranking by core/tools/popular-corpus-gen and lands in the
// repository through a reviewed commit; to be treated as the established side
// of a pair, the attacker's package would need genuine mass adoption ahead of
// its victim, at which point it is not impersonating anyone. This is the same
// argument official.go makes for its list, and unlike corpus membership it
// does not move when a third party re-ranks its search results.
//
// ─── WHY THE PUBLISHED FP AND RECALL NUMBERS CANNOT MOVE ────────────────────
//
// The demotion is DEAD CODE whenever the match index and this reference are
// the same list — and in the install guard they are. localGuard.detector()
// loads core/cli/seeds/npm_popular.txt (or a signature-verified bundle) as
// the npm index; this reference is a byte-identical mirror of that file
// (TestEstablishedReferenceMirrorsGuardSeed). A query present in the
// reference is therefore present in the index, and an index hit returns clean
// from the exact-match branch before any of this runs. So:
//
//   - guard_typosquat_fp_eval_test.go (BASELINE 453 / 1.87%, production gate
//     247 / 1.02%, recovering 206) reads a held-out corpus that
//     build-heldout-name-corpus.sh builds to have an EMPTY intersection with
//     the seed — verified: 0 of 12,334 held-out npm names are in the
//     5,000-name seed. No query in that harness can be in the reference.
//   - guard_typosquat_recall_eval_test.go (BASELINE 1,122, production gate
//     1,030, 8.2% given up) runs the OpenSSF malicious feed. 49 of its
//     210,741 npm names and 4 of its 8,355 PyPI names ARE in the seed — all
//     of them account-takeover compromises of legitimate packages (chalk,
//     debug, axios, the @tanstack family), not squats — and every one of
//     those already returns clean from the exact-match branch, contributing
//     nothing to typosquat recall before this change or after it.
//
// Re-measured after the change: 453 / 1.87%, 247 / 1.02%, 206 recovered,
// 1,030 / 8.2%, and docker 0.000% / 0.780%, swift 0.000%, github_actions
// 0.000%. Every published figure is byte-for-byte what it was.
//
// The check therefore bites in exactly one place: where the match index is
// NOT the reviewed list, i.e. the server's live keyword corpus, which is
// where all six false positives were produced.
//
// ─── THE DEEPER ROOT CAUSE, DELIBERATELY NOT FIXED HERE ─────────────────────
//
// The server ranks by npm keyword relevance while the guard ranks by
// downloads. Pointing the server at the reviewed seed would clear all six on
// the exact-match branch with no new mechanism — and would also replace the
// entire server corpus, moving every typosquat verdict the fleet emits, in a
// change no measurement in this repository can price. It is a separate wave.

// npmEstablishedSeed and pypiEstablishedSeed are byte-identical mirrors of
// core/cli/seeds/npm_popular.txt and core/cli/seeds/pypi_popular.txt.
//
// TWO COPIES OF ONE LIST. They are mirrors rather than one shared file
// because core/cli imports core/typosquat and not the reverse, and go:embed
// cannot reach outside its own directory. The copies are pinned byte-for-byte
// by TestEstablishedReferenceMirrorsGuardSeed, which fails with both paths in
// the message: regenerate BOTH with core/tools/popular-corpus-gen or neither.
// The byte equality is not cosmetic — the dead-code argument above depends on
// this file being the same list the guard loads as its index.
//
//go:embed seeds/npm_established.txt
var npmEstablishedSeed []byte

//go:embed seeds/pypi_established.txt
var pypiEstablishedSeed []byte

// establishedSources maps an ecosystem string, as Check receives it, onto the
// reviewed download-ranked list for that ecosystem. An ecosystem with no
// entry has no direction oracle and is never demoted — docker, swift,
// github_actions, go, maven and the rest are unaffected by this file.
var establishedSources = map[string][]byte{
	"npm":  npmEstablishedSeed,
	"pip":  pypiEstablishedSeed,
	"pypi": pypiEstablishedSeed,
}

var (
	establishedOnce  sync.Once
	establishedRanks map[string]map[string]int // ecosystem → normalized name → download rank (1 = most installed)
)

// loadEstablishedRanks parses the embedded reference lists once. Line order is
// rank, exactly as the seed header says ("LINE ORDER IS RANK ... do not
// sort"); '#' comments and blank lines are skipped and do not consume a rank.
// The first occurrence of a name wins, so a duplicated line cannot demote its
// own rank.
func loadEstablishedRanks() {
	establishedRanks = make(map[string]map[string]int, len(establishedSources))
	for ecosystem, data := range establishedSources {
		norm := NormalizerForFormat(ecosystem)
		idx := make(map[string]int, 5000)
		rank := 0
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			rank++
			key := norm(line)
			if key == "" {
				continue
			}
			if _, seen := idx[key]; !seen {
				idx[key] = rank
			}
		}
		establishedRanks[ecosystem] = idx
	}
}

// establishedRank returns the download rank of a name on the reviewed
// reference for its ecosystem (1 = most installed), and whether it is on the
// list at all. Ecosystems with no reference always return false.
func establishedRank(ecosystem, name string) (int, bool) {
	establishedOnce.Do(loadEstablishedRanks)
	idx, ok := establishedRanks[strings.ToLower(strings.TrimSpace(ecosystem))]
	if !ok {
		return 0, false
	}
	key := NormalizerForFormat(ecosystem)(name)
	if key == "" {
		return 0, false
	}
	rank, ok := idx[key]
	return rank, ok
}

// moreEstablishedThanTarget reports whether the CANDIDATE is at least as
// established as the popular name it was matched against — i.e. whether the
// typosquat claim points the wrong way round. Callers DEMOTE such a hit to
// "low"; they do not silence it. See Check.
//
// True when the candidate is on the reviewed download-ranked reference AND
// the target is either absent from it or ranks below the candidate.
//
// THE ABSENT-TARGET ARM IS THE LOAD-BEARING ONE and deserves its own
// justification: it is what clears `json5` → `json3` and `lie` → `li`, whose
// targets are not on the reviewed list at all. Reading "target absent" as
// "target is less established" is safe here precisely because the candidate's
// presence has already been established — the pair is "a package in the
// reviewed top-N of its ecosystem, matched against a name that is not". A
// genuine squat cannot have that shape without the squat itself having
// out-installed its victim.
//
// WHY THIS COSTS NO RECALL. The claim being deleted is "the candidate is
// impersonating the target". If the candidate is the more-installed of the
// two, that claim is false as a matter of fact, whatever the edit distance
// says; the two names really are one apart and the finding stays visible at
// "low" so a reader can see it. What it stops being is a reason to
// QUARANTINE.
//
// APPLIES AT EVERY TIER ABOVE "low", not just "high". The direction argument
// is semantic rather than a tuned threshold, so correcting `high` and
// knowingly leaving `medium` wrong would be arbitrary.
//
// Measured on the production export (7,099 rows), by re-running the real risk
// engine over every affected row:
//
//	high    15 rows → 6 demoted, 9 untouched. The 6 are exactly the
//	        wrong-direction set and all 6 stop flipping warn → quarantine
//	        (4 to allow, 2 to warn). The 9 are exactly the true positives
//	        and none is touched.
//	medium  172 rows → 135 demoted across 30 pairs, 37 untouched. 112 of
//	        the 135 change their overall score and ZERO change verdict —
//	        the three non-allow rows among them (@posthog/core@1.28.0,
//	        eslint-config-next@16.0.4 and @16.1.6) stay `warn` because
//	        another signal's MaxImpact ceiling is binding, not this weight.
//	        So the loosening half is 135 corrected display claims and no
//	        verdict movement at all.
//
// SCOPE, stated so the next reader does not over-credit it. Two neighbouring
// false-positive classes are deliberately NOT addressed:
//
//   - The combosquat floor. `prettier` reported as similar to `ret` and
//     `tailwindcss` to `css` are wrong-direction AND visibly false, but they
//     already sit at "low" and Check's demotion is guarded on
//     `Confidence != "low"`, so this changes nothing for them. Their breadth
//     is checkCombosquat's own deliberate trade (13.0% of benign packages
//     embed some popular name) and correcting it is separate work.
//   - Coincidental short-name collisions. `immer` → `mime` is 10 production
//     rows and is plainly false, but `mime` really is the more-downloaded of
//     the two (#197 vs #807), so the DIRECTION is not what is wrong with it.
//     25 medium rows across 12 pairs are in that class and this check
//     correctly declines to speak to them.
func moreEstablishedThanTarget(ecosystem, candidate, popular string) bool {
	if candidate == "" || popular == "" {
		return false
	}
	candRank, candKnown := establishedRank(ecosystem, candidate)
	if !candKnown {
		return false
	}
	targetRank, targetKnown := establishedRank(ecosystem, popular)
	if !targetKnown {
		return true
	}
	return candRank <= targetRank
}
