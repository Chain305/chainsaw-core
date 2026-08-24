package cli

// benign_fp_eval_test.go — measures the guard's FALSE-BLOCK rate on a corpus of
// real, top-download benign packages. Where detection_lead_eval (package
// intelligence) reports "any own-bytes signal fired" on benign input, this runs
// the actual guard verdict — analyzeArtifact, the exact BLOCK/WARN decision a
// user feels on install — so the published number is "benign top packages that
// would be REFUSED", not merely "flagged".
//
// Corpus: scripts/detection-eval/build-benign-corpus.sh fetches the pinned
// 860-package set (600 npm + 260 pypi top-downloads) into corpus-benign/pkgs.
// Skips when CHAINSAW_DETECTION_EVAL_CORPUS is unset, so CI stays hermetic; the
// size is asserted exactly, so a short or combined corpus reports as a CORPUS
// FAULT rather than as a detector number (see expectBenignCorpusSize).
//
// Run (-count=1 is mandatory — the test cache will replay a stale arm):
//   CHAINSAW_DETECTION_EVAL_CORPUS=scripts/detection-eval/corpus-benign/pkgs \
//     go test ./core/cli/ -run TestBenignFalseBlockRate -v -count=1 -timeout 25m

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type benignSample struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Label     string `json:"label"`
	File      string `json:"file"`
	Fetched   bool   `json:"fetched"`
}

func TestBenignFalseBlockRate(t *testing.T) {
	dir := os.Getenv("CHAINSAW_DETECTION_EVAL_CORPUS")
	if dir == "" {
		t.Skip("set CHAINSAW_DETECTION_EVAL_CORPUS=<dir> with a benign manifest.jsonl")
	}
	f, err := os.Open(filepath.Join(dir, "manifest.jsonl"))
	if err != nil {
		t.Fatalf("open manifest: %v", err)
	}
	defer f.Close()

	var (
		total, blocked, warned int
		byEco                  = map[string]int{}
		blockedEco             = map[string]int{}
		blockedSet, warnedSet  []string
		// blockedKeys is the identity of what was refused, keyed
		// "ecosystem:name" with the version deliberately dropped — the corpus
		// tracks "latest", so pinning versions would turn every routine corpus
		// rebuild into a red build for reasons unrelated to detection. The key
		// is built here rather than parsed back out of the log label: a scoped
		// npm name ("npm:@babel/core@7.1.0") contains two "@" and a Reason
		// string can contain more, so any split of the label is a bug waiting.
		blockedKeys = map[string][]string{}
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var s benignSample
		if json.Unmarshal([]byte(line), &s) != nil || s.Label != "benign" || !s.Fetched || s.File == "" {
			continue
		}
		tgz, err := os.ReadFile(s.File)
		if err != nil || len(tgz) == 0 {
			continue
		}
		total++
		byEco[s.Ecosystem]++
		v := analyzeArtifact(s.Ecosystem, tgz)
		label := s.Ecosystem + ":" + s.Name + "@" + s.Version
		switch {
		case v.Block:
			blocked++
			blockedEco[s.Ecosystem]++
			key := s.Ecosystem + ":" + s.Name
			blockedKeys[key] = append(blockedKeys[key], label+"  ["+v.Reason+"]")
			blockedSet = append(blockedSet, label+"  ["+v.Reason+"]")
		case v.Severity != "":
			warned++
			warnedSet = append(warnedSet, label+"  ["+v.Reason+"]")
		}
	}
	sort.Strings(blockedSet)
	sort.Strings(warnedSet)

	rate := func(n int) float64 {
		if total == 0 {
			return 0
		}
		return 100 * float64(n) / float64(total)
	}
	t.Logf("=== BENIGN FALSE-BLOCK EVAL (guard verdict on real top packages) ===")
	t.Logf("corpus: %d benign packages scanned (%v)", total, byEco)
	t.Logf("FALSE-BLOCK: %d/%d = %.2f%%   (by ecosystem: %v)", blocked, total, rate(blocked), blockedEco)
	t.Logf("soft-WARN:   %d/%d = %.2f%%", warned, total, rate(warned))
	if len(blockedSet) > 0 {
		t.Logf("BLOCKED (false positives — must be 0 for the block claim):\n  %s", strings.Join(blockedSet, "\n  "))
	} else {
		t.Logf("BLOCKED: none — 0 false blocks across %d top packages.", total)
	}
	if len(warnedSet) > 0 {
		t.Logf("WARNED (soft, does not break install):\n  %s", strings.Join(warnedSet, "\n  "))
	}

	// ─── WHAT DECIDES RED/GREEN ─────────────────────────────────────────────
	//
	// Two assertions, in this order:
	//
	//   1. CORPUS IDENTITY — the corpus is the right corpus, or nothing below
	//      it means anything.
	//   2. ACCEPTED FALSE-BLOCK SET — exactly which packages the guard refuses,
	//      by name. Not how many, and not what fraction.
	//
	// Until 2026-08-24 this was a percentage ceiling (maxBenignFalseBlockPct,
	// then 0.59) and it failed at both jobs:
	//
	//   SHRINK: the gate divides by a corpus size that build-benign-corpus.sh
	//   does not reproduce exactly — it truncates manifest.jsonl at start and
	//   appends from twelve parallel workers, and a re-entered build yielded 739
	//   packages instead of 860. The SAME five false blocks read 0.5814% at
	//   n=860 and 0.5903% at n=847, so a 1.4% corpus shrink turned the gate red
	//   with nothing having regressed. A gate that goes red for reasons the
	//   author cannot act on is a gate that gets muted.
	//
	//   GROWTH: worse, because it is silent. Rebuild at 600 npm + 600 pypi and
	//   SEVEN false blocks read 0.583% — under the ceiling. The budget absorbs
	//   two brand-new refused packages, which is precisely the event it was put
	//   there to catch.
	//
	//   DENOMINATOR: and the fraction was never the quantity claimed anyway. 8
	//   of the 860 tarballs (@esbuild/linux-x64, @rollup/rollup-linux-x64-gnu
	//   and -musl, lightningcss-linux-x64-gnu and -musl, node-releases,
	//   @babel/compat-data, @babel/helper-globals) unpack to ZERO source files
	//   and cannot produce an iocscan verdict at all. The published figure was
	//   false blocks per fetched tarball, not per scannable package.
	//
	// This is the doctrine already written down in the sibling file — see the
	// "THIS TEST NEVER FAILS ON A RATE" banner in
	// guard_typosquat_fp_eval_test.go: a threshold assertion "would be bumped
	// the first time it went red and would tell us nothing". The npm-at-zero
	// rail below is the one assertion in THIS file that has never needed tuning,
	// and the accepted set is its generalisation to the whole corpus.
	//
	// ─── THIS IS NOT A RUNTIME ALLOWLIST ────────────────────────────────────
	//
	// It reads like the per-package allowlist that acceptedBenignFalseBlocks'
	// own comment warns against, and it is the opposite of one. It changes
	// NOTHING about what the guard blocks. tqdm still hard-blocks on its
	// documented Telegram progress bar after this change, on every install, for
	// every user. Nothing here is consulted at install time; this file is not
	// even compiled into the binary. What changes is only that the test stops
	// expressing "four known-open cases" as a percentage that happens to round
	// the right way, and states them by name — so a FIFTH one fails the build on
	// its own identity, at any corpus size.
	//
	// 1. CORPUS IDENTITY. A short corpus must report as a CORPUS FAULT and must
	// never be mistakable for a detector result. This, not a percentage floor,
	// is what would have caught the silent 739-package run.
	if total != expectBenignCorpusSize {
		t.Fatalf("CORPUS FAULT: scanned %d benign packages, expected exactly %d — "+
			"rebuild the corpus (scripts/detection-eval/build-benign-corpus.sh) and "+
			"re-run. No detector conclusion can be drawn from this run. "+
			"If you pointed CHAINSAW_DETECTION_EVAL_CORPUS at a COMBINED "+
			"benign+malicious corpus, point it at corpus-benign/pkgs instead — "+
			"TestBlockCatchRate is the test that wants the combined one. "+
			"If the corpus was deliberately regrown, update expectBenignCorpusSize "+
			"and re-derive acceptedBenignFalseBlocks in the same commit.",
			total, expectBenignCorpusSize)
	}

	// 2. ACCEPTED FALSE-BLOCK SET. Any refused package not on the list fails the
	// build BY NAME, whatever the rate says.
	var unexpected []string
	for key, entries := range blockedKeys {
		if !acceptedBenignFalseBlocks[key] {
			unexpected = append(unexpected, entries...)
		}
	}
	sort.Strings(unexpected)
	if len(unexpected) > 0 {
		t.Errorf("NEW false block(s) — %d real top package(s) the guard refuses "+
			"that it did not refuse before:\n  %s\n"+
			"Each is a package a developer cannot install. Either fix the detector, "+
			"or add the name to acceptedBenignFalseBlocks with the reason it is "+
			"correct behaviour.", len(unexpected), strings.Join(unexpected, "\n  "))
	}
	// The reverse direction is good news, so it reports rather than fails: a
	// name on the list that no longer blocks means the list is stale and should
	// be pruned in the next detector commit.
	for key := range acceptedBenignFalseBlocks {
		if len(blockedKeys[key]) == 0 {
			t.Logf("NOTE: %s is on acceptedBenignFalseBlocks but no longer blocks — "+
				"prune it from the list.", key)
		}
	}

	// npm is held to zero separately: it is the largest ecosystem in the
	// corpus and has never produced a false block, so any npm entry is a
	// genuine regression rather than a known-open tuning question.
	if n := blockedEco["npm"]; n > 0 {
		t.Errorf("%d npm false block(s) — npm has been clean at 0; this is a regression, not a budget question", n)
	}

	// 3. BACKSTOP, deliberately loose. maxBenignFalseBlockPct no longer decides
	// red/green — the set above does — and it is set far above the measured
	// 0.47% so it can never fire on corpus drift. It is kept because it catches
	// one thing the set genuinely cannot: growth of the SET ITSELF. The set is
	// edited by hand, and the failure mode of a by-name gate is that someone
	// under deadline pastes a dozen new names into it rather than fixing the
	// detector. Every such paste is invisible to assertion 2 and visible here.
	//
	// It is still a percentage, but no longer over a moving denominator:
	// assertion 1 has already fatal'd unless total is exactly
	// expectBenignCorpusSize, so by the time this line runs the divisor is
	// pinned. That is what makes a percentage safe to keep here at all.
	if got := rate(blocked); got > maxBenignFalseBlockPct {
		t.Errorf("false-block rate %.2f%% exceeds the %.2f%% BACKSTOP (%d/%d). "+
			"This is not a tuning budget — at this level the guard is refusing real "+
			"top packages in bulk. Do not raise it; fix the detector or shrink "+
			"acceptedBenignFalseBlocks.", got, maxBenignFalseBlockPct, blocked, total)
	}
}

const (
	// expectBenignCorpusSize pins the IDENTITY of the corpus, not a floor. See
	// the CORPUS IDENTITY note above: build-benign-corpus.sh appends from twelve
	// parallel workers and a re-entered build silently produced 739 packages on
	// 2026-08-24. A floor ("at least 300") admitted that run and let it be read
	// as a detector result. An exact count cannot be.
	//
	// 860 = 600 npm + 260 pypi, as built by
	// scripts/detection-eval/build-benign-corpus.sh. Change this ONLY together
	// with a re-derived acceptedBenignFalseBlocks, in the same commit.
	expectBenignCorpusSize = 860

	// maxBenignFalseBlockPct is a BACKSTOP, not the gate — see note 3 above. It
	// was the gate until 2026-08-24 at 0.59%, where it both false-failed on a
	// 1.4% corpus shrink and silently absorbed two new false blocks on corpus
	// growth. 1.0% is roughly 2x the measured rate: loose enough that no corpus
	// rebuild can trip it, tight enough to catch a detector (or an over-edited
	// accepted set) refusing packages in bulk.
	//
	// Measured history of the number it backstops, over 860 packages:
	//   2.09% -> 1.05%  narrowed iocscan's credential-store pattern, which was
	//                   matching the English phrase "local state" in comments
	//   1.05% -> 0.81%  downgraded an exfil_host hit to a warning when its only
	//                   evidence is in tests/, docs examples, or vendored code
	//   0.81% -> 0.58%  required exfilHostRE matches to begin at a real host
	//                   boundary (2026-08-24). Several alternatives are bare
	//                   hostnames with nothing to anchor them, so under (?i)
	//                   they matched inside ordinary words: prompt_toolkit's
	//                   "Keys.BracketedPaste." hit `dPaste.`, and litellm's
	//                   deliberately-neutered docstring placeholder
	//                   "nothooks.slack.com" hit `hooks.slack.com/services/`.
	//                   See hostBoundaryOK in core/iocscan/scan.go.
	//   0.58% -> 0.47%  extended that same tests/docs/vendored downgrade to the
	//                   stealer_string tier, which had never consulted it.
	//                   textual blocked on a docs example defining a RichLog
	//                   subclass named KeyLogger. Cost measured at zero on the
	//                   238-sample DataDog corpus: only 2 samples carry a
	//                   stealer string at all and the one that hard-blocks
	//                   (@asyncapi/generator@2.8.6) sits at package/lib/
	//                   generator.js, a shipping path.
	//
	// PAIRED CATCH-RATE for the 0.81% -> 0.58% step, measured on the same
	// 238-sample DataDog corpus with -count=1 (the Go test cache will happily
	// replay a stale arm — check for "(cached)" before trusting an A/B):
	// 105/238 = 44.1% -> 104/238 = 43.7%. The one lost sample is
	// pypi:litellm@1.82.7, and it was blocked on that SAME nothooks.slack.com
	// docstring — boilerplate present in clean litellm releases too. Whatever
	// makes 1.82.7 malicious, the own-bytes scanners never detected it; the
	// block was coincidental. No real detection was traded away.
	maxBenignFalseBlockPct = 1.0
)

// acceptedBenignFalseBlocks is the exact set of real top packages the guard
// currently refuses, keyed "ecosystem:name" with the version dropped because
// the corpus tracks latest. Measured 4/860 on 2026-08-24.
//
// READ THIS BEFORE ADDING A NAME. This is a TEST fixture, not a runtime
// allowlist. Nothing in the guard consults it; every package below still hard-
// blocks on every install for every user. A runtime per-package allowlist is a
// thing an attacker targets — publish under an allowlisted name and walk
// through — and this repo deliberately does not have one. What this list does
// is state, by name, which refusals are already known and argued, so that a
// FIFTH one fails the build on its own identity instead of hiding inside a
// percentage.
//
// Each entry is a judgement that the block is defensible behaviour for a
// supply-chain guard rather than a detector bug:
//
//	pypi:tqdm            ships a documented Telegram progress-bar backend
//	                     (tqdm.contrib.telegram), so api.telegram.org/bot is in
//	                     shipping code by design.
//	pypi:ipython         the %dpaste magic posts to dpaste, from shipping code.
//	pypi:huggingface-hub references webhook.site from shipping code (hf_api.py)
//	                     as the documented endpoint for its webhooks feature.
//	pypi:browser-use     reads browser profile / credential-store paths as its
//	                     entire purpose, coupled with network sends.
//
// Adding a name means asserting the same of it, in writing, here.
var acceptedBenignFalseBlocks = map[string]bool{
	"pypi:tqdm":            true,
	"pypi:ipython":         true,
	"pypi:huggingface-hub": true,
	"pypi:browser-use":     true,
}

// TestBlockCatchRate is the paired half of TestBenignFalseBlockRate: over a
// combined corpus (benign + real malicious, e.g. the DataDog dataset) it reports
// the guard's HARD-BLOCK catch-rate on malware alongside the false-block rate on
// benign — both via the same analyzeArtifact verdict, so the numbers are directly
// comparable ("blocks X% of real malware at Y% false-block"). Offline behavioral
// subset only; the name/feed floor (228k OpenSSF) and server-side
// ioc/import-time providers catch more on top of this.
func TestBlockCatchRate(t *testing.T) {
	dir := os.Getenv("CHAINSAW_DETECTION_EVAL_CORPUS")
	if dir == "" {
		t.Skip("set CHAINSAW_DETECTION_EVAL_CORPUS=<combined benign+malicious corpus>")
	}
	f, err := os.Open(filepath.Join(dir, "manifest.jsonl"))
	if err != nil {
		t.Fatalf("open manifest: %v", err)
	}
	defer f.Close()

	var malTotal, malBlocked, benTotal, benBlocked int
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var s benignSample
		if json.Unmarshal([]byte(line), &s) != nil || !s.Fetched || s.File == "" {
			continue
		}
		tgz, err := os.ReadFile(s.File)
		if err != nil || len(tgz) == 0 {
			continue
		}
		blocked := analyzeArtifact(s.Ecosystem, tgz).Block
		switch s.Label {
		case "malicious":
			malTotal++
			if blocked {
				malBlocked++
			}
		case "benign":
			benTotal++
			if blocked {
				benBlocked++
			}
		}
	}
	pct := func(n, d int) float64 {
		if d == 0 {
			return 0
		}
		return 100 * float64(n) / float64(d)
	}
	t.Logf("=== BLOCK-BASED CATCH vs FP (analyzeArtifact hard-block; offline behavioral subset) ===")
	t.Logf("malware HARD-BLOCK catch: %d/%d = %.1f%%", malBlocked, malTotal, pct(malBlocked, malTotal))
	t.Logf("benign  false-block:      %d/%d = %.2f%%", benBlocked, benTotal, pct(benBlocked, benTotal))
	t.Logf("(offline subset — excludes name/feed floor + server-side ioc/import-time providers)")
}
