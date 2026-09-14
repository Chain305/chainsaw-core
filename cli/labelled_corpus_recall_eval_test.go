package cli

// labelled_corpus_recall_eval_test.go — the RECALL and SIGNAL-COVERAGE half of
// the server-side risk-engine instrument.
//
// ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
//
// server_risk_fp_eval_test.go (its sibling in this package) measures FALSE
// POSITIVES: how often the ~79 signals fire on popular, presumed-good
// packages. That is half a measurement. A pipeline that fires on nothing has a
// perfect false-positive rate and is worthless, and nothing in this repo could
// previously tell you so for the SERVER-side engine:
//
//   - detection_lead_eval_test.go measures the OFFLINE GUARD's own-bytes
//     detectors, and deliberately EXCLUDES the known-malicious lookup path
//     because it is measuring an early-detection moat, not product behaviour.
//   - malicious_corpus_test.go runs SYNTHETIC report shapes and proves only
//     internal consistency; its own header says it "does not prove a
//     real-world detection rate".
//
// So this harness asks the question the public package-intelligence surface
// actually depends on: given a coordinate we KNOW is malicious, does the full
// server-side pipeline say so — lookup path included, because on a public
// product the lookup path is legitimate, not a cheat.
//
// ─── WHAT IT REPORTS ────────────────────────────────────────────────────────
//
//  1. A CONFUSION MATRIX, not a single number. "Recall 91%" hides whether the
//     misses are benign-scored malware or unscannable rows.
//  2. Per-signal precision/recall across the labelled set.
//  3. SIGNAL COVERAGE — which registered signals NO corpus row exercises.
//     This is the number that says how much of the engine the corpus can
//     actually speak to, and it is the one most likely to be embarrassing.
//
// ─── WHAT IT DELIBERATELY DOES NOT DO ───────────────────────────────────────
//
// It does not fail the build on a recall threshold. There is no agreed
// threshold yet, and a number nobody has looked at should not become a gate by
// default — that is how a guard turns into a thing people mute. It fails only
// on CORPUS FAULTS: conditions under which the printed number would be a lie
// (no rows, unreadable seed, zero overlap between seed and scan output).
//
// Run:
//
//	scripts/detection-eval/build-labelled-corpus.sh
//	CHAINSAW_LABELLED_CORPUS=scripts/detection-eval/corpus-labelled/reports.jsonl \
//	  CHAINSAW_LABELLED_SEED=scripts/detection-eval/corpus-seed.tsv \
//	  go test ./core/cli/ -run TestLabelledCorpusRecall -v -count=1

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/risk"
)

type labelledRow struct {
	Eco      string
	Pkg      string
	Ver      string
	Label    string
	Expected []string
}

func labelKey(eco, pkg, ver string) string {
	return strings.ToLower(eco) + "|" + pkg + "|" + ver
}

// readLabelledSeed parses corpus-seed.tsv.
//
// LABELS. Four, not three: `vulnerable` was added 2026-09-14 for the socket.dev
// comparison and means "a published advisory affects this exact version, and no
// advisory calls it malicious". It is deliberately NOT folded into `suspicious`:
// that label measures INFERENCE from registry facts, this one measures ADVISORY
// MATCHING, and merging them would have buried the 10 protestware/deprecation
// rows under 67 CVE rows and invalidated the published suspicious-tier figure.
//
// It parses with explicit field indexing rather than a tab-splitting reader
// loop for a specific reason: the shell's `IFS=$'\t' read` collapses
// consecutive tabs (tab is an IFS whitespace character), which silently
// shifted 15% of generated rows in ingest-ossf.sh on 2026-09-13. Go's
// strings.Split does NOT collapse, so an empty field is visible here — and a
// row whose label does not parse is a CORPUS FAULT, not a row to skip.
func readLabelledSeed(path string) (map[string]labelledRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]labelledRow{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			return nil, fmt.Errorf("line %d: want >=5 tab fields, got %d: %q", ln, len(f), line)
		}
		label := strings.TrimSpace(f[4])
		switch label {
		case "malicious", "suspicious", "vulnerable", "benign":
		default:
			return nil, fmt.Errorf("line %d: bad label %q (row shifted?): %q", ln, label, line)
		}
		var expected []string
		if len(f) >= 6 {
			for _, s := range strings.Split(f[5], ",") {
				s = strings.TrimSpace(s)
				if s != "" && s != "-" && !strings.HasPrefix(s, "#") {
					expected = append(expected, s)
				}
			}
		}
		r := labelledRow{Eco: f[0], Pkg: f[1], Ver: f[2], Label: label, Expected: expected}
		out[labelKey(r.Eco, r.Pkg, r.Ver)] = r
	}
	return out, sc.Err()
}

// verdictIsAdverse reports whether a verdict means "do not just install this".
// The public surface renders five action verdicts; allow is the only one that
// waves a package through.
func verdictIsAdverse(v risk.Verdict) bool {
	switch v {
	case risk.VerdictQuarantine, risk.VerdictReplace, risk.VerdictWarn, risk.VerdictUpgradeAvailable:
		return true
	default:
		return false
	}
}

func TestLabelledCorpusRecall(t *testing.T) {
	corpusPath := os.Getenv("CHAINSAW_LABELLED_CORPUS")
	seedPath := os.Getenv("CHAINSAW_LABELLED_SEED")
	if corpusPath == "" || seedPath == "" {
		t.Skip("set CHAINSAW_LABELLED_CORPUS=<reports.jsonl> and CHAINSAW_LABELLED_SEED=<corpus-seed.tsv> " +
			"(build one with scripts/detection-eval/build-labelled-corpus.sh)")
	}

	seed, err := readLabelledSeed(seedPath)
	if err != nil {
		t.Fatalf("CORPUS FAULT: seed: %v", err)
	}
	if len(seed) == 0 {
		t.Fatal("CORPUS FAULT: seed parsed to zero rows")
	}
	rows, err := readServerRiskCorpus(corpusPath)
	if err != nil {
		t.Fatalf("CORPUS FAULT: %v", err)
	}

	type cell struct{ adverse, allowed, unscored int }
	matrix := map[string]*cell{}
	firedByLabel := map[string]map[string]int{} // label -> signal -> count
	labelTotals := map[string]int{}
	var (
		matched   int
		missedMal []string
		fpBenign  []string
	)
	seenSignals := map[string]bool{}
	// Derived from the corpus, never asserted in a constant: which
	// providers actually RAN on at least one row. A provider absent from
	// every row's ProviderTimings could not have produced its signals, so
	// those signals are "could not fire", not "did not fire" — and the
	// difference is the whole value of a coverage number.
	providersRan := map[string]struct{}{}
	// A provider that RAN is not necessarily a provider that COULD PRODUCE.
	// osv appears in ProviderTimings even when its bundle is absent or
	// empty — it runs, finds no corpus, and emits osv_bundle_dormant. Rows
	// where that happened must not let vuln.* be scored as "the engine
	// stayed quiet"; it is the same could-not-see case as a nil provider,
	// reached one step later.
	//
	// Tracked as "produced on at least one row": a provider is credited the
	// moment ANY row saw it work, so a partially-covered corpus is not
	// written off wholesale.
	providersProduced := map[string]struct{}{}
	malwareProviderRan := false

	for _, r := range rows {
		lr, ok := seed[labelKey(r.Eco, r.Pkg, r.Ver)]
		if !ok {
			// A scanned coordinate with no seed row cannot be graded. Not
			// fatal on its own — the coords file is generated from the seed,
			// so this only happens after a canonicalisation rename — but it
			// must not silently inflate any denominator.
			continue
		}
		matched++
		labelTotals[lr.Label]++
		if matrix[lr.Label] == nil {
			matrix[lr.Label] = &cell{}
		}
		if firedByLabel[lr.Label] == nil {
			firedByLabel[lr.Label] = map[string]int{}
		}

		var rep intelligence.Report
		if err := json.Unmarshal(r.Report, &rep); err != nil {
			matrix[lr.Label].unscored++
			continue
		}
		// Which providers declared themselves unable to produce on THIS row.
		dormantHere := map[string]bool{}
		for _, w := range rep.Observation.Warnings {
			if unavailabilityWarnCodes[w.Code] {
				dormantHere[w.Provider] = true
			}
		}
		for _, pt := range rep.Observation.ProviderTimings {
			providersRan[pt.Provider] = struct{}{}
			if !dormantHere[pt.Provider] {
				providersProduced[pt.Provider] = struct{}{}
			}
			if pt.Provider == "malware" {
				malwareProviderRan = true
			}
		}
		ev := risk.EvaluatePackage(intelligence.ProjectToRiskInput(&rep), risk.Options{})
		if ev == nil {
			matrix[lr.Label].unscored++
			continue
		}

		coord := r.Eco + "/" + r.Pkg + "@" + r.Ver
		switch {
		case ev.Verdict == risk.VerdictUnknown:
			// "Not evaluated" is its own bucket. Counting it as a catch
			// would be the fail-open this repo keeps rediscovering; counting
			// it as a miss would blame the engine for missing data.
			matrix[lr.Label].unscored++
		case verdictIsAdverse(ev.Verdict):
			matrix[lr.Label].adverse++
			if lr.Label == "benign" {
				fpBenign = append(fpBenign, coord+" -> "+string(ev.Verdict))
			}
		default:
			matrix[lr.Label].allowed++
			if lr.Label == "malicious" {
				missedMal = append(missedMal, coord)
			}
		}

		seen := map[string]bool{}
		for _, cat := range ev.DirectScore.Categories {
			for _, fs := range cat.FiredSignals {
				if seen[fs.ID] {
					continue
				}
				seen[fs.ID] = true
				seenSignals[fs.ID] = true
				firedByLabel[lr.Label][fs.ID]++
			}
		}
	}

	if matched == 0 {
		t.Fatalf("CORPUS FAULT: none of the %d scanned rows matched a seed row — "+
			"the corpus and the seed are not describing the same coordinates "+
			"(canonicalisation drift? wrong --out dir?)", len(rows))
	}

	// ─── report ──────────────────────────────────────────────────────────────
	t.Logf("labelled rows scanned and graded: %d of %d seed rows", matched, len(seed))
	t.Log("")
	t.Log("CONFUSION MATRIX  (adverse = quarantine|replace|warn|upgrade_available)")
	t.Logf("  %-11s %8s %8s %9s %8s", "label", "adverse", "allow", "unscored", "total")
	for _, l := range []string{"malicious", "suspicious", "vulnerable", "benign"} {
		c := matrix[l]
		if c == nil {
			c = &cell{}
		}
		t.Logf("  %-11s %8d %8d %9d %8d", l, c.adverse, c.allowed, c.unscored, labelTotals[l])
	}

	// ─── OBSERVABILITY GATE ──────────────────────────────────────────────────
	//
	// READ THIS BEFORE TRUSTING THE RECALL NUMBER BELOW.
	//
	// intelligence.BootstrapConfig documents "Nil disables the malware
	// provider". A corpus scanned WITHOUT CHAINSAW_SERVER_FP_MALWARE_DIR
	// therefore has no malware lookup at all, sc.known_malicious cannot fire
	// on any row, and recall over known-malware coordinates is pinned at 0%
	// BY CONSTRUCTION.
	//
	// The first run of this harness did exactly that and printed
	// "RECALL 0.0%" — which is not a measurement, it is the instrument
	// reporting its own blind spot in the same format as a result. That is
	// the failure server_risk_fp_eval_test.go's OBSERVABILITY section already
	// documents for maint.single_maintainer, and it is worse than having no
	// instrument because the number gets quoted.
	//
	// So dormancy is DERIVED FROM THE CORPUS, not asserted: if the malware
	// provider never appears in any report's ProviderTimings, recall is
	// declared UNOBSERVABLE and no percentage is printed.
	if !malwareProviderRan {
		t.Log("")
		t.Log("RECALL: UNOBSERVABLE for this corpus.")
		t.Log("  The malware provider did not run on ANY row — no report carries a")
		t.Log("  `malware` ProviderTiming — so sc.known_malicious could not fire and")
		t.Log("  a catch-rate here would measure the harness, not the engine.")
		t.Log("  Rebuild with a malware index:")
		t.Log("    CHAINSAW_SERVER_FP_MALWARE_DIR=<ossf/malicious-packages checkout> \\")
		t.Log("      scripts/detection-eval/build-labelled-corpus.sh")
	} else if c := matrix["malicious"]; c != nil {
		gradable := c.adverse + c.allowed
		if gradable > 0 {
			t.Logf("")
			t.Logf("RECALL (malicious, over GRADABLE rows only): %d/%d = %.1f%%",
				c.adverse, gradable, 100*float64(c.adverse)/float64(gradable))
			t.Logf("  %d malicious rows were unscored and are EXCLUDED from that denominator.", c.unscored)
			t.Logf("  Registries unpublish malware, so unscored is expected — but a recall")
			t.Logf("  figure quoted without this line is not the same number.")
		}
	}
	if c := matrix["benign"]; c != nil {
		gradable := c.adverse + c.allowed
		if gradable > 0 {
			t.Logf("")
			t.Logf("FALSE-POSITIVE RATE (benign scored adverse): %d/%d = %.1f%%",
				c.adverse, gradable, 100*float64(c.adverse)/float64(gradable))
		}
	}

	if len(missedMal) > 0 {
		t.Log("")
		t.Logf("MISSED malicious (%d) — scored allow:", len(missedMal))
		sort.Strings(missedMal)
		for _, m := range missedMal {
			t.Logf("  %s", m)
		}
	}
	if len(fpBenign) > 0 {
		t.Log("")
		t.Logf("FALSE POSITIVES on benign (%d):", len(fpBenign))
		sort.Strings(fpBenign)
		for _, m := range fpBenign {
			t.Logf("  %s", m)
		}
	}

	// ─── per-signal discrimination ───────────────────────────────────────────
	t.Log("")
	t.Log("PER-SIGNAL FIRES BY LABEL  (a signal that fires equally on both")
	t.Log("discriminates nothing, however severe it looks)")
	t.Logf("  %-42s %6s %6s %6s %6s", "signal", "mal", "susp", "vuln", "benign")
	var sigs []string
	for s := range seenSignals {
		sigs = append(sigs, s)
	}
	sort.Strings(sigs)
	for _, s := range sigs {
		t.Logf("  %-42s %6d %6d %6d %6d", s,
			firedByLabel["malicious"][s], firedByLabel["suspicious"][s],
			firedByLabel["vulnerable"][s], firedByLabel["benign"][s])
	}

	// ─── signal coverage: the uncomfortable number ───────────────────────────
	all := risk.AllSignals()
	var didNotFire, couldNotFire []string
	for _, sg := range all {
		if seenSignals[sg.ID] {
			continue
		}
		if prov, known := signalProducer(sg.ID); known && !providerRan(providersProduced, prov) {
			why := "never ran"
			if providerRan(providersRan, prov) {
				why = "ran but never produced (dormant/unavailable on every row)"
			}
			couldNotFire = append(couldNotFire,
				fmt.Sprintf("%s (provider %s %s)", sg.ID, strings.Join(prov, "/"), why))
			continue
		}
		didNotFire = append(didNotFire, sg.ID)
	}
	sort.Strings(didNotFire)
	sort.Strings(couldNotFire)

	t.Log("")
	t.Logf("PROVIDERS THAT RAN (%d): %s", len(providersRan), strings.Join(sortedKeys(providersRan), " "))
	t.Logf("SIGNAL COVERAGE: %d of %d registered signals fired on at least one corpus row (%.0f%%)",
		len(seenSignals), len(all), 100*float64(len(seenSignals))/float64(len(all)))
	t.Log("")
	t.Log("The split below is the point. A signal whose PROVIDER never ran could")
	t.Log("not have fired, so counting it as 'did not fire' measures the harness")
	t.Log("rather than the engine — the failure this file's malware-dormancy")
	t.Log("gate already guards for recall.")
	t.Log("")
	t.Logf("COULD NOT FIRE (%d) — provider absent from every row; says NOTHING about the engine:", len(couldNotFire))
	for _, s := range couldNotFire {
		t.Logf("  %s", s)
	}
	t.Logf("DID NOT FIRE (%d) — its provider ran and the signal stayed quiet; this IS about the corpus/engine:", len(didNotFire))
	for _, s := range didNotFire {
		t.Logf("  %s", s)
	}

	// ─── expected_signals, where the seed declares them ──────────────────────
	var expectMiss []string
	for _, r := range rows {
		lr, ok := seed[labelKey(r.Eco, r.Pkg, r.Ver)]
		if !ok || len(lr.Expected) == 0 {
			continue
		}
		var rep intelligence.Report
		if err := json.Unmarshal(r.Report, &rep); err != nil {
			continue
		}
		ev := risk.EvaluatePackage(intelligence.ProjectToRiskInput(&rep), risk.Options{})
		if ev == nil {
			continue
		}
		got := map[string]bool{}
		for _, cat := range ev.DirectScore.Categories {
			for _, fs := range cat.FiredSignals {
				got[fs.ID] = true
			}
		}
		for _, want := range lr.Expected {
			if !got[want] {
				expectMiss = append(expectMiss, fmt.Sprintf("%s/%s@%s expected %s", r.Eco, r.Pkg, r.Ver, want))
			}
		}
	}
	t.Log("")
	if len(expectMiss) == 0 {
		t.Log("EXPECTED-SIGNAL CHECK: every declared expected_signals fired.")
	} else {
		t.Logf("EXPECTED-SIGNAL MISSES (%d) — declared in the seed, did not fire:", len(expectMiss))
		sort.Strings(expectMiss)
		for _, m := range expectMiss {
			t.Logf("  %s", m)
		}
	}
}

// loadMalwareIndexFromDir builds a malware.Index from a local
// ossf/malicious-packages checkout (the `osv/malicious/<eco>/...` tree).
//
// Shared with TestBuildServerRiskCorpus via CHAINSAW_SERVER_FP_MALWARE_DIR.
// It lives here rather than in the FP harness because the RECALL eval is what
// needs it: without a loaded index, sc.known_malicious cannot fire and a
// catch-rate of zero would be an artifact of the instrument.
func loadMalwareIndexFromDir(dir string) (*malware.Index, int, error) {
	// Log to STDERR, not io.Discard.
	//
	// The first version of this function discarded the logger, and that one
	// line cost a whole finding. Index.Load warns when a load carries no
	// floor entries (core/malware/index.go) — the alarm that exists
	// specifically so "an index whose loader forgot the floor is detectable"
	// — and discarding the logger muted it. The eval then reported that the
	// product misses event-stream, which is false: the product merges the
	// floor and blocks it. Only this harness missed it.
	idx := malware.NewIndex(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	var entries []*malware.OSVEntry
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil // a single unreadable advisory must not void the run
		}
		e, parseErr := malware.ParseOSVEntry(data)
		if parseErr != nil || e == nil {
			return nil
		}
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	// MERGE THE FLOOR, exactly as every production loader does:
	// core/malware/sync.go (`entries = append(Floor(), entries...)`) and
	// core/cli/guard_eval.go. Index.Load REPLACES the whole index, so the
	// floor must ride in the SAME Load call — loading it separately first
	// would be silently discarded.
	//
	// Without this the harness measures a configuration production does not
	// run: OSV carries no MAL-* record for event-stream 3.3.6, ua-parser-js,
	// colourama or python3-dateutil (only CWE-506 vulnerability records the
	// malware lane never sees), so a floorless index reports the product
	// missing the most famous supply-chain attacks it actually blocks. That
	// is what the first run of this eval did. See P9F-297.
	entries = append(malware.Floor(), entries...)
	idx.Load(entries)

	// Fail loudly rather than measure a floorless index again. FloorLoaded
	// exists for exactly this check.
	if !idx.FloorLoaded() {
		return nil, 0, fmt.Errorf("malware index loaded without the known-malicious floor — "+
			"the eval would under-report the engine on %d curated incidents", len(malware.Floor()))
	}
	return idx, len(entries), nil
}

// signalProducer maps a signal ID to the ONE provider whose absence makes
// that signal unable to fire, or ("", false) when no single provider gates it.
//
// Deliberately partial and deliberately conservative. Returning ("", false)
// puts a signal in the DID NOT FIRE bucket — the bucket that reflects on the
// corpus — so an unmapped signal is reported as OUR gap, never excused as the
// harness's. The failure mode this file exists to prevent is the opposite:
// quietly writing off a signal as unobservable when it actually ran and stayed
// silent.
//
// Keyed on the ID PREFIX because that is how core/risk/registry_*.go already
// partitions the signal space, so a new signal in an existing family is
// classified correctly without touching this map.
// signalProducer maps a signal to the provider(s) that can make it fire.
//
// ANY-OF, and the slice is not cosmetic. `ai.*` was mapped to the single name
// "aiartifact", which is the REGISTRATION name in premium/register.go, not a
// provider's Name(). The three providers behind those signals return
// "pickle_scan", "model_card" and "agent_tool"
// (premium/provider_aiartifact.go:34,249,334), so providerRan(set,
// "aiartifact") could never be true and all nine ai.* signals were
// PERMANENTLY EXCUSED — including in a build that does link premium. That is
// the exact inverse of the F-1 failure: F-1 blamed the engine for a blind
// lane, this excused a lane that really did run. Both are the map being wrong
// rather than the engine being wrong, which is why the map is now pinned by
// TestSignalProducerNamesAreRealProviders.
func signalProducer(signalID string) ([]string, bool) {
	switch {
	case strings.HasPrefix(signalID, "vuln."):
		// Both the Trivy-backed `cve` provider and `osv` write VulnSection,
		// so neither alone gates these. Report the one that is the federated
		// source; if it never ran, no vulnerability signal could fire.
		return []string{"osv"}, true
	case strings.HasPrefix(signalID, "sc.typosquat"):
		return []string{"typosquat"}, true
	case signalID == "sc.known_malicious", strings.HasPrefix(signalID, "sc.transitive_malware"):
		return []string{"malware"}, true
	case signalID == "sc.provenance_verified", signalID == "sc.signature_verified", signalID == "sc.slsa_level_bonus":
		return []string{"provenance"}, true
	case signalID == "sc.repo_archived", signalID == "sc.repo_missing", signalID == "sc.repo_ownership_mismatch":
		return []string{"repolink"}, true
	case strings.HasPrefix(signalID, "cap."):
		return []string{"capability"}, true
	case strings.HasPrefix(signalID, "ai."):
		return []string{"pickle_scan", "model_card", "agent_tool"}, true
	case signalID == "sc.hidden_unicode":
		return []string{"hiddenunicode"}, true
	case signalID == "sc.install_script_fetches_remote", signalID == "sc.install_script_only":
		return []string{"installscripts"}, true
	case signalID == "sc.manifest_confusion":
		return []string{"manifestconfusion"}, true
	case signalID == "sc.shrinkwrap_present":
		return []string{"shrinkwrap"}, true
	case strings.HasPrefix(signalID, "qual.checksum"):
		return []string{"checksum"}, true
	default:
		// Unmapped => treated as DID NOT FIRE. See the doc comment: the
		// conservative direction is to blame ourselves, not the instrument.
		return nil, false
	}
}

// providerRan reports whether ANY of the named providers appears in a scanned
// row. Any-of, because a signal family can be fed by several providers and one
// of them running is enough for the signal to have had its chance.
func providerRan(set map[string]struct{}, providers []string) bool {
	for _, p := range providers {
		if _, ok := set[p]; ok {
			return true
		}
	}
	return false
}

// readSeedNames reads a one-name-per-line popular-package seed list, using
// the same "what is a name" rule as the shell corpus builders: comments and
// blank lines skipped, bare single-token lines only.
func readSeedNames(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.ContainsAny(line, " \t") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// unavailabilityWarnCodes are the warning codes that mean "this provider ran
// and could not produce", as distinct from "it ran and found nothing".
//
// The distinction is the whole basis of the COULD NOT FIRE / DID NOT FIRE
// split: osv emits osv_bundle_dormant when it has no corpus for the
// coordinate's ecosystem, and counting that as engine silence would report
// all seven vuln.* signals as a finding about the risk engine when it is a
// finding about the harness having no OSV bundle.
var unavailabilityWarnCodes = map[string]bool{
	"osv_bundle_dormant": true,
	"needs_artifact":     true,
	"decode":             true,
	"timeout":            true,
	"transport":          true,
}

// loadMalwareFloorOnly builds a malware index from the EMBEDDED floor alone.
//
// The floor is compiled into the binary (core/malware/seeds/known_malicious.json),
// so this needs no checkout, no network and no disk — which matters on a
// machine where the full OSSF tree is ~1GB and has already caused an ENOSPC
// link failure once this session.
//
// It is a strict subset of what CHAINSAW_SERVER_FP_MALWARE_DIR provides, and
// the caller logs which one is in use so a recall figure can never be quoted
// without knowing which corpus produced it.
func loadMalwareFloorOnly() (*malware.Index, int) {
	idx := malware.NewIndex(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	floor := malware.Floor()
	idx.Load(floor)
	return idx, len(floor)
}

// TestSignalProducerNamesAreRealProviders pins the map against the defect it
// just had: every name in signalProducer must be a value some provider's
// Name() method actually returns.
//
// It cannot verify that by reflection — the premium providers live in the root
// module and core/cli, being chainsaw-core, cannot import them — so it checks
// against a curated list carrying the file:line each name was read from. That
// is weaker than reflection and still catches the failure that occurred: the
// map said "aiartifact", which is the REGISTRATION name in
// premium/register.go:126,130,134, while the providers return "pickle_scan",
// "model_card" and "agent_tool". A name no provider returns can never match a
// ProviderTiming, so every signal mapped to it is permanently excused rather
// than graded — silently, and in every build including one that links premium.
//
// When a provider is renamed, this test fails and the citation says where to
// look. Add the new name here in the same commit.
func TestSignalProducerNamesAreRealProviders(t *testing.T) {
	// value -> where its Name() method is declared
	known := map[string]string{
		// core module
		"osv":               "core/intelligence/provider_osv.go (Name() = \"osv\")",
		"typosquat":         "core/intelligence/provider_typosquat.go",
		"malware":           "core/intelligence/provider_malware.go",
		"provenance":        "core/intelligence/provider_provenance.go",
		"repolink":          "core/intelligence/provider_repolink.go",
		"hiddenunicode":     "core/intelligence/provider_hiddenunicode.go",
		"installscripts":    "core/intelligence/provider_installscripts.go",
		"manifestconfusion": "core/intelligence/provider_manifestconfusion.go",
		"shrinkwrap":        "core/intelligence/provider_shrinkwrap.go",
		"checksum":          "core/intelligence/provider_checksum.go",
		"registrymetadata":  "core/intelligence/provider_registrymetadata.go",
		// premium (root module) — names read from the source, not importable here
		"capability":  "internal/intelligence/premium/provider_capability.go:43",
		"pickle_scan": "internal/intelligence/premium/provider_aiartifact.go:34",
		"model_card":  "internal/intelligence/premium/provider_aiartifact.go:249",
		"agent_tool":  "internal/intelligence/premium/provider_aiartifact.go:334",
		"maintenance": "internal/intelligence/premium/provider_maintenance.go:49",
	}
	// The registration names, which are NOT Name() values. Mapping a signal to
	// one of these is the bug this test exists to prevent.
	forbidden := map[string]string{
		"aiartifact": "registration name in premium/register.go:126,130,134 — the " +
			"providers return pickle_scan / model_card / agent_tool",
	}

	seen := map[string]bool{}
	for _, sg := range risk.AllSignals() {
		provs, ok := signalProducer(sg.ID)
		if !ok {
			continue
		}
		if len(provs) == 0 {
			t.Errorf("signal %q maps to an empty provider list", sg.ID)
			continue
		}
		for _, p := range provs {
			seen[p] = true
			if why, bad := forbidden[p]; bad {
				t.Errorf("signal %q maps to %q, which is not a provider Name(): %s", sg.ID, p, why)
				continue
			}
			if _, ok := known[p]; !ok {
				t.Errorf("signal %q maps to provider %q, which is not in this test's "+
					"known list. Either it is a typo — in which case the signal is "+
					"permanently excused from grading — or a provider was added and "+
					"this list needs the new name plus its file:line.", sg.ID, p)
			}
		}
	}
	t.Logf("signalProducer references %d distinct provider names, all accounted for", len(seen))
}
