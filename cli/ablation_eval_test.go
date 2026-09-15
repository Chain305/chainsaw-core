package cli

// ablation_eval_test.go — the FEEDLESS ABLATION instrument.
//
// ─── THE QUESTION THIS ANSWERS ──────────────────────────────────────────────
//
// docs/socket-comparison-2026-09-15-corpus-v1.md §4 reports malware 600/600
// and immediately disowns it: M1/M2/M3 are drawn from the OpenSSF
// malicious-packages feed that our own malware provider consumes. That number
// is FEED PARITY. It grades us on our own input.
//
// The honest question is the counterfactual: with a feed removed, what would
// the REST of the engine have caught? This file answers it by re-scoring the
// stored corpus with one provider's contribution blanked out of the Report
// before ProjectToRiskInput runs, and reporting the delta.
//
// ─── WHY BLANK A STORED REPORT RATHER THAN RE-SCAN ──────────────────────────
//
// A re-scan per ablation is ~5 minutes of real third-party traffic each, and
// the upstreams move between runs, so the delta would mix "we removed a
// provider" with "npm answered differently today". Blanking a stored Report
// and re-projecting is deterministic, free, and isolates exactly one
// variable. The cost is that it can only ablate providers whose entire
// contribution is a set of Report fields — which is stated per ablation
// below, and which is why the artifact lane is REFUSED rather than faked.
//
// ─── THE TRAP THIS FILE EXISTS INSIDE ───────────────────────────────────────
//
// Three times a published number from this repo has been an artifact of a
// DORMANT provider rather than a property of the product (docs/detection-
// benchmark-purpose.md §7). An ablation harness is the most dangerous possible
// place for that failure, because its output IS a zero: "we removed the feed
// and caught nothing" and "the provider was never wired" produce the same
// table cell.
//
// So every ablation must clear three gates before its row is believed, and a
// row that fails any of them prints DID NOT RUN instead of a number:
//
//	1. LIVENESS.  The provider appears in Report.Observation.ProviderTimings
//	   on at least one row. That field is written by the scanner for every
//	   provider that actually executed, so it is direct evidence of
//	   execution rather than an inference from the output.
//	2. CONTRIBUTION.  The provider wrote at least one POSITIVE fact across
//	   the corpus. A provider that ran and found nothing is a legitimate
//	   measurement (its delta is necessarily zero) but it must be LABELLED
//	   as such, never presented as a detection result.
//	3. REACHABILITY.  Blanking the fields must actually change the
//	   risk.Input the engine sees. This is the guard against a wrong field
//	   mapping: if a future refactor moves MalwareStatus and this file keeps
//	   clearing the old field, gates 1 and 2 still pass and the ablation
//	   silently becomes a no-op reporting "removing the malware feed costs
//	   us nothing". Gate 3 is the only one that catches that.
//
// Plus one gate on the instrument as a whole: BASELINE FIDELITY. Re-projecting
// an UNMODIFIED report must reproduce the verdict the scan persisted. If it
// does not, the re-projection is not the thing that produced the published
// numbers and no delta computed from it means anything.
//
// ─── EXIT CODES ─────────────────────────────────────────────────────────────
//
// exit 0 — every requested ablation was measured.
// exit 1 — ordinary test failure.
// exit 2 — DID NOT RUN. At least one ablation could not be honestly measured,
//          or the instrument failed its own baseline check. Every other row
//          in the printed table still stands; exit 2 is NEVER a pass and is
//          never a claim that the ablated recall was zero.
//
// exit 2 is reached via os.Exit, which skips testing's cleanup on purpose:
// this is a measuring instrument, and the exit code is the part callers read.
//
// ─── RUN ────────────────────────────────────────────────────────────────────
//
//	CHAINSAW_ABLATION_EVAL=1 \
//	CHAINSAW_ABLATION_REPORTS=<path>/corpus-v1/chainsaw/reports.jsonl \
//	CHAINSAW_ABLATION_TRUTH=docs/socket-comparison-2026-09-15-corpus-v1/ground-truth.csv \
//	  go test ./cli/ -run TestFeedlessAblation -v -count=1
//
// `go test` COLLAPSES the exit code: a test binary that exits 2 makes the
// package FAIL and `go test` itself returns 1, so the 2 never reaches the
// caller. To read the exit code the doctrine asks for, run the binary:
//
//	GOTOOLCHAIN=go1.25.8 go test -c -o /tmp/abl.test ./cli/
//	/tmp/abl.test -test.run TestFeedlessAblation -test.v; echo $?   # 0 or 2
//
// Under plain `go test` the DID NOT RUN banner on stderr is the signal and
// exit 1 is the code. Never read either as a pass.
//
// No network. No re-scan. Skips cleanly without the env var so a normal
// `go test` never sees it.

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/risk"
)

// ─── STRATA ─────────────────────────────────────────────────────────────────
//
// Deliberately NOT blended into one recall figure — see
// docs/detection-benchmark-purpose.md §5. Each group answers a different
// question and averaging them reports architecture as detector quality.

var (
	// ablFeedMalware is the stratum group the 600/600 headline comes from,
	// and the one whose independence is in question: every row here is
	// sourced from the same OpenSSF feed our malware provider consumes.
	ablFeedMalware = []string{"M1", "M2", "M3"}
	// ablIdentityMalware is the identity-attack stratum. The corpus-v1
	// report calls T1 "the closest thing to an independent result"; THIS
	// HARNESS DISPROVES THAT. Ablating the OpenSSF index alone takes T1
	// from 100/100 to 1/100, so 99 of its detections are the same feed
	// wearing a different stratum label. Kept as its own group because the
	// contrast is the finding, not because it is independent.
	ablIdentityMalware = []string{"T1"}
	ablVulnerable      = []string{"V1"}
	ablControl         = []string{"V2"}
	// ablBenign is where a detection is a FALSE POSITIVE.
	ablBenign = []string{"B1", "B2", "L1"}
	ablMaint  = []string{"R1"}
)

var ablGroups = []struct {
	name   string
	strata []string
	// fpGroup marks the groups where "detected" is an error, so the table
	// can label the column rather than leaving the reader to infer it.
	fpGroup bool
}{
	{"malware (M1+M2+M3, feed-parity)", ablFeedMalware, false},
	{"malware (T1, identity attack)", ablIdentityMalware, false},
	{"vulnerable (V1)", ablVulnerable, false},
	{"fixed control (V2)", ablControl, true},
	{"maintenance (R1)", ablMaint, false},
	{"benign (B1+B2+L1) — FALSE POSITIVES", ablBenign, true},
}

// ─── ABLATIONS ──────────────────────────────────────────────────────────────

type ablationSpec struct {
	name string
	// provider is the Observation.ProviderTimings name that must appear for
	// this ablation to be measurable at all (gate 1). Several names means
	// "any of these ran".
	providers []string
	// fired reports whether this provider contributed a POSITIVE fact to
	// this report (gate 2).
	fired func(*intelligence.Report) bool
	// apply removes every fact this provider contributed. It must be a pure
	// function of the Report and must not touch any other provider's fields
	// except where the dependency is real and documented (KEV under OSV).
	apply func(*intelligence.Report)
	// why records the honest scope of the removal, printed with the table.
	why string
}

func ablationSpecs() []ablationSpec {
	clearMalware := func(r *intelligence.Report) {
		// A nil MalwareIndex makes registry_providers return a nil malware
		// provider, so no PartialReport carries a malware verdict and the
		// merged section stays at its zero value — an EMPTY status, not
		// "clean". ProjectToRiskInput tests `== "malicious"`, so empty and
		// "clean" project identically; empty is used because it is the
		// state an unwired build actually produces.
		r.SupplyChain.MalwareStatus = ""
		r.SupplyChain.MalwareID = ""
		r.SupplyChain.MalwareSummary = ""
	}
	clearKEV := func(r *intelligence.Report) {
		r.Vulnerabilities.KnownExploited = false
		r.Vulnerabilities.KEVEntries = nil
	}
	clearOSV := func(r *intelligence.Report) {
		// ScannedAt goes too, and that is the whole point of clearing it:
		// it is what ProjectToRiskInput reads for VulnDataAvailable, and a
		// dormant OSV provider leaves it nil (the 2026-09-15 pilot's exact
		// shape — Supports() true, Run() silent, no Vulns partial). Leaving
		// it set would model "scanned and found nothing", which is a
		// DIFFERENT and flattering counterfactual: it tells the rollup the
		// vulnerability category is clean rather than unmeasured.
		r.Vulnerabilities.IsVulnerable = false
		r.Vulnerabilities.CVSSScore = 0
		r.Vulnerabilities.EPSSScore = 0
		r.Vulnerabilities.CVEs = nil
		r.Vulnerabilities.CVEDetails = nil
		r.Vulnerabilities.ClearedCVEs = nil
		r.Vulnerabilities.ScannerDBDigest = ""
		r.Vulnerabilities.ScannedAt = nil
		// KEV is POST-MERGE on the CVE list — provider_kev matches ids that
		// an advisory source already put in the Report. With no advisory
		// source there is nothing for it to match, so leaving KnownExploited
		// set would credit the ablated build with an exploitation fact it
		// could not have derived.
		clearKEV(r)
	}
	clearTyposquat := func(r *intelligence.Report) {
		r.SupplyChain.TyposquatStatus = ""
		r.SupplyChain.TyposquatConfidence = ""
		r.SupplyChain.TyposquatSimilarTo = ""
	}

	specs := []ablationSpec{
		{
			name:      "− OpenSSF malware index",
			providers: []string{"malware"},
			fired: func(r *intelligence.Report) bool {
				return r.SupplyChain.MalwareStatus == "malicious"
			},
			apply: clearMalware,
			why: "clears supplyChain.malware{Status,Id,Summary}. This is the " +
				"ablation the 600/600 headline needs: it removes the feed the " +
				"M strata were SELECTED from.",
		},
		{
			name:      "− OSV bundle (advisory lane)",
			providers: []string{"osv"},
			fired: func(r *intelligence.Report) bool {
				return len(r.Vulnerabilities.CVEs) > 0
			},
			apply: clearOSV,
			why: "clears the whole vulnerabilities section INCLUDING scannedAt " +
				"(so the category reads unmeasured, not clean) and KEV, which " +
				"is derived from the CVE list. NOT INDEPENDENT of the malware " +
				"ablation: OSV ingests ossf/malicious-packages as MAL-* " +
				"advisories, and all 600 malware-stratum rows carry one, so " +
				"the two ablations share an upstream. Do not add their deltas.",
		},
		{
			name:      "− typosquat detector",
			providers: []string{"typosquat"},
			fired: func(r *intelligence.Report) bool {
				return r.SupplyChain.TyposquatStatus == "suspected"
			},
			apply: clearTyposquat,
			why: "clears supplyChain.typosquat{Status,Confidence,SimilarTo}. " +
				"The detector in this build is seeded from npm+pypi popular " +
				"lists only, so its reach is bounded by seeds, not by design.",
		},
		{
			name:      "− KEV catalogue",
			providers: []string{"kev"},
			fired: func(r *intelligence.Report) bool {
				return r.Vulnerabilities.KnownExploited
			},
			apply: clearKEV,
			why:   "clears vulnerabilities.{knownExploited,kevEntries} only.",
		},
		{
			name: "− artifact / behavioural lane",
			// Every byte-bound provider. None of them can run without
			// artifact bytes, and the corpus was built metadata-only.
			providers: []string{
				"codesmell", "capability", "installscripts", "iocscan",
				"pysource", "hiddenunicode", "checksum", "manifestconfusion",
				"manifestconfusion-pypi", "shrinkwrap",
			},
			fired: func(r *intelligence.Report) bool {
				return !reflect.DeepEqual(r.Scan, intelligence.ArtifactScanSection{})
			},
			apply: func(r *intelligence.Report) {
				r.Scan = intelligence.ArtifactScanSection{}
			},
			why: "EXPECTED TO REFUSE. The corpus was scanned without artifact " +
				"bytes, so every byte-bound provider skipped itself with a " +
				"needs_artifact warning. There is nothing to remove, and a " +
				"zero delta here would mean 'the lane was never on', not " +
				"'the lane contributes nothing'.",
		},
	}

	// The combined row is the actual FEEDLESS number: everything an external
	// feed told us, gone at once. Composed from the individual specs so it
	// cannot drift from them.
	specs = append(specs, ablationSpec{
		name:      "− ALL feeds (malware + OSV + KEV + typosquat)",
		providers: []string{"malware", "osv", "kev", "typosquat"},
		fired: func(r *intelligence.Report) bool {
			return r.SupplyChain.MalwareStatus == "malicious" ||
				len(r.Vulnerabilities.CVEs) > 0 ||
				r.Vulnerabilities.KnownExploited ||
				r.SupplyChain.TyposquatStatus == "suspected"
		},
		apply: func(r *intelligence.Report) {
			clearMalware(r)
			clearOSV(r)
			clearTyposquat(r)
		},
		why: "what is left when every external feed is removed and only " +
			"registry-metadata inference remains.",
	})
	return specs
}

// ─── THE HARNESS ────────────────────────────────────────────────────────────

// ablOutcome mirrors socket_comparison_eval_test.go's classification exactly,
// so a row of this table is comparable with a row of §4 of the corpus-v1
// report. Do not "simplify" VerdictUnknown into cleared: a no-opinion is not
// a clear, and folding them would turn every advisory-coverage gap into a
// detection miss.
type ablOutcome int

const (
	ablDetected ablOutcome = iota
	ablCleared
	ablNoOpinion
)

func ablClassify(rep *intelligence.Report) ablOutcome {
	ev := risk.EvaluatePackage(intelligence.ProjectToRiskInput(rep), risk.Options{})
	switch {
	case ev == nil, ev.Verdict == risk.VerdictUnknown:
		return ablNoOpinion
	case verdictIsAdverse(ev.Verdict):
		return ablDetected
	default:
		return ablCleared
	}
}

type ablTally struct{ detected, cleared, noOpinion int }

func (t ablTally) n() int { return t.detected + t.cleared + t.noOpinion }

func (t ablTally) pct() string {
	if t.n() == 0 {
		return "   n/a"
	}
	return fmt.Sprintf("%5.1f%%", 100*float64(t.detected)/float64(t.n()))
}

// ablRefuse prints the DID NOT RUN banner and exits 2. Not t.Fatal: a
// caller reading $? must be able to tell "could not measure" (2) from
// "measured and the assertion failed" (1).
func ablRefuse(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\nABLATION DID NOT RUN (exit 2): "+format+"\n", args...)
	fmt.Fprintf(os.Stderr, "This is NOT a result. Do not read it as a zero.\n")
	os.Exit(2)
}

func TestFeedlessAblation(t *testing.T) {
	if os.Getenv("CHAINSAW_ABLATION_EVAL") == "" {
		t.Skip("feedless ablation instrument; set CHAINSAW_ABLATION_EVAL=1 — see docs/feedless-ablation.md")
	}
	reportsPath := os.Getenv("CHAINSAW_ABLATION_REPORTS")
	truthPath := os.Getenv("CHAINSAW_ABLATION_TRUTH")
	if reportsPath == "" || truthPath == "" {
		ablRefuse("CHAINSAW_ABLATION_REPORTS and CHAINSAW_ABLATION_TRUTH are both required")
	}

	rows, err := readServerRiskCorpus(reportsPath)
	if err != nil {
		ablRefuse("read %s: %v", reportsPath, err)
	}
	if len(rows) == 0 {
		ablRefuse("%s is empty", reportsPath)
	}
	truth, err := readAblationTruth(truthPath)
	if err != nil {
		ablRefuse("read %s: %v", truthPath, err)
	}
	t.Logf("corpus: %d scanned reports · ground truth: %d labelled coordinates", len(rows), len(truth))

	// Decode once. Every ablation works on a fresh copy derived from this
	// raw JSON, so no ablation can leak into the next one.
	type scored struct {
		key     string
		stratum string
		raw     []byte
		base    *intelligence.Report
		baseIn  risk.Input
	}
	var corpus []scored
	var unlabelled []string
	for _, r := range rows {
		key := ablKey(r.Eco, r.Pkg, r.Ver)
		st, ok := truth[key]
		if !ok {
			unlabelled = append(unlabelled, key)
			continue
		}
		var rep intelligence.Report
		if err := json.Unmarshal(r.Report, &rep); err != nil {
			ablRefuse("%s: report will not unmarshal into intelligence.Report: %v", key, err)
		}
		corpus = append(corpus, scored{
			key: key, stratum: st, raw: r.Report,
			base: &rep, baseIn: intelligence.ProjectToRiskInput(&rep),
		})
	}
	if len(unlabelled) > 0 {
		sort.Strings(unlabelled)
		// A partial join divides every recall by the wrong denominator, and
		// it does so QUIETLY — the table still prints plausible percentages.
		ablRefuse("%d scanned coordinate(s) have no ground-truth row, so every "+
			"denominator below would be wrong. First few: %s",
			len(unlabelled), strings.Join(unlabelled[:min(5, len(unlabelled))], ", "))
	}

	// ─── GATE 0: BASELINE FIDELITY ──────────────────────────────────────
	//
	// Re-projecting an untouched report must reproduce the verdict the scan
	// itself persisted. If it does not, this file is not re-scoring the run
	// that produced the published numbers, and no delta from it is a delta
	// FROM those numbers.
	var mismatch []string
	for i, c := range corpus {
		ev := risk.EvaluatePackage(c.baseIn, risk.Options{})
		got := ""
		if ev != nil {
			got = string(ev.Verdict)
		}
		if want := rows[i].Persisted; got != want {
			mismatch = append(mismatch, fmt.Sprintf("%s: persisted=%q reprojected=%q", c.key, want, got))
		}
	}
	if len(mismatch) > 0 {
		sort.Strings(mismatch)
		ablRefuse("baseline re-projection does not reproduce the stored verdict on "+
			"%d of %d rows — the instrument is not measuring the run it claims to. "+
			"First few:\n  %s", len(mismatch), len(corpus),
			strings.Join(mismatch[:min(8, len(mismatch))], "\n  "))
	}
	t.Logf("GATE 0 baseline fidelity: %d/%d re-projected verdicts match the persisted verdict", len(corpus), len(corpus))

	// ─── PROVIDER LIVENESS CENSUS ───────────────────────────────────────
	//
	// Straight off Observation.ProviderTimings, which the scanner writes for
	// every provider that executed. This is the evidence that separates
	// silence from absence, and it is printed whole so a reader can check it
	// rather than trust the conclusion.
	ranOn := map[string]int{}
	skippedNeedsArtifact := map[string]int{}
	for _, c := range corpus {
		for _, pt := range c.base.Observation.ProviderTimings {
			ranOn[pt.Provider]++
		}
		for _, w := range c.base.Observation.Warnings {
			if w.Code == "needs_artifact" {
				skippedNeedsArtifact[w.Provider]++
			}
		}
	}
	t.Log("")
	t.Logf("PROVIDERS THAT RAN (from Observation.ProviderTimings; n=%d rows)", len(corpus))
	for _, p := range ablSortedKeys(ranOn) {
		t.Logf("  %-26s ran on %4d rows", p, ranOn[p])
	}
	if len(skippedNeedsArtifact) > 0 {
		t.Log("PROVIDERS THAT SKIPPED THEMSELVES (needs_artifact — present but never executed)")
		for _, p := range ablSortedKeys(skippedNeedsArtifact) {
			t.Logf("  %-26s skipped on %4d rows", p, skippedNeedsArtifact[p])
		}
	}

	// ─── BASELINE TABLE ─────────────────────────────────────────────────
	base := map[string]ablTally{}
	for _, c := range corpus {
		tl := base[c.stratum]
		ablBump(&tl, ablClassify(c.base))
		base[c.stratum] = tl
	}

	t.Log("")
	t.Log("FULL (no ablation) — reproduces §4 of docs/socket-comparison-2026-09-15-corpus-v1.md")
	ablLogGroups(t, base)

	// ─── EACH ABLATION ──────────────────────────────────────────────────
	refusals := []string{}
	for _, spec := range ablationSpecs() {
		t.Log("")
		t.Logf("═══ %s", spec.name)
		t.Logf("    %s", strings.Join(wrapLines(spec.why, 72, "    "), "\n"))

		// GATE 1 — liveness.
		live := 0
		for _, p := range spec.providers {
			live += ranOn[p]
		}
		if live == 0 {
			t.Logf("    DID NOT RUN — none of %v appears in ProviderTimings on any row.",
				spec.providers)
			t.Logf("    A delta here would be the harness measuring its own wiring. "+
				"(needs_artifact skips recorded for: %v)",
				ablIntersectKeys(skippedNeedsArtifact, spec.providers))
			refusals = append(refusals, spec.name+" (gate 1: provider never executed)")
			continue
		}

		// GATE 2 — contribution. Plus GATE 3 — reachability, measured while
		// applying: how many rows' projected risk.Input actually moved.
		fired, inputChanged := 0, 0
		abl := map[string]ablTally{}
		flips := map[string]int{} // stratum -> detected in full, not detected after
		for _, c := range corpus {
			var rep intelligence.Report
			if err := json.Unmarshal(c.raw, &rep); err != nil {
				ablRefuse("%s: re-unmarshal failed: %v", c.key, err)
			}
			if spec.fired(&rep) {
				fired++
			}
			spec.apply(&rep)
			in := intelligence.ProjectToRiskInput(&rep)
			if !reflect.DeepEqual(in, c.baseIn) {
				inputChanged++
			}
			out := ablClassify(&rep)
			tl := abl[c.stratum]
			ablBump(&tl, out)
			abl[c.stratum] = tl
			if ablClassify(c.base) == ablDetected && out != ablDetected {
				flips[c.stratum]++
			}
		}

		if fired == 0 {
			// Legitimate, but it is a statement about the CORPUS, not about
			// the engine, and it must never be read as a detection result.
			t.Logf("    provider ran on %d rows and contributed 0 positive facts across "+
				"the corpus — the delta below is necessarily zero and measures "+
				"nothing about detection.", live)
			refusals = append(refusals, spec.name+" (gate 2: ran but contributed no facts)")
			ablLogGroups(t, abl)
			continue
		}
		if inputChanged == 0 {
			// The field mapping is wrong. Gates 1 and 2 both passed, so this
			// would otherwise print a confident zero delta.
			ablRefuse("%s: %d rows carry a positive fact from this provider, but blanking "+
				"the fields changed the projected risk.Input on ZERO rows. The field "+
				"mapping in ablationSpecs() no longer reaches ProjectToRiskInput — fix "+
				"the mapping, do not delete this check.", spec.name, fired)
		}
		t.Logf("    gates: provider ran on %d rows · contributed %d positive facts · "+
			"ablation moved the projected Input on %d rows", live, fired, inputChanged)
		ablLogGroups(t, abl)
		if len(flips) > 0 {
			t.Logf("    detections LOST vs full: %s", ablFlipSummary(flips))
		}
	}

	// ─── THE HEADLINE ───────────────────────────────────────────────────
	t.Log("")
	t.Log("READ THIS BEFORE QUOTING ANY CELL")
	t.Log("  · A row marked DID NOT RUN is not a zero. It is an unmeasured lane.")
	t.Log("  · Removing a provider models a build where that provider is absent, not")
	t.Log("    one where it ran and cleared the package. For the advisory lane that")
	t.Log("    distinction is load-bearing: a real build with no advisory source trips")
	t.Log("    the advisory-coverage gate and returns unknown for ecosystems with no")
	t.Log("    other source, so the ablated 'missed' counts here are a FLOOR on what a")
	t.Log("    feedless build would surface, not a prediction of its verdicts.")
	t.Log("  · The ablations are NOT mutually independent. OSV re-publishes")
	t.Log("    ossf/malicious-packages as MAL-* advisories, so the malware feed")
	t.Log("    reaches the engine down two lanes. Deltas do not add; the combined")
	t.Log("    row is the only one that removes the feed entirely.")
	t.Log("  · Corpus selection is not ablatable. M1/M2/M3 rows were CHOSEN because")
	t.Log("    the OpenSSF feed names them; a feedless build would also be facing a")
	t.Log("    different population. The malware recall under − OpenSSF is what our")
	t.Log("    other signals say about coordinates a feed already found, which is a")
	t.Log("    lower bound on independent detection and an upper bound on nothing.")

	if len(refusals) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d ablation(s) could not be honestly measured:\n", len(refusals))
		for _, r := range refusals {
			fmt.Fprintf(os.Stderr, "  · %s\n", r)
		}
		ablRefuse("every other row of the table above stands; these do not")
	}
}

// ─── HELPERS ────────────────────────────────────────────────────────────────

func ablBump(t *ablTally, o ablOutcome) {
	switch o {
	case ablDetected:
		t.detected++
	case ablCleared:
		t.cleared++
	default:
		t.noOpinion++
	}
}

func ablLogGroups(t *testing.T, by map[string]ablTally) {
	t.Helper()
	t.Logf("    %-38s %6s %8s %8s %10s", "group", "n", "detect", "clear", "no-opinion")
	for _, g := range ablGroups {
		var tl ablTally
		for _, s := range g.strata {
			x := by[s]
			tl.detected += x.detected
			tl.cleared += x.cleared
			tl.noOpinion += x.noOpinion
		}
		label := "recall"
		if g.fpGroup {
			label = "FP rate"
		}
		t.Logf("    %-38s %6d %8d %8d %10d   %s %s",
			g.name, tl.n(), tl.detected, tl.cleared, tl.noOpinion, label, tl.pct())
	}
}

func ablFlipSummary(flips map[string]int) string {
	var parts []string
	for _, k := range ablSortedKeys(flips) {
		parts = append(parts, fmt.Sprintf("%s −%d", k, flips[k]))
	}
	return strings.Join(parts, " · ")
}

func ablSortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ablIntersectKeys(m map[string]int, want []string) []string {
	var out []string
	for _, w := range want {
		if n, ok := m[w]; ok {
			out = append(out, fmt.Sprintf("%s=%d", w, n))
		}
	}
	if out == nil {
		return []string{"none"}
	}
	return out
}

func ablKey(eco, pkg, ver string) string {
	return strings.ToLower(eco) + "|" + pkg + "|" + ver
}

// readAblationTruth reads the corpus ground truth into coordinate -> stratum.
// encoding/csv rather than a split on commas: the notes column is quoted and
// contains commas, and a hand-rolled split silently shifts every field after
// it.
func readAblationTruth(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rdr := csv.NewReader(f)
	rdr.FieldsPerRecord = -1
	recs, err := rdr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(recs) < 2 {
		return nil, fmt.Errorf("ground truth has %d record(s)", len(recs))
	}
	col := map[string]int{}
	for i, h := range recs[0] {
		col[strings.TrimSpace(h)] = i
	}
	for _, need := range []string{"ecosystem", "package", "version", "stratum"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("ground truth has no %q column", need)
		}
	}
	out := make(map[string]string, len(recs)-1)
	for _, r := range recs[1:] {
		if len(r) <= col["stratum"] {
			continue
		}
		st := strings.TrimSpace(r[col["stratum"]])
		if st == "" {
			continue
		}
		out[ablKey(r[col["ecosystem"]], r[col["package"]], r[col["version"]])] = st
	}
	return out, nil
}
