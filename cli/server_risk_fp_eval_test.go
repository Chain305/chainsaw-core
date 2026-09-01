package cli

// server_risk_fp_eval_test.go — the FALSE-POSITIVE instrument for the
// SERVER-SIDE risk engine.
//
// ─── THE GAP THIS FILLS ─────────────────────────────────────────────────────
//
// Every eval harness that existed before this one measures the offline guard:
// benign_fp_eval_test.go, guard_eval_test.go, guard_typosquat_{fp,recall}_
// eval_test.go. All four call analyzeArtifact on package BYTES, and
// docs/launch/fp-rate-measurement-2026-08.md states that scope boundary
// outright. There was no false-positive harness for the server-side risk
// engine at all.
//
// The server decides on something the guard never sees: registry METADATA,
// fanned out across the provider set, projected by ProjectToRiskInput and
// scored by the ~76 signals in core/risk. A whole class of defect lives there
// and was invisible to every existing instrument:
//
//   - lic.missing + license.unidentified firing on Apache-2.0 Maven artifacts,
//     because the POM's licence NAME string is read where an SPDX id is
//     expected;
//   - maint.single_maintainer firing on Spring, because it reads the POM's
//     <developers> vanity field;
//   - copyleft counted twice (license.copyleft AND license.non_permissive,
//     both −20).
//
// ─── WHAT A SERVER-SIDE FALSE POSITIVE IS ───────────────────────────────────
//
// This is the design question, and it has a different answer than it does for
// the guard, so it is written down here rather than assumed.
//
// The guard emits a BINARY: block or don't. "False positive" there means "a
// package a developer cannot install", and the unit of measurement is
// obvious. The server emits a verdict, a 0–100 score, and a SET OF FIRED
// SIGNALS — and the verdict is a coarse function of the score, which is a
// weighted rollup over the signals. Every defect above is SIGNAL-level:
// guava, monolog and spring-core all still resolve to `allow` in the 96–99
// band with the licence signals firing. A verdict-level budget would have
// caught NONE of them. Neither would a score-distribution check; a −5 signal
// firing wrongly on 40% of Maven moves the mean by less than rounding.
//
// So: a server-side false positive is A SIGNAL THAT FIRES WHERE ITS OWN CLAIM
// IS UNTRUE — `lic.missing` on a package that declares Apache-2.0.
//
// Per-package ground truth for that does not exist at corpus scale. The
// operational proxy this file uses is: over a corpus of top-download,
// actively-maintained packages, each signal has a maximum plausible FIRE
// RATE, and a signal firing far above it is, by construction, mostly wrong.
// That makes the per-signal fire rate the load-bearing measurement, and it is
// what assertion 2 gates on.
//
// ─── ONE CORRECTION TO THE OBVIOUS DESIGN ───────────────────────────────────
//
// The fire-rate ceiling is keyed on (signal, ECOSYSTEM), not on signal alone.
// This is not a refinement, it is the difference between an instrument that
// works and one that does not. Maven is 70 of 400 rows. `lic.missing` firing
// on 40% of Maven is 7% of the corpus — under any global ceiling loose enough
// to permit the signal's legitimate npm fires. The defects this file exists
// to catch are ECOSYSTEM-SHAPED, because the code that produces them is a
// per-ecosystem reader. Aggregating across ecosystems averages the defect
// away.
//
// ─── EXPLICIT NON-GOAL: VERDICT DISTRIBUTION ────────────────────────────────
//
// Do not add an assertion on the verdict mix ("≤ N% of benign packages may be
// warn/quarantine"). The next reader will reach for it, because it is the
// direct transliteration of the guard's block budget, and it is the wrong
// instrument here for two independent reasons:
//
//  1. It has no power over the defect class. Every defect listed above leaves
//     the verdict at `allow`. A verdict gate reads green while the scoring
//     engine is wrong about most of Maven Central.
//  2. It is not even a false-positive measurement. A benign top package with
//     a real unpatched CVE SHOULD warn. Counting that as a false positive
//     pressures the engine toward silence, which is the opposite of what an
//     FP budget is for.
//
// The verdict IS recorded per row (persisted_verdict) and IS logged, because
// a drift there is worth seeing. It is not gated on.
//
// A second non-goal, recorded so it is a decision rather than an oversight:
// there is no FLOOR on positive-weight signals. `lic.spdx_present` failing to
// fire on Maven is the same defect seen from the other side, and a floor
// would catch it — but a floor is a claim about how much GOOD news a benign
// corpus must carry, which is a different argument needing its own evidence.
// The ceiling on lic.missing already fails the build on that defect. If a
// future defect is only visible as a missing positive, add floors then, with
// the reasoning written here.
//
// ─── RUN ────────────────────────────────────────────────────────────────────
//
//	scripts/detection-eval/build-server-risk-corpus.sh     # network, minutes
//	CHAINSAW_SERVER_FP_CORPUS=scripts/detection-eval/corpus-server-risk/reports.jsonl \
//	  go test ./core/cli/ -run TestServerRiskFalsePositives -v -count=1
//
// or `make server-fp-eval`. Skips cleanly without a corpus, so a fresh
// checkout stays green.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/risk"
)

// serverRiskRow is deliberately the shape core/intelligence/flipcount_prod_test.go
// already consumes via CHAINSAW_FLIP_CORPUS. One production export of
// intelligence_reports therefore feeds BOTH the flip counts and this harness,
// and a corpus built by build-server-risk-corpus.sh can be handed to the flip
// count without conversion. Two instruments reading one file cannot disagree
// about which coordinates they measured.
type serverRiskRow struct {
	Eco       string          `json:"eco"`
	Pkg       string          `json:"pkg"`
	Ver       string          `json:"ver"`
	Persisted string          `json:"persisted_verdict"`
	Report    json.RawMessage `json:"report"`
}

// ─── OBSERVABILITY: WHAT THIS BUILD CANNOT SEE ──────────────────────────────
//
// READ THIS BEFORE TRUSTING ANY ZERO IN THIS FILE'S OUTPUT.
//
// This harness reported `maint.single_maintainer` firing on 0 of 400 benign
// coordinates, including every Spring artifact, and that zero was taken as
// refuting a filed defect. It refuted nothing. The signal CANNOT FIRE HERE AT
// ALL:
//
//	core/cli is part of the PUBLIC core module. Go's internal-package rule
//	means it cannot import internal/intelligence/premium, and
//	`go list -deps -test ./core/cli/` confirms zero references to it. Every
//	Report.Maintenance.* field the risk engine reads is written in exactly
//	one place tree-wide — internal/intelligence/premium/provider_maintenance.go
//	— so in this build MaintainerCount and VersionCount are always 0.
//	maint.single_maintainer requires MaintainerCount == 1
//	(core/risk/registry_maintenance.go:153). Production links premium via
//	the enterprise build tag (cmd/chainsaw-proxy/premium_enterprise.go), so
//	the signal fires there and not here.
//
// A zero from an instrument that cannot see is not a measurement, and printing
// it beside real measurements launders "cannot see" into "measured clean".
// That is a worse failure than having no instrument, because it is trusted.
//
// The second half is nastier and is the reason this gate keys on INPUT FIELDS
// rather than on signals. An absent field does not only silence signals — it
// also disables SUPPRESSION GATES built on it, so a signal can fire MORE.
// maint.very_new_package gates on `VersionCount > 3`
// (registry_maintenance.go:118); with VersionCount pinned at 0 that gate is
// dead, and the harness's first run duly reported it firing on 41% of the top
// PyPI downloads, boto3 included, which was then filed as a new engine defect.
// It is this instrument's own false positive. On production boto3's
// VersionCount is in the hundreds and the signal stays dormant.
//
// So: each probe below names one risk.Input field, how to tell whether it
// carried data, and which signals stop being measurable when it does not —
// split into the ones it FEEDS (they go silent) and the ones it SUPPRESSES
// (they go loud). Whether a field is populated is then DERIVED FROM THE
// CORPUS, not asserted here: if a probe never sees data across every row, its
// signals are declared unobservable for that run. Link premium, or fix the
// producer, and the probe starts seeing data and the gate prunes itself.
//
// Assertion 0 then enforces the only rule that matters: maxFireRate MAY NOT
// CARRY A CEILING FOR AN UNOBSERVABLE SIGNAL, and an unobservable signal that
// fires anyway is a fatal contradiction rather than a curiosity.
type inputProbe struct {
	// Field is the risk.Input field, named as a reader would grep for it.
	Field string
	// HasData reports whether this projection carried a value for the field.
	// "Zero" must mean "not known" for the field to be probeable at all;
	// where the engine cannot distinguish an absent value from a real zero,
	// say so in Why rather than inventing a probe.
	HasData func(risk.Input) bool
	// Feeds are signals that cannot fire while the field is absent.
	Feeds []string
	// Suppresses are signals whose DAMPING gate reads the field, so while it
	// is absent they fire more often than production would. Their rates are
	// inflated, not deflated, and are equally unmeasurable.
	Suppresses []string
	// Why names the producer and the reason it may be missing.
	Why string
}

var serverRiskInputProbes = []inputProbe{
	{
		Field:   "MaintainerCount",
		HasData: func(in risk.Input) bool { return in.MaintainerCount != 0 },
		Feeds:   []string{"maint.single_maintainer"},
		Why: "Written only by internal/intelligence/premium/provider_maintenance.go:80 " +
			"(len(People.Maintainers)). Absent whenever the premium provider set is not " +
			"linked — which core/cli structurally cannot do.",
	},
	{
		Field:      "VersionCount",
		HasData:    func(in risk.Input) bool { return in.VersionCount != 0 },
		Feeds:      []string{"maint.healthy_cadence"},
		Suppresses: []string{"maint.very_new_package"},
		Why: "Written only by premium/provider_maintenance.go:117,141. Its absence makes " +
			"maint.very_new_package's `VersionCount > 3` guard a no-op, so that signal's " +
			"rate here is INFLATED, not deflated.",
	},
	{
		Field:   "LatestReleaseAt",
		HasData: func(in risk.Input) bool { return in.LatestReleaseAt != nil },
		Feeds:   []string{"maint.no_recent_release", "maint.healthy_cadence"},
		Why:     "Written only by premium/provider_maintenance.go:104,128,146.",
	},
	{
		Field:   "LastRepoCommitAt",
		HasData: func(in risk.Input) bool { return in.LastRepoCommitAt != nil },
		Feeds:   []string{"maint.abandoned_repo"},
		Why: "Written only by premium/provider_maintenance.go:91, which copies it from " +
			"the core repolink provider's SupplyChain output. The core provider alone " +
			"does not reach risk.Input.",
	},
	{
		Field:   "WeeklyDownloads",
		HasData: func(in risk.Input) bool { return in.WeeklyDownloads != nil },
		Feeds:   []string{"maint.unpopular_package"},
		Why:     "Written only by premium/provider_weekly_downloads.go.",
	},
	{
		Field:   "MaintainerAccountAgeDays",
		HasData: func(in risk.Input) bool { return in.MaintainerAccountAgeDays != 0 },
		Feeds: []string{
			"sc.maintainer_account_very_young",
			"sc.maintainer_account_young",
			"sc.maintainer_account_somewhat_young",
		},
		Why: "Written only by premium/provider_wave4_maintainer_age.go, which is " +
			"additionally feature-flagged per ecosystem. All three age tiers read this " +
			"one field and all three are gated on `<= 0 = unknown`.",
	},
}

// ─── DECLARED CORPUS ────────────────────────────────────────────────────────

// expectServerRiskCorpus pins the IDENTITY of the corpus per ecosystem, not a
// floor, for exactly the reason benign_fp_eval_test.go pins its 860: a rate
// divided by a denominator that drifts is a number nobody can act on. It
// stopped being a floor there on 2026-08-24 after a re-entered corpus build
// silently produced 739 packages instead of 860 and the percentage gate went
// red with nothing regressed.
//
// Here the stakes are higher, because the denominators are PER ECOSYSTEM and
// small. Sixty composer rows means one fire is 1.67%. If a build resolves 58,
// every composer ceiling in the table below is being read against the wrong
// divisor. So the counts are asserted per ecosystem, not just in total.
//
// Change these ONLY together with a re-derived maxFireRate table, in the same
// commit, and re-run the build.
var expectServerRiskCorpus = map[string]int{
	"npm":      100,
	"pypi":     100,
	"maven":    70,
	"composer": 60,
	"go":       70,
}

// ─── ASSERTION 2: PER-(SIGNAL, ECOSYSTEM) FIRE-RATE CEILING ─────────────────
//
// THIS IS THE LOAD-BEARING ASSERTION. Everything else in this file is a
// guardrail around it.
//
// Each entry declares: on a corpus of top-download benign packages in this
// ecosystem, this signal may fire on at most this fraction of them, and here
// is why that number and not zero.
//
// A (signal, ecosystem) pair that fires and is NOT in this table FAILS THE
// BUILD BY NAME. That is deliberate and it is the same doctrine as
// acceptedBenignFalseBlocks in benign_fp_eval_test.go: a negative signal
// firing on a top-download package is a claim about that package, and an
// undeclared claim is the event we want to hear about. It is also why this
// table is allowed to be long — length here is knowledge, and the backstop in
// assertion 4 is what watches it for bulk growth.
//
// A percentage is safe as a gate ONLY because assertion 1 has already fatal'd
// unless the per-ecosystem denominators are exactly the declared ones. Under a
// moving denominator these numbers would be the same trap the guard harness
// removed.
//
// THIS IS NOT A RUNTIME ALLOWLIST. Nothing in the risk engine consults this
// table; this file is not compiled into any binary. Every signal below still
// fires, on every scan, for every user. What the table states is which fires
// are already known and argued, so a new one fails on its own identity.
type sigEco struct {
	Signal    string
	Ecosystem string
}

type fireCeiling struct {
	// MaxPct is the fraction of this ecosystem's benign rows the signal may
	// fire on, as a percentage.
	MaxPct float64
	// Why must say why the signal legitimately fires at all, and why this
	// number. "Observed at X%" is not a reason; it is a measurement. An entry
	// whose Why is only a measurement is an entry nobody has argued.
	Why string
}

// defectBaseline marks a ceiling that is NOT a claim about how the world is.
// It is the measured size of a KNOWN DEFECT, recorded so the gate is usable
// today and so any WORSENING fails the build. Lowering the number is the
// acceptance test for the fix. Every such entry names the defect.
const defectBaseline = "DEFECT BASELINE — "

var maxFireRate = map[sigEco]fireCeiling{
	// ── lic.missing (−15) — "package does not declare a license" ──────────
	//
	// The single largest finding this instrument produced on its first run.
	// Every named example below ships an unambiguous OSI licence:
	// com.google.guava:guava is Apache-2.0, monolog/monolog is MIT,
	// ch.qos.logback:* is EPL-1.0/LGPL-2.1. The engine says they declare
	// nothing.
	{"lic.missing", "maven"}: {42, defectBaseline + "P8-06. 25/70 Apache-2.0 and EPL " +
		"artifacts read as unlicensed: the POM's <licenses><name> is a human string " +
		"(\"Apache License, Version 2.0\"), not an SPDX id, and the reader wants an id. " +
		"True value is near zero."},
	{"lic.missing", "composer"}: {65, defectBaseline + "P8-06, same root cause on the " +
		"packagist reader. 35/60, including monolog/monolog (MIT) and the whole " +
		"doctrine/* and sebastian/* families."},
	{"lic.missing", "go"}: {24, defectBaseline + "P8-06, same root cause on the module " +
		"reader. The Go module proxy exposes no licence field at all for many modules, " +
		"so part of this is a genuine data gap rather than a misread — but go-spew " +
		"(ISC) and fatih/color (MIT) publish one, so it is not all gap."},
	{"lic.missing", "pypi"}: {11, defectBaseline + "P8-06 residual. jinja2 (BSD-3-Clause) " +
		"and colorama (BSD-3-Clause) both declare licences via classifiers the reader " +
		"does not consult."},
	{"lic.missing", "npm"}: {5, "npm is the reader that mostly works — 2/100 versus 35/70 " +
		"on Maven. Both fires (react-is, fs-extra) are MIT-licensed, so this is a small " +
		"residual of the same defect and not a floor. Held near zero deliberately: npm is " +
		"the ecosystem with the best metadata, so it is where a regression shows first."},

	// ── license.unidentified (−15) — "licence string not recognised" ──────
	//
	// Fires alongside lic.missing on the same coordinates, so a mis-read POM
	// costs −30, not −15. That double charge is the reason a licence-reader
	// bug moves scores at all.
	{"license.unidentified", "maven"}: {88, defectBaseline + "P8-06. 58/70 — the worst " +
		"single number this harness measures. spring-core fires BOTH lic.spdx_present " +
		"AND license.unidentified on the same report, which is a self-contradiction the " +
		"engine currently emits with a straight face."},
	{"license.unidentified", "composer"}: {65, defectBaseline + "P8-06, co-fires 1:1 with " +
		"lic.missing on composer — same 35 coordinates."},
	{"license.unidentified", "go"}: {24, defectBaseline + "P8-06, co-fires 1:1 with " +
		"lic.missing on go — same 13 coordinates."},
	{"license.unidentified", "pypi"}: {28, defectBaseline + "P8-06. 23/100, more than three " +
		"times the pypi lic.missing rate, so this arm has failure modes of its own: " +
		"beautifulsoup4 and aiosignal declare licences the classifier does not resolve."},
	{"license.unidentified", "npm"}: {5, "Same two npm coordinates as lic.missing. Held near " +
		"zero for the same reason."},

	// ── license.ambiguous_classifier (−10) ────────────────────────────────
	//
	// This one is largely CORRECT and is here to show the contrast: a signal
	// firing at single digits on a benign corpus looks like a signal, not
	// like a reader bug.
	{"license.ambiguous_classifier", "pypi"}: {11, "Legitimate. PyPI classifiers genuinely " +
		"carry unversioned strings (\"Apache Software License\", \"BSD License\") that do " +
		"not resolve to one SPDX id. cryptography really is dual Apache-2.0/BSD-3-Clause."},
	{"license.ambiguous_classifier", "go"}: {13, "Legitimate, same shape: testify and " +
		"prometheus/client_golang expose licence text rather than an id."},
	{"license.ambiguous_classifier", "npm"}: {4, "Legitimate and rare — 1/100."},

	// ── license.copyleft / license.non_permissive (−20 each) ──────────────
	//
	// These fire on IDENTICAL coordinate sets in both ecosystems where they
	// fire at all: hashicorp/go-multierror + hashicorp/hcl (MPL-2.0) on go,
	// certifi + tqdm (MPL-2.0) on pypi. 100% co-fire, −40 for one licence.
	// The classification itself is right; charging for it twice is not.
	{"license.copyleft", "go"}: {6, "Legitimate classification — both are MPL-2.0. But see " +
		defectBaseline + "the double-count: license.non_permissive fires on the same two " +
		"coordinates for the same reason, so MPL-2.0 costs −40."},
	{"license.copyleft", "pypi"}: {5, "Legitimate classification — certifi and tqdm are " +
		"MPL-2.0. Same double-count as above."},
	// NEW on 2026-08-25 (Wave D), and it is a signal APPEARING because a
	// false NEGATIVE was closed, not a regression. Maven POMs carry the
	// licence NAME, and "Eclipse Public License v2.0" / "MPL 2.0" / "EPL
	// 2.0" / "Eclipse Public License 1.0" all failed a strict SPDX parse and
	// came back license.unidentified. They are genuine weak copyleft, so no
	// license.copyleft tag reached core/policy and an operator's copyleft
	// block rule could not fire on them. Now that names normalise, these
	// five classify correctly: h2database (EPL-1.0 / MPL-2.0 dual),
	// junit (EPL-1.0), jakarta.annotation-api (EPL-2.0) and two more.
	// NOT a defect baseline — the claim is TRUE and the -10 weak-copyleft
	// weight is what it should cost.
	{"license.copyleft", "maven"}: {10, "Legitimate classification, newly VISIBLE. These five " +
		"artifacts declare EPL/MPL as a licence NAME rather than an SPDX id; before the " +
		"name normalisation they were reported merely 'unidentified', which is a false " +
		"negative on a real copyleft dependency. Weak copyleft, -10."},
	{"license.non_permissive", "go"}: {6, defectBaseline + "the copyleft double-count. This " +
		"signal fires on exactly the coordinates license.copyleft fires on, adding a " +
		"second −20 for one licence fact. Measured co-fire: 2/2."},
	{"license.non_permissive", "pypi"}: {5, defectBaseline + "the copyleft double-count. " +
		"Measured co-fire: 2/2."},
	{"license.exception_present", "pypi"}: {6, "Legitimate — pandas, scipy and sglang carry " +
		"licences with exception clauses, which is what the signal says. −5, info severity."},

	// ── maint.very_new_package — DELETED, and the deletion is the point ───
	//
	// The 2026-08-25 first run declared four ceilings here (pypi 47, go 27,
	// npm 24, composer 22) off a measured 41% of the top PyPI downloads,
	// boto3 among them, and filed it as a new engine defect "not previously
	// on any Phase 8 list". It was this instrument's own false positive.
	//
	// The signal gates on `VersionCount > VeryNewPackageMaxVersions` (registry_maintenance.go:118).
	// VersionCount is written only by the premium maintenance provider, which
	// this build cannot link, so it is pinned at 0 and the guard never fires.
	// Production, which links premium, sees boto3's VersionCount in the
	// hundreds and the signal stays dormant.
	//
	// It has no ceiling now because assertion 0 REFUSES one: a rate measured
	// through a dead suppression gate is not a rate. Do not restore these
	// four lines to make a run green — restore them only after the probe for
	// VersionCount reports data, at which point assertion 0 stops objecting
	// on its own.

	// ── supply chain ──────────────────────────────────────────────────────
	{"sc.install_script_only", "npm"}: {4, "Legitimate and rare — 1/100. An npm package may " +
		"have an install script and nothing else remarkable; that is exactly what this " +
		"low-weight (−5) signal is for."},
}

// ─── ASSERTION 3: ACCEPTED (SIGNAL, COORDINATE) SET ─────────────────────────
//
// Direct transliteration of acceptedBenignFalseBlocks, restricted to the
// signals that carry HIGH or CRITICAL severity.
//
// Why restricted, when the guard's list is not: the guard's list covers
// BLOCKS, which are already the rare, individually-arguable event — four
// entries over 860 packages. Here every row fires two or three signals, so a
// (signal, coordinate) list over ALL fires would be ~1,000 entries, which is a
// data dump, not a set of judgements. High/critical is the honest analogue:
// those are the signals that on their own justify refusing a package, so one
// firing on a top-download package deserves a name and a written reason, the
// same way a block does.
//
// Note this is a SEVERITY test, not a verdict test — see the non-goal above.
// Severity is a property the signal declares about itself in core/risk;
// nothing here reads Evaluation.Verdict.
//
// Keyed (signal, "eco:name") with the version dropped, because the corpus
// tracks each package's current release and pinning versions would turn every
// routine rebuild into a red build for reasons unrelated to scoring.
type sigCoord struct {
	Signal string
	// Coord is "ecosystem:name" with the version dropped.
	Coord string
}

// The map value is the WRITTEN REASON the fire is correct behaviour, in the
// same spirit as the per-entry justifications above acceptedBenignFalseBlocks.
// Adding a name means asserting that reason, in writing, here.
//
// It ships EMPTY: measured 0/400 on 2026-08-25 — no high- or critical-severity
// signal fired on any of the 400 benign top-download coordinates. That is a
// result, not an omission, and it means the first entry anyone adds is a real
// event.
var acceptedServerRiskFires = map[sigCoord]string{}

// maxNegativeSignalsPerPackage is a BACKSTOP, deliberately loose. It is not
// the gate — assertions 2 and 3 are.
//
// It exists because the failure mode of a by-name table is that someone under
// deadline pastes a dozen new ceilings into maxFireRate rather than fixing the
// reader that produced them. Every such paste is invisible to assertion 2, by
// construction, and visible here: the mean number of negative-weight signals
// firing per benign top-download package. A scoring engine that is right about
// benign packages fires few; one that has been argued into permitting
// everything fires many.
//
// Like the guard's maxBenignFalseBlockPct, it sits well above the measured
// value so no corpus rebuild can trip it, and it divides by a denominator
// assertion 1 has already pinned.
const maxNegativeSignalsPerPackage = 3.0

// ─── THE HARNESS ────────────────────────────────────────────────────────────

func TestServerRiskFalsePositives(t *testing.T) {
	path := os.Getenv("CHAINSAW_SERVER_FP_CORPUS")
	if path == "" {
		t.Skipf("set CHAINSAW_SERVER_FP_CORPUS=<reports.jsonl> " +
			"(build one with scripts/detection-eval/build-server-risk-corpus.sh, " +
			"or point it at a production intelligence_reports export — the row " +
			"shape is the same one CHAINSAW_FLIP_CORPUS takes)")
	}
	rows, err := readServerRiskCorpus(path)
	if err != nil {
		t.Fatalf("CORPUS FAULT: %v", err)
	}

	var (
		byEco       = map[string]int{}
		fires       = map[sigEco]int{}
		fireCoords  = map[sigEco][]string{}
		sigSeverity = map[string]risk.Severity{}
		sigWeight   = map[string]float64{}
		verdicts    = map[string]int{}
		unknownRows []string
		negFires    int
		total       int
		// probeSeen[i] counts the rows on which probe i's field carried
		// data. A probe that ends at zero means the field is unpopulated in
		// this build, which makes its signals unmeasurable — see assertion 0.
		probeSeen = make([]int, len(serverRiskInputProbes))
	)

	for _, r := range rows {
		var rep intelligence.Report
		if err := json.Unmarshal(r.Report, &rep); err != nil {
			t.Fatalf("CORPUS FAULT: %s:%s@%s report will not unmarshal: %v",
				r.Eco, r.Pkg, r.Ver, err)
		}
		in := intelligence.ProjectToRiskInput(&rep)
		for i := range serverRiskInputProbes {
			if serverRiskInputProbes[i].HasData(in) {
				probeSeen[i]++
			}
		}
		ev := risk.EvaluatePackage(in, risk.Options{})
		if ev == nil {
			t.Fatalf("CORPUS FAULT: %s:%s@%s evaluated to nil", r.Eco, r.Pkg, r.Ver)
		}
		coord := r.Eco + ":" + r.Pkg
		total++
		byEco[r.Eco]++
		verdicts[string(ev.Verdict)]++
		if ev.Verdict == risk.VerdictUnknown {
			// Not a detector result. An unknown verdict means the facts were
			// unavailable, so its signals mostly did not fire — every fire
			// rate computed over it is deflated by a row that measured
			// nothing. Collected and fatal'd in assertion 1.
			unknownRows = append(unknownRows, coord+"@"+r.Ver)
		}

		// A signal appears once per evaluation; dedupe defensively across
		// categories so a future rollup change cannot double-count a fire
		// into a rate.
		seen := map[string]bool{}
		for _, cat := range ev.DirectScore.Categories {
			for _, fs := range cat.FiredSignals {
				if seen[fs.ID] {
					continue
				}
				seen[fs.ID] = true
				key := sigEco{Signal: fs.ID, Ecosystem: r.Eco}
				fires[key]++
				fireCoords[key] = append(fireCoords[key], coord)
				sigSeverity[fs.ID] = fs.Severity
				sigWeight[fs.ID] = fs.Weight
				if fs.Weight < 0 {
					negFires++
				}
			}
		}
	}

	// ─── REPORT (always, before any assertion) ─────────────────────────────
	rate := func(n, d int) float64 {
		if d == 0 {
			return 0
		}
		return 100 * float64(n) / float64(d)
	}
	t.Logf("=== SERVER-SIDE RISK-ENGINE FALSE-POSITIVE EVAL ===")
	t.Logf("corpus: %d benign coordinates (%v)", total, byEco)
	t.Logf("verdicts: %v   (LOGGED, NOT GATED — see the non-goal note in this file)", verdicts)
	t.Logf("mean negative-weight signals per package: %.2f", float64(negFires)/float64(max(total, 1)))
	t.Logf("--- per-(signal, ecosystem) fire rate on BENIGN top packages ---")
	keys := make([]sigEco, 0, len(fires))
	for k := range fires {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Signal != keys[j].Signal {
			return keys[i].Signal < keys[j].Signal
		}
		return keys[i].Ecosystem < keys[j].Ecosystem
	})
	for _, k := range keys {
		t.Logf("  %-34s %-9s %3d/%-3d = %6.2f%%  (w=%+.0f sev=%s)",
			k.Signal, k.Ecosystem, fires[k], byEco[k.Ecosystem],
			rate(fires[k], byEco[k.Ecosystem]), sigWeight[k.Signal], sigSeverity[k.Signal])
	}

	// ─── 0. OBSERVABILITY ──────────────────────────────────────────────────
	//
	// Runs FIRST and fatals, because every number printed above is only worth
	// reading once you know which of them this build was capable of producing.
	unobservable := map[string]string{} // signal -> why it cannot be measured
	var blindProbes []string
	for i, p := range serverRiskInputProbes {
		if probeSeen[i] > 0 {
			continue
		}
		blindProbes = append(blindProbes, fmt.Sprintf(
			"risk.Input.%s — 0/%d rows carried data. %s", p.Field, total, p.Why))
		for _, s := range p.Feeds {
			unobservable[s] = fmt.Sprintf(
				"cannot fire: it reads risk.Input.%s, unpopulated on all %d rows", p.Field, total)
		}
		for _, s := range p.Suppresses {
			unobservable[s] = fmt.Sprintf(
				"rate is INFLATED: its suppression gate reads risk.Input.%s, "+
					"unpopulated on all %d rows, so the gate is dead", p.Field, total)
		}
	}
	if len(blindProbes) > 0 {
		sort.Strings(blindProbes)
		blind := make([]string, 0, len(unobservable))
		for s, why := range unobservable {
			blind = append(blind, fmt.Sprintf("  %-38s %s", s, why))
		}
		sort.Strings(blind)
		t.Logf("!!! BLIND SPOT — this build cannot measure %d signal(s). "+
			"A 0.00%% for any of them below is NOT a result:\n%s\nUnpopulated inputs:\n  %s",
			len(unobservable), strings.Join(blind, "\n"), strings.Join(blindProbes, "\n  "))
	}
	// The gate. A ceiling is a written claim that a rate was measured and
	// argued; declaring one for a signal this build cannot observe records a
	// measurement that did not happen.
	var blindCeilings []string
	for k := range maxFireRate {
		if why, blind := unobservable[k.Signal]; blind {
			blindCeilings = append(blindCeilings, fmt.Sprintf("%s/%s — %s", k.Signal, k.Ecosystem, why))
		}
	}
	if len(blindCeilings) > 0 {
		sort.Strings(blindCeilings)
		t.Fatalf("UNOBSERVABLE CEILING(S) DECLARED — %d. maxFireRate claims a measured "+
			"rate for signal(s) this build cannot measure:\n  %s\n"+
			"Delete the entries, or make the input observable (link the provider that "+
			"writes it). Do NOT record a rate read through a dead input: that is how "+
			"`maint.single_maintainer: 0.00%%` came to be read as refuting a real defect.",
			len(blindCeilings), strings.Join(blindCeilings, "\n  "))
	}
	// The self-check. If a signal declared unobservable fires anyway, the
	// probe table is wrong — and a wrong blind-spot table is more dangerous
	// than none, because it excuses real fires.
	var contradictions []string
	for _, k := range keys {
		if _, blind := unobservable[k.Signal]; !blind {
			continue
		}
		if strings.HasPrefix(unobservable[k.Signal], "rate is INFLATED") {
			continue // expected to fire; that is the whole point of that class
		}
		contradictions = append(contradictions, fmt.Sprintf("%s on %s fired %d time(s) — %s",
			k.Signal, k.Ecosystem, fires[k], unobservable[k.Signal]))
	}
	if len(contradictions) > 0 {
		sort.Strings(contradictions)
		t.Fatalf("BLIND-SPOT TABLE IS WRONG — %d signal(s) declared unobservable fired "+
			"anyway:\n  %s\nserverRiskInputProbes maps the wrong field, or the signal has "+
			"a second input. Fix the table before reading any rate from this run.",
			len(contradictions), strings.Join(contradictions, "\n  "))
	}

	// ─── 1. CORPUS IDENTITY ────────────────────────────────────────────────
	// The corpus is the right corpus, or nothing below it means anything.
	// t.Fatalf, not t.Errorf: a wrong denominator must not be mistakable for
	// a detector result.
	for eco, want := range expectServerRiskCorpus {
		if byEco[eco] != want {
			t.Fatalf("CORPUS FAULT: %s has %d rows, expected exactly %d. "+
				"Rebuild with scripts/detection-eval/build-server-risk-corpus.sh. "+
				"No fire rate can be read from this run: every %s ceiling in "+
				"maxFireRate divides by %d. If the corpus was deliberately "+
				"resized, update expectServerRiskCorpus AND re-derive the "+
				"ceilings in the same commit.",
				eco, byEco[eco], want, eco, want)
		}
	}
	for eco, n := range byEco {
		if _, ok := expectServerRiskCorpus[eco]; !ok {
			t.Fatalf("CORPUS FAULT: %d rows from undeclared ecosystem %q. "+
				"Add it to expectServerRiskCorpus with its own ceilings, or "+
				"point CHAINSAW_SERVER_FP_CORPUS at the right file.", n, eco)
		}
	}
	if len(unknownRows) > 0 {
		sort.Strings(unknownRows)
		t.Fatalf("CORPUS FAULT: %d row(s) evaluated to verdict `unknown` — the "+
			"facts were unavailable, so these rows measured nothing and deflate "+
			"every rate they sit in:\n  %s\nRe-resolve them (the version may have "+
			"been yanked) or drop them from the seed and re-derive the counts.",
			len(unknownRows), strings.Join(unknownRows, "\n  "))
	}

	// ─── 2. PER-(SIGNAL, ECOSYSTEM) FIRE-RATE CEILING ──────────────────────
	var overCeiling, undeclared []string
	baselineCount := 0
	for _, k := range keys {
		// Positive-weight signals are GOOD NEWS. A ceiling on lic.spdx_present
		// would mean "at most this many of your packages may declare a
		// licence", which is not a sentence anyone wants to defend. The
		// mirror-image assertion for those is a FLOOR, and the header records
		// why this file deliberately does not have one yet.
		if sigWeight[k.Signal] >= 0 {
			continue
		}
		// Assertion 0 has already ruled on these: this build cannot measure
		// them, and it FATALS if anyone declares a ceiling for one. Demanding
		// a ceiling here as well would deadlock the two assertions against
		// each other — the only way out would be to declare the very number
		// assertion 0 exists to forbid. Report and move on.
		if why, blind := unobservable[k.Signal]; blind {
			t.Logf("NOT MEASURED (assertion 0): %s on %s fired %d/%d — %s. "+
				"No ceiling is demanded and none may be declared.",
				k.Signal, k.Ecosystem, fires[k], byEco[k.Ecosystem], why)
			continue
		}
		got := rate(fires[k], byEco[k.Ecosystem])
		ceil, declared := maxFireRate[k]
		if !declared {
			undeclared = append(undeclared, fmt.Sprintf(
				"%s on %s: %d/%d = %.2f%%  e.g. %s",
				k.Signal, k.Ecosystem, fires[k], byEco[k.Ecosystem], got,
				strings.Join(sampleCoords(fireCoords[k], 3), ", ")))
			continue
		}
		if strings.HasPrefix(ceil.Why, defectBaseline) {
			baselineCount++
		}
		if got > ceil.MaxPct {
			overCeiling = append(overCeiling, fmt.Sprintf(
				"%s on %s: %d/%d = %.2f%% exceeds the declared %.2f%% ceiling\n      declared reason: %s\n      e.g. %s",
				k.Signal, k.Ecosystem, fires[k], byEco[k.Ecosystem], got, ceil.MaxPct,
				ceil.Why, strings.Join(sampleCoords(fireCoords[k], 5), ", ")))
		}
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		t.Errorf("UNDECLARED (signal, ecosystem) fire(s) — %d pair(s) fired that "+
			"no one has argued for:\n  %s\n"+
			"Each is the risk engine making a claim about a top-download package. "+
			"Either the claim is wrong (fix the provider or the signal), or it is "+
			"right and belongs in maxFireRate with a ceiling and a written reason.",
			len(undeclared), strings.Join(undeclared, "\n  "))
	}
	if len(overCeiling) > 0 {
		sort.Strings(overCeiling)
		t.Errorf("FIRE-RATE CEILING exceeded — %d (signal, ecosystem) pair(s):\n  %s\n"+
			"At this rate the signal is not describing these packages, it is "+
			"describing the reader that produced their metadata. Do not raise the "+
			"ceiling to make this pass.", len(overCeiling), strings.Join(overCeiling, "\n  "))
	}
	// Report the instrument's own debt every run. A gate that is green only
	// because most of its ceilings encode known defects should say so out
	// loud, every time, rather than let "PASS" read as "the engine is right".
	t.Logf("ceilings: %d declared, %d of them DEFECT BASELINES (green here means "+
		"\"no worse than the known defects\", not \"correct\")", len(maxFireRate), baselineCount)

	// Good news reports rather than fails: a stale ceiling means the table
	// should be pruned in the next scoring commit.
	for k := range maxFireRate {
		if fires[k] == 0 {
			t.Logf("NOTE: %s/%s has a declared ceiling but no longer fires — prune it.",
				k.Signal, k.Ecosystem)
		}
	}

	// ─── 3. ACCEPTED (SIGNAL, COORDINATE) SET, high/critical only ──────────
	var unexpected []string
	for _, k := range keys {
		sev := sigSeverity[k.Signal]
		if sev != risk.SevHigh && sev != risk.SevCritical {
			continue
		}
		if sigWeight[k.Signal] >= 0 {
			continue // a positive signal firing is good news
		}
		for _, coord := range fireCoords[k] {
			pair := sigCoord{Signal: k.Signal, Coord: coord}
			if _, ok := acceptedServerRiskFires[pair]; !ok {
				unexpected = append(unexpected, fmt.Sprintf("%s on %s (severity %s, weight %+.0f)",
					k.Signal, coord, sev, sigWeight[k.Signal]))
			}
		}
	}
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		t.Errorf("NEW high/critical signal fire(s) on benign top packages — %d:\n  %s\n"+
			"A high or critical signal is one that on its own justifies refusing a "+
			"package. Either fix it, or add the (signal, coordinate) pair to "+
			"acceptedServerRiskFires with the reason it is correct behaviour.",
			len(unexpected), strings.Join(unexpected, "\n  "))
	}
	for pair := range acceptedServerRiskFires {
		found := false
		for _, k := range keys {
			if k.Signal != pair.Signal {
				continue
			}
			for _, coord := range fireCoords[k] {
				if coord == pair.Coord {
					found = true
				}
			}
		}
		if !found {
			t.Logf("NOTE: %s on %s is on acceptedServerRiskFires but no longer fires — prune it.",
				pair.Signal, pair.Coord)
		}
	}

	// ─── 4. BACKSTOP, deliberately loose ───────────────────────────────────
	if mean := float64(negFires) / float64(max(total, 1)); mean > maxNegativeSignalsPerPackage {
		t.Errorf("mean negative-weight signals per benign package is %.2f, above the "+
			"%.2f BACKSTOP. This is not a tuning budget: at this level the engine is "+
			"finding fault with top-download packages in bulk, or maxFireRate has "+
			"been pasted into rather than argued with. Do not raise it.",
			mean, maxNegativeSignalsPerPackage)
	}
}

func sampleCoords(all []string, n int) []string {
	uniq := map[string]bool{}
	out := []string{}
	sorted := append([]string(nil), all...)
	sort.Strings(sorted)
	for _, c := range sorted {
		if uniq[c] {
			continue
		}
		uniq[c] = true
		out = append(out, c)
		if len(out) == n {
			break
		}
	}
	if len(sorted) > len(out) {
		out = append(out, fmt.Sprintf("…(+%d more)", len(sorted)-len(out)))
	}
	return out
}

func readServerRiskCorpus(path string) ([]serverRiskRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open corpus: %w", err)
	}
	defer f.Close()
	var rows []serverRiskRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r serverRiskRow
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("line %d will not unmarshal: %w", n, err)
		}
		if r.Eco == "" || r.Pkg == "" || len(r.Report) == 0 {
			return nil, fmt.Errorf("line %d is missing eco/pkg/report", n)
		}
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan corpus: %w", err)
	}
	return rows, nil
}

// ─── CORPUS BUILDER ─────────────────────────────────────────────────────────
//
// Stage 2 of scripts/detection-eval/build-server-risk-corpus.sh. It lives here
// rather than in a `go run` main because the fan-out is reached through
// intelligence.Bootstrap and the harness that consumes its output is in this
// package — one build, one import set, and no new main package for
// `go build ./...` to have an opinion about.
//
// It scans through the REAL provider fan-out, not a stub and not
// analyzeArtifact. No artifact bytes are supplied, so the artifact-bound
// providers skip themselves via NeedsArtifact() — which is exactly the
// server's metadata-only shape, not a limitation of the harness.
//
// Gated on CHAINSAW_SERVER_FP_BUILD so it never runs in a normal `go test`.
func TestBuildServerRiskCorpus(t *testing.T) {
	if os.Getenv("CHAINSAW_SERVER_FP_BUILD") == "" {
		t.Skip("corpus builder; run via scripts/detection-eval/build-server-risk-corpus.sh")
	}
	coordsPath := os.Getenv("CHAINSAW_SERVER_FP_COORDS")
	outPath := os.Getenv("CHAINSAW_SERVER_FP_OUT")
	if coordsPath == "" || outPath == "" {
		t.Fatal("CHAINSAW_SERVER_FP_COORDS and CHAINSAW_SERVER_FP_OUT are required")
	}

	f, err := os.Open(coordsPath)
	if err != nil {
		t.Fatalf("open coords: %v", err)
	}
	var coords []serverRiskRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var c serverRiskRow
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			f.Close()
			t.Fatalf("coords line will not unmarshal: %v", err)
		}
		coords = append(coords, c)
	}
	f.Close()
	if len(coords) == 0 {
		t.Fatal("coords file is empty")
	}

	svc := intelligence.Bootstrap(intelligence.BootstrapConfig{})
	ctx, cancel := context.WithTimeout(context.Background(), 55*time.Minute)
	defer cancel()

	type result struct {
		line string
		err  string
	}
	results := make([]result, len(coords))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, c := range coords {
		wg.Add(1)
		go func(i int, c serverRiskRow) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rep, err := svc.Scan(ctx, intelligence.Request{
				Key: intelligence.Key{Ecosystem: c.Eco, Package: c.Pkg, Version: c.Ver},
			})
			if err != nil || rep == nil {
				results[i] = result{err: fmt.Sprintf("%s %s@%s: scan failed: %v", c.Eco, c.Pkg, c.Ver, err)}
				return
			}
			ev := risk.EvaluatePackage(intelligence.ProjectToRiskInput(rep), risk.Options{})
			verdict := ""
			if ev != nil {
				verdict = string(ev.Verdict)
			}
			raw, err := json.Marshal(rep)
			if err != nil {
				results[i] = result{err: fmt.Sprintf("%s %s@%s: marshal: %v", c.Eco, c.Pkg, c.Ver, err)}
				return
			}
			out, err := json.Marshal(serverRiskRow{
				Eco: c.Eco, Pkg: c.Pkg, Ver: c.Ver,
				Persisted: verdict, Report: raw,
			})
			if err != nil {
				results[i] = result{err: fmt.Sprintf("%s %s@%s: marshal row: %v", c.Eco, c.Pkg, c.Ver, err)}
				return
			}
			results[i] = result{line: string(out)}
		}(i, c)
	}
	wg.Wait()

	var lines, failures []string
	for _, r := range results {
		if r.err != "" {
			failures = append(failures, r.err)
			continue
		}
		lines = append(lines, r.line)
	}
	// Sorted output so two complete builds over the same coordinates are
	// byte-comparable with cmp — the same byte-stability property
	// build-benign-corpus.sh had to be retrofitted with.
	sort.Strings(lines)
	if err := os.WriteFile(outPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write corpus: %v", err)
	}
	t.Logf("wrote %d report(s) to %s", len(lines), outPath)
	if len(failures) > 0 {
		sort.Strings(failures)
		t.Fatalf("%d coordinate(s) failed to scan — refusing to publish a short "+
			"corpus, a fire rate over it would divide by the wrong number:\n  %s",
			len(failures), strings.Join(failures, "\n  "))
	}
}

// TestServerRiskFPHarnessHasARunner is the guard against the failure mode this
// whole file exists inside: an instrument with no runner.
//
// scripts/check-doc-repo-urls.sh sat in the tree for its entire life with zero
// callers — no Makefile target, no hook, no workflow — so the URL rule it
// encodes was never once enforced. tools/surface-drift-check had the same
// history and ten undocumented tools accumulated behind it. GitHub Actions
// billing is off by standing decision, so "wired into CI" is not a thing that
// can be true here; a Makefile target plus .githooks/pre-commit is the only
// place a check actually runs.
//
// So this test asserts the wiring, not the behaviour: the Makefile still has
// the targets, and they still name the harness and the corpus builder. Rename
// TestServerRiskFalsePositives without updating the Makefile and this fails.
//
// Skips when the Makefile is absent: core/ is exported standalone to the
// public chainsaw-core repo, which carries no Makefile, and a test that fails
// there would be a false alarm about a file that is deliberately not present.
func TestServerRiskFPHarnessHasARunner(t *testing.T) {
	root := "../.."
	mk, err := os.ReadFile(root + "/Makefile")
	if err != nil {
		t.Skipf("no Makefile at %s (standalone core/ checkout): %v", root, err)
	}
	makefile := string(mk)
	for _, want := range []string{
		"server-fp-eval:",
		"TestServerRiskFalsePositives",
		"server-fp-corpus:",
		"scripts/detection-eval/build-server-risk-corpus.sh",
		"check-url-prefixes:",
		"scripts/check-doc-repo-urls.sh",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("Makefile no longer contains %q — the instrument has lost its "+
				"runner. Re-point the target; do not delete this assertion.", want)
		}
	}

	hook, err := os.ReadFile(root + "/.githooks/pre-commit")
	if err != nil {
		t.Skipf("no .githooks/pre-commit: %v", err)
	}
	if !strings.Contains(string(hook), "check-doc-repo-urls.sh") {
		t.Errorf(".githooks/pre-commit no longer runs scripts/check-doc-repo-urls.sh. " +
			"That script had zero callers for its entire life once already (P8-37); " +
			"the hook is the only place it runs.")
	}
}
