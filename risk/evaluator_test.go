package risk

import (
	"testing"
	"time"
)

func TestEvaluatePackage_CleanPackageScoresHigh(t *testing.T) {
	published := time.Now().Add(-60 * 24 * time.Hour) // 60 days old
	latest := time.Now().Add(-15 * 24 * time.Hour)    // recent release

	in := Input{
		Ecosystem:        "npm",
		Package:          "lodash",
		Version:          "4.17.21",
		LicenseSPDX:      "MIT",
		ChecksumVerified: true,
		HasProvenance:    true,
		ProvenanceStatus: "verified",
		HasSourceRepo:    true,
		RepoLinkStatus:   "ok",
		VersionCount:     100,
		MaintainerCount:  3,
		PublishedAt:      &published,
		LatestReleaseAt:  &latest,
	}

	eval := EvaluatePackage(in, Options{})
	if eval.Verdict != VerdictAllow {
		t.Errorf("clean package verdict = %q, want %q", eval.Verdict, VerdictAllow)
	}
	if eval.RolledUp.Overall < 90 {
		t.Errorf("clean package overall = %d, want >= 90", eval.RolledUp.Overall)
	}
	if eval.EngineVersion != EngineVersion {
		t.Errorf("engine version = %q, want %q", eval.EngineVersion, EngineVersion)
	}
}

func TestEvaluatePackage_KnownMaliciousShortCircuits(t *testing.T) {
	in := Input{
		Ecosystem:        "npm",
		Package:          "evil-pkg",
		Version:          "1.0.0",
		IsKnownMalicious: true,
		MalwareID:        "CHW-MAL-1234",
		// All other signals would be clean — shouldn't matter.
		LicenseSPDX:      "MIT",
		ChecksumVerified: true,
	}

	eval := EvaluatePackage(in, Options{})
	if eval.Verdict != VerdictQuarantine {
		t.Errorf("malicious verdict = %q, want %q", eval.Verdict, VerdictQuarantine)
	}
	if eval.RolledUp.Overall != 0 {
		t.Errorf("malicious overall = %d, want 0", eval.RolledUp.Overall)
	}
	// The malicious signal should appear in the fired list so UI can
	// explain why.
	found := false
	for _, cs := range eval.RolledUp.Categories {
		for _, f := range cs.FiredSignals {
			if f.ID == SignalSCKnownMalicious {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("malicious signal not present in fired list")
	}
}

func TestEvaluatePackage_ChecksumMismatchShortCircuits(t *testing.T) {
	in := Input{
		Ecosystem:        "pypi",
		Package:          "tampered",
		Version:          "1.2.3",
		ChecksumMismatch: true,
		LicenseSPDX:      "MIT",
	}
	eval := EvaluatePackage(in, Options{})
	if eval.Verdict != VerdictQuarantine {
		t.Errorf("checksum mismatch verdict = %q, want quarantine", eval.Verdict)
	}
	if eval.RolledUp.Overall != 0 {
		t.Errorf("checksum mismatch overall = %d, want 0", eval.RolledUp.Overall)
	}
}

func TestEvaluatePackage_KEVOutweighsPlainHighCVSS(t *testing.T) {
	base := Input{
		Ecosystem:    "npm",
		Package:      "foo",
		Version:      "1.0.0",
		LicenseSPDX:  "MIT",
		IsVulnerable: true,
		MaxCVSS:      9.5,
	}
	baseEval := EvaluatePackage(base, Options{})

	kev := base
	kev.KnownExploited = true
	kevEval := EvaluatePackage(kev, Options{})

	if kevEval.RolledUp.Overall >= baseEval.RolledUp.Overall {
		t.Errorf("KEV should score strictly lower than plain critical CVSS: kev=%d base=%d",
			kevEval.RolledUp.Overall, baseEval.RolledUp.Overall)
	}
}

func TestEvaluatePackage_TakeoverCompoundDominates(t *testing.T) {
	publisherOnly := Input{
		Ecosystem:        "npm",
		Package:          "axios-like",
		Version:          "2.0.0",
		LicenseSPDX:      "MIT",
		PublisherChanged: true,
	}
	installOnly := Input{
		Ecosystem:        "npm",
		Package:          "axios-like",
		Version:          "2.0.0",
		LicenseSPDX:      "MIT",
		HasInstallScript: true,
	}
	both := Input{
		Ecosystem:        "npm",
		Package:          "axios-like",
		Version:          "2.0.0",
		LicenseSPDX:      "MIT",
		PublisherChanged: true,
		HasInstallScript: true,
	}

	pubEval := EvaluatePackage(publisherOnly, Options{})
	instEval := EvaluatePackage(installOnly, Options{})
	bothEval := EvaluatePackage(both, Options{})

	// The compound carries SevCritical so the verdict must escalate past
	// Allow even when the ceiling-bypass numerical overall is higher than
	// the per-primitive ceiling. Compounds bypass the per-signal ceiling
	// by design (their additive deficit stays authoritative); the
	// hasCriticalSignal escalation in resolveVerdict is what makes the
	// compound dominate the verdict.
	if bothEval.Verdict == VerdictAllow {
		t.Errorf("takeover compound must not Allow: verdict=%q overall=%d",
			bothEval.Verdict, bothEval.RolledUp.Overall)
	}
	if bothEval.Verdict == VerdictWarn {
		t.Errorf("takeover compound (Critical severity) must not resolve to bare Warn: verdict=%q overall=%d",
			bothEval.Verdict, bothEval.RolledUp.Overall)
	}
	if instEval.Verdict != VerdictAllow {
		t.Errorf("install-script-only (low-weight primitive) should be Allow, got %q (overall=%d)",
			instEval.Verdict, instEval.RolledUp.Overall)
	}
	// publisher-only fires sc.publisher_changed (High severity, MaxImpact
	// 40 under the rebalanced calibration) — verdict should land in Warn.
	if pubEval.Verdict != VerdictWarn {
		t.Errorf("publisher-only should be Warn under rebalanced ceiling, got %q (overall=%d)",
			pubEval.Verdict, pubEval.RolledUp.Overall)
	}
}

func TestEvaluatePackage_VerdictBandsFollowThresholds(t *testing.T) {
	// Push a package just under and just over each boundary by stacking
	// signals. This is a smoke test — exhaustive threshold math lives in
	// the category/overall unit tests.
	allowCase := Input{Ecosystem: "npm", Package: "ok", Version: "1.0.0", LicenseSPDX: "MIT"}
	if got := EvaluatePackage(allowCase, Options{}).Verdict; got != VerdictAllow {
		t.Errorf("clean-ish input verdict = %q, want allow", got)
	}

	// Stacked signals across multiple categories to drag Overall below
	// the Allow threshold. Publisher-change + install-script triggers
	// the takeover compound rule, but no instant-block (known-malicious
	// / checksum-mismatch) fires.
	warnCase := Input{
		Ecosystem:                  "npm",
		Package:                    "warnme",
		Version:                    "1.0.0",
		IsVulnerable:               true,
		MaxCVSS:                    8.0,
		RepoLinkStatus:             "ownership_mismatch",
		InstallScriptFetchesRemote: true,
		PublisherChanged:           true,
	}
	if got := EvaluatePackage(warnCase, Options{}).Verdict; got == VerdictAllow {
		t.Errorf("warn-band input verdict = %q, should not be allow", got)
	}
}

func TestEvaluatePackage_UpgradeAvailableResolution(t *testing.T) {
	in := Input{
		Ecosystem:      "npm",
		Package:        "vulny",
		Version:        "1.0.0",
		KnownExploited: true,
		IsVulnerable:   true,
		MaxCVSS:        9.8,
		CVEs:           []string{"CVE-2099-0001"},
	}
	eval := EvaluatePackage(in, Options{SafeUpgradeVersion: "1.0.1"})
	if eval.Verdict != VerdictUpgradeAvailable {
		t.Errorf("verdict = %q, want upgrade_available", eval.Verdict)
	}
	if eval.Resolution.SafeVersion != "1.0.1" {
		t.Errorf("SafeVersion = %q, want 1.0.1", eval.Resolution.SafeVersion)
	}
	if len(eval.Resolution.Rationale) == 0 {
		t.Errorf("rationale should be populated for non-allow verdicts")
	}
}

func TestEvaluatePackage_ReplaceResolutionWhenAlternativeKnown(t *testing.T) {
	in := Input{
		Ecosystem:      "npm",
		Package:        "abandoned",
		Version:        "1.0.0",
		KnownExploited: true,
		IsVulnerable:   true,
		MaxCVSS:        9.8,
	}
	eval := EvaluatePackage(in, Options{Alternative: "newpkg"})
	if eval.Verdict != VerdictReplace {
		t.Errorf("verdict = %q, want replace", eval.Verdict)
	}
	if eval.Resolution.Alternative != "newpkg" {
		t.Errorf("Alternative = %q, want newpkg", eval.Resolution.Alternative)
	}
}

func TestEvaluatePackage_QuarantineWhenNoResolutionPath(t *testing.T) {
	in := Input{
		Ecosystem:      "npm",
		Package:        "stuck",
		Version:        "1.0.0",
		KnownExploited: true,
		IsVulnerable:   true,
		MaxCVSS:        9.8,
	}
	eval := EvaluatePackage(in, Options{})
	if eval.Verdict != VerdictQuarantine {
		t.Errorf("verdict = %q, want quarantine", eval.Verdict)
	}
}

func TestEvaluatePackage_VersionAnomalyCap(t *testing.T) {
	// Three anomaly flags should cap at -30 total rather than stacking.
	manyFlags := Input{
		Ecosystem:           "npm",
		Package:             "anomaly",
		Version:             "1.0.0",
		LicenseSPDX:         "MIT",
		VersionAnomalyFlags: []string{"timestamp_regression", "major_skip", "content_drift"},
	}
	eval := EvaluatePackage(manyFlags, Options{})
	// The quality category base is 100; cap is -30; result should be 70.
	qs := eval.RolledUp.Categories[CategoryQuality]
	if qs.Score != 70 {
		t.Errorf("quality subscore with 3 anomaly flags = %d, want 70 (cap)", qs.Score)
	}
}

func TestEvaluatePackage_NilNowUsesRealClock(t *testing.T) {
	// Smoke test: the evaluator must work without an overridden Now.
	in := Input{Ecosystem: "npm", Package: "x", Version: "1.0.0", LicenseSPDX: "MIT"}
	eval := EvaluatePackage(in, Options{})
	if eval.EvaluatedAt.IsZero() {
		t.Error("EvaluatedAt should be set when Options.Now is nil")
	}
}

func TestEvaluatePackage_DeterministicWithFixedClock(t *testing.T) {
	fixed := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	opts := Options{Now: func() time.Time { return fixed }}
	in := Input{Ecosystem: "npm", Package: "x", Version: "1.0.0", LicenseSPDX: "MIT"}
	a := EvaluatePackage(in, opts)
	b := EvaluatePackage(in, opts)
	if !a.EvaluatedAt.Equal(b.EvaluatedAt) {
		t.Errorf("fixed clock should produce identical timestamps: %v vs %v", a.EvaluatedAt, b.EvaluatedAt)
	}
	if a.RolledUp.Overall != b.RolledUp.Overall {
		t.Errorf("same input should produce same score: %d vs %d", a.RolledUp.Overall, b.RolledUp.Overall)
	}
}

func TestComputeOverall_AllCleanScores100(t *testing.T) {
	cats := make(map[Category]CategoryScore, len(CategoryWeights))
	for cat := range CategoryWeights {
		cats[cat] = CategoryScore{Score: 100, DataAvailable: true}
	}
	if got := computeOverall(cats); got != 100 {
		t.Errorf("all-100 categories = %d, want 100", got)
	}
}

func TestComputeOverall_AllZeroScoresZero(t *testing.T) {
	cats := make(map[Category]CategoryScore, len(CategoryWeights))
	for cat := range CategoryWeights {
		cats[cat] = CategoryScore{Score: 0, DataAvailable: true}
	}
	if got := computeOverall(cats); got != 0 {
		t.Errorf("all-0 categories = %d, want 0", got)
	}
}

func TestComputeOverall_WeightedByCategory(t *testing.T) {
	// Only Vulnerability at 0, rest at 100: overall = 100 - 30 = 70.
	cats := make(map[Category]CategoryScore, len(CategoryWeights))
	for cat := range CategoryWeights {
		score := 100
		if cat == CategoryVulnerability {
			score = 0
		}
		cats[cat] = CategoryScore{Score: score, DataAvailable: true}
	}
	if got := computeOverall(cats); got != 70 {
		t.Errorf("vuln-zero, others-100 = %d, want 70", got)
	}
}

// TestComputeOverall_UnavailableCategoryRenormalises pins the regression
// fix: a category marked DataAvailable=false must NOT contribute its
// zero-deficit to the overall (which would silently treat "unscanned"
// as "perfect"). Instead, the remaining categories' weights are
// re-normalised so their (typically-100) clean scores roll up cleanly.
// Without this re-normalisation, the public idna 3.15 page scored 98
// despite the Vulnerability category never being scanned.
func TestComputeOverall_UnavailableCategoryRenormalises(t *testing.T) {
	cats := make(map[Category]CategoryScore, len(CategoryWeights))
	for cat := range CategoryWeights {
		score := 100
		available := true
		if cat == CategoryVulnerability {
			score = 100 // value irrelevant when DataAvailable=false
			available = false
		}
		cats[cat] = CategoryScore{Score: score, DataAvailable: available}
	}
	if got := computeOverall(cats); got != 100 {
		t.Errorf("vuln-unavailable, rest-100 should re-normalise to 100 = got %d", got)
	}
}

func TestComputeOverall_AllUnavailableReturnsZero(t *testing.T) {
	cats := make(map[Category]CategoryScore, len(CategoryWeights))
	for cat := range CategoryWeights {
		cats[cat] = CategoryScore{Score: 100, DataAvailable: false}
	}
	if got := computeOverall(cats); got != 0 {
		t.Errorf("all-unavailable should refuse to invent a score = got %d", got)
	}
}

// TestMaxImpactCalibration_PerTier asserts each tier of fired-alone signals
// lands the rolled-up overall in the documented band. See the MaxImpact
// policy table in docs/architecture/package-intelligence.md.
//
// Critical → ≤20 (KEV, dangerous pickle, sentinel malware/checksum).
// High    → 30-50 (typosquat-high, publisher-changed, repo-ownership-mismatch,
//
//	CVSS-high, etc.).
//
// Medium  → 50-75 (typosquat-medium, hidden-unicode, version-anomaly).
// Low     → 80-95 (CVSS-low, single-maintainer; weight only — no ceiling).
func TestMaxImpactCalibration_PerTier(t *testing.T) {
	// Each input fires the named signal in isolation against an
	// otherwise-clean Input. License is set so the no-license signal does
	// not compound the result.
	cases := []struct {
		name     string
		minScore int
		maxScore int
		in       Input
	}{
		// --- Critical tier — overall must be at quarantine grade. ---
		{
			name:     "critical/vuln.kev",
			minScore: 0, maxScore: 20,
			in: Input{
				Ecosystem: "npm", Package: "x", Version: "1.0.0", LicenseSPDX: "MIT",
				IsVulnerable: true, KnownExploited: true, MaxCVSS: 9.5, CVEs: []string{"CVE-2024-9999"},
			},
		},
		{
			name:     "critical/ai.dangerous_pickle_opcode",
			minScore: 0, maxScore: 20,
			in: Input{
				Ecosystem: "huggingface", Package: "evil-model", Version: "1.0.0", LicenseSPDX: "MIT",
				DangerousPickleOpcode: true, DangerousPickleFiles: []string{"weights.pkl"},
			},
		},
		// --- High tier — strong attack-pattern evidence. ---
		{
			name:     "high/sc.typosquat_high",
			minScore: 30, maxScore: 50,
			in: Input{
				Ecosystem: "npm", Package: "lodahs", Version: "1.0.0", LicenseSPDX: "MIT",
				IsSuspectedTyposquat: true, TyposquatConfidence: "high",
			},
		},
		{
			name:     "high/sc.publisher_changed",
			minScore: 30, maxScore: 50,
			in: Input{
				Ecosystem: "npm", Package: "p", Version: "1.0.0", LicenseSPDX: "MIT",
				PublisherChanged: true,
			},
		},
		{
			name:     "high/sc.repo_ownership_mismatch",
			minScore: 30, maxScore: 50,
			in: Input{
				Ecosystem: "npm", Package: "p", Version: "1.0.0", LicenseSPDX: "MIT",
				RepoLinkStatus: "ownership_mismatch",
			},
		},
		{
			name:     "high/vuln.cvss_high",
			minScore: 30, maxScore: 50,
			in: Input{
				Ecosystem: "npm", Package: "x", Version: "1.0.0", LicenseSPDX: "MIT",
				IsVulnerable: true, MaxCVSS: 7.5, CVEs: []string{"CVE-2024-1111"},
			},
		},
		// --- Medium tier — degrades but doesn't dominate. ---
		{
			// Rebalanced: typosquat-medium has NO ceiling now — the -20
			// weight alone determines impact, leaving overall in the
			// allow band. This is the jose@5.10.0 regression fix.
			name:     "medium-no-ceiling/sc.typosquat_medium",
			minScore: 80, maxScore: 100,
			in: Input{
				Ecosystem: "npm", Package: "loadash", Version: "1.0.0", LicenseSPDX: "MIT",
				IsSuspectedTyposquat: true, TyposquatConfidence: "medium",
			},
		},
		{
			name:     "medium/sc.hidden_unicode",
			minScore: 50, maxScore: 75,
			in: Input{
				Ecosystem: "npm", Package: "p", Version: "1.0.0", LicenseSPDX: "MIT",
				HasHiddenUnicode: true,
			},
		},
		{
			name:     "medium/qual.version_anomaly",
			minScore: 50, maxScore: 75,
			in: Input{
				Ecosystem: "npm", Package: "p", Version: "1.0.0", LicenseSPDX: "MIT",
				VersionAnomalyFlags: []string{"timestamp_regression"},
			},
		},
		// --- Low / soft signal — no ceiling, weight only. ---
		{
			name:     "low/vuln.cvss_low (no ceiling)",
			minScore: 80, maxScore: 100,
			in: Input{
				Ecosystem: "npm", Package: "x", Version: "1.0.0", LicenseSPDX: "MIT",
				IsVulnerable: true, MaxCVSS: 3.0, CVEs: []string{"CVE-2024-2222"},
			},
		},
		{
			name:     "low/maint.single_maintainer (no ceiling)",
			minScore: 80, maxScore: 100,
			in: Input{
				Ecosystem: "npm", Package: "p", Version: "1.0.0", LicenseSPDX: "MIT",
				MaintainerCount: 1,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eval := EvaluatePackage(tc.in, Options{})
			got := eval.RolledUp.Overall
			if got < tc.minScore || got > tc.maxScore {
				t.Errorf("overall=%d outside expected band [%d, %d] for %s",
					got, tc.minScore, tc.maxScore, tc.name)
			}
		})
	}
}

// TestMaxImpactCalibration_JoseRegressionScenario reproduces the failure mode
// that motivated the rebalance: a single sc.typosquat_medium hit must not
// collapse an otherwise-clean package into the warn-territory cap of 35.
// Under the rebalanced policy, the ceiling is 55 and the rollup math leaves
// overall around 80 — well above the warn threshold.
func TestMaxImpactCalibration_JoseRegressionScenario(t *testing.T) {
	in := Input{
		Ecosystem: "npm", Package: "jose", Version: "5.10.0", LicenseSPDX: "MIT",
		IsSuspectedTyposquat: true, TyposquatConfidence: "medium",
		// Otherwise clean.
		ChecksumVerified: true,
	}
	eval := EvaluatePackage(in, Options{})
	if eval.RolledUp.Overall < 60 {
		t.Errorf("overall=%d should be >= 60 (allow band) under rebalanced typosquat-medium ceiling",
			eval.RolledUp.Overall)
	}
	if eval.Verdict != VerdictAllow {
		t.Errorf("verdict=%q, want %q — single medium-confidence typosquat must not collapse otherwise-clean package",
			eval.Verdict, VerdictAllow)
	}
}
