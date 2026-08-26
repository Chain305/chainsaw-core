package risk

// Signal is one registered risk-scoring rule. Signals are declared at
// package-init time in registry_<category>.go files and added to Registry
// via register(). Evaluation walks the registry once per package.
//
// Weight convention:
//   - Negative weight = subtracts from the category subscore (bad signal).
//   - Positive weight = adds to the category subscore (good signal — e.g.
//     verified provenance, SPDX license present).
//   - A weight of -100 on a critical signal is reserved for instant-block
//     short-circuits (see compound.go and sc.known_malicious).
//
// Fires returns (fired, detail, evidence). detail is a user-readable
// one-liner; evidence is an optional map of structured fields that the
// UI can render (e.g., {"cvss": 9.8, "cve": "CVE-2024-1234"}). Evidence
// MAY be nil when there is nothing structured to attach.
type Signal struct {
	ID          string
	Category    Category
	Severity    Severity
	Weight      float64
	Title       string
	Description string
	Fires       func(in Input) (fired bool, detail string, evidence map[string]any)

	// MaxImpact is the maximum overall score this signal alone is allowed
	// to leave on the table (i.e. when no other negative signals fire).
	// 0 = no individual cap (rollup math alone determines the score).
	// e.g. MaxImpact=20 means "if this signal fires, overall <= 20"; the
	// evaluator computes the weighted-sum score, then enforces overall <=
	// max(MaxImpact across all fired signals). This addresses the
	// SupplyChain-weight-too-low structural issue: the category-weighted
	// rollup applies uncapped for the common case, but a single severe
	// signal in any category can dominate when warranted.
	//
	// Calibration notes lives in evaluator.go (search for "max-impact
	// floor"). Set sparingly — every MaxImpact is a per-signal claim that
	// "alone, this should drive overall to at most X".
	MaxImpact int

	// NotTunable, when true, locks the signal's weight against admin
	// overrides. The /api/risk/overrides PUT/DELETE endpoints reject
	// requests targeting any signal with NotTunable=true.
	//
	// We use an opt-OUT bool (not "Tunable" with default false) so a
	// new signal added in a future PR is tunable by default — only
	// signals deliberately flagged as load-bearing are protected. Set
	// it on:
	//   - SignalSCKnownMalicious (instant-block; -1000 sentinel)
	//   - SignalQualChecksumMismatch (instant-block; -1000 sentinel)
	//   - SignalVulnKEV (KEV — actively exploited; can't be policy'd
	//     down to ignore)
	// Pain 9 P2: stop a malicious or finger-fumbled admin from setting
	// SC_KNOWN_MALICIOUS to weight +1000 to suppress enforcement of
	// the known-malicious index.
	NotTunable bool
}

// maxImpactWarnTop is the tightest ceiling a signal can declare and still
// land INSIDE the warn band. It exists because resolveVerdict's band tests
// are strict (`overall < thresholdWarn`), so a ceiling of exactly
// thresholdWarn pins overall onto the boundary, skips band 2 entirely and
// resolves to Allow — the signal can never so much as warn, no matter how
// many uncapped signals fired alongside it. That defect shipped on four
// medium-tier signals (qual.version_anomaly, sc.hidden_unicode,
// sc.repo_archived, sc.repo_missing); see P8-02 in
// docs/plan_qa_phase8_remediation.md.
//
// Use this rather than a literal for any signal whose intended claim is
// "alone, this holds the package at the TOP of the warn band". Signals that
// mean something looser (a genuine allow-band ceiling) should declare no
// MaxImpact at all — a ceiling that cannot change the verdict is decorative,
// and TestCeilingedSignalRebutsItsOwnBand refuses one.
//
// Lowering a ceiling to the top of the warn band is safe in a way that
// lowering a band-1 ceiling to thresholdQuarantine-1 is NOT: only
// thresholdQuarantine gates UpgradePromotionEligible, so a 59 ceiling cannot
// delete an upgrade recommendation.
const maxImpactWarnTop = thresholdWarn - 1

// IsTunable reports whether the admin /api/risk/overrides surface is
// allowed to override this signal's weight. The sense is inverted from
// the struct field (NotTunable) for read-side convenience — handler
// code reads this; signal authors set NotTunable.
func (s Signal) IsTunable() bool { return !s.NotTunable }

// FiredSignal is the output of running a Signal against an Input — the
// persisted record that feeds the UI findings list and the API response.
type FiredSignal struct {
	ID       string         `json:"id"`
	Category Category       `json:"category"`
	Title    string         `json:"title"`
	Severity Severity       `json:"severity"`
	Weight   float64        `json:"weight"`
	Detail   string         `json:"detail,omitempty"`
	Evidence map[string]any `json:"evidence,omitempty"`
	// Compound is true when the record comes from a compound rule rather
	// than a primitive signal; UI can group these separately.
	Compound bool `json:"compound,omitempty"`
}
