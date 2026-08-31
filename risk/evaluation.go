package risk

import (
	"fmt"
	"time"
)

// EngineVersion is stamped onto every Evaluation so downstream consumers
// (API clients, Sonatype/JFrog plugins, the divergence dashboard) can
// distinguish v2 results from legacy trustscore results and from future
// versions of this engine. Bump the second digit on weight changes, bump
// the first on contract changes (new fields, renamed verdicts, etc.).
const EngineVersion = "2.0"

// Verdict is the action-oriented answer the engine returns per package:
// "what should the user do?" It is distinct from policy actions (allow /
// monitor / block / quarantine) so the risk engine can advise even when
// no explicit policy is configured. Policy ultimately decides whether
// a warn/upgrade-available translates into a block — verdicts are advice
// with structured resolution.
type Verdict string

const (
	VerdictAllow            Verdict = "allow"             // safe to use
	VerdictWarn             Verdict = "warn"              // use with caution; review signals
	VerdictUpgradeAvailable Verdict = "upgrade_available" // newer safe version of same package exists
	VerdictReplace          Verdict = "replace"           // recommend alternative package
	VerdictQuarantine       Verdict = "quarantine"        // block until manual review

	// VerdictUnknown means the engine COULD NOT EVALUATE this package —
	// the facts were unavailable (backend down, scan errored, no
	// Report). It is not a risk judgement at all, and in particular it
	// is NOT a weaker Allow: an evaluation that never ran must never
	// present as a clean bill of health.
	//
	// Consumers MUST NOT fold Unknown into the Allow bucket. On query /
	// reporting surfaces the honest handling is to report it as
	// "not evaluated" and let the operator decide; on enforcement
	// surfaces the unavailability posture is owned by core/coverage's
	// opt-in gate (docs/plan_optional_fail_closed.md), not by this
	// verdict — the risk engine advises, it does not gate.
	VerdictUnknown Verdict = "unknown"
)

// Key identifies a package version across ecosystems. Duplicated here (vs
// importing intelligence.Key) so this package has no intelligence
// dependency — enables future consumers that don't carry the full Report.
type Key struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version"`
}

// CategoryScore is the 0-100 subscore for one Category plus the signals
// that fired to produce it. Grade is a letter grade (A..F) for UI
// convenience — derived from Score, not stored independently.
//
// DataAvailable is false when the underlying data feed for this category
// was unavailable (e.g. CVE scan never ran for this package version).
// When false, the category is excluded from the overall weighted rollup
// and the UI renders the score as "—" rather than 100 — "absence of
// data" is not the same signal as "absence of findings". A regression
// of this distinction is what gave idna 3.15 a Vulnerability score of
// 100 despite the CVE pipeline never running.
type CategoryScore struct {
	Score         int           `json:"score"`
	Grade         string        `json:"grade"`
	DataAvailable bool          `json:"dataAvailable"`
	FiredSignals  []FiredSignal `json:"firedSignals,omitempty"`
}

// Score is the per-evaluation outcome: per-category subscores + overall.
// Overall is drop-in compatible with the legacy trust-score int (0-100)
// so policy TrustScoreMin/Max conditions continue to work unchanged.
//
// The shape mirrors Socket's package-scores model
// (https://docs.socket.dev/docs/package-scores): five 0–100 category
// subscores (Supply Chain, Quality, Maintenance, Vulnerability, License),
// plus a composite. We additionally expose MinCategoryScore /
// WorstCategory because Socket's UI emphasises the weakest dimension —
// a healthy weighted overall can hide a category-specific failure
// (e.g. quality A+ but supply-chain F due to a malware match), and the
// "worst category" view is what most reviewers act on first. Policy
// authors who want Socket-style minimum-of-categories gating should
// compare against MinCategoryScore rather than Overall.
type Score struct {
	Overall          int                        `json:"overall"`
	Categories       map[Category]CategoryScore `json:"categories"`
	MinCategoryScore int                        `json:"minCategoryScore"`
	WorstCategory    Category                   `json:"worstCategory,omitempty"`

	// CeilingSignal names the signal whose MaxImpact ceiling PINNED
	// Overall — empty when the ceiling did not bind, which is the common
	// case. When it is set, Overall is that signal's declared ceiling and
	// NOT the weighted rollup over Categories, so a reader who tries to
	// derive the composite from the category scores below will not get
	// this number and is not doing anything wrong. Every renderer that
	// shows Categories alongside Overall should say so; see P8-12.
	CeilingSignal string `json:"ceilingSignal,omitempty"`
}

// Resolution is the structured "what to do" advice. Fields are populated
// based on Verdict:
//
//	Allow            → Summary set; other fields empty
//	Warn             → Summary + Rationale (top-3 driving signal IDs)
//	UpgradeAvailable → SafeVersion populated
//	Replace          → Alternative populated (when known)
//	Quarantine       → Summary explains the instant-block signal
//
// TransitiveBlame is populated by the tree evaluator (future commit) when
// a parent package's rolled-up score was dragged down by a transitive
// descendant. Empty for single-package evaluations.
type Resolution struct {
	Verdict         Verdict  `json:"verdict"`
	Summary         string   `json:"summary"`
	SafeVersion     string   `json:"safeVersion,omitempty"`
	PatchAdvisory   string   `json:"patchAdvisory,omitempty"`
	Alternative     string   `json:"alternative,omitempty"`
	TransitiveBlame []Key    `json:"transitiveBlame,omitempty"`
	Rationale       []string `json:"rationale,omitempty"`

	// SafeVersionCorroborated says whether SafeVersion was confirmed to
	// be INSTALLABLE, not merely NAMED by an advisory. False (the zero
	// value, and therefore also every row written before matcher epoch
	// 9) means "the advisory names this fix and we could not confirm the
	// registry has published it".
	//
	// It exists because deleting an uncorroborated SafeVersion would
	// destroy real information: coordinated disclosure routinely names a
	// fix version days before the release lands, and "the fix is 4.19.2,
	// not yet on the registry" is strictly more useful to a reader than
	// silence. The defect this field addresses was the IMPERATIVE — a
	// PatchAdvisory reading "upgrade and re-scan" for a version that may
	// 404 — so the wording softens instead (see applyKnownFix).
	//
	// It is a DISPLAY bit. Nothing in the evaluator, internal/decision,
	// internal/scan or the CLI exit-code path reads it; the enforcement
	// consequence of corroboration lives in
	// intelligence.promoteToUpgradeAvailable, which refuses to promote
	// an uncorroborated candidate at all.
	SafeVersionCorroborated bool `json:"safeVersionCorroborated,omitempty"`

	// TransitiveSeverity is the severity-bucketed breakdown of issues found
	// in the transitive closure. Populated by evaluateTransitiveRisk after
	// the dep-tree walker resolves descendants. Zero values are valid: if
	// no transitive issues found, all counts are 0. Mirrors Socket's
	// "transitive_vulnerabilities" summary line.
	TransitiveSeverity TransitiveSeverity `json:"transitiveSeverity,omitempty"`
}

// TransitiveSeverity tallies issues found in the transitive dep closure.
// CriticalCount/HighCount/MediumCount/LowCount count vulns by CVSS tier
// across all descendants (cumulative, deduplicated by CVE ID across
// duplicate package versions in the tree). MalwareCount is the number of
// distinct descendants flagged sc.known_malicious. BlockedCount is the
// number of distinct descendants whose own verdict is `quarantine` or
// `replace`. Stays zero when transitive evaluation didn't run or the
// closure is empty.
type TransitiveSeverity struct {
	CriticalCount int `json:"criticalCount,omitempty"`
	HighCount     int `json:"highCount,omitempty"`
	MediumCount   int `json:"mediumCount,omitempty"`
	LowCount      int `json:"lowCount,omitempty"`
	MalwareCount  int `json:"malwareCount,omitempty"`
	BlockedCount  int `json:"blockedCount,omitempty"`
}

// Evaluation is the complete per-package result of the risk engine.
//
// DirectScore is the score from signals on this package alone. RolledUp is
// the score after folding in transitive descendants. For single-package
// evaluation (no graph), DirectScore == RolledUp.
type Evaluation struct {
	Key           Key        `json:"key"`
	DirectScore   Score      `json:"directScore"`
	RolledUp      Score      `json:"rolledUp"`
	Verdict       Verdict    `json:"verdict"`
	Resolution    Resolution `json:"resolution"`
	EvaluatedAt   time.Time  `json:"evaluatedAt"`
	EngineVersion string     `json:"engineVersion"`
}

// noFixSummaries maps every Resolution.Summary the evaluator emits that
// ASSERTS no fix exists to the sentence that replaces it once a patched
// version is known. Keyed on the exact strings resolveVerdict produces
// (evaluator.go) — resolution_display_test.go drives resolveVerdict and
// fails if any of them drifts, so this table cannot rot silently.
//
// The replacements keep the verdict's posture word-for-word: a
// quarantine still says manual review is required. The only thing that
// changes is that the sentence stops claiming a fix does not exist when
// the corpus knows one does.
var noFixSummaries = map[string]string{
	"High-risk package with no known safe version or alternative. Manual review required.": "High-risk package. Patched in %s — upgrade and re-scan. Manual review required until then.",
	"Critical signal present with no upgrade or alternative path. Manual review required.": "Critical signal present. Patched in %s — upgrade and re-scan. Manual review required until then.",
	"Package is high-risk with no safe version. Consider an alternative.":                  "Package is high-risk. Patched in %s — upgrade and re-scan, or consider an alternative.",
}

// noFixSummariesUncorroborated is the same table for the case where the
// fix version is NAMED by an advisory but was not confirmed installable.
// Same keys, same posture words, one difference: it reports a fact
// ("advisories name X") instead of issuing an instruction ("upgrade to
// X"), because the instruction may send a reader to a 404.
//
// Kept as a parallel table rather than a runtime rewrite of the
// corroborated strings so that resolution_display_test.go's drift check
// covers both wordings from the same key set.
var noFixSummariesUncorroborated = map[string]string{
	"High-risk package with no known safe version or alternative. Manual review required.": "High-risk package. Advisories name %s as the fix; it is not confirmed published yet. Manual review required.",
	"Critical signal present with no upgrade or alternative path. Manual review required.": "Critical signal present. Advisories name %s as the fix; it is not confirmed published yet. Manual review required.",
	"Package is high-risk with no safe version. Consider an alternative.":                  "Package is high-risk. Advisories name %s as the fix; it is not confirmed published yet. Consider an alternative.",
}

// ApplyKnownFix records a patched version on a Resolution for DISPLAY,
// and corrects a Summary that asserts no such version exists.
//
// It deliberately does NOT touch Verdict. The engine's upgrade_available
// promotion is driven by Options.SafeUpgradeVersion at evaluation time
// and reaches four enforcement surfaces (internal/decision,
// internal/scan's lockfile severity, the transitive rollup's blocked-node
// set, and the CLI exit-code bucket). Populating the display field after
// the fact keeps the enforcement answer byte-identical while the page
// stops printing a false sentence. See the caller,
// intelligence.MinimumSafeVersion, for how the version is derived.
//
// safeVersion == "" is a no-op: "we could not establish a version that
// clears every CVE" must render as today's output, not as a blank
// advisory.
func (r *Resolution) ApplyKnownFix(safeVersion string) {
	r.ApplyKnownFixCorroborated(safeVersion, true)
}

// ApplyKnownFixCorroborated is ApplyKnownFix with the corroboration bit
// made explicit. corroborated=false means the version is named by
// advisory data but was NOT confirmed to be published upstream, and the
// advisory sentence drops its imperative accordingly.
//
// AMENDS Phase 7 D-1/D-2 (docs/plan_qa_phase7_remediation.md). D-2 fixed
// the SOURCE of the safe version (per-CVE FixedVersion, resolved to the
// minimum clearing every CVE) and explicitly rejected
// intelligence_latest_probes.latest_version as a source because "latest
// upstream" is not "safe". That ruling stands and is not being revisited:
// the probe is still never a source. What is added here is that the same
// probe, plus the registry's published version timeline, is allowed to
// act as a CORROBORATOR — a one-directional check on whether the version
// D-2 chose can actually be installed. A founder decision is being
// extended, not corrected.
//
// The extension exists because D-1/D-2 left one sentence unexamined: the
// display path printed "Patched in X — upgrade and re-scan" for any X the
// advisory named, which is an instruction to install something that may
// not exist. Blanking X was considered and rejected (see
// Resolution.SafeVersionCorroborated).
func (r *Resolution) ApplyKnownFixCorroborated(safeVersion string, corroborated bool) {
	if r == nil || safeVersion == "" {
		return
	}
	// An evaluation that never ran carries no advice. VerdictUnknown means
	// the facts were unavailable — for a coordinate the registry never
	// published, the CVE rows on the report describe a DIFFERENT version,
	// so an upgrade line derived from them would be fiction attached to a
	// "not evaluated" result.
	if r.Verdict == VerdictUnknown {
		return
	}
	r.SafeVersion = safeVersion
	r.SafeVersionCorroborated = corroborated
	table := noFixSummaries
	if corroborated {
		r.PatchAdvisory = "Patched in " + safeVersion + " — upgrade and re-scan."
	} else {
		r.PatchAdvisory = "Advisories name " + safeVersion + " as the fix; it is not confirmed published yet."
		table = noFixSummariesUncorroborated
	}
	if replacement, ok := table[r.Summary]; ok {
		r.Summary = fmt.Sprintf(replacement, safeVersion)
	}
}

// ApplyKnownFix is the Evaluation-level convenience wrapper. Same
// display-only contract: Verdict, DirectScore, and RolledUp are never
// read or written.
func (e *Evaluation) ApplyKnownFix(safeVersion string) {
	e.ApplyKnownFixCorroborated(safeVersion, true)
}

// ApplyKnownFixCorroborated is the Evaluation-level wrapper carrying the
// corroboration bit. Same display-only contract.
func (e *Evaluation) ApplyKnownFixCorroborated(safeVersion string, corroborated bool) {
	if e == nil {
		return
	}
	e.Resolution.ApplyKnownFixCorroborated(safeVersion, corroborated)
}

// gradeForScore maps a 0-100 score to a letter grade. Thresholds chosen
// so that "allow" territory (>=60) lands in C or better — any D/F grade
// is at least warn territory. Keep in sync with the verdict decision
// table (see evaluator.go).
func gradeForScore(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}
