package risk

import (
	"sort"
	"time"
)

// Options tunes evaluator behaviour. Zero value means production defaults;
// tests use these hooks to pin time.Now and test edge cases.
type Options struct {
	// Now overrides time.Now for deterministic tests. Nil = real clock.
	Now func() time.Time

	// SafeUpgradeVersion is populated by the caller when they have
	// already determined a newer safe version exists for this package.
	// When non-empty AND the overall score is in the
	// upgrade-available band, the verdict resolves to UpgradeAvailable
	// with this string as SafeVersion. The intelligence package fills
	// this from the intelligence_latest_probes table.
	SafeUpgradeVersion string

	// Alternative is populated by the caller when a curated replacement
	// package is known. Used when Verdict would otherwise be Replace.
	Alternative string

	// CategoryWeights is an optional per-evaluation override. When nil,
	// the package-level CategoryWeights map is used. Must be validated
	// by the caller (internal/orgweights.ResolveWeights does this).
	CategoryWeights map[Category]float64

	// SignalWeightOverrides is an optional per-evaluation map of
	// signalID → effective weight. When non-nil, runPrimitiveSignals
	// and runCompoundRules consult this map after Fires() returns true
	// and use the override in place of the registered (constant)
	// weight. Pain 9: tunable per-signal weights via the
	// `risk_weight_overrides` table. Default-off — callers gate this
	// behind the `risk_threshold_overrides` feature flag and pass nil
	// when the flag is off, so the evaluator hot path stays free of
	// per-signal map lookups in the default deployment.
	SignalWeightOverrides map[string]int
}

func (o Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// categoryBase is the starting subscore for each category before signals
// are applied. Positive signals push above the base; negative signals pull
// below. 100 = perfect; bottoms at 0.
const categoryBase = 100

// verdict thresholds — kept as package-level consts so tests and docs share
// the same cutoffs with the decision table.
const (
	thresholdQuarantine = 30 // overall < 30 → quarantine or upgrade-available
	thresholdWarn       = 60 // 30..59 → warn
	// >= 60 → allow
)

// EvaluatePackage runs every registered signal and compound rule against
// the Input, computes per-category and overall scores, and resolves a
// Verdict + Resolution. Safe to call concurrently; no shared state is
// mutated.
//
// The result's DirectScore == RolledUp for single-package evaluations.
// The tree evaluator (future commit) produces distinct values by folding
// in transitive descendants.
func EvaluatePackage(in Input, opts Options) *Evaluation {
	fired := runPrimitiveSignals(in, opts.SignalWeightOverrides)

	// Short-circuit for instant-block signals. Checksum-mismatch gets the
	// same treatment as known-malicious — we know the bytes are wrong.
	if _, ok := fired[SignalSCKnownMalicious]; ok {
		return instantBlock(in, opts, fired, "Known-malicious package — do not install.")
	}
	if _, ok := fired[SignalQualChecksumMismatch]; ok {
		return instantBlock(in, opts, fired, "Artifact checksum mismatch — tampered or corrupted bytes.")
	}

	compoundFired := runCompoundRules(in, fired, opts.SignalWeightOverrides)

	catScores := computeCategoryScores(fired, compoundFired, in)
	overall := ComputeOverallWithWeights(catScores, opts.CategoryWeights)
	overall = applyMaxImpactCeiling(overall, fired, compoundFired)
	minScore, worst := minCategoryScore(catScores)

	direct := Score{
		Overall:          overall,
		Categories:       catScores,
		MinCategoryScore: minScore,
		WorstCategory:    worst,
	}
	verdict, resolution := resolveVerdict(overall, fired, compoundFired, opts)

	return &Evaluation{
		Key: Key{
			Ecosystem: in.Ecosystem,
			Package:   in.Package,
			Version:   in.Version,
		},
		DirectScore:   direct,
		RolledUp:      direct,
		Verdict:       verdict,
		Resolution:    resolution,
		EvaluatedAt:   opts.now(),
		EngineVersion: EngineVersion,
	}
}

// runPrimitiveSignals walks Registry and returns the map of fired signals
// keyed by ID. When overrides is non-nil and contains a key for a fired
// signal, the override is used in place of the registered constant
// weight. The default Weight on the registry is preserved for any
// signal not present in overrides — callers that want zero behavioural
// change pass nil.
func runPrimitiveSignals(in Input, overrides map[string]int) map[string]FiredSignal {
	out := make(map[string]FiredSignal, len(Registry))
	for id, sig := range Registry {
		ok, detail, evidence := sig.Fires(in)
		if !ok {
			continue
		}
		w := sig.Weight
		if overrides != nil {
			if ov, ok := overrides[id]; ok {
				w = float64(ov)
			}
		}
		out[id] = FiredSignal{
			ID:       id,
			Category: sig.Category,
			Title:    sig.Title,
			Severity: sig.Severity,
			Weight:   w,
			Detail:   detail,
			Evidence: evidence,
		}
	}
	return out
}

// runCompoundRules walks CompoundRules and returns the map of fired
// compound records keyed by ID. Compound rules have access to the set of
// primitives that already fired. The overrides map applies to compound
// IDs the same way it does for primitives.
func runCompoundRules(in Input, primitives map[string]FiredSignal, overrides map[string]int) map[string]FiredSignal {
	out := make(map[string]FiredSignal, len(CompoundRules))
	for _, rule := range CompoundRules {
		ok, detail, evidence := rule.Fires(in, primitives)
		if !ok {
			continue
		}
		w := rule.Weight
		if overrides != nil {
			if ov, ok := overrides[rule.ID]; ok {
				w = float64(ov)
			}
		}
		out[rule.ID] = FiredSignal{
			ID:       rule.ID,
			Category: rule.Category,
			Title:    rule.Title,
			Severity: rule.Severity,
			Weight:   w,
			Detail:   detail,
			Evidence: evidence,
			Compound: true,
		}
	}
	return out
}

// computeCategoryScores sums signal weights per category (plus compound
// rule weights), applies category-specific caps for composite signals
// (e.g., version anomaly), and clamps each to [0, 100].
func computeCategoryScores(primitives, compound map[string]FiredSignal, in Input) map[Category]CategoryScore {
	// Per-category accumulators.
	scores := make(map[Category]int, len(CategoryWeights))
	buckets := make(map[Category][]FiredSignal, len(CategoryWeights))
	for cat := range CategoryWeights {
		scores[cat] = categoryBase
	}

	// Primitives.
	for _, f := range primitives {
		// Sentinel weights (-1000) belong to short-circuit signals that
		// should already have been intercepted above; skip them here so
		// we don't corrupt the additive math if someone forgets.
		if f.Weight <= -999 {
			buckets[f.Category] = append(buckets[f.Category], f)
			continue
		}

		// SLSA level bonus is special-cased: dynamic per-level weight.
		// Mirrors the legacy trustscore.SLSALevelBonus contribution
		// (L2=+5, L3=+10, L4=+15).
		if f.ID == SignalSCSLSALevelBonus {
			var bonus int
			switch {
			case in.SLSALevel >= 4:
				bonus = 15
			case in.SLSALevel == 3:
				bonus = 10
			case in.SLSALevel == 2:
				bonus = 5
			}
			scores[f.Category] += bonus
			f.Weight = float64(bonus)
			buckets[f.Category] = append(buckets[f.Category], f)
			continue
		}

		// Version anomaly is special-cased: per-flag weight, capped.
		// f.Weight already carries the (possibly overridden) per-flag
		// weight — runPrimitiveSignals applied any
		// SignalWeightOverrides entry for SignalQualVersionAnomaly
		// before we got here. The cap (MaxVersionAnomalyPenalty) is
		// kept as a hardcoded floor; overriding per-flag weights is
		// the user-facing knob, the cap is engine policy.
		if f.ID == SignalQualVersionAnomaly {
			n := len(in.VersionAnomalyFlags)
			perFlag := int(f.Weight)
			if perFlag == 0 {
				perFlag = versionAnomalyWeightPerFlag
			}
			penalty := n * perFlag
			if penalty < MaxVersionAnomalyPenalty {
				penalty = MaxVersionAnomalyPenalty
			}
			scores[f.Category] += penalty
			// Reflect the actual applied weight on the fired record so
			// the UI shows what contributed to the score.
			f.Weight = float64(penalty)
			buckets[f.Category] = append(buckets[f.Category], f)
			continue
		}

		scores[f.Category] += int(f.Weight)
		buckets[f.Category] = append(buckets[f.Category], f)
	}

	// Compound rules add on top of primitives.
	for _, f := range compound {
		scores[f.Category] += int(f.Weight)
		buckets[f.Category] = append(buckets[f.Category], f)
	}

	// Clamp each category to [0, 100] and sort firedSignals for stable
	// output (by severity desc, then ID asc).
	out := make(map[Category]CategoryScore, len(scores))
	for cat, raw := range scores {
		clamped := raw
		if clamped < 0 {
			clamped = 0
		}
		if clamped > 100 {
			clamped = 100
		}
		list := buckets[cat]
		sort.SliceStable(list, func(i, j int) bool {
			if list[i].Severity.Rank() != list[j].Severity.Rank() {
				return list[i].Severity.Rank() > list[j].Severity.Rank()
			}
			return list[i].ID < list[j].ID
		})
		out[cat] = CategoryScore{
			Score:         clamped,
			Grade:         gradeForScore(clamped),
			DataAvailable: dataAvailable(cat, in),
			FiredSignals:  list,
		}
	}
	return out
}

// dataAvailable reports whether the underlying data feed for this
// category was actually consulted for the given Input. "Data
// unavailable" is a distinct outcome from "data clean" — a
// Vulnerability score of 100 with VulnDataAvailable=false means
// "never scanned", not "scanned and clean". The UI renders unavailable
// categories as "—" and the rollup re-normalises remaining weights.
//
// Currently only Vulnerability is gated because that is the regression
// surface — Maintenance always has Tier-1 publish/maintainer data on
// any cached package, and Quality/License/SupplyChain signals stay
// dormant when their underlying inputs are missing.
func dataAvailable(cat Category, in Input) bool {
	switch cat {
	case CategoryVulnerability:
		return in.VulnDataAvailable
	default:
		return true
	}
}

// computeOverall rolls category subscores into a single 0-100 overall score
// using the category weights from CategoryWeights:
//
//	deficit = sum_over_cat((100 - cat_score) * cat_weight)
//	overall = 100 - deficit
//
// This formula means each category contributes deficit proportional to its
// weight. A cat_score of 0 in Vulnerability removes 30 points from overall
// (30 * 0.30 * (100-0)/100 * 100 = 30). A cat_score of 100 everywhere = 100.
func computeOverall(cats map[Category]CategoryScore) int {
	// Re-normalise across categories whose data was actually scanned.
	// A category with DataAvailable=false would otherwise contribute its
	// (100 - clean = 0) deficit and silently behave like a perfect 100,
	// which collapses "we have no idea" into "all clear" — the regression
	// this rollup correction removes.
	availableWeight := 0.0
	for cat, weight := range CategoryWeights {
		cs, ok := cats[cat]
		if !ok || !cs.DataAvailable {
			continue
		}
		availableWeight += weight
	}
	if availableWeight == 0 {
		return 0
	}
	deficit := 0.0
	for cat, weight := range CategoryWeights {
		cs, ok := cats[cat]
		if !ok || !cs.DataAvailable {
			continue
		}
		deficit += float64(100-cs.Score) * (weight / availableWeight)
	}
	overall := 100 - int(deficit+0.5) // round-half-up
	if overall < 0 {
		overall = 0
	}
	if overall > 100 {
		overall = 100
	}
	return overall
}

// ComputeOverallFromCategories is the exported wrapper around
// computeOverall. The tree evaluator mutates the per-category subscores
// to fold in transitive deficits and needs to recompute Overall from
// the adjusted map; no caller outside internal/risk should need this
// otherwise. Additive — does not change any existing behaviour.
func ComputeOverallFromCategories(cats map[Category]CategoryScore) int {
	return computeOverall(cats)
}

// ComputeOverallWithWeights is the weights-aware sibling of
// computeOverall. When weights is nil the package-level CategoryWeights
// map is used, preserving bit-identical behaviour with computeOverall.
// When weights is non-nil the caller has validated & normalised the map
// (internal/orgweights.ResolveWeights does this) and the same
// deficit-rollup formula runs against those numbers.
//
// Additive — existing call sites that invoke computeOverall (or the
// ComputeOverallFromCategories wrapper) are unchanged. The per-
// evaluation override path goes through this function via
// Options.CategoryWeights.
func ComputeOverallWithWeights(cats map[Category]CategoryScore, weights map[Category]float64) int {
	if weights == nil {
		return computeOverall(cats)
	}
	// Re-normalise across DataAvailable categories — same correction as
	// computeOverall, applied to the per-evaluation weight overrides.
	availableWeight := 0.0
	for cat, weight := range weights {
		cs, ok := cats[cat]
		if !ok || !cs.DataAvailable {
			continue
		}
		availableWeight += weight
	}
	if availableWeight == 0 {
		return 0
	}
	deficit := 0.0
	for cat, weight := range weights {
		cs, ok := cats[cat]
		if !ok || !cs.DataAvailable {
			continue
		}
		deficit += float64(100-cs.Score) * (weight / availableWeight)
	}
	overall := 100 - int(deficit+0.5)
	if overall < 0 {
		overall = 0
	}
	if overall > 100 {
		overall = 100
	}
	return overall
}

// ResolveVerdictFromScore is the exported wrapper around resolveVerdict
// used by the tree evaluator when a rolled-up score crosses a verdict
// threshold. The fired-signal maps are forwarded unchanged so the
// resulting Resolution carries the same rationale as the single-package
// evaluation.
func ResolveVerdictFromScore(overall int, primitives, compound map[string]FiredSignal, opts Options) (Verdict, Resolution) {
	return resolveVerdict(overall, primitives, compound, opts)
}

// resolveVerdict runs the decision table from the plan (§5) against the
// overall score and the set of fired signals. Returns the verdict + a
// fully-populated Resolution.
//
// Critical-signal rule: if any primitive OR compound signal with severity
// Critical fired (other than instant-block, which already short-circuited),
// the verdict can never be Allow — we promote to the best-available
// resolution path. This prevents KEV / takeover-compound / other strong
// signals from being diluted by otherwise-clean categories.
func resolveVerdict(overall int, primitives, compound map[string]FiredSignal, opts Options) (Verdict, Resolution) {
	rationale := topRationale(primitives, compound, 3)
	hasCritical := hasCriticalSignal(primitives, compound)

	// Band 1: overall under the quarantine threshold.
	if overall < thresholdQuarantine {
		if opts.SafeUpgradeVersion != "" {
			return VerdictUpgradeAvailable, Resolution{
				Verdict:     VerdictUpgradeAvailable,
				Summary:     "High-risk version. Upgrade to a safer version.",
				SafeVersion: opts.SafeUpgradeVersion,
				Rationale:   rationale,
			}
		}
		if opts.Alternative != "" {
			return VerdictReplace, Resolution{
				Verdict:     VerdictReplace,
				Summary:     "Package is high-risk with no safe version. Consider an alternative.",
				Alternative: opts.Alternative,
				Rationale:   rationale,
			}
		}
		return VerdictQuarantine, Resolution{
			Verdict:   VerdictQuarantine,
			Summary:   "High-risk package with no known safe version or alternative. Manual review required.",
			Rationale: rationale,
		}
	}

	// Band 2: overall in warn band (30..59).
	if overall < thresholdWarn {
		// Critical-signal escalation: Critical signals (KEV, dangerous
		// pickle, takeover compound) MUST NOT resolve to bare Warn even
		// when the MaxImpact ceiling pins overall above the quarantine
		// threshold. Promote to upgrade/replace/quarantine so consumers
		// see a blocking-grade verdict.
		if hasCritical {
			if opts.SafeUpgradeVersion != "" {
				return VerdictUpgradeAvailable, Resolution{
					Verdict:     VerdictUpgradeAvailable,
					Summary:     "Critical signal present. Upgrade to a safer version.",
					SafeVersion: opts.SafeUpgradeVersion,
					Rationale:   rationale,
				}
			}
			if opts.Alternative != "" {
				return VerdictReplace, Resolution{
					Verdict:     VerdictReplace,
					Summary:     "Critical signal present. Consider an alternative package.",
					Alternative: opts.Alternative,
					Rationale:   rationale,
				}
			}
			return VerdictQuarantine, Resolution{
				Verdict:   VerdictQuarantine,
				Summary:   "Critical signal present with no upgrade or alternative path. Manual review required.",
				Rationale: rationale,
			}
		}
		// If a safe upgrade is known, prefer that over bare Warn.
		if opts.SafeUpgradeVersion != "" {
			return VerdictUpgradeAvailable, Resolution{
				Verdict:     VerdictUpgradeAvailable,
				Summary:     "Package has notable risk. A safer version is available.",
				SafeVersion: opts.SafeUpgradeVersion,
				Rationale:   rationale,
			}
		}
		return VerdictWarn, Resolution{
			Verdict:   VerdictWarn,
			Summary:   "Package has notable risk signals. Review before use.",
			Rationale: rationale,
		}
	}

	// Band 3: overall >= 60. Normally Allow — but if a Critical signal
	// fired, we do not allow. Promote to the best available resolution.
	if hasCritical {
		if opts.SafeUpgradeVersion != "" {
			return VerdictUpgradeAvailable, Resolution{
				Verdict:     VerdictUpgradeAvailable,
				Summary:     "Critical signal present despite otherwise-clean categories. Upgrade to a safer version.",
				SafeVersion: opts.SafeUpgradeVersion,
				Rationale:   rationale,
			}
		}
		if opts.Alternative != "" {
			return VerdictReplace, Resolution{
				Verdict:     VerdictReplace,
				Summary:     "Critical signal present. Consider an alternative package.",
				Alternative: opts.Alternative,
				Rationale:   rationale,
			}
		}
		return VerdictQuarantine, Resolution{
			Verdict:   VerdictQuarantine,
			Summary:   "Critical signal present with no upgrade or alternative path. Manual review required.",
			Rationale: rationale,
		}
	}

	return VerdictAllow, Resolution{
		Verdict: VerdictAllow,
		Summary: "Package shows no blocking risk signals.",
	}
}

// hasCriticalSignal returns true when any primitive or compound signal
// with Severity Critical fired. Instant-block signals (known-malicious,
// checksum-mismatch) are short-circuited before this function runs, so
// we never see them here — this exclusively catches elevated signals
// like KEV and the takeover-compound.
func hasCriticalSignal(primitives, compound map[string]FiredSignal) bool {
	for _, f := range primitives {
		if f.Severity == SevCritical {
			return true
		}
	}
	for _, f := range compound {
		if f.Severity == SevCritical {
			return true
		}
	}
	return false
}

// topRationale returns the IDs of the top-N fired signals sorted by
// severity-desc, then absolute-weight-desc, then ID-asc. Used to populate
// Resolution.Rationale.
func topRationale(primitives, compound map[string]FiredSignal, n int) []string {
	all := make([]FiredSignal, 0, len(primitives)+len(compound))
	for _, f := range primitives {
		if f.Severity == SevInfo {
			// Positive signals don't belong in a "why this is risky" list.
			continue
		}
		all = append(all, f)
	}
	for _, f := range compound {
		all = append(all, f)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Severity.Rank() != all[j].Severity.Rank() {
			return all[i].Severity.Rank() > all[j].Severity.Rank()
		}
		ai, aj := absF(all[i].Weight), absF(all[j].Weight)
		if ai != aj {
			return ai > aj
		}
		return all[i].ID < all[j].ID
	})
	if n > len(all) {
		n = len(all)
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = all[i].ID
	}
	return out
}

func absF(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// applyMaxImpactCeiling enforces per-signal max-overall ceilings.
//
// CALIBRATION APPROACH (chosen during the risk-V2 score-shift remediation —
// see docs/risk-v2-score-shift.md). The category-weighted-deficit rollup
// (computeOverall) systematically over-scores packages where a single
// severe signal lives in a low-weight category — e.g. SupplyChain at
// weight 0.35 means a -40 typosquat penalty (zeroed category) only
// removes 35 points from overall. Re-weighting categories (Approach B)
// would move every package's score; switching the rollup formula
// (Approach C) is too aggressive. Instead we keep the weighted-sum
// rollup for the common case and add a per-signal MaxImpact ceiling:
// each signal that declares a MaxImpact pins the overall score to <=
// that value when it fires alone or with other less-impactful signals.
// The smallest declared MaxImpact among fired primitives (and
// compound rules — though compound MaxImpact is read off Registry's
// CompoundRules slice via fired ID lookup if ever needed) wins.
//
// Floor factor: we use the literal MaxImpact value rather than scaling
// it because each signal's MaxImpact is a direct policy claim.
func applyMaxImpactCeiling(overall int, primitives, compound map[string]FiredSignal) int {
	// Compound rules indicate genuine multi-signal elevation; they bypass
	// the per-signal ceiling so the additive deficit from a compound stays
	// authoritative. The ceiling is for the lone-signal case where the
	// category-weighted-rollup undersells severity.
	if len(compound) > 0 {
		return overall
	}
	cap := -1 // -1 = no cap
	for id := range primitives {
		sig, ok := Registry[id]
		if !ok || sig.MaxImpact <= 0 {
			continue
		}
		if cap == -1 || sig.MaxImpact < cap {
			cap = sig.MaxImpact
		}
	}
	if cap == -1 {
		return overall
	}
	if overall > cap {
		return cap
	}
	return overall
}

// minCategoryScore returns the worst (lowest) category subscore and the
// category it came from. Used to populate Score.MinCategoryScore /
// WorstCategory for Socket-style "weakest dimension" gating
// (https://docs.socket.dev/docs/package-scores). Categories iterate in
// the stable order defined by AllCategories() so a tie returns a
// deterministic winner.
func minCategoryScore(cats map[Category]CategoryScore) (int, Category) {
	if len(cats) == 0 {
		return 0, ""
	}
	minScore := categoryBase
	var worst Category
	for _, cat := range AllCategories() {
		cs, ok := cats[cat]
		if !ok {
			continue
		}
		if worst == "" || cs.Score < minScore {
			minScore = cs.Score
			worst = cat
		}
	}
	return minScore, worst
}

// instantBlock produces a zero-score Quarantine verdict for instant-kill
// signals (known-malicious, checksum-mismatch). The fired signal map is
// preserved on category breakdowns so UI/API consumers still see the full
// evidence of WHY the package was blocked — we just skip the additive math.
func instantBlock(in Input, opts Options, fired map[string]FiredSignal, summary string) *Evaluation {
	cats := make(map[Category]CategoryScore, len(CategoryWeights))
	buckets := make(map[Category][]FiredSignal, len(CategoryWeights))
	for _, f := range fired {
		buckets[f.Category] = append(buckets[f.Category], f)
	}
	for cat := range CategoryWeights {
		list := buckets[cat]
		sort.SliceStable(list, func(i, j int) bool {
			if list[i].Severity.Rank() != list[j].Severity.Rank() {
				return list[i].Severity.Rank() > list[j].Severity.Rank()
			}
			return list[i].ID < list[j].ID
		})
		cats[cat] = CategoryScore{Score: 0, Grade: "F", DataAvailable: true, FiredSignals: list}
	}
	// Instant-block: every dimension is at floor — surface that
	// uniformly so MinCategoryScore consumers see the same picture as
	// Overall. WorstCategory left empty because no single category is
	// uniquely responsible.
	score := Score{Overall: 0, Categories: cats, MinCategoryScore: 0}
	return &Evaluation{
		Key: Key{
			Ecosystem: in.Ecosystem,
			Package:   in.Package,
			Version:   in.Version,
		},
		DirectScore:   score,
		RolledUp:      score,
		Verdict:       VerdictQuarantine,
		Resolution:    Resolution{Verdict: VerdictQuarantine, Summary: summary},
		EvaluatedAt:   opts.now(),
		EngineVersion: EngineVersion,
	}
}
