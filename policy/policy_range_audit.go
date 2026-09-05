package policy

import (
	"errors"
	"fmt"
	"math"
	"reflect"

	"github.com/chain305/chainsaw-core/tenancy"
)

// policy_range_audit.go — the discovery half of the A1 threshold bounds.
//
// A1 (commit 514ead3f) stopped NEW out-of-range thresholds from being
// written: Store.Create refuses them outright, and Store.Update refuses
// only the violations an edit INTRODUCES so that a pre-existing row can
// still be disabled, approved or rolled back. That grandfathering is
// deliberate and correct — and it is also why a row already carrying
// `cvssMin: 999` stays exactly as it is, forever, with nothing anywhere
// telling the operator it exists. In block mode that row reads as "we
// refuse criticals" on every screen that lists it, and blocks nothing.
// The mirror case, `cvssMin: 0`, is inside the bound Create enforces
// (so it is not even a violation) and matches every package including
// ones with no CVE at all — a match-all block.
//
// This file answers "which of my live rows are like that, and what does
// each one actually do?" It is READ-ONLY and it never repairs anything:
// rewriting a block policy's threshold changes what that policy refuses,
// which is an operator's decision, not a sweep's.
//
// Every classification below is derived from the evaluator's own compare
// in matchesConditions (core/policy/evaluator.go), not from the field
// name. Each rule records the comparison it was derived from in
// RangeAuditFinding.Comparison so a reviewer can check the claim against
// the evaluator without trusting this file's prose.

// Severity of a range-audit finding.
const (
	// RangeAuditSeverityError marks a value OUTSIDE the bound
	// Store.Create now enforces. The API would refuse this value today;
	// the row predates the bound (or was written straight to SQL).
	RangeAuditSeverityError = "error"
	// RangeAuditSeverityWarning marks a value INSIDE the bound that is
	// nevertheless degenerate — the evaluator's compare is satisfied by
	// every package. `cvssMin: 0` is the canonical case, and it is the
	// same call `chainsaw policy lint` makes for policy FILES.
	RangeAuditSeverityWarning = "warning"
)

// Effect of the value on the evaluator's compare.
const (
	// RangeEffectNeverFires: no package can satisfy the compare. A
	// policy's conditions are AND-ed, so one unsatisfiable condition
	// means the whole policy never matches.
	RangeEffectNeverFires = "never_fires"
	// RangeEffectMatchesEverything: every package satisfies the compare,
	// including one carrying no data for the signal at all.
	RangeEffectMatchesEverything = "matches_everything"
)

// RangeAuditFinding is one out-of-range or degenerate numeric condition
// on one policy row, with the consequence spelled out.
type RangeAuditFinding struct {
	OrgID      string `json:"orgId,omitempty"`
	PolicyID   string `json:"policyId"`
	PolicyName string `json:"policyName"`
	// Kind is the policy's role in evaluation — "exception" and
	// "routing" rows never have their conditions read at all, which the
	// Consequence says in words.
	Kind   string `json:"kind,omitempty"`
	Mode   string `json:"mode"`
	Status string `json:"status"`

	Severity string  `json:"severity"`
	Field    string  `json:"field"`
	Value    float64 `json:"value"`
	// Min and Max are the legal bounds for Field; nil means unbounded on
	// that side (packageAge has no ceiling). ValidRange is the same
	// thing in words, for the text rendering.
	Min        *float64 `json:"min,omitempty"`
	Max        *float64 `json:"max,omitempty"`
	ValidRange string   `json:"validRange"`

	Effect string `json:"effect"`
	// Comparison quotes the evaluator compare this finding was derived
	// from, so the consequence can be checked rather than believed.
	Comparison  string `json:"comparison"`
	Consequence string `json:"consequence"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// rangeStyle is which side of the compare the threshold sits on.
type rangeStyle int

const (
	// styleMin: the evaluator DROPS the package when signal < value, so
	// a value above the signal's ceiling can never be met and a value at
	// or below its floor is always met.
	styleMin rangeStyle = iota
	// styleMax: the evaluator DROPS the package when signal > value.
	styleMax
)

// rangeFieldRule describes one numeric condition: the bound Store.Create
// enforces, the DOMAIN of the signal the evaluator compares it against,
// and which way the compare runs. Everything else is derived.
type rangeFieldRule struct {
	field       string // dotted JSON path, matching RangeError.Field
	structField string // Conditions field name, for the "what else narrows this?" question
	style       rangeStyle

	// boundMin/boundMax is the range Store.Create accepts. Inf means
	// unbounded on that side.
	boundMin, boundMax float64
	// signalMin/signalMax is the range the SIGNAL itself can take. It is
	// not always the same as the bound: requireSlsaLevel is bounded to
	// [1,4] but SLSALevel is 0 for an unattested package, which is why
	// requireSlsaLevel: 0 matches everything rather than nothing.
	signalMin, signalMax float64

	// signal names the thing being compared ("CVSS score").
	signal string
	// comparison quotes the evaluator.
	comparison string
	// floorMeans explains what a package with NO data scores, so the
	// match-all consequence names it ("a package with no CVE at all
	// scores 0").
	floorMeans string
	// absentPopulation, when non-empty, is the qualifier for a signal a
	// package can LACK entirely — the trust-score bounds fail closed on
	// a nil score, so "matches everything" is really "matches everything
	// that has a trust score".
	absentPopulation string
	suggestion       string

	get func(Conditions) (float64, bool)
}

func f64(v float64) *float64 { return &v }

// rangeFieldRules is the whole bounded surface, in report order. It
// mirrors conditionRangeViolations (store.go) field for field —
// TestAuditPolicyRanges_CoversEveryStoreRangeError pins that any value
// Store.Create refuses is reported here.
var rangeFieldRules = []rangeFieldRule{
	{
		field: "conditions.cvssMin", structField: "CVSSMin", style: styleMin,
		boundMin: 0, boundMax: 10, signalMin: 0, signalMax: 10,
		signal:     "CVSS score",
		comparison: "the evaluator drops the package when ctx.CVSSScore < cvssMin",
		floorMeans: "a package with no CVE at all scores 0",
		suggestion: "use a real severity floor (cvssMin: 7 for high, 9 for critical), or pair the rule with isVulnerable: true",
		get:        func(c Conditions) (float64, bool) { return derefFloat(c.CVSSMin) },
	},
	{
		field: "conditions.cvssMax", structField: "CVSSMax", style: styleMax,
		boundMin: 0, boundMax: 10, signalMin: 0, signalMax: 10,
		signal:     "CVSS score",
		comparison: "the evaluator drops the package when ctx.CVSSScore > cvssMax",
		floorMeans: "a package with no CVE at all scores 0",
		suggestion: "drop the upper bound entirely if the rule is not meant to exclude the most severe CVEs",
		get:        func(c Conditions) (float64, bool) { return derefFloat(c.CVSSMax) },
	},
	{
		field: "conditions.epssMin", structField: "EPSSMin", style: styleMin,
		boundMin: 0, boundMax: 1, signalMin: 0, signalMax: 1,
		signal:     "EPSS probability",
		comparison: "the evaluator drops the package when ctx.EPSSScore < epssMin",
		floorMeans: "a package with no EPSS record at all scores 0",
		suggestion: "use a real probability floor (epssMin: 0.1), or pair the rule with isVulnerable: true",
		get:        func(c Conditions) (float64, bool) { return derefFloat(c.EPSSMin) },
	},
	{
		field: "conditions.epssMax", structField: "EPSSMax", style: styleMax,
		boundMin: 0, boundMax: 1, signalMin: 0, signalMax: 1,
		signal:     "EPSS probability",
		comparison: "the evaluator drops the package when ctx.EPSSScore > epssMax",
		floorMeans: "a package with no EPSS record at all scores 0",
		suggestion: "drop the upper bound entirely if the rule is not meant to exclude the most exploitable CVEs",
		get:        func(c Conditions) (float64, bool) { return derefFloat(c.EPSSMax) },
	},
	{
		field: "conditions.trustScoreMin", structField: "TrustScoreMin", style: styleMin,
		boundMin: 0, boundMax: 100, signalMin: 0, signalMax: 100,
		signal:           "trust score",
		comparison:       "the evaluator drops the package when it has no trust score, or when ctx.TrustScore < trustScoreMin",
		floorMeans:       "the lowest score a rated package can carry is 0",
		absentPopulation: "a package with no trust score matches neither trust bound",
		suggestion:       "use a real floor (trustScoreMin: 40), or express the intent with signalsUnavailable instead",
		get:              func(c Conditions) (float64, bool) { return derefInt(c.TrustScoreMin) },
	},
	{
		field: "conditions.trustScoreMax", structField: "TrustScoreMax", style: styleMax,
		boundMin: 0, boundMax: 100, signalMin: 0, signalMax: 100,
		signal:           "trust score",
		comparison:       "the evaluator drops the package when it has no trust score, or when ctx.TrustScore > trustScoreMax",
		floorMeans:       "the lowest score a rated package can carry is 0",
		absentPopulation: "a package with no trust score matches neither trust bound",
		suggestion:       "drop the upper bound entirely if the rule is not meant to exclude well-rated packages",
		get:              func(c Conditions) (float64, bool) { return derefInt(c.TrustScoreMax) },
	},
	{
		field: "conditions.requireSlsaLevel", structField: "RequireSLSALevel", style: styleMin,
		boundMin: 1, boundMax: 4, signalMin: 0, signalMax: 4,
		signal:     "SLSA build level",
		comparison: "the evaluator drops the package when ctx.SLSALevel < requireSlsaLevel",
		floorMeans: "an unattested package is level 0",
		suggestion: "SLSA levels run 1-4; use requireAttestation: true for the 'any verified attestation' rule",
		get:        func(c Conditions) (float64, bool) { return derefInt(c.RequireSLSALevel) },
	},
	{
		// packageAge is a MAXIMUM age: the evaluator keeps packages
		// younger than it. There is no ceiling to be degenerate against,
		// so only a negative value is reportable.
		field: "conditions.packageAge", structField: "PackageAge", style: styleMax,
		boundMin: 0, boundMax: math.Inf(1), signalMin: 0, signalMax: math.Inf(1),
		signal:     "package age in days",
		comparison: "the evaluator drops the package when its age in days > packageAge",
		floorMeans: "a package published today is 0 days old",
		suggestion: "packageAge is a maximum age in days and cannot be negative",
		get:        func(c Conditions) (float64, bool) { return derefInt(c.PackageAge) },
	},
	{
		field: "conditions.cooldownDays", structField: "CooldownDays", style: styleMax,
		boundMin: 0, boundMax: math.Inf(1), signalMin: 0, signalMax: math.Inf(1),
		signal:     "version publish age in days",
		comparison: "the evaluator drops the package when this version's age in days > cooldownDays",
		floorMeans: "a version published today is 0 days old",
		suggestion: "cooldownDays is a window in days and cannot be negative",
		get:        func(c Conditions) (float64, bool) { return derefInt(c.CooldownDays) },
	},
}

func derefFloat(v *float64) (float64, bool) {
	if v == nil {
		return 0, false
	}
	return *v, true
}

func derefInt(v *int) (float64, bool) {
	if v == nil {
		return 0, false
	}
	return float64(*v), true
}

// AuditRanges reports every numeric condition in this store's org whose
// value the evaluator can never satisfy, or always satisfies. Read-only:
// it lists and classifies, and changes nothing.
func (s *Store) AuditRanges() ([]RangeAuditFinding, error) {
	if s == nil || s.sql == nil {
		return nil, errors.New("policy store unavailable")
	}
	policies, err := s.List()
	if err != nil {
		return nil, err
	}
	return AuditPolicyRanges(tenancy.NormalizeOrgID(s.orgID), policies), nil
}

// AuditPolicyRanges is AuditRanges over an already-fetched set, so the
// CLI can audit what `GET /api/policies` returned without a database.
// orgID is stamped on every finding and may be empty when the caller does
// not know it (the policies list endpoint does not carry one).
//
// Findings preserve the input order of policies (List() sorts by
// precedence) and, within a policy, the order of rangeFieldRules.
func AuditPolicyRanges(orgID string, policies []Policy) []RangeAuditFinding {
	var out []RangeAuditFinding
	for _, p := range policies {
		out = append(out, auditOnePolicy(orgID, p)...)
	}
	return out
}

func auditOnePolicy(orgID string, p Policy) []RangeAuditFinding {
	type candidate struct {
		finding RangeAuditFinding
		rule    rangeFieldRule
		// ceilingOnly marks an in-bound upper bound sitting at the top of
		// its signal's domain (cvssMax: 10). That is idiomatic shorthand
		// for "no upper limit" whenever the rule narrows on something
		// else, and is only worth reporting when it does not.
		ceilingOnly bool
		// pairViolation marks a min>max contradiction, which is
		// unsatisfiable because of its sibling rather than because the
		// signal cannot reach the threshold. The consequence sentence has
		// to say so or it states something visibly false.
		pairViolation bool
	}
	var cands []candidate

	for _, r := range rangeFieldRules {
		v, ok := r.get(p.Conditions)
		if !ok {
			continue
		}
		effect, degenerate := classifyValue(r, v)
		if !degenerate {
			continue
		}
		f := RangeAuditFinding{
			OrgID:      orgID,
			PolicyID:   p.ID,
			PolicyName: p.Name,
			Kind:       string(p.Kind),
			Mode:       string(p.Mode),
			Status:     string(p.Status),
			Severity:   severityFor(r, v),
			Field:      r.field,
			Value:      v,
			Effect:     effect,
			Comparison: r.comparison,
			Suggestion: r.suggestion,
		}
		f.Min, f.Max, f.ValidRange = boundsOf(r)
		cands = append(cands, candidate{
			finding:     f,
			rule:        r,
			ceilingOnly: r.style == styleMax && effect == RangeEffectMatchesEverything && f.Severity == RangeAuditSeverityWarning,
		})
	}

	// The min>max pairs. Mirrors conditionRangeViolations: a pair is only
	// compared when both halves are individually legal, so one bad value
	// produces one finding rather than two.
	for _, pf := range pairFindings(p) {
		cands = append(cands, candidate{finding: pf, rule: ruleFor(pf.Field), pairViolation: true})
	}
	if len(cands) == 0 {
		return nil
	}

	// A field that matches everything narrows nothing, so it must not
	// count as the "other constraint" that makes a sibling look harmless.
	// cvssMin: 0 paired with cvssMax: 10 is two inert conditions, not two
	// narrowings, and the policy matches every package.
	inert := map[string]bool{}
	for _, c := range cands {
		if c.finding.Effect == RangeEffectMatchesEverything {
			inert[c.rule.structField] = true
		}
	}

	out := make([]RangeAuditFinding, 0, len(cands))
	for _, c := range cands {
		narrowed := narrowsBeyond(p, c.rule.structField, inert)
		if c.ceilingOnly && narrowed {
			continue
		}
		c.finding.Consequence = rangeConsequence(p, c.rule, c.finding, narrowed, c.pairViolation)
		out = append(out, c.finding)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// classifyValue is the whole derivation. styleMin drops the package when
// the signal is BELOW the value, so a value above the signal's ceiling can
// never be met and one at or below its floor always is; styleMax is the
// mirror. NaN is neither: every float comparison against it is false, so
// the evaluator never drops anything.
func classifyValue(r rangeFieldRule, v float64) (string, bool) {
	if math.IsNaN(v) {
		return RangeEffectMatchesEverything, true
	}
	switch r.style {
	case styleMin:
		if v > r.signalMax {
			return RangeEffectNeverFires, true
		}
		if v <= r.signalMin {
			return RangeEffectMatchesEverything, true
		}
	case styleMax:
		if v < r.signalMin {
			return RangeEffectNeverFires, true
		}
		if v >= r.signalMax {
			return RangeEffectMatchesEverything, true
		}
	}
	return "", false
}

func severityFor(r rangeFieldRule, v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < r.boundMin || v > r.boundMax {
		return RangeAuditSeverityError
	}
	return RangeAuditSeverityWarning
}

func boundsOf(r rangeFieldRule) (*float64, *float64, string) {
	var min, max *float64
	if !math.IsInf(r.boundMin, -1) {
		min = f64(r.boundMin)
	}
	if !math.IsInf(r.boundMax, 1) {
		max = f64(r.boundMax)
	}
	switch {
	case min != nil && max != nil:
		return min, max, fmt.Sprintf("%s to %s", formatBound(*min), formatBound(*max))
	case min != nil:
		return min, nil, fmt.Sprintf("%s or greater", formatBound(*min))
	case max != nil:
		return nil, max, fmt.Sprintf("%s or less", formatBound(*max))
	default:
		return nil, nil, "unbounded"
	}
}

func ruleFor(field string) rangeFieldRule {
	for _, r := range rangeFieldRules {
		if r.field == field {
			return r
		}
	}
	return rangeFieldRule{field: field}
}

// pairFindings reports the min>max contradictions. Each is reported on
// the MIN field with the sibling's value as the ceiling, exactly as
// conditionRangeViolations reports it, so the two surfaces name the same
// field for the same row.
func pairFindings(p Policy) []RangeAuditFinding {
	var out []RangeAuditFinding
	add := func(minField string, lo, hi float64) {
		r := ruleFor(minField)
		f := RangeAuditFinding{
			PolicyID:   p.ID,
			PolicyName: p.Name,
			Kind:       string(p.Kind),
			Mode:       string(p.Mode),
			Status:     string(p.Status),
			Severity:   RangeAuditSeverityError,
			Field:      minField,
			Value:      lo,
			Min:        f64(r.boundMin),
			Max:        f64(hi),
			ValidRange: fmt.Sprintf("%s to %s", formatBound(r.boundMin), formatBound(hi)),
			Effect:     RangeEffectNeverFires,
			Comparison: r.comparison + ", and again when it is above the paired maximum",
			Suggestion: "the minimum is above the maximum; no " + r.signal + " can satisfy both",
		}
		out = append(out, f)
	}
	c := p.Conditions
	if inBound(c.CVSSMin, 0, 10) && inBound(c.CVSSMax, 0, 10) && c.CVSSMin != nil && c.CVSSMax != nil && *c.CVSSMin > *c.CVSSMax {
		add("conditions.cvssMin", *c.CVSSMin, *c.CVSSMax)
	}
	if inBound(c.EPSSMin, 0, 1) && inBound(c.EPSSMax, 0, 1) && c.EPSSMin != nil && c.EPSSMax != nil && *c.EPSSMin > *c.EPSSMax {
		add("conditions.epssMin", *c.EPSSMin, *c.EPSSMax)
	}
	if inBoundInt(c.TrustScoreMin, 0, 100) && inBoundInt(c.TrustScoreMax, 0, 100) &&
		c.TrustScoreMin != nil && c.TrustScoreMax != nil && *c.TrustScoreMin > *c.TrustScoreMax {
		add("conditions.trustScoreMin", float64(*c.TrustScoreMin), float64(*c.TrustScoreMax))
	}
	return out
}

func inBound(v *float64, lo, hi float64) bool {
	if v == nil {
		return true
	}
	return !math.IsNaN(*v) && !math.IsInf(*v, 0) && *v >= lo && *v <= hi
}

func inBoundInt(v *int, lo, hi float64) bool {
	if v == nil {
		return true
	}
	return float64(*v) >= lo && float64(*v) <= hi
}

// narrowsBeyond reports whether the policy constrains anything besides
// the named condition field and the other fields that match everything.
// An identifier or a scope counts; a bare parameter field that the
// evaluator only reads inside another condition's branch does not
// (nonConstrainingConditionFields, store.go).
func narrowsBeyond(p Policy, structField string, inert map[string]bool) bool {
	if hasPolicyIdentifier(p.Identifier) || hasPolicyScope(p.Scope) {
		return true
	}
	v := reflect.ValueOf(p.Conditions)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" || f.Name == structField || inert[f.Name] {
			continue
		}
		if _, skip := nonConstrainingConditionFields[f.Name]; skip {
			continue
		}
		if conditionFieldIsSet(v.Field(i)) {
			return true
		}
	}
	return false
}

// rangeConsequence turns the classification into the sentence an
// operator can act on. Order matters: a row whose conditions the
// evaluator never reads has no enforcement consequence at all, and
// saying otherwise would send someone to edit a rule that does nothing.
func rangeConsequence(p Policy, r rangeFieldRule, f RangeAuditFinding, narrowed, pairViolation bool) string {
	switch p.Kind {
	case KindException:
		return "no effect on enforcement: this row is an exception, and the evaluator matches an exception on its identifier and scope alone — it never reads these conditions."
	case KindRouting:
		return "no effect on enforcement: routing rules are evaluated by the routing engine, which never reads conditions and never gates an install."
	}

	var s string
	switch f.Effect {
	case RangeEffectNeverFires:
		// A min>max pair is unsatisfiable because of its SIBLING, not
		// because the signal cannot reach the threshold. Saying "no
		// package's trust score can reach 80 — the highest possible is
		// 100" is visibly false and sends the reader to the wrong half of
		// the rule; the contradiction is the maximum of 20.
		why := whyNever(r, f.Value)
		if pairViolation {
			why = whyNeverPair(r, f.Value, f.Max)
		}
		s = fmt.Sprintf("never fires: %s, and a policy's conditions are AND-ed, so this %s policy %s.",
			why, modeNoun(p.Mode), modeMatchesNothing(p.Mode))
	case RangeEffectMatchesEverything:
		why := whyAll(r, f.Value)
		if narrowed {
			s = fmt.Sprintf("matches every package (%s), so this condition narrows nothing — what the policy does is decided entirely by its other conditions.", why)
		} else {
			s = fmt.Sprintf("matches every package (%s), and nothing else on this policy narrows it, so this %s policy %s.",
				why, modeNoun(p.Mode), modeMatchesEverything(p.Mode, r.absentPopulation != ""))
		}
	default:
		return ""
	}
	if p.Status != StatusEnabled {
		s += fmt.Sprintf(" The row is %s, so it does not evaluate until it is enabled.", statusNoun(p.Status))
	}
	return s
}

// whyNeverPair explains a min>max contradiction in terms of the pair,
// which is the only thing that makes it unsatisfiable.
func whyNeverPair(r rangeFieldRule, lo float64, hi *float64) string {
	if hi == nil {
		return fmt.Sprintf("the minimum %s is above the paired maximum", r.signal)
	}
	return fmt.Sprintf("no package's %s can be at or above %s and at or below %s at the same time",
		r.signal, formatBound(lo), formatBound(*hi))
}

func whyNever(r rangeFieldRule, v float64) string {
	if r.style == styleMin {
		if math.IsInf(r.signalMax, 1) {
			return fmt.Sprintf("no package's %s can reach %s", r.signal, formatBound(v))
		}
		return fmt.Sprintf("no package's %s can reach %s — the highest possible is %s",
			r.signal, formatBound(v), formatBound(r.signalMax))
	}
	return fmt.Sprintf("no package's %s can be at or below %s — the lowest possible is %s",
		r.signal, formatBound(v), formatBound(r.signalMin))
}

func whyAll(r rangeFieldRule, v float64) string {
	if math.IsNaN(v) {
		return fmt.Sprintf("a NaN threshold makes every %s comparison false, so nothing is ever excluded", r.signal)
	}
	base := ""
	if r.style == styleMin {
		base = fmt.Sprintf("every package's %s is at or above %s", r.signal, formatBound(v))
	} else {
		base = fmt.Sprintf("every package's %s is at or below %s", r.signal, formatBound(v))
	}
	if r.absentPopulation != "" {
		return fmt.Sprintf("%s, and %s, so this matches every rated package; %s", base, r.floorMeans, r.absentPopulation)
	}
	return fmt.Sprintf("%s — %s", base, r.floorMeans)
}

// modeNoun is the mode as it reads in a sentence.
func modeNoun(m Mode) string {
	if m == ModeBlockAfterGrace {
		return "block-after-grace"
	}
	if m == "" {
		return "unset-mode"
	}
	return string(m)
}

func statusNoun(s Status) string {
	if s == "" {
		return "in an unset status"
	}
	return string(s)
}

// modeMatchesNothing / modeMatchesEverything render what the policy DOES
// once the condition's behaviour is known. block_after_grace is a block
// with a downgrade window, so it is spoken as one.
func modeMatchesNothing(m Mode) string {
	switch m {
	case ModeBlock:
		return "blocks nothing"
	case ModeBlockAfterGrace:
		return "blocks nothing once its grace window ends"
	case ModeQuarantine:
		return "quarantines nothing"
	case ModeMonitor:
		return "records nothing"
	case ModeAllow:
		return "exempts nothing"
	default:
		return "matches nothing"
	}
}

func modeMatchesEverything(m Mode, ratedOnly bool) string {
	subject := "every request that reaches it"
	if ratedOnly {
		subject = "every request whose package carries the signal"
	}
	switch m {
	case ModeBlock:
		return "blocks " + subject
	case ModeBlockAfterGrace:
		return "blocks " + subject + " once its grace window ends"
	case ModeQuarantine:
		return "quarantines " + subject
	case ModeMonitor:
		return "records a would-block for " + subject
	case ModeAllow:
		return "exempts " + subject + " from every lower-priority rule"
	default:
		return "matches " + subject
	}
}
