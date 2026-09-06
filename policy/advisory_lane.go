package policy

// advisory_lane.go — the DARK ADVISORY LANE marker.
//
// THE DEFECT THIS NAMES. apt, yum, dnf, swift, huggingface (and cocoapods)
// declare ConditionCVE / ConditionEPSS / ConditionCVSS as SupportFull in
// proxy_matrix.go, but no lane populates the vulnerability signals behind
// those columns for them:
//
//   - the proxy lane: internal/hooks.selectTrivialTarget switches on
//     repository format and has no case for any of them. The alpine /
//     debian / redhat cases in that switch are CONTAINER-LAYER ecosystems
//     reached through the OCI inspector, never through an apt/yum/dnf
//     repository pull, so no vulnerability_metadata row is ever written.
//   - the intel lane: core/intelligence.supportedOSVEcosystems has no
//     bucket for any of them, so osvProvider.Supports returns false and
//     scanner.go skips it.
//
// So `{"cvssMin": 7.0}` in block mode on an apt repo evaluates forever
// against CVSSScore = 0.0, never matches, never blocks, and NOTHING
// recorded that the control did not run. That last clause is the whole
// bug: the operator cannot tell a control that CANNOT RUN from one that
// ran and found nothing.
//
// WHY THIS IS A MARKER AND NOT A MATRIX EDIT. Lowering those cells to
// SupportNone is the obvious fix and it is a PROXY FAIL-OPEN, twice over.
// Both halves are proved mechanically in
// unsupported_semantics_doctrine_test.go; the short form:
//
//  1. Support(...) == SupportNone makes detectUnsupported fire, and
//     evaluator.go `continue`s past the WHOLE policy. Every NEGATIVE-
//     POLARITY block rule keyed on these columns fires TODAY precisely
//     because the dark signal reads as "absent" — `isVulnerable: false`,
//     `cvssMax: 5.0`, `epssMax: 0.5` all match against the 0.0/false
//     zero values and BLOCK. Lowering the cell turns all three off.
//     That is the fail-open docs/plan_qa_phase8_remediation.md:1285
//     (P8-17 WITHDRAWN) and :1284 (P8-16, "RECONCILE UPWARD ONLY")
//     rejected, and it is why ten `pub` cells are held at Full in
//     internal/intelligence/premium/policy_matrix_provider_drift_test.go.
//
//  2. There is no proportionate consequence to swap in, either.
//     Conditions is a PURE CONJUNCTION (matchesConditions returns false
//     on the first mismatch), so "treat the unsupported column as a
//     non-match for that condition" and "skip the whole policy" are the
//     SAME VERDICT for every input. The only semantics that differs —
//     ignore the dark column and evaluate the rest — makes an allow-mode
//     rule match MORE coordinates, which converts a block into an allow.
//
// So the verdict machinery is left exactly where it is, and what ships is
// the fact that was missing: a distinct, recorded, operator-visible
// statement that a named condition on a named ecosystem had no advisory
// source behind it. Verdict-neutral by construction — nothing in this
// file is consulted by matchesPolicy, matchesConditions or resolveAction.
//
// KNOWN RESIDUAL — THE EVAL CACHE. Evaluator.Evaluate serves repeat
// coordinates from evalCache without re-entering evaluatePolicies, so a
// cached verdict emits no dark-lane event, exactly as it emits no
// unsupported-ecosystem skip event today. The marker is therefore a
// per-cache-miss signal, not a per-request counter: an operator sees the
// condition named, which is what they need, but must not read event
// COUNTS as request counts. Moving the emission above the cache would put
// an audit write on the hot path for every request; that trade was not
// worth making for a signal whose job is to name a misconfiguration once.
//
// WHY THE TABLE LIVES HERE AND NOT IN core/intelligence. The authoritative
// derivation is core/intelligence/advisory_coverage.go's
// ecosystemHasAdvisorySource (the complement of supportedOSVEcosystems)
// unioned with scannerAdvisedEcosystems. core/policy CANNOT import it:
// core/intelligence already imports core/policy, so the edge would be a
// cycle. Injecting it through a collaborator seam was the alternative and
// was rejected — an un-wired seam is a guard that cannot run, and this
// repo has been bitten by exactly that (CLAUDE.md §3). The table is
// therefore mirrored here, default-on, and pinned to the authority by
// TestPolicyAdvisoryLaneMatchesIntelligenceCoverage in core/intelligence,
// which CAN see both. Break either side and that test goes red.

// vulnerabilityLaneConditions are the matrix columns whose value is read
// out of the vulnerability advisory lane — the CVE feed (OSV bucket or a
// scanner-written vulnerability_metadata row) and the CVSS / EPSS scores
// carried on those advisories.
//
// ConditionMalwareIndex is deliberately NOT here. Malware rides a wholly
// separate lane (core/intelligence's malware coverage registry over the
// OSV/GHSA malicious-packages feed), whose coverage set is independent of
// supportedOSVEcosystems — swift is a definitive-source member with a
// completeness claim, huggingface is definitive-on-a-hit without one, and
// apt/yum/dnf are covered by no source but light up automatically through
// the registry's dynamic half. None of that is decided by the advisory
// feed, so an advisory-lane marker must not speak for it.
var vulnerabilityLaneConditions = []ConditionType{
	ConditionCVE,
	ConditionCVSS,
	ConditionEPSS,
}

// ecosystemsWithAdvisorySource is the set of matrix ecosystems for which
// SOME lane can produce a vulnerability advisory:
//
//   - an OSV bucket exists (core/intelligence.supportedOSVEcosystems), or
//   - the Trivy-backed scanner lane structurally advises on it
//     (core/intelligence.scannerAdvisedEcosystems — docker only, which
//     earns it: OCI layer inspection extracts real apk/dpkg/rpm packages
//     and looks each up against buckets upstream trivy-db genuinely
//     ships).
//
// Everything NOT in here is dark: huggingface, cocoapods, swift, apt,
// yum, dnf. cocoapods is in the dark set even though selectTrivialTarget
// DOES route it, because the bundle's cocoapods bucket is unverified —
// routed-but-unverified is the state that produced 61 false
// `ALLOW 97-100` rows in production and is exactly the state
// core/intelligence's scannerAdvisedEcosystems exists to exclude.
//
// Membership is a claim about a third-party bundle and about a different
// Go module's routing table; there is nothing in core/policy to derive it
// from, so it is hand-listed and pinned by the cross-module drift test
// named in the file header. Do not "simplify" it into a derivation.
var ecosystemsWithAdvisorySource = map[Ecosystem]struct{}{
	EcoNPM:      {},
	EcoPyPI:     {},
	EcoMaven:    {},
	EcoCargo:    {},
	EcoRubyGems: {},
	EcoNuGet:    {},
	EcoComposer: {},
	EcoGo:       {},
	EcoPub:      {},
	EcoDocker:   {},
}

// EcosystemHasAdvisorySource reports whether any lane in this build can
// produce a vulnerability advisory for the ecosystem. An unknown key
// answers TRUE: the marker exists to name a KNOWN absence, and claiming
// "no advisory source" about an ecosystem this build has never heard of
// would be a statement about coverage made from ignorance. (That is the
// same reasoning core/intelligence's knownEcosystems applies to a
// repository NAME leaking into the ecosystem field — `maven-hosted` is a
// routing bug, not an uncovered ecosystem.)
func EcosystemHasAdvisorySource(ecosystem Ecosystem) bool {
	if _, known := SupportMatrix[ecosystem]; !known {
		return true
	}
	_, ok := ecosystemsWithAdvisorySource[ecosystem]
	return ok
}

// EcosystemsWithoutAdvisorySource returns the dark ecosystems, sorted, for
// operator-facing surfaces (`chainsaw policy preflight`) and for the
// cross-module drift test.
func EcosystemsWithoutAdvisorySource() []Ecosystem {
	out := make([]Ecosystem, 0, 8)
	for _, eco := range AllEcosystems() {
		if !EcosystemHasAdvisorySource(eco) {
			out = append(out, eco)
		}
	}
	return out
}

// DarkAdvisoryConditions returns the vulnerability-lane columns a policy's
// conditions reference when the ecosystem has no advisory source behind
// them — i.e. the conditions that WILL be evaluated, against a zero value
// that no lane could ever have set.
//
// Empty for every supported ecosystem, and empty for a policy that uses
// none of the vulnerability-lane columns. The result is REPORTING ONLY;
// no caller may use it to skip, short-circuit or re-weight a rule. See
// the file header for why.
func DarkAdvisoryConditions(ecosystem Ecosystem, c Conditions) []ConditionType {
	if ecosystem == "" || EcosystemHasAdvisorySource(ecosystem) {
		return nil
	}
	used := ConditionsUsedBy(c)
	if len(used) == 0 {
		return nil
	}
	inUse := make(map[ConditionType]struct{}, len(used))
	for _, u := range used {
		inUse[u] = struct{}{}
	}
	var out []ConditionType
	for _, cond := range vulnerabilityLaneConditions {
		if _, ok := inUse[cond]; !ok {
			continue
		}
		// A column that is ALSO SupportNone for this ecosystem is
		// already reported by detectUnsupported, with the whole policy
		// skipped. Reporting it twice under two reasons would tell the
		// operator the rule both did and did not run.
		if IsUnsupported(ecosystem, cond) {
			continue
		}
		out = append(out, cond)
	}
	return out
}
