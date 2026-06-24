package githubactions

// report.go bridges scanner Findings into the per-workflow
// intelligence.Report shape consumed by the v2 risk-engine projector.
//
// Until this bridge existed, the scan-actions CLI and
// /api/v1/intel/evaluate-actions endpoint emitted findings directly
// without ever building an intelligence.Report — so the Wave 4 Action
// signals registered against the v2 engine never fired on user-facing
// scans. BuildReport closes that loop: it takes the same []Finding the
// CLI/API already had and produces the Report shape ProjectToRiskInput
// understands.
//
// Import note: this file adds a new edge githubactions -> intelligence.
// intelligence already imports typosquat and malware (both of which we
// also import) but does NOT import githubactions, so this edge is
// cycle-free. Verified by reading the import lists in
// internal/intelligence/*.go before adding the dependency.

import (
	"sort"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/risk"
)

// reportEcosystem is the synthetic ecosystem stamped onto every Report
// BuildReport produces. It matches the ecosystem string the typosquat
// detector uses for Action lookups, so future code that inspects the
// Report's Identity can route on a single canonical value.
const reportEcosystem = "github_actions"

// reportPackage is the synthetic package name used when none of the
// findings carry a usable owner/name pair (or when callers want to
// treat the entire scan as a single virtual package). The angle-bracket
// form mirrors how the CLI prints "<unknown>" for missing files —
// it is never a valid GitHub Actions slug, so consumers cannot mistake
// it for a real package coordinate.
const reportPackage = "<workflow scan>"

// BuildReport projects scanner Findings into the per-workflow
// intelligence.Report shape used by the v2 risk-engine projector. One
// Report per scan invocation; Identity uses ecosystem "github_actions"
// with a synthetic Package = "<workflow scan>" so the projector treats
// it like any other ecosystem report.
//
// The mapping from scanner.Finding to intelligence.ActionFinding is
// straightforward: Signal/Severity/Detail copy across, and Ref is
// reduced from the structured ActionRef to the raw `uses:` string
// (preferring f.Ref.Raw, falling back to a reconstructed
// "owner/name@version" when Raw is empty).
//
// The result is always non-nil: an empty findings slice still yields a
// Report with an Actions section whose Findings slice is empty, so
// callers can blindly hand the result to ProjectToRiskInput without a
// nil-check.
func BuildReport(findings []Finding) *intelligence.Report {
	out := &intelligence.Report{
		Identity: intelligence.IdentitySection{
			Ecosystem: reportEcosystem,
			Package:   reportPackage,
		},
		Actions: &intelligence.ActionsSection{
			Findings: make([]intelligence.ActionFinding, 0, len(findings)),
		},
	}
	for _, f := range findings {
		out.Actions.Findings = append(out.Actions.Findings, intelligence.ActionFinding{
			Signal:   f.Signal,
			Severity: f.Severity,
			Ref:      refString(f.Ref),
			Detail:   f.Detail,
		})
	}
	return out
}

// RiskBlock is the wire shape both the CLI JSON output and the v1
// evaluate-actions API response use to surface the v2 risk-engine view
// of a workflow scan. Signals lists the IDs that fired (sorted, stable);
// Fields carries the projected risk.Input fields with zero-values
// elided so the JSON stays compact.
//
// Living next to BuildReport keeps the entire scanner -> Report ->
// risk.Input -> risk.Evaluation pipeline buildable from a single
// package: callers just hand the helper a []Finding and emit the
// resulting block alongside their existing findings/summary output.
type RiskBlock struct {
	Signals []string       `json:"signals"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// EvaluateRisk runs scanner findings through BuildReport ->
// ProjectToRiskInput -> risk.EvaluatePackage and projects the result
// into a wire-friendly RiskBlock. The intent is the v2 risk-engine
// signals registered for Actions (Wave 4) and the `risk` block in CLI
// JSON / API output stay in sync without each call site re-implementing
// the projection.
//
// Signals are extracted from the Evaluation's primitive fired-signals
// (per-category) — we surface the full set, not just Action-prefixed
// IDs, because a workflow could in principle drag in non-Action signals
// via shared categories. Sorting is alphabetical for diffability.
//
// Fields are the action-specific projected booleans + ref slices, with
// zero values omitted so consumers don't have to reason about absent vs
// false. We deliberately do NOT dump the entire risk.Input — most of
// its fields are package-level (CVEs, EPSS, license, etc.) and are
// always zero for an Actions-only scan, so emitting them would just be
// noise.
func EvaluateRisk(findings []Finding) RiskBlock {
	report := BuildReport(findings)
	in := intelligence.ProjectToRiskInput(report)
	eval := risk.EvaluatePackage(in, risk.Options{})

	out := RiskBlock{Signals: collectFiredSignals(eval), Fields: actionInputFields(in)}
	return out
}

// collectFiredSignals walks every category's FiredSignals on the
// Evaluation's DirectScore (the only score populated for a single
// EvaluatePackage call) and returns a sorted, deduped slice of signal
// IDs. Returns an empty slice rather than nil so JSON encoding always
// emits "signals":[] for a clean evaluation.
func collectFiredSignals(eval *risk.Evaluation) []string {
	if eval == nil {
		return []string{}
	}
	seen := make(map[string]struct{})
	for _, cat := range eval.DirectScore.Categories {
		for _, s := range cat.FiredSignals {
			seen[s.ID] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// actionInputFields returns a map[string]any of the Action-related
// risk.Input fields, omitting zero values. This is the "projected
// risk.Input minus zero-value fields" surface documented in the
// scan-actions Wave-7 plan.
func actionInputFields(in risk.Input) map[string]any {
	out := make(map[string]any)
	if in.ActionRefUnpinned {
		out["ActionRefUnpinned"] = true
	}
	if len(in.ActionRefUnpinnedRefs) > 0 {
		out["ActionRefUnpinnedRefs"] = in.ActionRefUnpinnedRefs
	}
	if in.ActionRefTyposquat {
		out["ActionRefTyposquat"] = true
	}
	if len(in.ActionRefTyposquats) > 0 {
		out["ActionRefTyposquats"] = in.ActionRefTyposquats
	}
	if in.ActionRefUnknownPublisher {
		out["ActionRefUnknownPublisher"] = true
	}
	if len(in.ActionRefUnknownPublishers) > 0 {
		out["ActionRefUnknownPublishers"] = in.ActionRefUnknownPublishers
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// refString returns the raw `uses:` form of an ActionRef. Prefers
// ref.Raw (verbatim from the workflow) so blame display is exact;
// falls back to a synthesized "owner/name@version" so we never emit
// an empty Ref when the parser only populated the structured fields.
func refString(ref ActionRef) string {
	if ref.Raw != "" {
		return ref.Raw
	}
	if ref.Owner == "" && ref.Name == "" {
		return ""
	}
	s := ref.Owner + "/" + ref.Name
	if ref.Version != "" {
		s += "@" + ref.Version
	}
	return s
}
