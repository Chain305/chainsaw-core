package intelligence

import (
	"fmt"
	"sort"
	"strings"

	"github.com/chain305/chainsaw-core/metadata"
	"github.com/chain305/chainsaw-core/risk"
)

// supplychain_alert.go is the non-CVE half of the after-the-fact alerter.
// DiffReports (vuln_alert.go) iterates next.Vulnerabilities.CVEs and
// nothing else, so a coordinate that flips clean → malicious on the
// malware feed, on a typosquat matcher fix, on a publisher-change signal
// or on a risk-verdict recompute produced ZERO alerts: the refresher
// re-verdicted it correctly and nobody was told. This file computes that
// diff; the dispatch (finding, webhook, events row) lives in
// internal/server/recall_alerts.go.
//
// Shape and conventions deliberately mirror DiffReports: nil prior means
// no diff window, one event per trigger, deterministic output order.
//
// SCOPE. This diffs a deliberately SMALL set of signals — malware,
// typosquat, publisher change, the two install-script bools, and the
// risk verdict. It is NOT a general "what changed" diff, and reading it
// as one will mislead you. Most of ArtifactScanSection is untouched:
// MaliciousIOC, ImportTimeExecution, BuildRsExecutes, HiddenUnicodeHits,
// ManifestConfusion, DangerousPickleOpcode, NonExistentAuthor,
// FirstTimeCollaborator and the rest, plus VersionAnomaly,
// RepoLinkStatus and PublishVelocityAnomaly. A package that gains three
// of those between scans while its verdict band holds produces ZERO
// events — the verdict trigger is what is meant to catch the composite,
// and it only fires when the band actually moves.
//
// It is also a STATE diff, not an EVENT diff. A second distinct
// observation inside an already-bad state is silent: malware id MAL-1 ->
// MAL-2 (a different payload), publisher added eve -> added mallory (a
// second takeover), typosquat target lodash -> react (a retarget) all
// emit nothing, because the answer to "would this be refused now?" did
// not change. Defensible, and deliberate, but it means recall is not an
// audit trail of everything that happened to a coordinate.
//
// Three fields are deliberately NOT diffed here:
//
//   - SupplyChain.ReservedNamespaceViolation — no provider writes it
//     (report.go, the ReservedNamespaceViolation doc comment). A diff
//     over a field with no writer can only ever produce noise.
//   - SupplyChain.RepoLastCommitAt / RepoArchived — in-memory mirrors
//     that the persistence layer does not store, so the loaded `prior`
//     never carries them and EVERY refresh would look like a flip. The
//     persisted equivalents live on MaintenanceSection.

// SupplyChainAlertTrigger discriminates why DiffSupplyChain emitted one
// event. Surfaced verbatim on the webhook payload's alert_reason field
// and inside the synthetic finding PolicyID (`recall:<trigger>`), so
// these strings are a wire contract — renames are breaking changes.
type SupplyChainAlertTrigger string

const (
	// AlertMalwareAppeared — SupplyChain.MalwareStatus became
	// "malicious". The recall case the whole feature exists for.
	AlertMalwareAppeared SupplyChainAlertTrigger = "malware_appeared"
	// AlertTyposquatAppeared — SupplyChain.TyposquatStatus entered a
	// suspect state ("suspected"/"confirmed") from a non-suspect one.
	AlertTyposquatAppeared SupplyChainAlertTrigger = "typosquat_appeared"
	// AlertPublisherChanged — SupplyChain.PublisherChanged went from
	// nil/false to true: a new principal can now push this coordinate.
	AlertPublisherChanged SupplyChainAlertTrigger = "publisher_changed"
	// AlertInstallScriptAppeared — an install script (or an install
	// script that fetches remote code) appeared on an artifact scan
	// that ran on BOTH sides of the diff — see the Scan.Performed guard
	// in DiffSupplyChain.
	AlertInstallScriptAppeared SupplyChainAlertTrigger = "install_script_appeared"
	// AlertVerdictDegraded — Report.Risk.Verdict moved to a strictly
	// worse KNOWN verdict. Transitions into or out of VerdictUnknown
	// are never reported; see recallVerdictRank.
	AlertVerdictDegraded SupplyChainAlertTrigger = "verdict_degraded"
)

// SupplyChainAlertEvent is one strengthening transition the diff found.
// PriorValue/NextValue record the transition verbatim for the audit
// trail; Detail carries the human-readable specifics (malware id,
// typosquat target, install-script kind).
type SupplyChainAlertEvent struct {
	OrgID     string
	RepoName  string
	Ecosystem string
	Package   string
	Version   string
	Trigger   SupplyChainAlertTrigger
	Detail    string
	PriorValue,
	NextValue string
}

// DiffSupplyChain computes the strengthening supply-chain transitions
// implied by (prior, next).
//
// Only STRENGTHENING transitions are reported. clean → malicious is an
// alert; malicious → clean is not — that is a retraction, and a
// retraction path does not exist yet (plan_attestation_and_recall.md R2).
// The same asymmetry applies to every signal below.
//
// prior == nil returns nil, matching DiffReports: a first-ever scan of a
// coordinate has no reference frame and is not a recall.
func DiffSupplyChain(row metadata.PackageMetadataRow, ecosystem string, prior, next *Report) []SupplyChainAlertEvent {
	if next == nil || prior == nil {
		return nil
	}
	ps, ns := prior.SupplyChain, next.SupplyChain
	var out []SupplyChainAlertEvent
	add := func(trigger SupplyChainAlertTrigger, detail, priorVal, nextVal string) {
		out = append(out, SupplyChainAlertEvent{
			OrgID:      row.OrgID,
			RepoName:   row.Repository,
			Ecosystem:  ecosystem,
			Package:    row.Package,
			Version:    row.Version,
			Trigger:    trigger,
			Detail:     detail,
			PriorValue: priorVal,
			NextValue:  nextVal,
		})
	}

	if !malicious(ps.MalwareStatus) && malicious(ns.MalwareStatus) {
		detail := strings.TrimSpace(ns.MalwareSummary)
		if id := strings.TrimSpace(ns.MalwareID); id != "" {
			detail = strings.TrimSpace(id + " " + detail)
		}
		add(AlertMalwareAppeared, detail, statusText(ps.MalwareStatus), statusText(ns.MalwareStatus))
	}

	// Gated on the SAME predicate the is_typosquat column and the
	// inventory facet use (TyposquatIsActionable), not on "status is
	// suspected" alone. The two disagreeing means a low-confidence hit
	// mints a finding that the rest of the product calls not actionable
	// — and a matcher update that mass-reclassifies a cohort to
	// low-confidence suspected is precisely the event this feature was
	// built to notice, so the disagreement would surface at its worst
	// moment.
	priorSquat := TyposquatIsActionable(ps.TyposquatStatus, ps.TyposquatConfidence)
	nextSquat := TyposquatIsActionable(ns.TyposquatStatus, ns.TyposquatConfidence)
	if !priorSquat && nextSquat {
		target := strings.TrimSpace(ns.TyposquatSimilarTo)
		detail := "similar to " + target
		// Trimmed before the emptiness test, not after: a
		// whitespace-only target otherwise renders as "similar to "
		// with nothing after it.
		if target == "" {
			detail = "no target recorded"
		}
		if c := strings.TrimSpace(ns.TyposquatConfidence); c != "" {
			detail += " (confidence " + c + ")"
		}
		add(AlertTyposquatAppeared, detail, statusText(ps.TyposquatStatus), statusText(ns.TyposquatStatus))
	}

	if !boolVal(ps.PublisherChanged) && boolVal(ns.PublisherChanged) {
		add(AlertPublisherChanged, publisherDetail(ns), boolText(ps.PublisherChanged), boolText(ns.PublisherChanged))
	}

	// Artifact-derived triggers only when the artifact scan actually ran
	// on BOTH sides. A true → false Performed flip means "nobody looked",
	// not "it got better"; a false → true flip means "we finally looked",
	// not "a new risk appeared". Diffing Scan.* across an unperformed
	// side turns every large artifact (the 256 MiB skip) into a phantom
	// alert.
	if prior.Scan.Performed && next.Scan.Performed {
		switch {
		case !prior.Scan.InstallScriptFetches && next.Scan.InstallScriptFetches:
			add(AlertInstallScriptAppeared, "install script fetches remote code",
				scanText(prior.Scan.InstallScriptKind), scanText(next.Scan.InstallScriptKind))
		case !prior.Scan.HasInstallScript && next.Scan.HasInstallScript:
			add(AlertInstallScriptAppeared, "install script added",
				scanText(prior.Scan.InstallScriptKind), scanText(next.Scan.InstallScriptKind))
		}
	}

	// The verdict is subject to the same "we finally looked" rule as the
	// artifact fields above, and for a while it escaped it.
	//
	// A stored verdict is computed from whatever facts that cycle had.
	// If the advisory lane times out on cycle N, the report carries no
	// CVEs, the verdict resolves to `allow`, and that is what gets
	// persisted — markNoAdvisoryCoverage does NOT rescue this, because it
	// returns early for any ecosystem that has an advisory source at all,
	// so there is no SignalsUnavailable and no Unknown to make the row
	// self-describing. On cycle N+1 the lane answers, the verdict
	// resolves to `quarantine`, and a naive diff reports
	// `allow -> quarantine` — a CRITICAL recall paging everyone who
	// pulled the package, for a CVE that may be months old and was never
	// absent from the package, only from our view of it.
	//
	// So: compare verdicts only when the later evaluation rests on no
	// MORE data than the earlier one. A category that gained
	// availability between the two is new evidence arriving, not the
	// package getting worse. Losing data is already silent, because a
	// thinner evaluation scores better, and improvements do not alert.
	if pv, nv, ok := knownVerdicts(prior, next); ok && recallVerdictRank(nv) > recallVerdictRank(pv) {
		if gainedEvidence(prior, next) {
			// Deliberately silent. The verdict really did worsen, but
			// the honest reading is "we could not see this before", and
			// a Critical page that says a package changed when our
			// coverage changed is how an alert channel earns its mute.
		} else {
			add(AlertVerdictDegraded, fmt.Sprintf("risk verdict %s → %s", pv, nv), string(pv), string(nv))
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Trigger != out[j].Trigger {
			return out[i].Trigger < out[j].Trigger
		}
		return out[i].Package < out[j].Package
	})
	return out
}

// gainedEvidence reports whether next's evaluation had a risk category
// with data available that prior's did not.
//
// Keyed on risk.CategoryScore.DataAvailable, which is the engine's own
// record of "this feed answered".
//
// The hazard is ASYMMETRY, not absence. Both sides missing category data
// is symmetric ignorance: we know nothing about either evaluation's
// coverage, which is no reason to believe coverage is what moved, so the
// verdict change is taken at face value. One side having it and the
// other not is the case we cannot interpret, and there we stay quiet.
//
// EvaluatePackage always constructs the category map (evaluator.go:437),
// so in production both sides carry it and the set comparison below is
// what actually runs; the nil arms exist for reports built by something
// other than a full evaluation.
func gainedEvidence(prior, next *Report) bool {
	priorCats := availableCategories(prior)
	nextCats := availableCategories(next)
	if priorCats == nil && nextCats == nil {
		return false
	}
	if priorCats == nil || nextCats == nil {
		return true
	}
	for cat := range nextCats {
		if !priorCats[cat] {
			return true
		}
	}
	return false
}

// availableCategories returns the set of risk categories whose feed
// answered, or nil when the evaluation cannot be inspected.
func availableCategories(r *Report) map[risk.Category]bool {
	if r == nil || r.Risk == nil || r.Risk.DirectScore.Categories == nil {
		return nil
	}
	out := make(map[risk.Category]bool, len(r.Risk.DirectScore.Categories))
	for cat, cs := range r.Risk.DirectScore.Categories {
		if cs.DataAvailable {
			out[cat] = true
		}
	}
	return out
}

func malicious(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "malicious")
}

// typosquatSuspect reports whether a TyposquatStatus value is one of the
// suspect states. "clean", "confirmed_safe", "unknown" and "" are not —
// note that "confirmed_safe" is a CLEAN state despite the prefix it
// shares with "confirmed".
func typosquatSuspect(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "suspected", "confirmed":
		return true
	}
	return false
}

func boolVal(b *bool) bool { return b != nil && *b }

func boolText(b *bool) string {
	if b == nil {
		return "unset"
	}
	if *b {
		return "true"
	}
	return "false"
}

func statusText(s string) string {
	if v := strings.TrimSpace(s); v != "" {
		return v
	}
	return "unset"
}

func scanText(kind string) string {
	if v := strings.TrimSpace(kind); v != "" {
		return v
	}
	return "none"
}

func publisherDetail(sc SupplyChainSection) string {
	var parts []string
	if len(sc.PublisherAdded) > 0 {
		parts = append(parts, "added "+strings.Join(sc.PublisherAdded, ", "))
	}
	if len(sc.PublisherRemoved) > 0 {
		parts = append(parts, "removed "+strings.Join(sc.PublisherRemoved, ", "))
	}
	if len(parts) == 0 {
		return "publisher set changed"
	}
	return strings.Join(parts, "; ")
}

// knownVerdicts returns the pair of risk verdicts to compare, and false
// when the comparison must not be made at all: either side missing a
// risk.Evaluation (the v2 engine is off), or either side carrying
// VerdictUnknown.
//
// VerdictUnknown is NOT foldable into allow (core/risk/evaluation.go,
// the VerdictUnknown doc comment). allow → unknown is a LOSS OF
// EVALUATION, not bad news; unknown → quarantine is not a strengthening
// flip from a known-good state, because there was no known state. Both
// must stay silent — the alternative is a recall storm every time the
// risk engine is toggled or a backend is briefly unreachable.
func knownVerdicts(prior, next *Report) (risk.Verdict, risk.Verdict, bool) {
	if prior.Risk == nil || next.Risk == nil {
		return "", "", false
	}
	pv, nv := prior.Risk.Verdict, next.Risk.Verdict
	if recallVerdictRank(pv) < 0 || recallVerdictRank(nv) < 0 {
		return "", "", false
	}
	return pv, nv, true
}

// recallVerdictRank orders the KNOWN verdicts clean → blocking with the
// same ladder provider_transitiverisk.go's verdictRank uses, and differs
// from it in exactly one place: everything NOT on the ladder returns -1
// instead of 0.
//
// That single difference is the whole point. verdictRank's `return 0`
// tail folds VerdictUnknown into the same bucket as VerdictAllow, which
// is safe where it is used (picking the worse of two verdicts) and is a
// recall storm here: allow → unknown would read as "no change" while
// unknown → quarantine would read as a degradation from a clean state
// that never existed. core/risk/evaluation.go is explicit that Unknown
// means the engine COULD NOT EVALUATE and must never be folded into
// Allow. So: not comparable, no alert, in either direction.
func recallVerdictRank(v risk.Verdict) int {
	switch v {
	case risk.VerdictAllow:
		return 0
	case risk.VerdictWarn:
		return 1
	case risk.VerdictUpgradeAvailable:
		return 2
	case risk.VerdictReplace:
		return 3
	case risk.VerdictQuarantine:
		return 4
	}
	return -1
}
