package intelligence

// trustscore.go is the bridge between the merged intelligence.Report and
// the composite trust-score computation in internal/trustscore. It is NOT
// a Provider — it runs post-merge in the Scan pipeline once all Tier-1/2
// providers have contributed their slices.
//
// The function is intentionally pure: it reads from the Report and writes
// TrustScore + TrustScoreBreakdown back onto Report.SupplyChain. Callers
// decide when to invoke it (typically once, after the merge, before
// persistence).

import (
	"os"
	"strings"

	"github.com/chain305/chainsaw-core/hiddenunicode"
	"github.com/chain305/chainsaw-core/intelligence/osv"
	"github.com/chain305/chainsaw-core/risk"
	"github.com/chain305/chainsaw-core/trustscore"
)

// trustScoreAttestationFirst is the runtime gate for the SLSA-substrate
// reframe. Default is ON (true), matching the user choice for
// "block-by-default for Tier-1 ecosystems" — the trust score and the
// seeded baseline policy agree. Operators who need score continuity
// during a staged rollout can set CHAINSAW_TRUSTSCORE_ATTESTATION_FIRST=false
// to revert to the legacy +25 additive Provenance contribution.
//
// The check is intentionally cheap (one os.Getenv per call); the scan
// pipeline already does many of these and a knob this load-bearing
// justifies the explicitness over a one-time package-init read.
func trustScoreAttestationFirst() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("CHAINSAW_TRUSTSCORE_ATTESTATION_FIRST")))
	switch v {
	case "0", "false", "off", "no":
		return false
	}
	return true
}

// OrgWeightsResolver is a package-level hook that resolves the per-org
// category-weight override used by the v2 risk engine in shadow mode.
// Default is a no-op returning nil so behaviour stays bit-identical to
// pre-override state when no store is wired. Bootstrap replaces it once
// from cmd/chainsaw-proxy with a closure over the real orgweights.Store.
// Invoked from ComputeTrustScore; implementations must be cheap (a
// single DB round-trip is acceptable; nothing blocking).
//
// The orgID threaded in is the scan's org attribution — today's scan
// hot path uses the "_shadow" sentinel for non-tenant-scoped refreshes
// ("_shadow" sentinel for non-tenant-scoped refreshes). Implementations
// must tolerate that sentinel.
var OrgWeightsResolver func(orgID string) map[string]float64 = func(string) map[string]float64 { return nil }

// OrgSignalWeightsResolver is the per-signal counterpart to
// OrgWeightsResolver. Pain 9 (Agent D): when the
// `risk_threshold_overrides` feature flag is on, the bootstrap closure
// reads from the `risk_weight_overrides` table and returns a map of
// signalID → effective weight. Default is a no-op so the engine
// behaves bit-identically to pre-Pain-9 deployments. The map is
// threaded into risk.Options.SignalWeightOverrides; nil/empty leaves
// the consts in place. Implementations must be cheap (cached read
// path lives in internal/risk/weight_resolver.go).
var OrgSignalWeightsResolver func(orgID string) map[string]int = func(string) map[string]int { return nil }

// publishVelocityAnomalyThreshold is the default trailing-24h push count
// above which the velocity anomaly bit fires. Kept local to this file so
// the intelligence package does not take a dependency on internal/policy;
// the production orchestrator can override by reading the live policy
// constant before ComputeTrustScore runs and setting the velocity fields
// directly on the SupplyChainSection.
const publishVelocityAnomalyThreshold = 20

// ComputeTrustScore projects the merged Report onto a trustscore.Signals,
// runs trustscore.Compute, and writes the result back onto
// report.SupplyChain.TrustScore / TrustScoreBreakdown (as the Breakdown
// JSON string trustscore.BreakdownJSON produces).
//
// Safe to call with a nil Report — the function no-ops. Idempotent: the
// score is recomputed from whatever the Report currently says, so calling
// it twice on the same Report produces the same score.
func ComputeTrustScore(report *Report) {
	ComputeTrustScoreForOrg(report, "")
}

// ComputeTrustScoreForOrg is the orgID-aware variant. Pain 9 (Validator
// D.2): the previous implementation passed a literal "_shadow" to the
// resolver hooks, which made per-(org, signal) overrides operationally
// inert because no override row matched that synthetic ID. Callers that
// know the request's org should call this directly so the resolver
// callbacks (OrgWeightsResolver, OrgSignalWeightsResolver) actually get
// asked about the real tenant. Empty orgID falls back to no-override
// behaviour (the resolver still runs but won't match any row).
func ComputeTrustScoreForOrg(report *Report, orgID string) {
	if report == nil {
		return
	}
	signals := trustscore.Signals{
		// Malware — instant kill when true.
		IsKnownMalicious: report.SupplyChain.MalwareStatus == "malicious",

		// Vulnerability.
		IsVulnerable: report.Vulnerabilities.IsVulnerable,
		MaxCVSS:      report.Vulnerabilities.CVSSScore,
		// CISA KEV match — provider_kev sets this when one of the
		// package's CVEs appears in the Known Exploited Vulnerabilities
		// catalog. Additive with CVSS rather than replacing it.
		KnownExploitedCVE: report.Vulnerabilities.KnownExploited,

		// AI-artifact scan signals (PickleScan / ModelCard / MCP
		// manifest) projected from the merged Scan section.
		DangerousPickleOpcode:        report.Scan.DangerousPickleOpcode,
		ModelCardInjection:           report.Scan.ModelCardInjection,
		AgentToolDangerousCapability: report.Scan.AgentToolDangerousCapability,

		// Metadata.
		LicenseSPDX:        report.Metadata.LicenseExpression,
		VersionReleaseDate: report.Release.PublishedAt,

		// Typosquat.
		IsSuspectedTyposquat: report.SupplyChain.TyposquatStatus == "suspected",
		TyposquatConfidence:  report.SupplyChain.TyposquatConfidence,

		// Checksum.
		ChecksumVerified: report.Artifact.Digests.Verified,

		// Install-script.
		HasInstallScript:           report.Scan.HasInstallScript,
		InstallScriptFetchesRemote: report.Scan.InstallScriptFetches,
		ImportTimeExecution:        report.Scan.ImportTimeExecution,
		ImportTimeKind:             report.Scan.ImportTimeKind,
		MaliciousIOC:               report.Scan.MaliciousIOC,

		// Provenance.
		HasProvenance:    report.Provenance.Verified || report.Provenance.Status == "verified",
		ProvenanceStatus: report.Provenance.Status,
		// SLSA-substrate inputs (Phase 6 reframe). The SLSA level
		// drives the trustscore.SLSALevelBonus; AttestationFirst
		// flips the scorer to base-30/base-70 + level bonus instead
		// of the legacy +25 additive contribution.
		SLSALevel:        report.Provenance.SLSALevel,
		AttestationFirst: trustScoreAttestationFirst(),

		// Source repo + liveness.
		HasSourceRepo:  report.URLs.SourceRepoURL != "",
		RepoLinkStatus: report.SupplyChain.RepoLinkStatus,

		// Hidden Unicode — compare the scanner hit count against the
		// configured threshold so the trust-score bit agrees with the
		// policy evaluator.
		HasHiddenUnicode: report.Scan.HiddenUnicodeHits >= hiddenunicode.Threshold() &&
			report.Scan.HiddenUnicodeHits > 0,

		// Publisher change.
		PublisherChanged: deref(report.SupplyChain.PublisherChanged),

		// Version anomaly flags.
		VersionAnomalyFlags: report.SupplyChain.VersionAnomalyFlags,
	}

	// Publish velocity anomaly — prefer the explicit bool when the
	// orchestrator (or a future provider) has set it; otherwise fall
	// back to the cached 24h counter against the default threshold.
	if report.SupplyChain.PublishVelocityAnomaly != nil {
		signals.PublishVelocityAnomaly = *report.SupplyChain.PublishVelocityAnomaly
	} else if report.SupplyChain.PublishVelocity24h > publishVelocityAnomalyThreshold {
		signals.PublishVelocityAnomaly = true
	}

	// Legacy Compute() still runs, but its Total is no longer
	// authoritative — Risk-V2 below overwrites SupplyChain.TrustScore.
	// We keep computing Compute() because the per-signal Breakdown JSON
	// it produces is rendered by the UI and audit-log explanation paths.
	// See internal/trustscore/score.go header for the contract.
	score := trustscore.Compute(signals)
	report.SupplyChain.TrustScoreBreakdown = score.BreakdownJSON()

	// --- Risk-V2 is authoritative ---
	//
	// v2 always runs (the risk.Enabled() / risk.ShadowEnabled() gates have been retired). The
	// per-org weights resolver, when wired, supplies category-weight
	// overrides; otherwise the engine's package-level defaults apply.
	var weights map[risk.Category]float64
	if OrgWeightsResolver != nil {
		if raw := OrgWeightsResolver(orgID); len(raw) > 0 {
			weights = make(map[risk.Category]float64, len(raw))
			for k, v := range raw {
				weights[risk.Category(k)] = v
			}
		}
	}
	var signalOverrides map[string]int
	if OrgSignalWeightsResolver != nil {
		signalOverrides = OrgSignalWeightsResolver(orgID)
	}
	eval := risk.EvaluatePackage(ProjectToRiskInput(report), risk.Options{
		CategoryWeights:       weights,
		SignalWeightOverrides: signalOverrides,
	})
	if eval == nil {
		// v2 produced nothing — fall back to legacy total so the field
		// is at least populated. This branch is defensive; eval is
		// non-nil for every code path EvaluatePackage takes today.
		report.SupplyChain.TrustScore = score.Total
		return
	}
	// A package whose ONLY real problem is a set of CVEs that all have a
	// published patch is not a "manual review required" case — it is a
	// one-line upgrade. promoteToUpgradeAvailable re-runs the evaluator
	// with risk.Options.SafeUpgradeVersion set, but only when all three
	// promotion gates hold; it returns nil (and the verdict stands
	// exactly as it is today) for every other package. See the function
	// for the gates, and risk.UpgradePromotionEligible for two of them.
	safeVersion := MinimumSafeVersion(report)
	if promoted := promoteToUpgradeAvailable(report, eval, safeVersion, weights, signalOverrides); promoted != nil {
		eval = promoted
	}

	// Display fields. On the promoted path this is a no-op re-write of
	// the SafeVersion resolveVerdict already set, plus the patch
	// advisory sentence; on every non-promoted path it is the original
	// display-only behaviour — the page stops rendering "no known safe
	// version" next to its own "Fix available" signal without the
	// verdict moving.
	eval.ApplyKnownFix(safeVersion)

	report.Risk = eval
	report.SupplyChain.TrustScore = eval.RolledUp.Overall
}

// LatestVersionCorroborator, when non-nil, answers "what version does the
// registry currently advertise as latest for this package?" from the
// persisted intelligence_latest_probes row. It is consulted ONLY when the
// Report being scored does not already carry Release.LatestVersion (the
// same fact, fresher, from this scan's own registry-metadata provider).
//
// Store.NewStore installs the DB-backed implementation. It stays nil in
// unit tests and in any binary with no intelligence store, which keeps
// ComputeTrustScoreForOrg pure by default.
//
// A nil hook is not a failure: see upgradeCandidateCorroborated for what
// "no corroboration available" means (the advisory data alone is allowed
// to carry the claim, because it is the data that makes the claim TRUE —
// the probe is only ever a veto).
var LatestVersionCorroborator func(ecosystem, pkg string) (latest string, ok bool)

// promoteToUpgradeAvailable decides whether this package's verdict may be
// promoted to risk.VerdictUpgradeAvailable, and returns the promoted
// Evaluation when it may. nil means "leave the verdict exactly as it is".
//
// Promotion is enforcement-visible by design — internal/decision maps
// quarantine→Blocked but upgrade_available→Monitored, internal/scan drops
// the lockfile severity, the transitive rollup drops the node from
// blockedNodes, and `intel scan` moves it to the warn exit bucket. So the
// three gates below are all required, and each one is a REFUSAL by
// default:
//
//	(a) EVIDENCE. MinimumSafeVersion(report) — the maximum of the
//	    per-CVE FixedVersion values across every advisory that still
//	    affects this coordinate, empty if a single one of them has no
//	    published fix, and never a version that is not strictly greater
//	    than the installed one. That value, and only that value, is the
//	    candidate: it is the lowest version we can PROVE clears
//	    everything. A bare "latest version" probe is not evidence of
//	    non-vulnerability and is never used as the candidate.
//	    Corroboration (upgradeCandidateCorroborated) then vetoes the
//	    promotion if the registry's advertised latest is BELOW the
//	    candidate — i.e. the advisory names a fix that is not published
//	    yet, so the upgrade we would recommend is not installable.
//
//	(b) VULNERABILITY-DRIVEN and (c) NOT THE BOTTOM BAND both live in
//	    risk.UpgradePromotionEligible, next to the category taxonomy and
//	    the band thresholds they read.
//
// The re-evaluation is a second pure EvaluatePackage call with identical
// weights, so the scores are byte-identical to the first pass; the final
// guard asserts that, and refuses the promotion if the engine ever
// disagrees.
func promoteToUpgradeAvailable(
	report *Report,
	eval *risk.Evaluation,
	safeVersion string,
	weights map[risk.Category]float64,
	signalOverrides map[string]int,
) *risk.Evaluation {
	if report == nil || eval == nil || safeVersion == "" {
		return nil
	}
	if !risk.UpgradePromotionEligible(eval) {
		return nil
	}
	if !upgradeCandidateCorroborated(report, safeVersion) {
		return nil
	}
	promoted := risk.EvaluatePackage(ProjectToRiskInput(report), risk.Options{
		CategoryWeights:       weights,
		SignalWeightOverrides: signalOverrides,
		SafeUpgradeVersion:    safeVersion,
	})
	if promoted == nil || promoted.Verdict != risk.VerdictUpgradeAvailable {
		return nil
	}
	if promoted.Resolution.SafeVersion != safeVersion {
		return nil
	}
	// Promotion must change the VERDICT and nothing else. If the score
	// moved, something other than the option we flipped is in play and
	// the safe answer is the un-promoted one.
	if promoted.DirectScore.Overall != eval.DirectScore.Overall ||
		promoted.RolledUp.Overall != eval.RolledUp.Overall {
		return nil
	}
	return promoted
}

// upgradeCandidateCorroborated asks the registry-advertised latest
// version whether the candidate is actually installable.
//
// The candidate comes from advisory fix data, which can name a version
// the registry has not published (a coordinated-disclosure fix version
// announced ahead of the release, or a typo in a feed). Recommending
// such an upgrade would send the user to a 404 while quietly unblocking
// the package, so a latest BELOW the candidate is a veto.
//
// Sources, in order: the Report's own Release.LatestVersion (written by
// the registry-metadata provider during this same scan) and then the
// persisted daily probe via LatestVersionCorroborator. When neither is
// available we PROCEED on the advisory data alone — that is the
// documented fallback, and it is sound because the probe was never the
// thing that made the claim true; MinimumSafeVersion is. An undecidable
// comparison, by contrast, is a refusal: we cannot prove the candidate
// is installable, so we do not promote.
func upgradeCandidateCorroborated(report *Report, candidate string) bool {
	latest := strings.TrimSpace(report.Release.LatestVersion)
	if latest == "" && LatestVersionCorroborator != nil {
		if probed, ok := LatestVersionCorroborator(report.Identity.Ecosystem, report.Identity.Package); ok {
			latest = strings.TrimSpace(probed)
		}
	}
	if latest == "" {
		return true
	}
	cmp, err := osv.CompareVersions(report.Identity.Ecosystem, latest, candidate)
	if err != nil {
		return false
	}
	return cmp >= 0
}

// deref returns the pointed-to bool or false when nil.
func deref(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}

// ReapplyKnownFixAfterTransitive restores the upgrade promotion and the
// known-fix display fields after evaluateTransitiveRisk has overlaid the
// tree pass onto report.Risk.
//
// WHY THIS EXISTS. The scan pipeline runs ComputeTrustScoreForOrg first
// and evaluateTransitiveRisk second (scanner.go: ComputeTrustScoreForOrg
// then evaluateTransitiveRisk). The overlay replaces Verdict and
// Resolution wholesale from a root evaluation that EvaluateTree produced
// with a bare risk.Options{} — so it carries neither the promotion nor
// the SafeVersion / PatchAdvisory / corrected Summary that
// ComputeTrustScoreForOrg had just established. Without this call a
// package whose dependency graph resolves to more than one node silently
// reverts to bare quarantine AND to the false "no known safe version"
// summary, while the identical package with no resolvable deps keeps
// both. The feature would be coherent only for single-node graphs, and
// the display-only fix that shipped before it would be silently absent
// on exactly the packages most likely to have dependencies.
//
// WHY IT IS SAFE. It re-runs the same three gates against the OVERLAID
// evaluation, not the pre-overlay one:
//   - a transitive malware / critical finding fires supply_chain signals,
//     which risk.UpgradePromotionEligible vetoes outright;
//   - a more-conservative secondEval verdict has already been folded in
//     by the overlay, so the gates see the worse of the two;
//   - the rolled-up score is the post-transitive one, so band-1 packages
//     dragged below the quarantine threshold BY their dependencies stay
//     ineligible.
//
// A package can therefore only keep its promotion here if it still earns
// it after its dependency graph has been accounted for.
//
// WHY NOT pass SafeUpgradeVersion into EvaluateTree instead: that field is
// a single string, so it would apply the ROOT's safe version to every
// descendant node, promoting dependencies on evidence that belongs to
// their parent. Descendants get their own promotion through
// risk.Options.PerNodeSafeUpgrade instead — one proven version per node,
// each derived from that node's own cached Report and each re-gated on
// that node's own signals (see evaluateTransitiveRisk and
// risk.promoteNodeInTree). This function stays the ROOT's owner, because
// only here are the gates re-run against the post-overlay evaluation.
func ReapplyKnownFixAfterTransitive(report *Report, orgID string) {
	if report == nil || report.Risk == nil {
		return
	}
	var weights map[risk.Category]float64
	if OrgWeightsResolver != nil {
		if raw := OrgWeightsResolver(orgID); len(raw) > 0 {
			weights = make(map[risk.Category]float64, len(raw))
			for k, v := range raw {
				weights[risk.Category(k)] = v
			}
		}
	}
	var signalOverrides map[string]int
	if OrgSignalWeightsResolver != nil {
		signalOverrides = OrgSignalWeightsResolver(orgID)
	}

	safeVersion := MinimumSafeVersion(report)
	if promoted := promoteToUpgradeAvailable(report, report.Risk, safeVersion, weights, signalOverrides); promoted != nil {
		// The tree pass owns these three; a re-evaluation of the root
		// input cannot reproduce them, so carry them across explicitly.
		promoted.Resolution.TransitiveBlame = report.Risk.Resolution.TransitiveBlame
		promoted.Resolution.TransitiveSeverity = report.Risk.Resolution.TransitiveSeverity
		promoted.RolledUp = report.Risk.RolledUp
		report.Risk = promoted
	}
	report.Risk.ApplyKnownFix(safeVersion)
}
