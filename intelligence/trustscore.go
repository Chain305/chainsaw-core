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
	report.Risk = eval
	report.SupplyChain.TrustScore = eval.RolledUp.Overall
}

// deref returns the pointed-to bool or false when nil.
func deref(p *bool) bool {
	if p == nil {
		return false
	}
	return *p
}
