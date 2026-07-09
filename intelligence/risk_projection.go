package intelligence

// risk_projection.go projects the merged intelligence.Report onto the
// flat risk.Input the risk-engine v2 evaluator consumes. This is the ONLY
// piece of glue between the intelligence package and internal/risk — the
// risk package intentionally has no intelligence dependency, so future
// consumers (the tree evaluator, external adapters) can use the engine
// without lugging the full Report type around.
//
// The projection is a pure function: same Report in, same Input out. Nil
// Report yields a zero-value Input so callers never need to nil-check.
// Every field is deliberate — anywhere the Report schema is not yet rich
// enough to populate a risk.Input field, we default to zero and leave a
// TODO pointing at the follow-up. Phase 2 (shadow mode) tolerates those
// under-fires because legacy remains authoritative.

import (
	"github.com/chain305/chainsaw-core/capability"
	"github.com/chain305/chainsaw-core/hiddenunicode"
	"github.com/chain305/chainsaw-core/risk"
)

// ProjectToRiskInput flattens a merged Report into the risk engine's
// Input shape. Safe with a nil Report (returns the zero Input).
func ProjectToRiskInput(r *Report) risk.Input {
	if r == nil {
		return risk.Input{}
	}

	in := risk.Input{
		// Identity — used by the evaluator to stamp the result's Key and
		// by Resolution.TransitiveBlame in future tree evaluations.
		Ecosystem: r.Identity.Ecosystem,
		Package:   r.Identity.Package,
		Version:   r.Identity.Version,

		// --- Vulnerability ---
		IsVulnerable:   r.Vulnerabilities.IsVulnerable,
		MaxCVSS:        r.Vulnerabilities.CVSSScore,
		EPSSScore:      r.Vulnerabilities.EPSSScore,
		CVEs:           r.Vulnerabilities.CVEs,
		KnownExploited: r.Vulnerabilities.KnownExploited,
		FixAvailable:   anyCVEFixAvailable(r.Vulnerabilities.CVEDetails),
		FixedCVEs:      fixedCVEs(r.Vulnerabilities.CVEDetails),

		// --- Supply-chain ---
		IsKnownMalicious: r.SupplyChain.MalwareStatus == "malicious",
		MalwareID:        r.SupplyChain.MalwareID,
		MalwareSummary:   r.SupplyChain.MalwareSummary,

		IsSuspectedTyposquat: r.SupplyChain.TyposquatStatus == "suspected",
		TyposquatConfidence:  r.SupplyChain.TyposquatConfidence,
		TyposquatSimilarTo:   r.SupplyChain.TyposquatSimilarTo,

		PublisherChanged: deref(r.SupplyChain.PublisherChanged),

		HasInstallScript:           r.Scan.HasInstallScript,
		InstallScriptFetchesRemote: r.Scan.InstallScriptFetches,

		// Pain 9 (Agent D): env-var read and network-call axes are
		// projected into risk.Input so the new compound rule
		// CompoundSCEnvNetInstall can fire when all three of {env-var,
		// network, install-script} are present. Single-axis env-var and
		// single-axis network detectors remain context-only — too
		// noisy to act on alone.
		EnvVarAccess:  r.Scan.EnvVarAccess,
		NetworkAccess: r.Scan.NetworkAccess,

		// Mirror the same threshold logic ComputeTrustScore uses — the
		// hidden-unicode bit only fires when the hit count is both
		// strictly positive AND meets the configured threshold. Keeping
		// these two engines' bit-flips identical avoids divergence on
		// the hidden-unicode axis alone.
		HasHiddenUnicode: r.Scan.HiddenUnicodeHits >= hiddenunicode.Threshold() &&
			r.Scan.HiddenUnicodeHits > 0,

		// Provenance: either the normalized Verified bool OR the legacy
		// Status=="verified" string. Providers populate whichever field
		// their backend natively returns; accepting both keeps us robust
		// to the mixed state during the provenance schema migration.
		HasProvenance:    r.Provenance.Verified || r.Provenance.Status == "verified",
		ProvenanceStatus: r.Provenance.Status,
		// SLSALevel feeds the per-level supply-chain bonus signal.
		SLSALevel: r.Provenance.SLSALevel,
		// SignatureVerified comes from the upstream sigstore/PGP probe.
		// nil = not run (treat as false); &true = verified; &false =
		// failed verification (no positive bonus, but no penalty either —
		// the failure is already reflected in ProvenanceStatus).
		SignatureVerified: r.Artifact.SignatureVerified != nil && *r.Artifact.SignatureVerified,

		HasSourceRepo:  r.URLs.SourceRepoURL != "",
		RepoLinkStatus: r.SupplyChain.RepoLinkStatus,

		// ReservedNamespaceViolation is a *bool on the Report so the
		// evaluator can distinguish "not evaluated" from "evaluated
		// clean". deref collapses both nil and &false to false — the
		// risk signal stays dormant until an enricher sets &true.
		ReservedNamespaceViolation: deref(r.SupplyChain.ReservedNamespaceViolation),

		// --- Maintenance ---
		PublishedAt:      r.Release.PublishedAt,
		LatestReleaseAt:  r.Maintenance.LatestReleaseAt,
		LastRepoCommitAt: r.Maintenance.LastRepoCommitAt,
		VersionCount:     r.Maintenance.VersionCount,
		MaintainerCount:  r.Maintenance.MaintainerCount,
		// RepoArchived: pass the *bool through unchanged. Three-state
		// preservation means downstream consumers can distinguish a
		// confirmed-not-archived repo (&false) from an unprobed one
		// (nil). The deref helper still exists for fields where the
		// "unknown collapses to false" contract is genuinely intended.
		RepoArchived: r.Maintenance.RepoArchived,

		// --- Maintenance: GitHub repo activity & package-age ---
		// Stars/Forks/OpenIssues/Subscribers are zero when the repo-link
		// provider has not run or returned no data; zero is also a valid
		// "this repo has no stars" answer. Maintenance-grade signals
		// treat both the same — there is no separate data-available bit
		// for repo activity.
		Stars:            r.Maintenance.Stars,
		Forks:            r.Maintenance.Forks,
		OpenIssues:       r.Maintenance.OpenIssues,
		Subscribers:      r.Maintenance.Subscribers,
		FirstPublishedAt: r.Maintenance.FirstPublishedAt,

		// --- Maintenance: VersionDataAvailable ---
		// True when the registry's full version timeline was populated
		// for this package. When false, version-count-based maintenance
		// signals (very-new-package, etc.) MUST treat the absence as
		// "no data" rather than "zero versions" — see input.go.
		VersionDataAvailable: len(r.Maintenance.VersionTimeline) > 0,

		// --- Vulnerability: VulnDataAvailable ---
		// True when the CVE provider produced a row for this package
		// (whether or not it found anything). Report.Vulnerabilities is
		// a value type, so we cannot inspect a *VulnSection nil-vs-non-nil
		// directly — the PartialReport.Vulns pointer is collapsed to a
		// VulnSection value during the scanner merge. Vulnerabilities.ScannedAt
		// is the most reliable "scan completed" proxy — provider_cve.go
		// stamps it whenever vulnerability_metadata returned a row, and
		// the empty-but-scanned case (clean package) still produces a
		// non-nil ScannedAt. Empty PartialReport (no CVE row) leaves
		// ScannedAt nil.
		VulnDataAvailable: r.Vulnerabilities.ScannedAt != nil,

		// --- License ---
		LicenseSPDX: r.Metadata.LicenseExpression,
		LicenseTags: risk.Classify(r.Metadata.LicenseExpression),
		// TODO(risk-engine-v2): LicensePolicyBlocked /
		// LicenseChangedFromPrev require a license-policy provider
		// (or a meta-diff extension). Default false for now.
		LicensePolicyBlocked:   false,
		LicenseChangedFromPrev: false,

		// --- Socket-gap Wave 1 ---
		DeprecatedByMaintainer:  deref(r.Release.Yanked) || r.Release.Deprecated != "",
		DeprecationReason:       r.Release.Deprecated,
		ShrinkwrapPresent:       r.Scan.ShrinkwrapPresent,
		ManifestConfusion:       r.Scan.ManifestConfusion,
		ManifestConfusionFields: r.Scan.ManifestConfusionFields,

		// --- Quality ---
		ChecksumVerified:    r.Artifact.Digests.Verified,
		ChecksumMismatch:    checksumMismatch(r.Artifact.Digests),
		VersionAnomalyFlags: r.SupplyChain.VersionAnomalyFlags,

		// --- Gap 4b: minified code ---
		// IsMinifiedCode and MinifiedFiles are populated from the
		// ArtifactScanSection.MinifiedFiles list (set by the capability
		// scanner extraction path when CHAINSAW_CAPABILITY_SCAN=1). The
		// legacy MinifiedCode bool from codesmell sets the bool only when the
		// full file-list is unavailable.
		IsMinifiedCode: len(r.Scan.MinifiedFiles) > 0 || r.Scan.MinifiedCode,
		MinifiedFiles:  r.Scan.MinifiedFiles,

		// --- Gap 4b: weekly downloads ---
		// WeeklyDownloads is populated by the downloads provider.
		// nil  → air-gap / ecosystem not supported → signal dormant.
		// &-1  → fetch failed → SevUnknown fires.
		// &n   → actual count → low-download signal may fire.
		WeeklyDownloads: r.Maintenance.WeeklyDownloads,

		// --- Wave-4 RTT signals (now projected; previously decorative) ---
		SuspiciousRepoStars:      r.Scan.SuspiciousRepoStars,
		FirstTimeCollaborator:    r.Scan.FirstTimeCollaborator,
		MaintainerAccountAgeDays: r.Scan.MaintainerAccountAgeDays,
		NonExistentAuthor:        r.Scan.NonExistentAuthor,

		// --- AI artifact ---
		ArtifactSubtype:              r.Identity.ArtifactSubtype,
		DangerousPickleOpcode:        r.Scan.DangerousPickleOpcode,
		DangerousPickleFiles:         r.Scan.DangerousPickleFiles,
		DangerousPickleSummary:       r.Scan.DangerousPickleSummary,
		SuspiciousPickleOpcode:       r.Scan.SuspiciousPickleOpcode,
		UnsafeSerializationFormat:    r.Scan.UnsafeSerializationFormat,
		PrefersSafetensorsAvailable:  r.Scan.PrefersSafetensorsAvailable,
		ModelCardInjection:           r.Scan.ModelCardInjection,
		ModelCardKinds:               r.Scan.ModelCardKinds,
		AgentToolDeclared:            r.Scan.AgentToolDeclared,
		AgentToolDangerousCapability: r.Scan.AgentToolDangerousCapability,
		AgentToolCapabilities:        r.Scan.AgentToolCapabilities,
		MCPServerUnverified:          r.Scan.MCPServerUnverified,
		PromptTemplateInjection:      r.Scan.PromptTemplateInjection,
	}

	// PublishVelocityAnomaly — prefer the explicit pointer when an
	// orchestrator or provider has set it; otherwise fall back to the
	// cached 24h counter against the same threshold trustscore.go uses.
	// Keeping the two engines' velocity bits in sync here prevents a
	// whole class of spurious divergence signals.
	if r.SupplyChain.PublishVelocityAnomaly != nil {
		in.PublishVelocityAnomaly = *r.SupplyChain.PublishVelocityAnomaly
	} else if r.SupplyChain.PublishVelocity24h > publishVelocityAnomalyThreshold {
		in.PublishVelocityAnomaly = true
	}

	// --- Gap 2: capability grading ---
	// Project CapabilityReport into the flat Cap* bool + evidence fields
	// the capability risk signals consume. The projection is skipped when
	// CapabilityReport is nil (CHAINSAW_CAPABILITY_SCAN not set, or the scan
	// ran but found nothing because Analyze returned an empty report).
	projectCapabilityReport(r.Scan.CapabilityReport, &in)

	// --- Gap 4a: git/http URL dependencies ---
	// Classify each dependency's version string across all four manifest
	// buckets. npm-only: skip for ecosystems with no DependenciesSection.
	projectURLDeps(r, &in)

	// --- GitHub Actions ---
	// Project ActionsSection.Findings into the flat ActionRef* fields the
	// Wave 4 risk-engine signals consume. ActionsSection is populated
	// upstream; today the scan-actions CLI and evaluate-actions API don't
	// yet build a Report — they emit findings directly. Closing that
	// loop is a follow-up. Until then this branch stays inert (Actions
	// is nil for every existing call site) and the projection is purely
	// additive.
	projectActionsSection(r.Actions, &in)

	return in
}

// projectActionsSection walks the report's Action findings (if any) and
// flips the matching ActionRef* booleans / appends to the ref slices on
// the risk.Input. Refs are deduped per-signal so a ref appearing in
// multiple findings of the same kind is recorded once.
//
// action.malicious is projected onto the dedicated ActionRefMalicious
// pair (Wave 7 — SignalActionMalicious is now a formal v2 signal). This
// is independent from IsKnownMalicious, which remains sourced from
// SupplyChainSection.MalwareStatus at the package level — a malicious
// Action ref does not retroactively mark the consuming repo's package
// as malware.
func projectActionsSection(s *ActionsSection, in *risk.Input) {
	if s == nil || len(s.Findings) == 0 {
		return
	}
	seenUnpinned := make(map[string]struct{})
	seenTyposquat := make(map[string]struct{})
	seenUnknown := make(map[string]struct{})
	seenMalicious := make(map[string]struct{})
	for _, f := range s.Findings {
		switch f.Signal {
		case "action.unpinned_ref":
			in.ActionRefUnpinned = true
			if _, ok := seenUnpinned[f.Ref]; !ok {
				seenUnpinned[f.Ref] = struct{}{}
				in.ActionRefUnpinnedRefs = append(in.ActionRefUnpinnedRefs, f.Ref)
			}
		case "action.typosquat":
			in.ActionRefTyposquat = true
			if _, ok := seenTyposquat[f.Ref]; !ok {
				seenTyposquat[f.Ref] = struct{}{}
				in.ActionRefTyposquats = append(in.ActionRefTyposquats, f.Ref)
			}
		case "action.unknown_publisher":
			in.ActionRefUnknownPublisher = true
			if _, ok := seenUnknown[f.Ref]; !ok {
				seenUnknown[f.Ref] = struct{}{}
				in.ActionRefUnknownPublishers = append(in.ActionRefUnknownPublishers, f.Ref)
			}
		case "action.malicious":
			in.ActionRefMalicious = true
			if _, ok := seenMalicious[f.Ref]; !ok {
				seenMalicious[f.Ref] = struct{}{}
				in.ActionRefMaliciousRefs = append(in.ActionRefMaliciousRefs, f.Ref)
			}
		}
	}
}

// anyCVEFixAvailable is the package-level "fix available" rollup: true
// when ANY CVE on the package has a known patched version. Mixed cases
// (one CVE fixed, one stalled) still fire — triage benefits from knowing
// at least part of the work is unblocked.
func anyCVEFixAvailable(details []CVEDetail) bool {
	for _, d := range details {
		if d.FixAvailable || d.FixedVersion != "" {
			return true
		}
	}
	return false
}

// fixedCVEs returns the subset of CVE IDs with a known fix version, in
// the input order. Surfaced as evidence on SignalVulnFixAvailable.
func fixedCVEs(details []CVEDetail) []string {
	var out []string
	for _, d := range details {
		if d.FixAvailable || d.FixedVersion != "" {
			out = append(out, d.CVE)
		}
	}
	return out
}

// checksumMismatch returns true only when we have BOTH a declared and an
// actual digest, they disagree, and the artifact has not been marked
// verified. "Not verified" alone is not a mismatch — it's ambiguous
// (missing digest, provider skipped, etc.). A true mismatch is stronger
// evidence than a simple verification failure and earns the instant-block
// short-circuit in the v2 evaluator.
func checksumMismatch(d ArtifactDigest) bool {
	if d.Verified {
		return false
	}
	if d.Declared == "" || d.Actual == "" {
		return false
	}
	return d.Declared != d.Actual
}

// projectCapabilityReport converts a capability.Report into the flat
// Cap* bool + evidence fields on risk.Input. Safe with a nil report.
// The conversion from capability.Evidence → risk.capEvidenceEntry is
// done here so the risk package remains free of any capability import.
func projectCapabilityReport(rep *capability.Report, in *risk.Input) {
	if rep == nil {
		return
	}

	mapEvidence := func(ev []capability.Evidence) []risk.CapEvidenceEntry {
		out := make([]risk.CapEvidenceEntry, 0, len(ev))
		for _, e := range ev {
			out = append(out, risk.CapEvidenceEntry{
				File:    e.File,
				Line:    e.Line,
				Snippet: e.Snippet,
			})
		}
		return out
	}

	if ev, ok := rep.Capabilities[capability.CapNetwork]; ok {
		in.CapNetwork = true
		in.CapNetworkEvidence = mapEvidence(ev)
	}
	if ev, ok := rep.Capabilities[capability.CapShell]; ok {
		in.CapShell = true
		in.CapShellEvidence = mapEvidence(ev)
	}
	if ev, ok := rep.Capabilities[capability.CapFilesystemWrite]; ok {
		in.CapFilesystemWrite = true
		in.CapFilesystemWriteEvidence = mapEvidence(ev)
	}
	if ev, ok := rep.Capabilities[capability.CapFilesystemRead]; ok {
		in.CapFilesystemRead = true
		in.CapFilesystemReadEvidence = mapEvidence(ev)
	}
	if ev, ok := rep.Capabilities[capability.CapEnvAccess]; ok {
		in.CapEnvAccess = true
		in.CapEnvAccessEvidence = mapEvidence(ev)
	}
	if ev, ok := rep.Capabilities[capability.CapNativeCode]; ok {
		in.CapNativeCode = true
		in.CapNativeCodeEvidence = mapEvidence(ev)
	}
	if ev, ok := rep.Capabilities[capability.CapDynamicEval]; ok {
		in.CapDynamicEval = true
		in.CapDynamicEvalEvidence = mapEvidence(ev)
	}
}

// projectURLDeps classifies each dependency version string in the
// report's DependenciesSection and sets HasGitURLDep/GitURLDeps and
// HasHTTPURLDep/HTTPURLDeps on the risk.Input. Runs for all ecosystems
// but only produces hits when the version strings use git/http forms
// (an npm-specific feature).
func projectURLDeps(r *Report, in *risk.Input) {
	// Collect all four dependency buckets in one pass.
	buckets := [][]DependencyRef{
		r.Dependencies.Direct,
		r.Dependencies.Dev,
		r.Dependencies.Peer,
		r.Dependencies.Optional,
	}
	for _, bucket := range buckets {
		for _, dep := range bucket {
			switch risk.ClassifyDepURL(dep.Constraint) {
			case risk.DepURLGit:
				in.HasGitURLDep = true
				in.GitURLDeps = append(in.GitURLDeps, dep.Name)
			case risk.DepURLHTTP:
				in.HasHTTPURLDep = true
				in.HTTPURLDeps = append(in.HTTPURLDeps, dep.Name)
			}
		}
	}
}
