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
	"strings"

	"github.com/chain305/chainsaw-core/capability"
	"github.com/chain305/chainsaw-core/hiddenunicode"
	"github.com/chain305/chainsaw-core/intelligence/osv"
	"github.com/chain305/chainsaw-core/risk"
)

// projectedVersionCount answers "how many published versions do we know
// about", preferring an explicit Maintenance.VersionCount and falling back
// to the length of the version timeline.
//
// WHY THE FALLBACK EXISTS. Maintenance.VersionCount has exactly ONE writer
// tree-wide — internal/intelligence/premium/provider_maintenance.go, whose
// primary branch is literally `section.VersionCount = len(VersionTimeline)`.
// The timeline itself is written by the CORE registry-metadata provider
// (applyTimeline). So any build that fans out the core providers without the
// premium set — the public core module, every core/... test, the offline
// paths — held a full timeline and reported VersionCount 0.
//
// That is not a cosmetic gap. maint.very_new_package suppresses itself on
// `VersionCount > 3` (core/risk/registry_maintenance.go), so a zeroed count
// DISABLES A DAMPING GATE and the signal fires MORE. Measured on the 400-row
// benign corpus before this fallback: 41% of the top-100 PyPI downloads,
// boto3 among them, flagged "very new package". Deriving the count where the
// timeline already sits costs nothing and removes the whole class.
//
// It cannot over-count: it is the same expression the premium provider uses,
// and it only ever runs when nothing more authoritative was supplied.
func projectedVersionCount(r *Report) int {
	if r.Maintenance.VersionCount > 0 {
		return r.Maintenance.VersionCount
	}
	return len(r.Maintenance.VersionTimeline)
}

// ProjectToRiskInput flattens a merged Report into the risk engine's
// Input shape. Safe with a nil Report (returns the zero Input).
func ProjectToRiskInput(r *Report) risk.Input {
	if r == nil {
		return risk.Input{}
	}

	// A version the registry never published is NOT EVALUATED, not
	// clean. Everything below this point reads facts off the Report,
	// and for such a coordinate those fields hold packument-level
	// fallbacks (the package's maintainers, its latest release date,
	// its repo stars) — data about a DIFFERENT version. Projecting them
	// produces a scored report whose score is mostly measuring its own
	// blind spot, and a hallucinated version pin comes back with a
	// plausible grade instead of an answer.
	//
	// Route it through the existing unavailability machinery rather
	// than inventing vocabulary: SignalsUnavailable short-circuits
	// EvaluatePackage to UnavailableEvaluation → VerdictUnknown → the
	// CLI's "NOT EVALUATED" render → `intel scan` counts it toward
	// INCOMPLETE and exits 2. Return immediately and carry no facts:
	// half a fact set is what got us here.
	//
	// ONE DELIBERATE, NARROW REVERSAL OF THAT RULE (P8-44). The "carry no
	// facts" rule is right for every ADDITIVE fact — those are the ones
	// whose partial set produces a score that measures its own blind
	// spot. It was wrong for the two INSTANT-BLOCK facts, and the
	// difference is structural rather than a matter of degree:
	// risk.instantBlock is a closed short-circuit that ignores every
	// other fact, does no additive math, and returns a fixed zero-score
	// quarantine, so an otherwise-empty Input cannot corrupt it.
	//
	// Carrying them is not optional cleanliness — it is the whole fix.
	// The malware provider is Tier 1 and needs no artifact, so it runs
	// in parallel with registry metadata and its verdict IS in the
	// merged Report by the time this projection runs (scanner.go's
	// partialIsBlocking even short-circuits the fan-out on
	// MalwareStatus == "malicious"). Dropping it here meant an
	// unpublished or yanked MALICIOUS version — the case you most want
	// flagged — came back NOT EVALUATED.
	//
	// TYPOSQUAT IS DELIBERATELY NOT CARRIED. It is not an instant block:
	// it flows through the additive rollup, which needs exactly the
	// facts that were never fetched, and since the band-1 boundary fix
	// sc.typosquat_high quarantines — so carrying it would make a
	// typo'd version pin on a merely near-popular name start blocking on
	// an empty fact set. It is surfaced as TEXT on the unavailable
	// evaluation's reason instead, where it informs without gating.
	if reason, ok := packageNotFoundReason(r); ok {
		return unavailableInput(r, reason)
	}
	if reason, ok := versionNotFoundReason(r); ok {
		return unavailableInput(r, reason)
	}

	// Same treatment for a version string that can never be matched at
	// all — an unresolved manifest property ("${slf4jVersion}"), our own
	// synthetic "metadata" marker for a maven-metadata.xml upload, or a
	// Maven resolver directive. Scoring these produced a clean Allow,
	// which is the worst possible answer: the coordinate reads as
	// scanned and safe while no advisory could ever attach to it. 27
	// such rows were live in production on 2026-08-23.
	//
	// VerdictUnknown maps to Monitored, not Blocked
	// (internal/decision/decision.go), so this stops them rendering as
	// clean without refusing anything a user is trying to do.
	if reason, ok := versionNotEvaluableReason(r); ok {
		return unavailableInput(r, reason)
	}

	// THIRD unavailability arm, and the one without which P8-05's warning
	// is inert (see advisory_coverage.go, trap 1). Seven ecosystems —
	// huggingface, swift, cocoapods, docker, apt, yum, dnf — have no
	// advisory feed at all, so nothing ever looked for a vulnerability in
	// them. Every category then started at risk.categoryBase = 100 and the
	// verdict came back ALLOW: 27 apt/yum/dnf runs produced a
	// byte-identical `ALLOW 96 (A) / Vulnerability 100 A (0 findings)`,
	// openssl 1.1.1k among them.
	//
	// Checked LAST of the three because it is the weakest claim. "This
	// package does not exist" and "this version was never published" are
	// facts about the coordinate; this one is a fact about US — our build
	// has no feed — and when a report carries both, the coordinate fact is
	// the more useful thing to print.
	//
	// Same Monitored-not-Blocked posture as its siblings: VerdictUnknown
	// maps to Monitored in internal/decision, so this stops the rows
	// rendering as clean without refusing anything a user is trying to do.
	// It DOES move `chainsaw intel scan` from exit 0/1 to exit 2 for any
	// lockfile containing one, via treeExitCode — that is the intended
	// effect (an unevaluated node is not a passing node) and it needs its
	// own count alongside the verdict delta.
	if reason, ok := noAdvisorySourceReason(r); ok {
		return unavailableInput(r, reason)
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
		VersionCount:     projectedVersionCount(r),
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

// unavailableInput builds the risk.Input for a coordinate whose facts
// could not be obtained. It is the ONE place the "carry no facts" rule is
// reversed, and it is reversed for exactly two fields.
//
// Every unavailability return in this file goes through here — today
// versionNotFoundReason, versionNotEvaluableReason and
// packageNotFoundReason. A fourth added later inherits the malware carry
// automatically, which is the point: the defect this fixes was one of
// three sibling returns being written without it and nothing joining
// them. TestEveryUnavailableReturnCarriesMalware pins that.
//
// What is carried, and why only this:
//
//	IsKnownMalicious / MalwareID / MalwareSummary — the instant-block
//	  fact. risk.EvaluatePackage answers it BEFORE the
//	  SignalsUnavailable short-circuit (see the ORDERING INVARIANT note
//	  in core/risk/evaluator.go), and instantBlock ignores every other
//	  fact, so an empty Input cannot corrupt the result.
//
// What is NOT carried, deliberately:
//
//	IsSuspectedTyposquat — additive, not instant-block. It needs the
//	  fact set that was never fetched, and sc.typosquat_high now
//	  quarantines. Appended to the human-readable reason instead, so the
//	  operator sees it without it gating anything.
//	everything else — the packument-level fallbacks (maintainers, latest
//	  release date, repo stars) that describe a DIFFERENT version.
func unavailableInput(r *Report, reason string) risk.Input {
	return risk.Input{
		Ecosystem:          r.Identity.Ecosystem,
		Package:            r.Identity.Package,
		Version:            r.Identity.Version,
		SignalsUnavailable: true,
		UnavailableReason:  withTyposquatNote(r, reason),

		IsKnownMalicious: r.SupplyChain.MalwareStatus == "malicious",
		MalwareID:        r.SupplyChain.MalwareID,
		MalwareSummary:   r.SupplyChain.MalwareSummary,
	}
}

// withTyposquatNote appends the typosquat finding to an unavailability
// reason as prose.
//
// The reason is rendered inside UnavailableEvaluation's summary sentence,
// so this stays a clause: no leading capital, no trailing period, no em
// dash. It is text and nothing else — it reaches no signal, no weight and
// no verdict, which is precisely why it is safe to surface on a fact set
// we already said we do not trust.
func withTyposquatNote(r *Report, reason string) string {
	if r.SupplyChain.TyposquatStatus != "suspected" {
		return reason
	}
	note := "the name is also flagged as a suspected typosquat"
	if similar := strings.TrimSpace(r.SupplyChain.TyposquatSimilarTo); similar != "" {
		note += " of " + similar
	}
	if strings.TrimSpace(reason) == "" {
		return note
	}
	return reason + "; " + note
}

// versionNotFoundReason reports whether any provider recorded positive
// evidence that the requested version does not exist upstream, and
// returns the operator-facing explanation to attach to the unavailable
// evaluation.
//
// The wording is deliberately non-accusatory. A freshly published
// version can 404 on a CDN edge or a lagging mirror for minutes, and a
// private registry may legitimately not carry the version at all, so the
// copy points at the two things the reader can actually check rather
// than asserting the package is fake. It is rendered inside
// UnavailableEvaluation's summary sentence, so it stays a clause: no
// leading capital, no trailing period, no em dash (the surrounding
// sentence already owns one).
func versionNotFoundReason(r *Report) (string, bool) {
	for _, w := range r.Observation.Warnings {
		if w.Code == WarnVersionNotFound {
			return "version not found in the registry's published versions; " +
				"check for a typo or a hallucinated version pin", true
		}
	}
	return "", false
}

// packageNotFoundReason reports whether a provider recorded positive
// evidence that the PACKAGE — not merely the requested version — does not
// exist upstream (P8-04).
//
// Checked BEFORE versionNotFoundReason because it is the stronger and more
// actionable claim: "there is no such package" tells the reader to look at
// the NAME, where "that version was never published" points at the pin. A
// report can in principle carry both.
//
// The wording stays non-accusatory for the same reason its sibling's does —
// a private registry, a proxy that does not mirror the package, and a name
// the model invented all produce this shape — but it does name the thing
// worth naming, because a package that does not exist is exactly the
// slopsquat surface. Rendered inside UnavailableEvaluation's summary
// sentence, so it stays a clause: no leading capital, no trailing period,
// no em dash.
func packageNotFoundReason(r *Report) (string, bool) {
	for _, w := range r.Observation.Warnings {
		if w.Code == WarnPackageNotFound {
			return "no package by this name was found in the registry; " +
				"check the spelling, or whether the name was invented by a " +
				"model rather than published", true
		}
	}
	return "", false
}

// versionNotEvaluableReason reports whether the ingest guard stamped this
// report as carrying a version that can never be matched against an
// advisory range (see UnevaluableVersionReason). Phrased as a clause to
// match versionNotFoundReason: it is rendered inside
// UnavailableEvaluation's summary sentence.
func versionNotEvaluableReason(r *Report) (string, bool) {
	for _, w := range r.Observation.Warnings {
		if w.Code == WarnVersionNotEvaluable {
			return "the recorded version cannot be matched against any advisory range; " +
				"it is an unresolved manifest property, a resolver directive, or an " +
				"internal marker rather than a published version", true
		}
	}
	return "", false
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

// MinimumSafeVersion returns the lowest version of THIS package that
// clears EVERY CVE currently affecting it, or "" when no such version is
// known.
//
// It is a DISPLAY-ONLY resolver. The value it returns must never be fed
// to risk.Options.SafeUpgradeVersion: doing so would make the evaluator's
// upgrade_available promotion branches fire, which weakens enforcement in
// four places (internal/decision quarantine→Monitored, internal/scan
// lockfile severity critical→low, the transitive rollup's blockedNodes
// set, and the `intel scan` exit-code bucket). The verdict is not this
// function's business; the sentence the UI prints next to it is.
//
// Algorithm:
//
//  1. The obligation set is Vulnerabilities.CVEs — the ids that actually
//     affect this coordinate — minus ClearedCVEs. CVEDetails entries for
//     ids outside that set are ignored: a fix for a CVE that does not
//     affect us is not a bound on our upgrade.
//  2. Every id in the obligation set must carry a CVEDetail with a
//     non-empty FixedVersion. One id without a fix and we return "" —
//     naming a "safe version" that is still vulnerable to the remaining
//     CVE is a strictly worse failure than saying nothing, which is the
//     whole reason this is a minimum-clearing-ALL and not a first-hit.
//  3. The answer is the MAXIMUM of those per-CVE fixed versions under the
//     ecosystem's own ordering (osv.CompareVersions — PEP 440 for PyPI,
//     Gem for RubyGems, Maven for Maven/Composer, NuGet's four-segment
//     order, SemVer elsewhere). Maximum, not minimum: a version below any
//     one CVE's fix is still affected by that CVE.
//  4. Any unparseable operand, or a result that is not STRICTLY GREATER
//     than the installed version, yields "". Both are the same rule —
//     never advise an upgrade we cannot prove is one.
func MinimumSafeVersion(r *Report) string {
	if r == nil || len(r.Vulnerabilities.CVEs) == 0 {
		return ""
	}

	cleared := make(map[string]struct{}, len(r.Vulnerabilities.ClearedCVEs))
	for _, id := range r.Vulnerabilities.ClearedCVEs {
		cleared[normalizeCVEID(id)] = struct{}{}
	}

	// Latest fix wins within a duplicated id — providers occasionally
	// merge two advisories for the same CVE with different backport
	// branches, and the higher one is the one that clears both.
	fixes := make(map[string]string, len(r.Vulnerabilities.CVEDetails))
	eco := r.Identity.Ecosystem
	for _, d := range r.Vulnerabilities.CVEDetails {
		fv := strings.TrimSpace(d.FixedVersion)
		if fv == "" {
			continue
		}
		id := normalizeCVEID(d.CVE)
		prev, seen := fixes[id]
		if !seen {
			fixes[id] = fv
			continue
		}
		cmp, err := osv.CompareVersions(eco, fv, prev)
		if err != nil {
			// Undecidable duplicate — refuse the whole answer rather
			// than silently keeping the arbitrary first one.
			return ""
		}
		if cmp > 0 {
			fixes[id] = fv
		}
	}

	best := ""
	obligations := 0
	for _, raw := range r.Vulnerabilities.CVEs {
		id := normalizeCVEID(raw)
		if id == "" {
			continue
		}
		if _, ok := cleared[id]; ok {
			continue
		}
		obligations++
		fv, ok := fixes[id]
		if !ok {
			return "" // this CVE has no known fix — there is no safe version
		}
		if best == "" {
			best = fv
			continue
		}
		cmp, err := osv.CompareVersions(eco, fv, best)
		if err != nil {
			return ""
		}
		if cmp > 0 {
			best = fv
		}
	}
	if obligations == 0 || best == "" {
		return ""
	}

	// The advisory's fix must be ahead of what is installed. A fix at or
	// below the installed version means the advisory data and the
	// coordinate disagree; advising a downgrade would be worse than
	// advising nothing.
	installed := strings.TrimSpace(r.Identity.Version)
	if installed == "" {
		return ""
	}
	// osv.CompareVersions answers CONFIDENTLY AND WRONGLY when the two
	// operands have mismatched prefix shapes. Measured against production
	// data on 2026-08-23:
	//
	//	Compare("composer", "5.4.5", "v6.3.0")            = 1  (wrong)
	//	Compare("composer", "5.4.5", "swiftmailer-6.2.5") = 1  (wrong)
	//	Compare("composer", "v6.3.0", "v5.4.5")           = 1  (right)
	//	Compare("composer", "6.3.0", "5.4.5")             = 1  (right)
	//
	// err is nil in every case, so the guard below cannot see it. Without
	// this shape check the promotion advised downgrading swiftmailer from
	// v6.3.0 to 5.4.5 — an older, still-vulnerable release — on real
	// production coordinates.
	//
	// So: refuse unless both operands are shapes the comparator actually
	// orders correctly. Refusing costs an upgrade hint on 2.5% of
	// coordinates (166 of 6511 in prod carry a non-numeric-leading
	// version, concentrated in docker/go/huggingface); getting it wrong
	// costs a user a downgrade into a known CVE.
	//
	// UPDATE: the comparator itself was fixed in the following change —
	// osv.compareVersions now normalises the prefix on both operands and
	// the Maven family refuses a non-numeric lead (matcher epoch 3). So
	// the inversion above no longer reaches here.
	//
	// This guard is kept anyway, deliberately. It is the last check
	// before the product tells a human "upgrade to X", the single place
	// where being wrong sends someone backwards into a known CVE, and it
	// is two comparisons. Defence in depth at the point of advice costs
	// nothing and does not depend on a distant invariant holding.
	bestCmp, bestOK := comparableVersion(best)
	installedCmp, installedOK := comparableVersion(installed)
	if !bestOK || !installedOK {
		return ""
	}
	cmp, err := osv.CompareVersions(eco, bestCmp, installedCmp)
	if err != nil || cmp <= 0 {
		return ""
	}
	return best
}

// comparableVersion normalizes v into a shape osv.CompareVersions orders
// correctly, reporting false when no such shape exists.
//
// A single leading "v"/"V" is stripped. That is what actually fixes the
// mixed-shape inversion: the comparator is right when BOTH operands carry
// the prefix and right when NEITHER does, and wrong only when they
// disagree — so normalizing both sides identically preserves ordering for
// same-shaped inputs and repairs it for mixed ones. Go module versions are
// canonically v-prefixed while advisory bounds frequently are not, so the
// mixed case is routine, not exotic.
//
// Anything that still does not lead with a digit after stripping — a
// package-name prefix ("swiftmailer-6.2.5"), a date-stamped docker tag, an
// arbitrary label — is refused rather than trusted.
func comparableVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	if v[0] == 'v' || v[0] == 'V' {
		v = v[1:]
	}
	if v == "" || v[0] < '0' || v[0] > '9' {
		return "", false
	}
	return v, true
}

// normalizeCVEID upper-cases and trims an advisory id so the obligation
// set and the detail list join on the same key. Feeds mix "CVE-2024-1"
// and "cve-2024-1" shapes depending on provider.
func normalizeCVEID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
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
