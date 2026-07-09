package intelligence

// adapters.go projects the intelligence.Report onto the legacy persistence
// and policy-evaluation types that the rest of chainsaw already consumes.
// This is the critical interop bridge Phase B / C rely on: the intelligence
// pipeline produces a Report, the existing policy engine consumes the
// legacy shapes, and these adapters keep them in sync without forking the
// evaluator.

import (
	"time"

	"github.com/chain305/chainsaw-core/hiddenunicode"
	"github.com/chain305/chainsaw-core/metadata"
	"github.com/chain305/chainsaw-core/supplychain"
	"github.com/chain305/chainsaw-core/trustscore"
)

// ToLegacyPackageMetadata projects the Report onto the persisted
// metadata.PackageMetadata shape. Called from the Phase B swap in
// server_repo_pipeline.go to keep the existing evaluator untouched.
//
// Returns nil when the receiver is nil. repoName is the chainsaw proxy
// repo name (not the upstream source repo URL) — it's required because
// PackageMetadata is keyed by (org, repository, package, version) and the
// Report carries no repo-name concept of its own.
func (r *Report) ToLegacyPackageMetadata(repoName string) *metadata.PackageMetadata {
	if r == nil {
		return nil
	}
	meta := &metadata.PackageMetadata{
		Repository:            repoName,
		Package:               r.Identity.Package,
		Version:               r.Identity.Version,
		LicenseSPDX:           r.Metadata.LicenseExpression,
		PackageReleaseDate:    r.Release.CreatedAt,
		VersionReleaseDate:    r.Release.PublishedAt,
		SHA256Hash:            r.Artifact.Digests.SHA256,
		UpstreamURL:           r.Identity.RegistryBase,
		ProvenanceStatus:      r.Provenance.Status,
		TrustScore:            r.SupplyChain.TrustScore,
		TrustScoreBreakdown:   r.SupplyChain.TrustScoreBreakdown,
		TyposquatStatus:       r.SupplyChain.TyposquatStatus,
		TyposquatSimilarTo:    r.SupplyChain.TyposquatSimilarTo,
		MalwareStatus:         r.SupplyChain.MalwareStatus,
		MalwareID:             r.SupplyChain.MalwareID,
		ChecksumVerified:      r.Artifact.Digests.Verified,
		ChecksumDeclared:      r.Artifact.Digests.Declared,
		ChecksumActual:        r.Artifact.Digests.Actual,
		SourceRepo:            r.URLs.SourceRepoURL,
		RepoLinkStatus:        r.SupplyChain.RepoLinkStatus,
		RepoLinkLastCheckedAt: r.SupplyChain.RepoLinkLastChecked,
		InstallScriptKind:     r.Scan.InstallScriptKind,
		PublisherSet:          publisherSetFromReport(r),
		VersionAnomalyFlags:   r.SupplyChain.VersionAnomalyFlags,
		HiddenUnicodeHits:     r.Scan.HiddenUnicodeHits,
		PublishVelocity24h:    r.SupplyChain.PublishVelocity24h,
		Yanked:                r.Release.Yanked != nil && *r.Release.Yanked,
	}

	// Carry observation timestamps through so downstream readers that
	// sort on updated_at see the intelligence pipeline's write time.
	if !r.Observation.CollectedAt.IsZero() {
		meta.CreatedAt = r.Observation.CollectedAt
		meta.UpdatedAt = r.Observation.CollectedAt
	}

	return meta
}

// ToLegacyVulnerabilityMetadata projects Report.Vulnerabilities onto the
// metadata.VulnerabilityMetadata shape. Returns nil when the receiver is
// nil.
func (r *Report) ToLegacyVulnerabilityMetadata(repoName string) *metadata.VulnerabilityMetadata {
	if r == nil {
		return nil
	}
	vm := &metadata.VulnerabilityMetadata{
		Repository:      repoName,
		Package:         r.Identity.Package,
		Version:         r.Identity.Version,
		IsVulnerable:    r.Vulnerabilities.IsVulnerable,
		CVSSScore:       r.Vulnerabilities.CVSSScore,
		EPSSScore:       r.Vulnerabilities.EPSSScore,
		CVEs:            append([]string(nil), r.Vulnerabilities.CVEs...),
		ScannerDBDigest: r.Vulnerabilities.ScannerDBDigest,
	}
	if r.Vulnerabilities.ScannedAt != nil {
		vm.ScannedAt = *r.Vulnerabilities.ScannedAt
	}
	if !r.Observation.CollectedAt.IsZero() {
		vm.CreatedAt = r.Observation.CollectedAt
		vm.UpdatedAt = r.Observation.CollectedAt
	}
	return vm
}

// ToLegacyCheckResult projects Report.SupplyChain (plus the install-script
// and hidden-unicode scan results) onto the supplychain.CheckResult shape
// used by the policy evaluator. Returns nil when the receiver is nil.
//
// SignalBag and TrustScore are rebuilt from the Report: callers don't need
// to round-trip through the orchestrator's private state. The trustscore
// here is the *same* composite value persisted in SupplyChain.TrustScore —
// ComputeTrustScore is responsible for populating both ends.
func (r *Report) ToLegacyCheckResult() *supplychain.CheckResult {
	if r == nil {
		return nil
	}
	res := &supplychain.CheckResult{
		IsKnownMalicious:     r.SupplyChain.MalwareStatus == "malicious",
		MalwareID:            r.SupplyChain.MalwareID,
		MalwareSummary:       r.SupplyChain.MalwareSummary,
		IsSuspectedTyposquat: r.SupplyChain.TyposquatStatus == "suspected",
		TyposquatConfidence:  r.SupplyChain.TyposquatConfidence,
		TyposquatSimilarTo:   r.SupplyChain.TyposquatSimilarTo,

		HasInstallScript:           r.Scan.HasInstallScript,
		InstallScriptFetchesRemote: r.Scan.InstallScriptFetches,
		ImportTimeExecution:        r.Scan.ImportTimeExecution,
		MaliciousIOC:               r.Scan.MaliciousIOC,
		InstallScriptKind:          r.Scan.InstallScriptKind,

		PublisherChanged:    deref(r.SupplyChain.PublisherChanged),
		PublisherSetAdded:   append([]string(nil), r.SupplyChain.PublisherAdded...),
		PublisherSetRemoved: append([]string(nil), r.SupplyChain.PublisherRemoved...),

		VersionAnomaly:      deref(r.SupplyChain.VersionAnomaly),
		VersionAnomalyFlags: append([]string(nil), r.SupplyChain.VersionAnomalyFlags...),

		HasHiddenUnicode: r.Scan.HiddenUnicodeHits >= hiddenunicode.Threshold() &&
			r.Scan.HiddenUnicodeHits > 0,
		HiddenUnicodeHits:  r.Scan.HiddenUnicodeHits,
		HiddenUnicodeKinds: append([]string(nil), r.Scan.HiddenUnicodeKinds...),

		PublishVelocity24h: r.SupplyChain.PublishVelocity24h,
	}

	// Rebuild SignalBag to match the orchestrator's existing flat map so
	// downstream BOM / audit emitters don't have to branch on "where did
	// this CheckResult come from".
	res.SignalBag = map[string]any{
		"isKnownMalicious":           res.IsKnownMalicious,
		"isSuspectedTyposquat":       res.IsSuspectedTyposquat,
		"hasInstallScript":           res.HasInstallScript,
		"installScriptFetchesRemote": res.InstallScriptFetchesRemote,
		"importTimeExecution":        res.ImportTimeExecution,
		"maliciousIOC":               res.MaliciousIOC,
		"installScriptKind":          res.InstallScriptKind,
	}

	// TrustScore: recompute from the Report so callers who only read the
	// CheckResult (policy evaluator) see the same composite number the
	// persisted metadata carries.
	res.TrustScore = trustscore.Score{
		Total:      r.SupplyChain.TrustScore,
		ComputedAt: r.Observation.CollectedAt,
		IsComplete: r.Provenance.Status != "" || r.Provenance.Verified,
	}

	return res
}

// publisherSetFromReport extracts the normalised publisher set the store
// persists. Report.People carries three publisher-ish lists; we prefer
// PublisherIDs (the canonical normalised shape), falling back to the union
// of maintainers + authors when the upstream extractor didn't populate
// IDs.
func publisherSetFromReport(r *Report) []string {
	if len(r.People.PublisherIDs) > 0 {
		return append([]string(nil), r.People.PublisherIDs...)
	}
	out := make([]string, 0, len(r.People.Maintainers)+len(r.People.Authors))
	out = append(out, r.People.Maintainers...)
	out = append(out, r.People.Authors...)
	if len(out) == 0 {
		return nil
	}
	return out
}

// Ensure adapters compile against the metadata / supplychain types even
// when the callers are in a partial-dep state. These are zero-cost.
var (
	_ = time.Time{}
)
