// Package intelligence provides a unified, cache-first package-intelligence
// service that powers the inline proxy hot path, the Shodan-style admin UI,
// and any external consumer that queries by (ecosystem, package, version).
//
// The Report schema below aligns with the normalized schema in
// deep-research-report-package-interfaces-inventory.md and is extended with
// a SupplyChain section covering the chainsaw-specific policy signals
// (malware, typosquat, trust score, publisher changes, version anomalies,
// publish velocity, repo-link status).
package intelligence

import (
	"time"

	"github.com/chain305/chainsaw-core/capability"
	"github.com/chain305/chainsaw-core/risk"
)

// Key identifies a single package version uniquely across ecosystems.
type Key struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version"`
}

// Report is the canonical, cross-ecosystem record for a single package
// version. Every field a policy condition consumes is reachable from this
// struct; callers do not need to go to the underlying signal modules.
type Report struct {
	Identity        IdentitySection     `json:"identity"`
	Release         ReleaseSection      `json:"release"`
	URLs            URLSection          `json:"urls"`
	Artifact        ArtifactSection     `json:"artifact"`
	People          PeopleSection       `json:"people"`
	Metadata        MetadataSection     `json:"metadata"`
	Provenance      ProvenanceSection   `json:"provenance"`
	Scan            ArtifactScanSection `json:"artifactScan"`
	SupplyChain     SupplyChainSection  `json:"supplyChain"`
	Vulnerabilities VulnSection         `json:"vulnerabilities"`
	Maintenance     MaintenanceSection  `json:"maintenance"`
	Dependencies    DependenciesSection `json:"dependencies,omitzero"`
	Observation     ObservationSection  `json:"observation"`

	// Risk is the v2 risk-engine evaluation for this package version. nil
	// when the v2 engine is disabled (back-compat default). When populated,
	// Risk.RolledUp.Overall is mirrored into SupplyChain.TrustScore so
	// existing policy TrustScoreMin/Max conditions keep working.
	Risk *risk.Evaluation `json:"risk,omitempty"`

	// Actions carries GitHub Actions evaluation results when the report
	// covers a workflow scan. Optional — leave nil when no Action data is
	// present (the common case for traditional package reports). Populated
	// upstream by a scanner-to-Report bridge; projected into risk.Input by
	// ProjectToRiskInput.
	Actions *ActionsSection `json:"actions,omitempty"`
}

// ActionsSection carries GitHub Actions evaluation results when the
// report's Identity.Ecosystem is "github_actions" or when an upstream
// workflow scan was attached. Populated by the scanner in
// internal/githubactions; projected into risk.Input by
// ProjectToRiskInput.
type ActionsSection struct {
	Findings []ActionFinding `json:"findings,omitempty"`
}

// ActionFinding is one issue surfaced against a GitHub Action ref.
// Mirrors internal/githubactions.Finding but lives here so the
// intelligence package doesn't import githubactions (which would risk
// import cycles when scanners produce Reports).
type ActionFinding struct {
	// Signal is one of: "action.unpinned_ref", "action.typosquat",
	// "action.unknown_publisher", "action.malicious".
	Signal string `json:"signal"`
	// Severity is one of: "high", "medium", "low".
	Severity string `json:"severity,omitempty"`
	// Ref is the raw uses: string for blame display.
	Ref string `json:"ref,omitempty"`
	// Detail is optional context (typosquat suggestion, malware reason).
	Detail string `json:"detail,omitempty"`
}

// DependenciesSection lists the package's manifest-declared dependencies
// from the upstream registry. The shape is intentionally cross-ecosystem
// — npm "dependencies" + "peerDependencies" + "optionalDependencies",
// PyPI "requires_dist", Cargo "dependencies", Maven "dependencies",
// Composer "require", NuGet "dependencies", RubyGems "dependencies"
// all map onto Direct[]. Transitive resolution requires individual
// scans of each Direct entry; the transitiveRisk Tier-3 provider walks
// the cached intelligence rows it can find and rolls up the risk.
type DependenciesSection struct {
	// Direct is the manifest-declared production dependency list, in
	// stable registry-emitted order. Each entry carries the
	// version-constraint string verbatim — the consuming UI can decide
	// whether to display it as-is or normalise.
	Direct []DependencyRef `json:"direct,omitempty"`
	// Dev / peer / optional are split out so the UI can group them; all
	// four lists feed the transitive walker, but only Direct counts
	// toward the dependencyCount badge.
	Dev      []DependencyRef `json:"dev,omitempty"`
	Peer     []DependencyRef `json:"peer,omitempty"`
	Optional []DependencyRef `json:"optional,omitempty"`
}

// DependencyRef is one outbound dep declaration. Ecosystem may be set
// when it differs from the parent (rare — only when a manifest pins a
// cross-ecosystem dep). Empty Ecosystem means "same as parent".
type DependencyRef struct {
	Ecosystem  string `json:"ecosystem,omitempty"`
	Name       string `json:"name"`
	Constraint string `json:"constraint,omitempty"`
}

// IdentitySection names the package version and where it came from.
type IdentitySection struct {
	Ecosystem    string `json:"ecosystem"`
	Package      string `json:"package"`
	Version      string `json:"version"`
	Namespace    string `json:"namespace,omitempty"`
	PURL         string `json:"purl,omitempty"`
	RegistryBase string `json:"registryBase,omitempty"`
	// ArtifactSubtype mirrors common.PackageCoordinate.Subtype. Empty for
	// traditional ecosystems. Stable values: "model", "dataset", "space",
	// "agent-tool", "mcp-server", "prompt-template".
	ArtifactSubtype string `json:"artifactSubtype,omitempty"`
}

// ReleaseSection carries publish-time, listing, and latest-version facts.
type ReleaseSection struct {
	PublishedAt   *time.Time `json:"publishedAt,omitempty"`
	CreatedAt     *time.Time `json:"createdAt,omitempty"`
	ModifiedAt    *time.Time `json:"modifiedAt,omitempty"`
	LatestVersion string     `json:"latestVersion,omitempty"`
	Listed        *bool      `json:"listed,omitempty"`
	Yanked        *bool      `json:"yanked,omitempty"`
	Prerelease    *bool      `json:"prerelease,omitempty"`
	// Deprecated is the npm-style maintainer deprecation string
	// (populated by the deprecation provider; empty when absent).
	Deprecated string `json:"deprecated,omitempty"`
}

// URLSection records registry-advertised URLs for human follow-up.
type URLSection struct {
	MetadataURL      string `json:"metadataUrl,omitempty"`
	ArtifactURL      string `json:"artifactUrl,omitempty"`
	SourceRepoURL    string `json:"sourceRepoUrl,omitempty"`
	HomepageURL      string `json:"homepageUrl,omitempty"`
	DocumentationURL string `json:"documentationUrl,omitempty"`
	IssuesURL        string `json:"issuesUrl,omitempty"`
	ReadmeURL        string `json:"readmeUrl,omitempty"`
}

// ArtifactSection stores file identity and declared vs actual hashes.
type ArtifactSection struct {
	Filename  string         `json:"filename,omitempty"`
	Packaging string         `json:"packaging,omitempty"`
	Size      int64          `json:"size,omitempty"`
	Digests   ArtifactDigest `json:"digests,omitempty"`

	// SignatureVerified is the three-state outcome of an upstream
	// signature check projected from the merged Provenance section by
	// provider_signature_verify.go. nil = no signature was available
	// for this ecosystem / version (don't penalise; very common today).
	// true = a signature was present and verified against an
	// independent trust root (sigstore today; PGP TODO). false = a
	// signature was present but failed verification.
	//
	// Distinct from Digests.Verified, which only proves "the bytes
	// match the declared hash" — both halves of that comparison come
	// from data the attacker controls, so the digest check is a
	// bit-flip canary, not a security boundary. SignatureVerified is
	// the real cryptographic boundary when it's non-nil.
	SignatureVerified *bool `json:"signatureVerified,omitempty"`
	// SignatureKind identifies the verifier that produced
	// SignatureVerified: "sigstore" | "pgp" | "" (unknown / not run).
	// Mirrors ProvenanceSection.Kind values for the subset of formats
	// that constitute "real" upstream signature verification.
	SignatureKind string `json:"signatureKind,omitempty"`
	// SignatureKeyID is the verifying identity, when known: the
	// sigstore SignerID / BuilderID, or PGP key fingerprint. Empty
	// when unknown — not a failure indicator.
	SignatureKeyID string `json:"signatureKeyId,omitempty"`
}

// ArtifactDigest carries every hash form any ecosystem may use.
type ArtifactDigest struct {
	SHA256     string `json:"sha256,omitempty"`
	SHA512     string `json:"sha512,omitempty"`
	SHA1       string `json:"sha1,omitempty"`
	MD5        string `json:"md5,omitempty"`
	Blake2b256 string `json:"blake2b_256,omitempty"`
	Integrity  string `json:"integrity,omitempty"`
	Declared   string `json:"declared,omitempty"`
	Actual     string `json:"actual,omitempty"`
	Verified   bool   `json:"verified,omitempty"`
}

// PeopleSection names publishers / maintainers — the identity axis for
// publisherChanged and publishVelocityAnomaly signals.
type PeopleSection struct {
	Authors          []string `json:"authors,omitempty"`
	Maintainers      []string `json:"maintainers,omitempty"`
	PublisherIDs     []string `json:"publisherIds,omitempty"`
	TrustedPublisher *bool    `json:"trustedPublisher,omitempty"`
}

// MetadataSection carries registry-advertised descriptive metadata.
type MetadataSection struct {
	Summary           string   `json:"summary,omitempty"`
	Description       string   `json:"description,omitempty"`
	Keywords          []string `json:"keywords,omitempty"`
	LicenseExpression string   `json:"licenseExpression,omitempty"`
	RequiresRuntime   string   `json:"requiresRuntime,omitempty"`
	Platforms         []string `json:"platforms,omitempty"`
}

// ProvenanceSection mirrors the inventory-doc provenance model and is
// normalised across sigstore / x509 / sumdb / swift-signature / oci-referrer.
//
// Intelligence is informational only — fields here describe what
// verification produced, never whether to allow or block. Enforcement is
// the policy engine's job (see internal/policy.Conditions matchers like
// RequireSLSALevel, RequireBuilderID, ForbidCacheStale).
type ProvenanceSection struct {
	Kind            string   `json:"kind,omitempty"`   // none|sigstore|x509|sumdb|swift-signature|oci-referrer|gpg-commit|other
	Status          string   `json:"status,omitempty"` // verified|unverified|unavailable|missing|failed
	Available       bool     `json:"available"`
	Verified        bool     `json:"verified"`
	Endpoint        string   `json:"endpoint,omitempty"`
	SubjectDigest   string   `json:"subjectDigest,omitempty"`
	BundleURL       string   `json:"bundleUrl,omitempty"`
	BundleFormat    string   `json:"bundleFormat,omitempty"` // sigstore-bundle|in-toto|cms|gpg-detached|sumdb-note
	SignerID        string   `json:"signerId,omitempty"`
	BuilderID       string   `json:"builderId,omitempty"`
	SourceRepo      string   `json:"sourceRepo,omitempty"`
	SourceCommit    string   `json:"sourceCommit,omitempty"`
	TransparencyLog string   `json:"transparencyLog,omitempty"`
	CertChain       []string `json:"certificateChain,omitempty"`

	// SLSALevel is the SLSA build level (1-4) the verified attestation
	// claims, or 0 when no level can be inferred (presence-only formats
	// like APT/YUM gpg, or v0.2 predicates without builder ID). Populated
	// only when Verified == true.
	SLSALevel int `json:"slsaLevel,omitempty"`

	// CacheStale is true when the verification result was served from
	// the Sigstore last-known-good cache because Rekor/Fulcio was
	// unreachable. Operators who require fresh transparency-log proof
	// can refuse decisions on stale data via the ForbidCacheStale
	// policy condition.
	CacheStale bool `json:"cacheStale,omitempty"`

	// Warnings collects non-fatal verification notes (e.g. "served from
	// stale cache", "in-toto subject mismatch with registry digest").
	// Empty for clean verifications.
	Warnings []string `json:"warnings,omitempty"`
}

// ArtifactScanSection captures everything computed by scanning the bytes
// of the archive itself (install scripts, hidden unicode, clam/trivy on
// artifacts). Populated only when the caller passed an Artifact to Scan.
type ArtifactScanSection struct {
	Performed            bool           `json:"performed"`
	ScannedAt            *time.Time     `json:"scannedAt,omitempty"`
	ScannedArtifactSHA   string         `json:"scannedArtifactSha256,omitempty"`
	InstallScriptKind    string         `json:"installScriptKind,omitempty"` // none|present|fetches_remote|eval_encoded
	HasInstallScript     bool           `json:"hasInstallScript"`
	InstallScriptFetches bool           `json:"installScriptFetchesRemote"`
	HiddenUnicodeHits    int            `json:"hiddenUnicodeHits,omitempty"`
	HiddenUnicodeKinds   []string       `json:"hiddenUnicodeKinds,omitempty"`
	ManifestFilesSeen    []string       `json:"manifestFilesSeen,omitempty"`
	ExtraFindings        map[string]any `json:"extraFindings,omitempty"`

	// Socket-gap Wave 1. ShrinkwrapPresent is npm-specific and set by
	// the shrinkwrap provider; ManifestConfusion is npm-specific and
	// set by the manifestconfusion provider.
	ShrinkwrapPresent bool `json:"shrinkwrapPresent,omitempty"`
	// ShrinkwrapSuppressed is true when at least one lockfile match
	// was found but ALL matches were suppressed by context filters
	// (test/example/docs paths, or a manifest-declared
	// bundledDependencies block). Lets operators see "we found
	// lockfiles but suppressed them" without re-firing the signal.
	ShrinkwrapSuppressed    bool     `json:"shrinkwrapSuppressed,omitempty"`
	ManifestConfusion       bool     `json:"manifestConfusion,omitempty"`
	ManifestConfusionFields []string `json:"manifestConfusionFields,omitempty"`

	// Socket-gap Wave 3 — Tier-2 source-code scanners (all ride the
	// Wave-0 shared artifact map; see internal/codesmell). Each bool
	// is true when the corresponding scanner observed at least one
	// hit above its threshold. Empty scanner matches leave them false.
	UsesEval            bool `json:"usesEval,omitempty"`
	NetworkAccess       bool `json:"networkAccess,omitempty"`
	ShellAccess         bool `json:"shellAccess,omitempty"`
	FilesystemAccess    bool `json:"filesystemAccess,omitempty"`
	EnvVarAccess        bool `json:"envVarAccess,omitempty"`
	NativeBinaryPresent bool `json:"nativeBinaryPresent,omitempty"`
	HighEntropyStrings  bool `json:"highEntropyStrings,omitempty"`
	URLStrings          bool `json:"urlStrings,omitempty"`
	MinifiedCode        bool `json:"minifiedCode,omitempty"`

	// Socket-gap Wave 4. TrivialPackage + TooManyFiles ride the shared
	// Wave-0 artifact map. The three RTT signals (NonExistentAuthor,
	// FirstTimeCollaborator, SuspiciousRepoStars) populate here only
	// when their per-ecosystem feature flag is enabled and the
	// provider actually completed a lookup.
	TrivialPackage    bool `json:"trivialPackage,omitempty"`
	TrivialPackageLOC int  `json:"trivialPackageLoc,omitempty"`
	TooManyFiles      bool `json:"tooManyFiles,omitempty"`
	TooManyFilesCount int  `json:"tooManyFilesCount,omitempty"`
	NonExistentAuthor bool `json:"nonExistentAuthor,omitempty"`
	// FirstTimeCollaborator is three-state: nil = undecidable (no
	// prior publisher_set persisted, or prior.People not hydrated);
	// *true = the incoming version has at least one publisher not seen
	// in the most-recent prior publisher set; *false = every incoming
	// publisher was already present. bool projections (e.g. the policy
	// EvaluationContext) treat nil as false / "no signal".
	FirstTimeCollaborator *bool `json:"firstTimeCollaborator,omitempty"`
	SuspiciousRepoStars   bool  `json:"suspiciousRepoStars,omitempty"`
	// MaintainerAccountAgeDays is the youngest publisher / maintainer
	// account age in days, computed by the maintainerAccountAge
	// provider against ecosystem-specific user-profile endpoints.
	// 0 means the provider was disabled or upstream was unreachable —
	// downstream policy must treat 0 as "no signal" (fail-open).
	MaintainerAccountAgeDays int `json:"maintainerAccountAgeDays,omitempty"`

	// AI artifact scan results. Populated by provider_pickle (HuggingFace
	// + any ecosystem that publishes pickle weights), provider_modelcard
	// (HuggingFace), and provider_agenttool (npm / pip / huggingface).
	DangerousPickleOpcode        bool     `json:"dangerousPickleOpcode,omitempty"`
	DangerousPickleFiles         []string `json:"dangerousPickleFiles,omitempty"`
	DangerousPickleSummary       string   `json:"dangerousPickleSummary,omitempty"`
	SuspiciousPickleOpcode       bool     `json:"suspiciousPickleOpcode,omitempty"`
	UnsafeSerializationFormat    bool     `json:"unsafeSerializationFormat,omitempty"`
	PrefersSafetensorsAvailable  bool     `json:"prefersSafetensorsAvailable,omitempty"`
	ModelCardInjection           bool     `json:"modelCardInjection,omitempty"`
	ModelCardKinds               []string `json:"modelCardKinds,omitempty"`
	AgentToolDeclared            bool     `json:"agentToolDeclared,omitempty"`
	AgentToolDangerousCapability bool     `json:"agentToolDangerousCapability,omitempty"`
	AgentToolCapabilities        []string `json:"agentToolCapabilities,omitempty"`
	MCPServerUnverified          bool     `json:"mcpServerUnverified,omitempty"`
	PromptTemplateInjection      bool     `json:"promptTemplateInjection,omitempty"`

	// --- Gap 4b: minified file list ---
	// MinifiedFiles is the list of paths (relative to package root) that
	// DetectMinified flagged as minified/bundled JS. Populated when
	// CHAINSAW_CAPABILITY_SCAN=1 (same extraction path as CapabilityReport).
	// Complements the existing MinifiedCode bool from the codesmell scanner.
	MinifiedFiles []string `json:"minifiedFiles,omitempty"`

	// --- Gap 2: capability grading ---
	// CapabilityReport holds the output of capability.Analyze for npm/yarn/bun
	// packages when CHAINSAW_CAPABILITY_SCAN=1. nil when the scan did not run
	// (feature flag off, non-npm ecosystem, or extraction failure).
	CapabilityReport *capability.Report `json:"capabilityReport,omitempty"`
}

// SupplyChainSection carries the chainsaw-specific signals not in the
// inventory-doc schema — these map 1:1 onto the policy Conditions fields
// added over the last twelve LHF PRs.
type SupplyChainSection struct {
	MalwareStatus          string     `json:"malwareStatus,omitempty"` // clean|malicious|unknown
	MalwareID              string     `json:"malwareId,omitempty"`
	MalwareSummary         string     `json:"malwareSummary,omitempty"`
	TyposquatStatus        string     `json:"typosquatStatus,omitempty"` // clean|suspected|confirmed_safe
	TyposquatConfidence    string     `json:"typosquatConfidence,omitempty"`
	TyposquatSimilarTo     string     `json:"typosquatSimilarTo,omitempty"`
	TrustScore             int        `json:"trustScore,omitempty"`
	TrustScoreBreakdown    string     `json:"trustScoreBreakdown,omitempty"`
	PublisherChanged       *bool      `json:"publisherChanged,omitempty"`
	PublisherAdded         []string   `json:"publisherAdded,omitempty"`
	PublisherRemoved       []string   `json:"publisherRemoved,omitempty"`
	VersionAnomaly         *bool      `json:"versionAnomaly,omitempty"`
	VersionAnomalyFlags    []string   `json:"versionAnomalyFlags,omitempty"`
	PublishVelocity24h     int        `json:"publishVelocity24h,omitempty"`
	PublishVelocityAnomaly *bool      `json:"publishVelocityAnomaly,omitempty"`
	RepoLinkStatus         string     `json:"repoLinkStatus,omitempty"` // unknown|ok|archived|missing|ownership_mismatch
	RepoLinkLastChecked    *time.Time `json:"repoLinkLastCheckedAt,omitempty"`
	// RepoLastCommitAt and RepoArchived are runtime-only mirrors of the
	// repo-link probe's secondary fields. Plumbed in-memory only — the
	// persistence layer (package_metadata) does not store these. The
	// Tier-3 maintenance enricher reads them when projecting onto
	// MaintenanceSection so the risk engine can fire the
	// repo-archived / abandoned-repo signals without a second HTTP call.
	RepoLastCommitAt *time.Time `json:"repoLastCommitAt,omitempty"`
	RepoArchived     *bool      `json:"repoArchived,omitempty"`

	// ReservedNamespaceViolation is set by the reserved-namespace
	// enforcement path when a public-ecosystem lookup targets a name
	// that's reserved for a private registry (classic dep-confusion
	// risk). The *bool distinguishes "not evaluated" (nil) from
	// "evaluated and clean" (false) so the risk engine can keep the
	// signal dormant rather than falsely reporting safety.
	ReservedNamespaceViolation *bool  `json:"reservedNamespaceViolation,omitempty"`
	ReservedNamespaceReason    string `json:"reservedNamespaceReason,omitempty"`

	// TransitiveCoverage records how much of the direct-dep graph the
	// transitive risk evaluator could actually see. Populated by
	// evaluateTransitiveRisk when at least one direct dep is declared.
	// The policy evaluator can read Resolved < Total as "this verdict
	// is incomplete" — a clean RolledUp score with partial coverage is
	// not the same signal as a clean score with full coverage.
	TransitiveCoverage *TransitiveCoverage `json:"transitiveCoverage,omitempty"`
}

// TransitiveCoverage captures resolved-vs-total dep counts for one
// transitive evaluation pass. Resolved is the number of Direct deps
// whose cached intelligence row was found and folded into the rolled-up
// risk; Total is the count of Direct entries the walker considered.
// Complete is the convenience boolean (Resolved == Total && Total > 0).
//
// MaxDepth and ClosureSize describe the N-level walk (Pain 5
// uplift): MaxDepth is the level cap that was in effect for this
// evaluation (configurable via CHAINSAW_TRANSITIVE_DEPTH, hard-capped
// at 10), and ClosureSize is the count of distinct descendants the
// walker actually resolved across all levels (excluding the root).
// The deep-dive UI uses ClosureSize to render copy like "fix parent
// X unblocks 47 descendants" — when MaxDepth=1 the values fall back
// to the historical direct-only meaning.
type TransitiveCoverage struct {
	Resolved    int  `json:"resolved"`
	Total       int  `json:"total"`
	Complete    bool `json:"complete"`
	MaxDepth    int  `json:"maxDepth,omitempty"`
	ClosureSize int  `json:"closureSize,omitempty"`
}

// MaintenanceSection carries release-cadence and repo-liveness facts
// that feed the risk engine's maintenance category. Populated by a
// post-merge enricher from data registry providers already fetched —
// this section does NOT have its own network I/O.
type MaintenanceSection struct {
	LatestReleaseAt  *time.Time `json:"latestReleaseAt,omitempty"`
	LastRepoCommitAt *time.Time `json:"lastRepoCommitAt,omitempty"`
	VersionCount     int        `json:"versionCount,omitempty"`
	MaintainerCount  int        `json:"maintainerCount,omitempty"`
	RepoArchived     *bool      `json:"repoArchived,omitempty"`

	// FirstPublishedAt is the timestamp of the *earliest* released version
	// in this package's history. Distinct from Release.PublishedAt (which
	// is *this* version's publish time) and LatestReleaseAt (the most
	// recent version). Sourced from VersionTimeline when populated.
	// Drives the "package age" view distinct from "version recency".
	FirstPublishedAt *time.Time `json:"firstPublishedAt,omitempty"`

	// Stars / Forks / OpenIssues / Subscribers are the GitHub repo
	// activity counts pulled when SupplyChain.SourceRepo resolves to a
	// GitHub URL. Zero values are valid: zero means "fetched and the repo
	// has zero stars" — distinguishable from "field absent in JSON" via
	// the omitempty wire tag. Drives the maintenance grade and feeds the
	// Stars row in the public package page. Stays zero for non-GitHub
	// repos until per-host providers land.
	Stars       int `json:"stars,omitempty"`
	Forks       int `json:"forks,omitempty"`
	OpenIssues  int `json:"openIssues,omitempty"`
	Subscribers int `json:"subscribers,omitempty"`

	// WeeklyDownloads is the registry download count for the last 7 days.
	// nil   → no data (air-gap mode: CHAINSAW_OFFLINE=1, or ecosystem has no
	//          download API). Leaves risk.Input.WeeklyDownloads nil — signal stays
	//          dormant (fail-open).
	// &(-1) → fetch was attempted but failed (network error, rate-limit, etc.).
	//          Propagated to risk.Input.WeeklyDownloads=-1 which triggers
	//          SevUnknown from the maint.unpopular_package signal.
	// &n    → actual count. Triggers low-download signal when below threshold.
	WeeklyDownloads *int `json:"weeklyDownloads,omitempty"`

	// VersionTimeline is the full set of (version, publishedAt) tuples
	// the registry-metadata provider extracted from the upstream packument
	// (npm `versions` map + `time` map; pypi `releases` map; cargo
	// `versions` array — when straightforward to extract).
	//
	// This is the authoritative source of "how many versions exist" and
	// "what does the prior history look like" for any ecosystem whose
	// registry exposes a full timeline in a single call. Without it, the
	// per-org `package_metadata` table is the only source — which is
	// proxy-driven and therefore sparse for any package whose hot-path
	// downloads we have not yet observed (the typical case for a fresh
	// scan of a popular dependency).
	//
	// Risk-engine consumers (VersionCount, version-anomaly history) MUST
	// prefer this slice when non-empty; the sparse store fallback is
	// retained only for ecosystems that do not surface a full timeline in
	// metadata fetches (maven, rubygems, nuget, composer).
	//
	// Held in memory only — never persisted as new rows in
	// `package_metadata` (those rows are intentionally proxy-driven). The
	// slice rides with the cached intelligence_reports JSONB blob and is
	// recomputed on the next refresh.
	VersionTimeline []VersionRelease `json:"versionTimeline,omitempty"`
}

// VersionRelease is a single (version, publishedAt) tuple from a
// registry's full version timeline. PublishedAt is zero when the
// registry omits the publish date for that version.
type VersionRelease struct {
	Version     string    `json:"version"`
	PublishedAt time.Time `json:"publishedAt,omitempty"`
}

// VulnSection mirrors the existing VulnerabilityMetadata shape, populated
// by the CVE provider (Trivy + EPSS).
type VulnSection struct {
	IsVulnerable    bool       `json:"isVulnerable"`
	CVSSScore       float64    `json:"cvssScore,omitempty"`
	EPSSScore       float64    `json:"epssScore,omitempty"`
	CVEs            []string   `json:"cves,omitempty"`
	ScannerDBDigest string     `json:"scannerDbDigest,omitempty"`
	ScannedAt       *time.Time `json:"scannedAt,omitempty"`

	// CVEDetails carries per-CVE metadata that the flat CVEs []string
	// can't express — currently fix-version info from Trivy. Empty when
	// no upstream advisory ships a fixed-version field, which is the
	// common case for advisories still pending a patched release.
	CVEDetails []CVEDetail `json:"cveDetails,omitempty"`

	// KnownExploited is true when at least one of CVEs appears in the
	// CISA KEV catalog. Populated by the KEV provider post-merge.
	KnownExploited bool `json:"knownExploited,omitempty"`
	// KEVEntries is the catalog detail for each matched CVE (date
	// added + ransomware flag). Omitted when KnownExploited is false.
	KEVEntries []KEVEntry `json:"kevEntries,omitempty"`
}

// CVEDetail is per-CVE detail keyed alongside VulnSection.CVEs. Trivy
// advisories supply FixedVersion when an upstream patched release
// exists; FixAvailable is the convenience boolean the risk projector
// reads.
type CVEDetail struct {
	CVE          string `json:"cve"`
	FixedVersion string `json:"fixedVersion,omitempty"`
	FixAvailable bool   `json:"fixAvailable,omitempty"`
}

// KEVEntry is a single row of CISA's Known Exploited Vulnerabilities
// catalog, trimmed to the fields chainsaw surfaces in the UI and risk
// engine.
type KEVEntry struct {
	CVE                        string `json:"cve"`
	DateAdded                  string `json:"dateAdded,omitempty"`
	KnownRansomwareCampaignUse bool   `json:"knownRansomwareCampaignUse,omitempty"`
}

// ObservationSection records provider-level diagnostics so a consumer can
// see *why* a field is empty. Warnings never fail a Scan — they're how
// partial success surfaces.
type ObservationSection struct {
	CollectedAt     time.Time        `json:"collectedAt"`
	FreshUntil      time.Time        `json:"freshUntil"`
	Cached          bool             `json:"cached"`
	RefreshReason   string           `json:"refreshReason,omitempty"`
	DocStatus       string           `json:"docStatus,omitempty"` // official|official-plus-observed|provisional
	Warnings        []Warning        `json:"warnings,omitempty"`
	ProviderTimings []ProviderTiming `json:"providerTimings,omitempty"`
	// Partial is true when the Scan that produced this Report was
	// capped via Options.MaxTier — i.e. the higher-tier providers were
	// deliberately skipped to return inside a tighter deadline. The UI
	// uses this together with TierComplete / TierTotal to decide
	// whether to keep polling for a fuller report.
	Partial bool `json:"partial,omitempty"`
	// TierComplete is the highest provider tier that ran to completion
	// for this Report. Zero on the noop path / unset reports.
	TierComplete int `json:"tierComplete,omitempty"`
	// TierTotal is the maximum tier the registered providers can
	// produce for the requested ecosystem — i.e. the value
	// TierComplete will reach once Partial flips to false. Stamped on
	// every Report so the UI can render "tier X of Y" without a
	// separate provider-catalog round-trip.
	TierTotal int `json:"tierTotal,omitempty"`
}

// Warning is a provider-level non-fatal diagnostic.
type Warning struct {
	Provider string    `json:"provider"`
	Code     string    `json:"code"`
	Message  string    `json:"message,omitempty"`
	At       time.Time `json:"at"`
}

// Warning codes — stable strings that UI/API consumers can key on.
const (
	WarnTimeout         = "timeout"
	WarnUpstream5xx     = "upstream_5xx"
	WarnUpstream4xx     = "upstream_4xx"
	WarnBreakerOpen     = "breaker_open"
	WarnNeedsArtifact   = "needs_artifact"
	WarnParseFailed     = "parse_failed"
	WarnFeatureDisabled = "feature_disabled"
	WarnRateLimited     = "rate_limited"
	WarnUnsupported     = "ecosystem_unsupported"

	// Transitive-risk visibility codes. Emitted by evaluateTransitiveRisk
	// when a direct dep cannot be folded into the rolled-up score, so
	// operators can tell a clean verdict from one with blind spots.
	WarnTransitiveDepNotCached             = "transitive_dep_not_cached"
	WarnTransitiveDepConstraintUnparseable = "transitive_dep_constraint_unparseable"
	WarnTransitiveDepLookupError           = "transitive_dep_lookup_error"
)

// ProviderTiming captures per-provider runtime (for observability).
type ProviderTiming struct {
	Provider string        `json:"provider"`
	Duration time.Duration `json:"durationNanos"`
	Error    string        `json:"error,omitempty"`
}
