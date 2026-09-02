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
	"os"
	"strconv"
	"strings"
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
	Performed            bool       `json:"performed"`
	ScannedAt            *time.Time `json:"scannedAt,omitempty"`
	ScannedArtifactSHA   string     `json:"scannedArtifactSha256,omitempty"`
	InstallScriptKind    string     `json:"installScriptKind,omitempty"` // none|present|fetches_remote|eval_encoded|mutates_dependency
	HasInstallScript     bool       `json:"hasInstallScript"`
	InstallScriptFetches bool       `json:"installScriptFetchesRemote"`

	// ImportTimeExecution is set by the pysource provider when a Python
	// package runs malicious behavior at IMPORT/INSTALL time (top-level
	// obfuscated decode-and-exec, import-time env/credential exfil, or a
	// top-level shell call) — the PyPI malware class the install-script and
	// manifest signals miss. Kind/Detail name the shape and the file.
	ImportTimeExecution bool   `json:"importTimeExecution,omitempty"`
	ImportTimeKind      string `json:"importTimeExecutionKind,omitempty"`   // obfuscated_exec|import_time_exfil|top_level_shell
	ImportTimeDetail    string `json:"importTimeExecutionDetail,omitempty"` // file the signal fired on

	// MaliciousIOC is set by the iocscan provider when the source embeds a
	// high-confidence indicator of compromise: an exfil sink host (Discord/
	// Telegram/Slack webhook, paste/anon-file drop, tunnel, OOB host) or a
	// stealer string coupled with a network send. Cross-ecosystem.
	MaliciousIOC       bool   `json:"maliciousIOC,omitempty"`
	MaliciousIOCKind   string `json:"maliciousIOCKind,omitempty"`   // exfil_host|stealer_string
	MaliciousIOCDetail string `json:"maliciousIOCDetail,omitempty"` // indicator + file

	// BuildRsExecutes is set by the installscripts provider when a cargo
	// crate ships a build.rs that performs shell or network execution at
	// build time — the Rust supply-chain analogue of an install script
	// that fetches remote code. Cargo-only. BuildRsPrimitives lists the
	// detected primitives (the build.rs:<hit> tokens) for the audit trail.
	BuildRsExecutes   bool     `json:"buildRsExecutes,omitempty"`
	BuildRsPrimitives []string `json:"buildRsPrimitives,omitempty"`

	HiddenUnicodeHits  int            `json:"hiddenUnicodeHits,omitempty"`
	HiddenUnicodeKinds []string       `json:"hiddenUnicodeKinds,omitempty"`
	ManifestFilesSeen  []string       `json:"manifestFilesSeen,omitempty"`
	ExtraFindings      map[string]any `json:"extraFindings,omitempty"`

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

	// ContainerScanIncomplete is an INFO-level marker set by the pickle
	// provider when an untrusted model container could not be fully scanned:
	// a zip-bomb / cap trip (entry-count or aggregate decompressed-size), or a
	// nested zip we deliberately did not recurse into (depth 1 only). Streams
	// extracted BEFORE the trip are still scanned, so a critical finding can
	// coexist with this flag; it exists so an operator sees that coverage was
	// bounded rather than the scan silently claiming a clean result.
	// ContainerScanNote carries the human-readable reason.
	ContainerScanIncomplete bool   `json:"containerScanIncomplete,omitempty"`
	ContainerScanNote       string `json:"containerScanNote,omitempty"`

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

	// ClearedCVEs is the VETO channel: CVE ids this contributor
	// positively evaluated against THIS coordinate and concluded do NOT
	// apply. It is the only way a false positive from another source can
	// ever leave a report — mergeVulns is otherwise union-only, so
	// anything that lands once is permanent and (because the
	// intelligence row is universal) global.
	//
	// Three-state, and the distinction is the whole design:
	//   nil       — this contributor has nothing to say about vulns.
	//               MOST contributors are here. Silence is NOT a veto.
	//   non-empty — evaluated, and these ids are affirmatively excluded.
	//   listed in both CVEs and ClearedCVEs — impossible by
	//               construction; producers subtract their own hits.
	//
	// Only a contributor that range-evaluated the exact (ecosystem,
	// package, version) coordinate may populate this. A source that
	// merely failed to find a CVE must leave it nil — see
	// osv.Index.LookupEx, which separates "cleared" from "undecidable"
	// for precisely this reason.
	ClearedCVEs []string `json:"clearedCves,omitempty"`

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
	// CVSS is the per-CVE base score. Zero means "this contributor did
	// not carry a score for this id" — it is NOT a claim that the CVE
	// scores zero. mergeVulns needs per-CVE scores to recompute the
	// section-level max after a veto removes an entry; without them,
	// dropping the CVE that WAS the max would leave a stale aggregate
	// (the removal would show in the id list but not in the score the
	// policy engine and max_cvss column actually read). The OSV provider
	// populates it from the advisory record; the Trivy-backed cve
	// provider leaves it zero because vulnerability_metadata.cve_details
	// carries no per-CVE score column.
	CVSS float64 `json:"cvss,omitempty"`
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
	// MatcherEpoch records which generation of the advisory matcher and
	// risk engine produced this Report. See CurrentMatcherEpoch. Rows
	// written before the epoch existed decode to 0, which is below every
	// real epoch and therefore always stale — that is deliberate, and is
	// how the one-time rescan of legacy rows happens.
	MatcherEpoch int `json:"matcherEpoch,omitempty"`
}

// CurrentMatcherEpoch is the generation number of the advisory matcher and
// the risk engine. A cached Report stamped with a lower epoch is treated as
// stale no matter how recently it was collected.
//
// Why this exists. Every read path in the system is cache-first, and the
// cache is keyed only by coordinate — so a Report persisted under an older,
// buggier matcher is served forever. The 24h TTL does not save us: the row
// is refreshed by re-running the SAME logic, so a wrong verdict is copied
// forward rather than corrected. That is not hypothetical. The lodash
// 4.17.21 false positive (an open-ended OSV GIT range out-voting the correct
// [0, 4.17.21) SEMVER range) was fixed in the matcher in v0.20.8, and the
// missing MaxImpact ceiling on vuln.cvss_critical was fixed in the risk
// engine in v0.21.2 — and an external QA pass reproduced BOTH afterwards,
// because the row predating the fixes was still being replayed verbatim.
// Without an epoch, every future matcher or scoring fix ships the same way:
// correct in the code, invisible to any coordinate anyone has already looked
// at.
//
// The bump discipline: increment this in the SAME commit as any change that
// can alter a verdict for an unchanged coordinate — advisory range matching,
// version comparison, signal weights, MaxImpact ceilings, the category
// rollup. Do NOT bump it for changes that only affect newly-observed data
// (a new provider field, a new warning code); those ride the normal TTL.
//
// The cost of a bump is a one-time recompute of every coordinate as it is
// next requested, coalesced by the singleflight and cross-replica leader
// machinery in Scan. The cost of forgetting to bump it is shipping a fix
// that no user ever sees.
//
// Epoch history:
//
//	1 — initial epoch (2026-08-22). Establishes the baseline and retires
//	    every row written before it, which is the set carrying the two
//	    defects named above.
//	2 — upgrade_available promotion (2026-08-23). risk.Options.
//	    SafeUpgradeVersion is now populated by ComputeTrustScoreForOrg
//	    for packages whose risk is CVE-driven and whose every advisory
//	    has a published fix, so those coordinates resolve to
//	    upgrade_available instead of bare quarantine/warn. That is a
//	    verdict change for UNCHANGED coordinates — exactly the bump
//	    discipline above — and it is enforcement-visible
//	    (internal/decision Blocked→Monitored, internal/scan
//	    critical→low). Every row written at epoch 1 replays the old
//	    verdict until it is rescanned.
//
//	3 — osv.compareVersions normalises a leading "v"/"V" on BOTH
//	    operands and the Maven-family branch now refuses a
//	    non-numeric lead instead of reading it as a qualifier. The old
//	    code answered confidently and wrongly whenever the two
//	    operands disagreed about carrying the prefix, with a nil
//	    error, so advisoryAffectsEx mis-evaluated `introduced` /
//	    `fixed` / `lastAffected` bounds. Measured against the 166
//	    production coordinates whose version does not start with a
//	    digit: 51 comparisons changed answer — all Composer vX.Y.Z
//	    tags, and in the FALSE-NEGATIVE direction (a version that
//	    compared as BELOW an `introduced` bound, and so cleared the
//	    advisory, now correctly compares above it). A further 156
//	    became undecidable; every one of those is a junk coordinate
//	    (unresolved Maven POM placeholders like "${slf4jVersion}",
//	    the literal "metadata", one name-prefixed tag), which the old
//	    code was silently ordering against real advisory bounds.
//	    This changes which CVEs attach to a coordinate, so every
//	    epoch-2 row must be recomputed.
//	4 — the Pub (Dart/Flutter) ecosystem is now downloaded, canonicalised
//	    and supported. Coordinates with ecosystem "pub" previously got NO
//	    advisory matching at all: the feed was never fetched and
//	    CanonicalEcosystem returned "", so canonicalKey produced "" and
//	    Lookup found nothing. They were absent rather than false-clean
//	    (osvProvider.Run shape 2 declines to stamp a Vulns section for an
//	    uncovered package), but they were uncovered. 6 such rows were live
//	    in production on 2026-08-23. Advisories can now attach to them, so
//	    every epoch-3 pub row must be recomputed.
//	5 — the upgrade promotion now survives the transitive tree pass for
//	    DESCENDANTS, not just the root (2026-08-23). EvaluateTree
//	    re-derives every node from its risk.Input, so a dependency that
//	    had legitimately earned upgrade_available in its own scan was
//	    re-evaluated as bare quarantine inside a parent's tree, stayed in
//	    computeTransitiveSeverity's blockedNodes set, and inflated the
//	    parent's persisted Risk.Resolution.TransitiveSeverity.blockedCount
//	    — a dependency with a published fix for every advisory affecting
//	    it was reported to the user as unfixable. Each descendant now
//	    carries its OWN evidence into the tree pass
//	    (risk.Options.PerNodeSafeUpgrade, filled from that descendant's
//	    own cached Report) and is re-gated on its OWN signals and band, so
//	    malware-flagged and KEV-pinned descendants stay blocked. Verdicts
//	    and blockedCount therefore change for UNCHANGED coordinates,
//	    which is exactly what this counter is for; every epoch-4 row with
//	    resolvable dependencies must be recomputed.
//	6 — the MaxImpact band-boundary collisions are corrected, re-arming five
//	    signals that could not reach the verdict their ceiling claimed
//	    (2026-08-25). applyMaxImpactCeiling pins overall to EXACTLY the
//	    declared ceiling, and both of resolveVerdict's band tests are strict
//	    `<`, so a ceiling equal to a threshold fell through into the weaker
//	    band. sc.typosquat_high (ceiling 30) resolved to bare WARN — a
//	    high-confidence typosquat could never block — and is now SevCritical
//	    so it rides the band-2 critical escalation its two ceiling-30 peers
//	    already used. The four SevMedium ceiling-60 signals
//	    (qual.version_anomaly, sc.hidden_unicode, sc.repo_archived,
//	    sc.repo_missing) had no escalation available at all: 60 skipped band
//	    2 entirely and returned ALLOW, so hidden-Unicode/Trojan-Source could
//	    not produce so much as a warning from the server while the offline
//	    guard hard-blocked it. Their ceilings move to maxImpactWarnTop (59).
//	    Neither the band tests nor the thresholds were touched. This changes
//	    verdicts for UNCHANGED coordinates in the enforcement-STRENGTHENING
//	    direction — warn → quarantine for a lone high-confidence typosquat,
//	    allow → warn for a package whose tightest ceiling is one of the four
//	    — so every epoch-5 row must be recomputed. The flip population is
//	    exactly the rows where one of the five was the tightest fired
//	    ceiling.
//
//	    The typosquat half of that population WAS measured, against a
//	    read-only export of production `intelligence_reports` (7,099 rows):
//	    12 rows move warn → quarantine. Half of them were false — `ms`
//	    reported as a squat of `msw`, `is-typed-array` of `is-typedarray`,
//	    `json5` of `json3`, `esutils` of `tsutils`, `lie` of `li` — because
//	    the detector had no popularity-DIRECTION check and named whichever
//	    of the pair was in the loaded corpus as the victim. Promoting the
//	    signal without that check would have hard-blocked five of npm's
//	    most-depended-on packages. It ships WITH the check
//	    (core/typosquat/established.go): a hit is demoted to
//	    sc.typosquat_low when the candidate is at least as established as
//	    its claimed target on a reviewed download ranking. So the epoch-6
//	    typosquat flip population is the SIX remaining rows — chalkk,
//	    expres, lodashs, reqeusts (two versions) and colourama — every one
//	    a genuine squat of a household name. The other four signals'
//	    populations are not measurable from source and were not measured.
//	7 — coverage honesty (2026-08-25). ONE bump for the whole wave, because
//	    the five changes below all move the same rows and splitting them
//	    would cost five recomputes of the same corpus for one measurement.
//	    Every one of them changes a verdict for an UNCHANGED coordinate.
//
//	    (a) Ecosystem case is normalised in every provider's Supports()
//	        whitelist (cve, typosquat, malware, checksum, registrymetadata).
//	        A display-cased coordinate — `PyPI`, `NPM` — kept its OSV and
//	        registry-metadata lanes and silently lost the rest, because
//	        scanner.go skips an unsupported provider with a bare `continue`
//	        that emits no warning and writes no timing entry. Those rows
//	        were scored against a strictly smaller fact set than their
//	        lower-cased twins. Direction is score-DOWN (lanes only ever add
//	        deficits), i.e. enforcement-strengthening, and it re-arms the
//	        malware lane that (c) below makes load-bearing.
//	    (b) The literal dist-tag name `latest` is dereferenced to a concrete
//	        version before Scan on the public intel path. Every packument
//	        runner decides absence by asking whether the requested string is
//	        a KEY of the registry's versions map, and `latest` is a tag name
//	        and never a key, so the coordinate returned WarnVersionNotFound →
//	        VerdictUnknown → NOT EVALUATED / 0 (F) for a package that is
//	        fine. Rows already keyed on the literal string are NOT retired by
//	        this bump — after the fix that coordinate is never requested on
//	        that path again, so the epoch check is never reached for it — and
//	        need the one-shot purge in
//	        core/pgstore/migrate_latest_sentinel.go. docker (`latest` is a
//	        real tag) and the Maven family (`LATEST` is a resolver directive)
//	        are excluded from both halves.
//	    (c) The known-malicious instant block is hoisted ABOVE
//	        EvaluatePackage's SignalsUnavailable short-circuit, and the three
//	        unavailability returns in risk_projection.go now carry the two
//	        instant-block facts. The malware provider is Tier 1 and fans out
//	        in parallel, so its verdict was computed and merged — and then
//	        deleted by a projection that returned before reading it. An
//	        unpublished or yanked MALICIOUS version returned NOT EVALUATED.
//	        Direction is unknown → quarantine: enforcement-strengthening, and
//	        the strongest single tightening in the wave.
//	    (d) A package that does not exist upstream AT ALL is no longer graded
//	        clean, IN THE ECOSYSTEMS WHERE THAT CAN BE KNOWN. The
//	        package-level probe distinguishes a definite 404 from an outage
//	        and mints WarnPackageNotFound, which the projection routes to
//	        Unknown. Previously `rubygems colourama` scored ALLOW 96 (A),
//	        `pypi requests-python` ALLOW 92 (A) — a textbook slopsquat graded
//	        A. Direction is allow → unknown.
//
//	        The marker is restricted to ecosystems with ONE canonical
//	        registry: npm/yarn/bun, pypi/pip, cargo, rubygems, nuget,
//	        composer, cocoapods, pub. A 404 from the one registry this
//	        provider asks is only evidence about the PACKAGE when that
//	        registry owns the whole namespace. The Maven family and Go are
//	        federated — a groupId lives in Central, maven.google.com, JitPack
//	        or a corporate mirror, and a module path is the identity while
//	        proxy.golang.org is a cache of public VCS — so they keep the
//	        pre-existing `not_found`, which says the true thing: not found in
//	        the registry we checked. Measured on the same 7,099-row export:
//	        the unrestricted rule would have relabelled 1,547 registry-
//	        COVERAGE gaps as absent packages, 1,405 of them real Android /
//	        AndroidX coordinates published to maven.google.com, plus
//	        unresolved-property coordinates like `${project.groupId}:txw2`.
//	        Restricting it leaves 152 package_not_found rows, every one in a
//	        single-canonical ecosystem.
//	    (e) The seven ecosystems with no advisory source at all (huggingface,
//	        swift, cocoapods, docker, apt, yum, dnf) stop flooring at ALLOW.
//	        When no vulnerability lane covered the coordinate AND none
//	        produced data, the scan now stamps WarnUnsupported and the
//	        projection routes it to Unknown instead of letting every category
//	        start at categoryBase = 100. Direction is allow → unknown, and it
//	        is the largest population in the wave by row count.
//
//	        The stamp's WORDING now distinguishes two facts it used to
//	        conflate. Its complement was taken over every string, so a
//	        repository NAME that had leaked into the ecosystem column —
//	        `maven-hosted`, `npmjs-hosted`, `rubygems-hosted`,
//	        `crates-hosted`, 8 rows in the export — was reported as an
//	        UNCOVERED ECOSYSTEM. That claim is false: they are ordinary
//	        maven/npm/rubygems/cargo packages and every one of those
//	        ecosystems has full advisory coverage. The verdict is unchanged
//	        and deliberately so — every provider's Supports() rejects the
//	        string, so nothing scanned those reports and Unknown is correct;
//	        suppressing the marker would be a fail-open that the P8-34
//	        refutation test forbids. What changes is that the reason names
//	        the routing problem instead, which is the thing a reader can
//	        act on.
//
//	        Per the Phase 7 Wave 6 ruling the real fix is upstream and NOT
//	        in the canonicaliser: Refresher.refreshRow and its server wiring
//	        no longer substitute a repository NAME for repo.Format when a
//	        row cannot be resolved. That was the last live producer of these
//	        rows; the upload and publish paths were moved to repo.Format in
//	        Wave 6, so an org's hosted-registry uploads carry `maven` and
//	        are scanned normally. The 8 in the export are historical.
//
//	    Flip population, by shape rather than by number — it is not
//	    measurable from source and was NOT measured: (a) every row whose
//	    stored ecosystem string is not already lower-case; (b) every row with
//	    version = 'latest' outside docker and Maven; (c) rows carrying
//	    MalwareStatus="malicious" together with an unavailability warning;
//	    (d) rows for coordinates whose PACKAGE 404s upstream in a
//	    single-canonical-registry ecosystem; (e) every row in the seven
//	    uncovered ecosystems with no ScannedAt. (d) and (e) also move
//	    `chainsaw intel scan` from exit 0/1 to exit 2 for any lockfile
//	    containing one, via treeExitCode.
//
//	    That CI-exit delta HAS now been counted, on the 7,099-row read-only
//	    production export, by TestPhase8UnevaluatedProbe: 1,983 coordinates
//	    (27.93%) came back NOT EVALUATED under the uncorrected wave, and 457
//	    (6.44%) come back under it as it now stands. The whole 1,526-row
//	    difference is (d): registry-coverage gaps that the unrestricted rule
//	    was relabelling as absent packages. (e)'s correction moves no row —
//	    it changes what 8 of them SAY — which is why the two are counted
//	    separately rather than netted. The remaining 457 are the genuinely
//	    uncovered ecosystems and the genuinely absent packages, including
//	    `npm leftpadd`, `pip colourama`, `pub htttp` and
//	    `pub flutter_secure_strorage`.
//	8 — licence correctness (2026-08-25). ONE bump for Wave D's licence
//	    half, for the same reason epoch 7 was one bump: all four changes
//	    move overlapping rows and splitting them would buy four recomputes
//	    of one corpus for one measurement. Every one changes a verdict or a
//	    score for an UNCHANGED coordinate.
//
//	    (a) Free-text licence NAMES are normalised to SPDX ids on READ, in
//	        risk.Classify (core/risk/license_classifier.go). Registries
//	        overwhelmingly carry the name, not the id — "The Apache Software
//	        License, Version 2.0", "MIT License", "Apache 2.0" — and all of
//	        them failed a strict SPDX parse and came back
//	        license.unidentified at -15. Measured on the 400-package benign
//	        corpus: 58 of 70 Maven artifacts (82.9%) and 28 of 100 PyPI
//	        packages. Direction is score-UP (a -15 over-call is removed), so
//	        this half is enforcement-LOOSENING and is the largest measured
//	        false-positive source in the engine.
//	    (b) The SAME normalisation closes a false NEGATIVE, and that half is
//	        enforcement-strengthening. "Eclipse Public License v2.0", "MPL
//	        2.0" and "GNU Lesser General Public License" are genuine
//	        copyleft and were also reported merely "unidentified", so no
//	        license.copyleft tag reached the policy engine and a copyleft
//	        block rule could not fire on them. They now classify, and
//	        versionless names keep the family ("LGPL") rather than a
//	        fabricated version, because the strength band does not depend on
//	        the version.
//	    (c) Copyleft is no longer double-counted, and licence strength is
//	        tiered (core/risk/registry_license.go). license.non_permissive
//	        is by definition the superset of license.copyleft and both were
//	        -20, so every copyleft package paid -40 — twice what BUSL-1.1
//	        paid, and enough to beat a vuln.cvss_high in
//	        UpgradePromotionEligible's dominance test, which suppressed the
//	        upgrade recommendation for every copyleft package with a fixable
//	        CVE. Now: weak copyleft -10, source-available -20, strong
//	        copyleft -30. Direction is score-UP for weak copyleft and for
//	        strong copyleft (-40 → -10 / -30) and unchanged for
//	        source-available, and it turns WARN into UPGRADE_AVAILABLE for
//	        the CVE-plus-copyleft population.
//	    (d) The Composer reader implements Packagist's `composer/2.0`
//	        minified metadata format (core/intelligence/
//	        provider_registrymetadata.go). It did not, in two ways, and
//	        between them they were the single largest FP cell in the corpus.
//	        A removed field is encoded as the literal string "__unset" in a
//	        position typed map[string]string, so one such field anywhere in
//	        a package's version history aborted the decode of the WHOLE
//	        document and the report came back with NO facts at all — which
//	        the scorer reads as clean. 35 of the 60 most-installed Composer
//	        packages (58.3%) carry one. Separately, entries after the first
//	        are DELTAS, so 99.4% of version entries carry no licence key and
//	        every non-latest coordinate silently lost its licence, its
//	        maintainers, its dependencies and its source repo. Direction is
//	        BOTH: score-UP for the 35 that were paying a phantom -30 licence
//	        deficit, and allow → unknown for nonexistent Composer versions,
//	        which could not reach the version-not-found promotion while the
//	        decode was failing ahead of it (guzzlehttp/guzzle 99.99.99
//	        graded ALLOW 96).
//
//	    Flip population, by shape rather than by number — it is not
//	    measurable from source and was NOT measured, and the two directions
//	    are deliberately NOT netted: (a) every row whose stored
//	    Metadata.LicenseExpression is a licence name rather than an SPDX id,
//	    which is most of Maven Central and a quarter of PyPI; (b) the subset
//	    of those whose name denotes a copyleft licence — small in count,
//	    and the only shape in this epoch where a policy that previously
//	    could not fire begins to; (c) every row carrying license.copyleft,
//	    and within it the rows that also carry a fixable vulnerability
//	    signal, which are the ones whose VERDICT moves rather than just
//	    their score; (d) every Composer row, in both directions — the 35
//	    empty-report shapes gain facts, and any Composer row pinned to a
//	    version the registry never published moves from allow to unknown.
//	9 — safe-version corroboration (2026-08-31, QA Phase 9 P0-B). ONE bump
//	    covering TWO changes that MUST NOT BE SPLIT, plus the cocoapods
//	    advisory-coverage correction (P0-C) which rides this bump rather
//	    than taking one of its own.
//
//	    (a) MinimumSafeVersion now refuses a candidate that the registry's
//	        OWN enumerated version list contradicts. Advisory `fixed`
//	        endpoints are hand-entered upstream and were taken verbatim, so
//	        ApplyKnownFix printed "Patched in X — upgrade and re-scan" for
//	        versions that 404. Measured on a live production replay of the
//	        439 CVE-bearing rows: 359 resolved a non-empty answer, 3 of
//	        them named a version the registry does not list. The rule is
//	        CONDITIONAL — an absent timeline vetoes nothing, per the
//	        WarnVersionNotFound doctrine above.
//
//	    (b) The Go handler now populates Maintenance.VersionTimeline from
//	        the module proxy's @v/list. runGo was the one major-ecosystem
//	        handler that never called applyTimeline, which is why 39 of the
//	        43 timeline-less rows in that replay were Go.
//
//	    WHY (a) AND (b) ARE ONE EPOCH. The backfill drain calls Scan with
//	    AllowStale:false — a full network rescan. Shipping (a) at this
//	    epoch and (b) at the next would rescan every Go row while it still
//	    had no timeline and PERSIST the blanking: 39 rows lose their
//	    upgrade guidance, 10 lose their promotion, and
//	    `go github.com/emicklei/go-restful@v2.15.0` goes warn →
//	    quarantine → Blocked. Only a second bump plus a second full drain
//	    would undo it. This is the inverse of the Phase 8 serve-floor
//	    incident.
//
//	    (c) Corroboration moved ABOVE the display write and no longer
//	        fails open when NOTHING is known. Previously an absent
//	        "latest" returned corroborated=true; it now also requires a
//	        populated timeline. Measured cost: 4 rows of 359 (1.1%).
//	        An uncorroborated fix version is still RECORDED — only the
//	        imperative wording is withdrawn, and the new
//	        Resolution.SafeVersionCorroborated bit says which is which.
//	        This AMENDS Phase 7 D-1/D-2: D-2's ruling that
//	        intelligence_latest_probes.latest_version is not a safe-version
//	        SOURCE is untouched; it is admitted only as a corroborator.
//
//	    Flip population, by shape: (a) the rows whose stored
//	    Resolution.SafeVersion is absent from that coordinate's own
//	    VersionTimeline — 3 in the replay, and the only ones losing the
//	    value outright; (b) every Go row, which gains VersionCount and
//	    VersionDataAvailable and therefore becomes eligible for
//	    maint.very_new_package and maint.healthy_cadence for the first
//	    time — direction is BOTH (a +10 cadence signal for established
//	    modules, a -10 very-new signal for modules under 30 days old with
//	    <=3 tags); (c) the 4 rows with neither a latest nor a timeline,
//	    which lose an upgrade_available promotion and gain the softened
//	    advisory wording; (d) every row with a non-empty SafeVersion,
//	    whose PatchAdvisory sentence is rewritten when uncorroborated.
//	    Fixing the computation fixes nothing for the 359 cached rows
//	    without this bump: store.go serves the persisted risk_evaluation
//	    verbatim and the refresher short-circuits on
//	    `reportFresh && latest == row.Version`, which is exactly the
//	    most-pulled coordinates. The staged drain in
//	    docs/runbooks/matcher-epoch-backfill.md is REQUIRED and, at the
//	    time of this commit, OUTSTANDING.
//	epoch 10 (2026-09-01, P8-11): maint.single_maintainer no longer fires on
//	    Maven/Gradle. The maintainer list for those ecosystems is built from
//	    the POM `<developers>` block, which is hand-written prose; spring-core
//	    lists exactly one developer, so the signal read "single maintainer,
//	    bus-factor risk" off a documentation field. See
//	    core/risk/registry_maintenance.go.
//
//	    THIS BUMP WAS ALMOST OMITTED, AND THE REASONING THAT NEARLY OMITTED
//	    IT IS THE INTERESTING PART. The signal is SevLow, weight -5, and the
//	    Phase 8 plan says outright that it "cannot move a verdict" — so the
//	    first version of this change shipped without a bump on the theory
//	    that it was score-affecting only. That is false. Bands are strict
//	    integer comparisons on `overall` (`overall < thresholdWarn`), and
//	    overall = 100 - int(deficit+0.5), so suppressing a -5 maintenance
//	    signal removes 5 x 0.15 = 0.75 of deficit — enough to cross an
//	    integer boundary. Brute-forcing the real EvaluatePackage over 1024
//	    maintenance-heavy inputs found 9 verdict flips, every one
//	    `overall=59 warn` -> `overall=60 allow`; the smallest is
//	    {typosquat_medium, stale_repo_commit, manifest_confusion}. A weight
//	    small enough to look cosmetic still moves a verdict when the band
//	    test is a strict integer compare.
//
//	    Flip direction is UN-BLOCKING (warn -> allow), so the flip
//	    population is Maven/Gradle coordinates with a single `<developers>`
//	    entry sitting exactly on the 59/60 edge. Small, but it is the
//	    direction that needs measuring, not the one that fails safe.
//	epoch 11 (2026-09-02, P8-70): sc.publisher_changed stops firing on every
//	    Maven/Gradle package that had ever been scanned before. This is the
//	    SevHigh sibling of the epoch-10 finding — weight -25, MaxImpact 40,
//	    and it feeds CompoundSCTakeoverSignature at -55 — but the defect
//	    turned out NOT to be the one P8-70 was filed against.
//
//	    P8-70 alleged that the POM `<developers>` roster churns and so the
//	    diff over it false-positives. The prod data says something worse:
//	    the diff was never comparing rosters at all. The two sides of the
//	    comparison were extracted by two different pieces of code that
//	    disagreed on which POM element IS the publisher identity. The
//	    persisted baseline (fetchMavenPublisherSet, package_metadata
//	    .publisher_set) preferred `<developer><id>` — `ggregory`. The
//	    incoming set (runMaven, Report.People.PublisherIDs) never parsed
//	    `<id>` at all and used `<email>`, else `<name>` —
//	    `ggregory@apache.org`. Those identifier spaces do not intersect, so
//	    the diff saw a COMPLETE publisher replacement on every maven
//	    coordinate with any scan history, forever.
//
//	    Measured on prod 2026-09-01, before the fix: 30 maven/gradle
//	    coordinates carried publisherChanged=true, and ALL 30 had a
//	    zero-size intersection between the two sides — i.e. 30/30 were
//	    manufactured by the mismatch, not by a roster change. Nineteen of
//	    them have byte-identical `<id>` sets across the two versions being
//	    compared (all six org.apache.commons:commons-lang3 rows, all three
//	    commons-text rows, five scala-library rows, ...). The only maven
//	    rows that ever came back publisherChanged=false in the whole corpus
//	    were org.apache.maven:maven-parent, forced false by the
//	    canonicalParentPOMs allowlist — so the allowlist was not mitigating
//	    an edge case, it was the only thing suppressing a signal that
//	    otherwise fired on 100% of what it evaluated.
//
//	    The fix routes both sides through MavenDeveloperPublisherIDs
//	    (`<id>` -> `<email>` -> `<name>`). The BASELINE extractor is
//	    semantically unchanged, so no publisher_set backfill is needed and
//	    no new false positives are introduced by re-persisting it; only the
//	    incoming side moves.
//
//	    Flip population and direction, replayed through the real
//	    EvaluatePackage over the 30 stored prod reports: 19 rows clear to
//	    publisherChanged=false, and 6 of those 19 change VERDICT — every
//	    one warn -> allow (commons-chain 1.2, commons-lang3 3.14.0,
//	    commons-lang3 3.20.0, commons-text 1.15.0, maven-reporting-api 3.0,
//	    slf4j-bom 2.1.0-alpha1). The other 13 gain score inside the same
//	    band. Direction is UNIFORMLY UN-BLOCKING; nothing becomes more
//	    restrictive. The ceiling, if every one of the 30 cleared, is 15
//	    flips — that is the number to compare against if a later change
//	    also addresses the residual.
//
//	    RESIDUAL, deliberately NOT fixed here. Eleven of the 30 still fire
//	    after this bump because their `<id>` sets genuinely differ across
//	    versions — a committer joining (commons-digester, commons-lang,
//	    commons-logging), or an org rename (`lightbend` -> `akka` across
//	    the scala-lang artifacts). None is an account takeover. That is
//	    P8-70's original claim and it survives: a POM `<developers>` edit
//	    is still not an access-control event. It stays open pending the
//	    groupId-ownership design recorded in the P8-70 row.
//
//	    A bump is REQUIRED rather than optional: store.go serves the
//	    persisted risk_evaluation verbatim, so the 19 cached rows keep
//	    their manufactured SevHigh finding until the epoch invalidates
//	    them.
//	epoch 12 (2026-09-02, P8-70 severity demotion + Wave J J-1): TWO changes,
//	    ONE bump, deliberately — they landed together so the corpus is
//	    invalidated once rather than twice.
//
//	    P8-70: `sc.publisher_changed` no longer fires on Maven/Gradle. Its
//	    input is the POM `<developers>` block, and of the 30 coordinates that
//	    ever fired it, ZERO were takeovers — they were committer additions,
//	    removals, and the lightbend->akka rename. The fact is kept by a new
//	    `sc.pom_developer_list_changed` (SevLow, -5, and deliberately NO
//	    MaxImpact: a ceiling asserts the signal alone justifies holding a
//	    package below a band, which a 0-of-30 true-positive rate refutes).
//	    The SevCritical -55 takeover compound is blocked for these ecosystems
//	    twice, implicitly and explicitly, because the implicit block
//	    evaporates the moment anyone re-widens the primitive.
//	    Flip population: 13 of the 16 affected prod rows, EVERY ONE
//	    `warn` -> `allow`. Uniformly enforcement-weakening, which is the
//	    direction that must be measured rather than assumed.
//
//	    Wave J J-1: a closure node whose version violates a constraint the
//	    ROOT declares on that same name is refused before it enters the graph.
//	    Measured flip count: ZERO tree verdicts across all 7,756 prod rows —
//	    43 closures shrank and 4 blame lists changed, so it is report-
//	    affecting but not verdict-affecting. It rides this bump rather than
//	    needing its own.
//
//	    The J-1 scoping is the interesting part and must not be widened
//	    casually: root-declared constraints only, single-version ecosystems
//	    only, and OPERATOR-BEARING constraints only. That last limit came out
//	    of measurement, not theory — an earlier cut that treated a bare
//	    version as a pin flipped 11 verdicts, 10 of them go/maven, including
//	    a `quarantine` -> `allow` that discarded four transitive criticals.
//	    A bare version is a soft requirement in Maven, a minimum under Go MVS,
//	    and a lower bound in NuGet.
//	epoch 13 (2026-09-02, P8-71): sticky supply-chain facts now bind the
//	    VERDICT, not just the display.
//
//	    The stored `report` and the stored `risk_evaluation` were snapshots
//	    of two different moments. risk.EvaluatePackage ran on the in-flight
//	    report inside ComputeTrustScoreForOrg; only afterwards, inside
//	    Store.Upsert, did mergeReportPayload revive the sticky-on-silence
//	    supply-chain fields from the prior row. So a fact was preserved for
//	    DISPLAY and discarded for ENFORCEMENT — the dashboard said
//	    publisher-changed and the verdict, which is what actually gates,
//	    did not.
//
//	    Measured on prod before the fix, at epoch 12, across all ecosystems:
//	    28 rows with publisherChanged=true and no publisher signal in the
//	    evaluation beside them, 180 with versionAnomaly=true and no
//	    qual.version_anomaly, 83 across repoLinkStatus and 12 across
//	    typosquatStatus — 298 distinct rows, and ZERO rows the other way
//	    round in every one of those categories. The strict
//	    one-directionality is what proves the mechanism rather than a
//	    write-ordering artefact: a FIRED signal implies the incoming scan
//	    genuinely observed the fact, so only the revival direction can drift.
//
//	    The fix applies the carry-forward to the RISK INPUT, in runFanout,
//	    before the evaluation, instead of to the report afterwards.
//	    Evaluation stays where it is; both columns derive from one set of
//	    facts. The rules live in ONE function (applyStickySupplyChain) that
//	    both runFanout and mergeReportPayload call, so a sticky field added
//	    later cannot reintroduce the split — that generality is why this
//	    was preferred over re-evaluating inside the store.
//
//	    VersionAnomalyFlags now travels with the VersionAnomaly bool as one
//	    fact. qual.version_anomaly fires on the FLAGS and never on the bool,
//	    so the bool-only carry-forward revived a fact whose evidence had
//	    been dropped: 161 of the 180 drifted rows say versionAnomaly=true
//	    with an empty flag list. A fact without its evidence cannot bind
//	    anything.
//
//	    Flip population and direction, replayed through the real evaluator
//	    over all 298 stored prod reports, before vs after, same engine:
//	    189 rows change VERDICT and every single one is
//	    ENFORCEMENT-STRENGTHENING — 181 allow -> warn, 7
//	    upgrade_available -> warn, 1 upgrade_available -> quarantine
//	    (org.apache.maven.shared:maven-shared-utils 3.1.0, whose CVSS-9.8
//	    upgrade promotion no longer holds once a second non-CVE problem is
//	    visible). Nothing becomes more permissive. As a model check, the
//	    replayed BEFORE verdict reproduces the stored verdict for 288 of
//	    the 298 rows; the 10 that differ are engine drift accumulated since
//	    those rows were written, not this change.
//
//	    Of the 189, THIRTY-SIX flip from facts the corpus already holds.
//	    The other 153 need a scan to observe version-anomaly flags, because
//	    the flags those rows lost are not recoverable from the row that
//	    overwrote them — the pair-carry stops the evidence being dropped
//	    from here on, it does not resurrect what is already gone. Both
//	    numbers are stated because quoting only 189 would overstate what
//	    the drain itself does, and quoting only 36 would understate the
//	    defect.
//
//	    A bump is REQUIRED, not optional: store.go serves the persisted
//	    risk_evaluation verbatim, so every affected cached row keeps its
//	    fact-free verdict until the epoch invalidates it. A staged drain is
//	    needed on deploy — this is the strengthening direction, so the
//	    backlog is rows that will start warning, and the drain should be
//	    watched rather than assumed.
const CurrentMatcherEpoch = 13

// MinServeableEpoch is the floor a cached row must meet to be SERVED. It
// normally equals CurrentMatcherEpoch and MUST be returned to that value
// once a staged backfill finishes; TestMinServeableEpochIsNotLeftLowered
// fails while it is lowered without an explicit opt-in.
//
// # WHY IT IS SEPARATE FROM CurrentMatcherEpoch
//
// CurrentMatcherEpoch is two things at once: the generation a fresh Scan
// STAMPS, and the floor reads REFUSE below. Those coincide in the steady
// state, where a handful of rows are stale at any moment and every direct
// read path treats a stale row as a cache miss and rescans on demand.
//
// They come apart on a deploy that raises the epoch by more than the
// backlog can absorb. Raising it retires EVERY existing row at once, and
// the transitive-risk provider is the one read path whose miss handler
// cannot heal itself: lookupDepReport treats a superseded row like a miss
// and provider_transitiverisk.go DROPS the dependency with a warning
// rather than enqueuing a rescan. Measured on the 5 -> 8 bump against the
// production export: dependency lookups served fall from 92,046 to
// 11,744, so every rollup collapses to direct-only. The recompute sweep
// drains 500 rows an hour (DefaultRecomputeMaxRows, one-hour tick), so
// that is roughly a week of silently degraded transitive resolution.
//
// The backfill cannot run ahead of the deploy, because an epoch-8 row can
// only be produced by epoch-8 code. And it cannot be shortcut by
// re-scoring the stored report instead of rescanning: epoch 7(a) restored
// provider lanes that display-cased coordinates never ran at all, 7(d)
// added a network probe, and 8(d) fixed a decoder — those rows are
// missing FACTS, not just mis-scored, so re-stamping them from stored
// data would convert a visible "stale" state into an invisible "wrong"
// one, which is the failure the epoch counter exists to prevent.
//
// So the sequence is: deploy with this floor held at the OLD epoch, let
// the sweep drain the backlog to CurrentMatcherEpoch, then raise this to
// match and redeploy. Holding the floor down during the drain is not a
// regression — it serves exactly the verdicts production is already
// serving today — whereas flipping cold makes transitive resolution
// strictly worse than today until the sweep catches up.
//
// This is the SERVE gate only. The drain-side predicates (Store.Facets'
// backlog count, IterateMatcherStale/CountMatcherStale, and the
// "recompute pending" flag on Store.Search) deliberately stay on
// CurrentMatcherEpoch: the sweep must still target every row below the
// current generation, and the operator must still see the true backlog.
// TestDrainPredicatesTrackCurrentEpochNotServeFloor pins that split.
var MinServeableEpoch = envMinServeableEpoch()

// envMinServeableEpoch reads CHAINSAW_INTELLIGENCE_MIN_SERVEABLE_EPOCH,
// the staged-deploy override. Anything absent, unparseable, or outside
// (0, CurrentMatcherEpoch] falls back to CurrentMatcherEpoch — a typo in
// a deploy variable must not silently widen what the cache will serve.
func envMinServeableEpoch() int {
	raw := strings.TrimSpace(os.Getenv("CHAINSAW_INTELLIGENCE_MIN_SERVEABLE_EPOCH"))
	if raw == "" {
		return CurrentMatcherEpoch
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > CurrentMatcherEpoch {
		return CurrentMatcherEpoch
	}
	return n
}

// MatcherSupersededForRecompute reports whether this Report was produced by
// a generation below the CURRENT stamp epoch — the question "does this row
// need recomputing", which is NOT the same question as "may I serve it".
//
// The two came apart when MinServeableEpoch was introduced, and conflating
// them broke the very backfill the serve floor exists to stage. During the
// v0.21.9 deploy the recompute sweep selected rows below CurrentMatcherEpoch
// (correct), handed each to Scan, and Scan's cache short-circuit asked
// MatcherStale() — which follows the SERVE floor. With the floor held at 5,
// an epoch-5 row is not stale, so Scan returned the cached row untouched and
// the sweep counted it as recomputed. Production logged
// "recomputed=1500 failed=0" for three consecutive sweeps while the backlog
// sat at exactly 3,453.
//
// So: read paths ask MatcherStale (serve floor, lowered during a staged
// backfill). Recompute decisions ask this (stamp epoch, never lowered).
// scanner.go's comment states the invariant this restores — a row from a
// superseded matcher has "no escape hatch — not even AllowStale".
func (r *Report) MatcherSupersededForRecompute() bool {
	if r == nil {
		return true
	}
	return r.Observation.MatcherEpoch < CurrentMatcherEpoch
}

// MatcherStale reports whether this Report was produced by a superseded
// generation of the matcher or risk engine, and so must not be served from
// cache. A nil Report is stale: callers treat "no report" and "unusable
// report" the same way, which keeps the check safe at every call site.
//
// Compares against MinServeableEpoch, not CurrentMatcherEpoch — see that
// variable for why the two exist. They are equal outside a staged
// backfill.
func (r *Report) MatcherStale() bool {
	if r == nil {
		return true
	}
	return r.Observation.MatcherEpoch < MinServeableEpoch
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

	// WarnVulnRangeUndecidable is emitted when an advisory's version
	// range could not be ordered against the queried version under that
	// ecosystem's grammar. It is a WARNING and nothing more: the
	// advisory is neither counted as a hit (that would manufacture the
	// false-positive class this wave removes) nor as a veto (that would
	// let a malformed bound silently delete a real finding). Undecidable
	// is a third state, and it stays visible instead of collapsing into
	// either verdict.
	WarnVulnRangeUndecidable = "vuln_range_undecidable"

	// WarnVersionNotFound is emitted when a registry answered with a
	// package document that enumerated its published versions and the
	// requested version was NOT among them. It is positive evidence of
	// absence, not absence of evidence: a fetch failure, a package-level
	// 404, or a document carrying an empty/absent version list must
	// never produce this code — that is where registry lag, yanked-
	// version pruning, and private or mirrored registries serving
	// partial documents live, and treating those as "does not exist"
	// would manufacture false positives at scale.
	//
	// It is deliberately NOT a risk signal. A signal is a fact about a
	// package we EVALUATED; "this version does not exist" means we
	// evaluated nothing. Minting a signal would also drop it into the
	// tunable-weights surface, letting an operator dial hallucinated-
	// version detection down to zero. Instead risk_projection.go turns
	// this warning into risk.Input.SignalsUnavailable, which the
	// evaluator short-circuits to VerdictUnknown.
	//
	// Classified as an OK code in core/coverage/status.go — like
	// not_found, it is a real answer from the source, not an outage, so
	// it must not trip the opt-in fail-closed coverage gate.
	WarnVersionNotFound = "version_not_found"

	// WarnPackageNotFound is emitted when BOTH the per-version endpoint
	// and the package-level document 404 — positive evidence that the
	// PACKAGE, not merely the version, does not exist upstream.
	//
	// It is the stronger sibling of WarnVersionNotFound and it exists
	// because the two were collapsed. Every Group-A probe reduced its
	// outcome to a bare bool, so a package-level 404 and a registry
	// outage arrived at promoteVersionNotFound indistinguishable and
	// both kept the generic `not_found` code — which the projection
	// never consumes and core/coverage classifies as OK. The result,
	// verified against live registries on 2026-08-25: `rubygems
	// colourama` → ALLOW 96 (A), `nuget Newtonsoft.Json.net` → ALLOW 86
	// (B), `pypi requests-python` → ALLOW 92 (A). `requests-python` is a
	// textbook slopsquat of `requests`, graded A.
	//
	// SAME DISCIPLINE AS ITS SIBLING: only positive evidence. A 5xx, a
	// timeout, a transport error or a decode failure on the package-level
	// probe must never produce this code — isDefiniteAbsence is an
	// allowlist of exactly {not_found, http_404} for that reason.
	//
	// Like WarnVersionNotFound it is NOT a risk signal: it means we
	// evaluated nothing, not that we found something.
	// risk_projection.go turns it into risk.Input.SignalsUnavailable →
	// VerdictUnknown.
	//
	// Classified as an OK code in core/coverage/status.go, following the
	// version_not_found precedent: the registry ANSWERED, and the answer
	// was "no such package". That is not an outage, so it must not trip
	// the opt-in fail-closed coverage gate — the refusal that is
	// warranted comes from the unknown verdict, which every surface
	// reads, not from a gate only opted-in orgs run.
	WarnPackageNotFound = "package_not_found"

	// WarnVersionNotEvaluable is stamped by the ingest gate in
	// version_evaluable.go when the coordinate's VERSION component can
	// never be ordered against an advisory range — an uninterpolated
	// `${…}` build property, our synthetic `metadata` marker for
	// maven-metadata.xml uploads, a Maven meta-version, or an empty
	// string.
	//
	// It is a statement about the COORDINATE, not about the package, and
	// that is what distinguishes it from its two neighbours:
	// WarnVersionNotFound means the registry answered and the version was
	// not published; WarnVulnRangeUndecidable means one advisory's bound
	// could not be ordered on this occasion. This code means we never had
	// a version to evaluate at all, and no future matcher improvement
	// will change that.
	//
	// It exists because the row is otherwise indistinguishable from a
	// clean one: it carries a collected_at, warning_count 0, is_malicious
	// false, and no advisory can ever attach to it. Every list surface
	// therefore counted it as scanned. The Message carries the reason
	// code (see UnevaluableVersion*) so a consumer can render why without
	// re-deriving the rule.
	WarnVersionNotEvaluable = "version_not_evaluable"

	// Transitive-risk visibility codes. Emitted by evaluateTransitiveRisk
	// when a direct dep cannot be folded into the rolled-up score, so
	// operators can tell a clean verdict from one with blind spots.
	WarnTransitiveDepNotCached             = "transitive_dep_not_cached"
	WarnTransitiveDepConstraintUnparseable = "transitive_dep_constraint_unparseable"
	WarnTransitiveDepLookupError           = "transitive_dep_lookup_error"
	// WarnTransitiveDepSuperseded is the cached-but-retired case, split
	// out from WarnTransitiveDepNotCached because the two call for
	// opposite operator responses. "Not cached" means the dependency has
	// never been scanned and someone should look at why. "Superseded"
	// means it HAS been scanned and is waiting on the recompute sweep —
	// nothing to chase, and it drains on its own.
	//
	// The distinction is load-bearing right after an epoch bump, when
	// this is the reason for nearly every excluded dep. It used to
	// report as "not in cache", which sent operators hunting for a scan
	// that had already happened.
	WarnTransitiveDepSuperseded = "transitive_dep_superseded"

	// WarnTransitiveDepConstraintConflict is emitted when a closure node
	// was REFUSED because its resolved version violates a constraint the
	// ROOT package declares on that same dependency name. See
	// violatesDeclaredRootConstraint in provider_transitiverisk.go for
	// the rule and its deliberate limits.
	//
	// This is not a cache problem and not a parse problem: the dependency
	// resolved fine, to a version this package provably cannot install.
	// It is the only transitive warning that reports a node the walker
	// found and then threw away, so it is emitted at every depth rather
	// than only for the root's own direct edges.
	WarnTransitiveDepConstraintConflict = "transitive_dep_constraint_conflict"
)

// ProviderTiming captures per-provider runtime (for observability).
type ProviderTiming struct {
	Provider string        `json:"provider"`
	Duration time.Duration `json:"durationNanos"`
	Error    string        `json:"error,omitempty"`
}
