package risk

import "time"

// Input is the flattened set of facts a single package version presents to
// the evaluator. The intelligence package projects a merged Report to this
// struct before calling EvaluatePackage, which keeps this package free of
// any intelligence dependency (and therefore usable by future consumers
// that do not carry the full Report type — e.g., the tree evaluator or
// external adapters).
//
// A nil Input is safe; every field has a sensible zero meaning (unknown).
// Callers SHOULD populate as many fields as they have; the evaluator never
// panics on missing data, it simply leaves the corresponding signals
// un-fired.
type Input struct {
	// Identity — for blame / resolution pointers.
	Ecosystem string
	Package   string
	Version   string

	// --- Vulnerability ---
	IsVulnerable   bool
	MaxCVSS        float64
	EPSSScore      float64 // 0..1 probability of exploitation
	KnownExploited bool    // CISA KEV / actively exploited
	CVEs           []string
	// FixAvailable is true when at least one CVE on this package has a
	// patched upstream version — drives triage prioritization (KEV +
	// fix-available = top of queue; KEV + no-fix = exception candidate).
	FixAvailable bool
	// FixedCVEs is the subset of CVEs that have a known fix version,
	// surfaced as evidence on the fix-available signal.
	FixedCVEs []string

	// --- Supply-chain ---
	IsKnownMalicious bool
	MalwareID        string
	MalwareSummary   string

	IsSuspectedTyposquat bool
	TyposquatConfidence  string // "high"|"medium"|"low"
	TyposquatSimilarTo   string

	PublisherChanged bool

	HasInstallScript           bool
	InstallScriptFetchesRemote bool

	// EnvVarAccess is true when the artifact scanner observed reads of
	// process environment variables (process.env, os.environ, %ENV, ...).
	// On its own this is a context-only signal — most legitimate code
	// also reads env vars — so the v2 engine does NOT register a
	// single-axis penalty for it. The compound rule
	// CompoundSCEnvNetInstall is the block carrier (env-var ∧ network ∧
	// install-script). See Pain 9 plan, registry_supplychain.go, and
	// compound.go for the rationale.
	EnvVarAccess bool
	// NetworkAccess is true when the artifact scanner observed network
	// primitives (fetch, http.get, urllib, ...) anywhere in the package
	// body — not necessarily inside an install script. Treated as
	// context-only for the same reason EnvVarAccess is, and feeds the
	// CompoundSCEnvNetInstall block carrier.
	NetworkAccess bool

	HasHiddenUnicode bool

	HasProvenance    bool
	ProvenanceStatus string // "verified" rewards
	// SLSALevel is the SLSA build level (1-4) the verified attestation
	// claims, or 0 when no level is known. Drives the per-level
	// supply-chain bonus in registry_supplychain.go (mirrors the legacy
	// trustscore.SLSALevelBonus contribution under the attestation-first
	// reframe).
	SLSALevel int
	// SignatureVerified is the upstream-signature verdict (sigstore /
	// PGP) projected from Provenance by provider_signature_verify. true
	// awards a positive supply-chain bonus separate from the
	// HasProvenance reward — checksum and provenance are not the same as
	// a real cryptographic verification against an independent trust
	// root.
	SignatureVerified bool

	HasSourceRepo  bool
	RepoLinkStatus string // "ok"|"archived"|"missing"|"ownership_mismatch"|"unknown"|""

	ReservedNamespaceViolation bool
	PublishVelocityAnomaly     bool

	// --- Wave-4 RTT (return-trip-time) signals ---
	// SuspiciousRepoStars fires when the repo star/age/maintainer-age
	// composite triggers all-three-of-three (low stars + young repo + young
	// maintainer). High-confidence by construction, so the projected risk
	// signal carries a heavy negative weight.
	SuspiciousRepoStars bool
	// FirstTimeCollaborator is three-state — &true: confirmed first-publish
	// from this maintainer for the package, &false: known repeat collaborator,
	// nil: unknown. Only &true fires the risk signal; nil and &false stay
	// dormant so sparse data does not penalise.
	FirstTimeCollaborator *bool
	// MaintainerAccountAgeDays is the oldest maintainer's account age in
	// days. 0 means unknown — no signal fires. Tiered penalties under 180
	// days approximate the legacy "very-young account" scoring band.
	MaintainerAccountAgeDays int
	// NonExistentAuthor fires when the declared author email/name does not
	// resolve to an existing account on the registry — strong indicator of
	// a rushed/anonymous publish.
	NonExistentAuthor bool

	// --- Maintenance ---
	PublishedAt      *time.Time // this version
	LatestReleaseAt  *time.Time // latest version of package (any)
	FirstPublishedAt *time.Time // earliest version of package (any)
	LastRepoCommitAt *time.Time
	VersionCount     int
	MaintainerCount  int

	// Stars / Forks / OpenIssues / Subscribers are projected from
	// Maintenance section. Used by quality-grade signals that mirror
	// Socket's stargazer/fork/watcher dimensions.
	Stars       int
	Forks       int
	OpenIssues  int
	Subscribers int

	// VersionDataAvailable is true when the registry's full version
	// timeline was successfully fetched for this package. When false, the
	// maintenance category treats version-count-based signals as dormant
	// (data unavailable, not "package has 0 versions"). Prevents the
	// `maint.very_new_package` false-positive that fires when the sparse
	// proxy-driven store returns 0 versions for a popular package.
	VersionDataAvailable bool

	// VulnDataAvailable is true when a CVE scan actually completed for
	// this package version (whether or not it found anything). When false,
	// the Vulnerability category is marked DataAvailable=false in the
	// resulting CategoryScore and is excluded from the overall rollup —
	// "we have not scanned" must not score the same as "we scanned and
	// found nothing".
	VulnDataAvailable bool
	// RepoArchived is three-state — preserved as *bool so policy/risk
	// authors can distinguish "archived = true" (high-signal: repo is
	// read-only, package shouldn't see new releases), "archived = false"
	// (probed, not archived), and nil (probe failed / unknown — e.g.
	// non-GitHub repo or auth missing). Collapsing nil → false here used
	// to silently mask probe failures; callers now branch explicitly.
	RepoArchived *bool

	// --- License ---
	LicenseSPDX            string
	LicensePolicyBlocked   bool // upstream policy flagged the license
	LicenseChangedFromPrev bool
	// LicenseTags is the Classify() output over LicenseSPDX. Populated by
	// the risk projection so both the risk engine and policy evaluator
	// share one SPDX parse. A nil slice means "not yet classified" and
	// all License* tag signals stay dormant.
	LicenseTags []LicenseTag

	// --- Socket-gap Wave 1 ---
	// DeprecatedByMaintainer is true when the registry surfaced a
	// deprecation / yanked flag on this version (npm deprecated string,
	// PyPI / Cargo yanked bool).
	DeprecatedByMaintainer bool
	DeprecationReason      string
	// ShrinkwrapPresent is true when the npm tarball ships a
	// npm-shrinkwrap.json — an npm-specific lockfile that bypasses the
	// consumer's review path.
	ShrinkwrapPresent bool
	// ManifestConfusion is true when the npm registry JSON's
	// package.json diverges semantically from the tarball's. Populated
	// by the npm-only manifestconfusion provider.
	ManifestConfusion       bool
	ManifestConfusionFields []string

	// --- Quality ---
	ChecksumVerified    bool
	ChecksumMismatch    bool // stronger than "not verified" — we know it's wrong
	VersionAnomalyFlags []string
	// IsMinifiedCode is true when the artifact scanner detected at least one
	// minified/bundled JS/TS file in the shipped source. Evidence is the list
	// of file paths that tripped the heuristic.
	IsMinifiedCode bool
	MinifiedFiles  []string

	// --- Maintenance download signal ---
	// WeeklyDownloads is the registry download count for the last 7 days.
	// nil means the value is unknown (air-gap mode, fetch error, or
	// ecosystem does not expose download counts). Only non-nil values drive
	// the maint.unpopular_package signal; nil leaves the signal dormant so
	// sparse data never produces a false positive.
	WeeklyDownloads *int

	// --- AI artifact ---
	// ArtifactSubtype mirrors PackageCoordinate.Subtype. Empty for traditional
	// ecosystems. Stable values: "model", "dataset", "space", "agent-tool",
	// "mcp-server", "prompt-template".
	ArtifactSubtype string

	// DangerousPickleOpcode is true when at least one pickle file in the
	// artifact references a known-dangerous module (os/subprocess/builtins
	// .eval/...). Drives an instant-block-class signal.
	DangerousPickleOpcode bool
	// DangerousPickleFiles lists the in-artifact paths that triggered the
	// signal. Surfaced as evidence for the finding.
	DangerousPickleFiles []string
	// DangerousPickleSummary is a short freeform string captured from the
	// scanner output (e.g. "os.system in pytorch_model.bin").
	DangerousPickleSummary string

	// SuspiciousPickleOpcode is true at warn level — the pickle imports
	// modules that are uncommon for model checkpoints but not always
	// malicious (ctypes, torch.distributed, ...).
	SuspiciousPickleOpcode bool

	// UnsafeSerializationFormat is true when the artifact ships unsafe
	// pickle weights without a safetensors alternative present.
	UnsafeSerializationFormat bool
	// PrefersSafetensorsAvailable is true when both pickle and safetensors
	// are present — we recommend the consumer pin to safetensors.
	PrefersSafetensorsAvailable bool

	// ModelCardInjection is true when the model card contains hidden
	// unicode, jailbreak language, embedded scripts, or base64 payloads
	// in YAML frontmatter.
	ModelCardInjection bool
	// ModelCardKinds enumerates the card finding kinds — surfaced as
	// evidence so the UI can render a checklist.
	ModelCardKinds []string

	// AgentToolDeclared is true when the package self-declares an MCP
	// server or agent tool (npm `mcpServers`, pyproject mcp.server entry
	// point, etc.).
	AgentToolDeclared bool
	// AgentToolDangerousCapability is true when the declared tool schema
	// reveals filesystem write, subprocess execution, or arbitrary
	// network egress.
	AgentToolDangerousCapability bool
	// AgentToolCapabilities enumerates the dangerous capabilities so the
	// UI can render specifics ("filesystem-write", "subprocess", ...).
	AgentToolCapabilities []string

	// MCPServerUnverified is true when an MCP server package lacks any
	// verifiable provenance, sigstore attestation, or repo ownership
	// match. Quality-category signal.
	MCPServerUnverified bool

	// PromptTemplateInjection is true when a prompt-template artifact
	// (HF dataset tagged "prompt", *.prompt file, etc.) contains
	// jailbreak language or hidden unicode.
	PromptTemplateInjection bool

	// --- Package.json URL dependencies ---
	// HasGitURLDep is true when at least one resolved dependency version is
	// a git URL (git+https://, git+ssh://, git://, github:user/repo).
	// These bypass the registry hash chain and cannot be audit-locked.
	// Stays zero until the manifest-projection wiring lands.
	HasGitURLDep bool
	// GitURLDeps enumerates the dep names (keys) whose version resolved to
	// a git URL. Surfaced as evidence on the signal.
	GitURLDeps []string

	// HasHTTPURLDep is true when at least one resolved dependency version is
	// a raw http:// or https:// tarball URL, excluding known-good registry
	// origins (registry.npmjs.org, registry.yarnpkg.com).
	// Stays zero until the manifest-projection wiring lands.
	HasHTTPURLDep bool
	// HTTPURLDeps enumerates the dep names (keys) whose version resolved to
	// a raw HTTP/HTTPS tarball URL. Surfaced as evidence on the signal.
	HTTPURLDeps []string

	// --- GitHub Actions ---
	// These fields back the registry_actions.go signals. They stay zero
	// (and the corresponding signals stay dormant) until the Actions
	// parser + projection wiring lands.
	ActionRefUnpinned          bool     // any Action ref in this scope is not pinned to a SHA
	ActionRefUnpinnedRefs      []string // raw uses: strings of the unpinned refs (for blame)
	ActionRefUnknownPublisher  bool     // any Action ref's owner is not in the known-good list
	ActionRefUnknownPublishers []string
	ActionRefTyposquat         bool
	ActionRefTyposquats        []string
	ActionRefMalicious         bool // any Action ref appears in the malicious-Action feed
	ActionRefMaliciousRefs     []string

	// --- Runtime capability grading (Gap 2 / Socket-parity) ---
	// These fields are populated by the capability scanner
	// (internal/capability) for npm packages when the
	// CHAINSAW_CAPABILITY_SCAN=1 env var is set. They stay zero (and the
	// corresponding cap.* signals stay dormant) until the feature flag is
	// enabled.  Evidence slices carry up to 3 file+line+snippet examples
	// per capability; the corresponding *Evidence field may be nil even
	// when the bool is true (e.g. file-level detections with no line number).
	CapNetwork         bool
	CapNetworkEvidence []CapEvidenceEntry

	CapShell         bool
	CapShellEvidence []CapEvidenceEntry

	CapFilesystemWrite         bool
	CapFilesystemWriteEvidence []CapEvidenceEntry

	CapFilesystemRead         bool
	CapFilesystemReadEvidence []CapEvidenceEntry

	CapEnvAccess         bool
	CapEnvAccessEvidence []CapEvidenceEntry

	CapNativeCode         bool
	CapNativeCodeEvidence []CapEvidenceEntry

	CapDynamicEval         bool
	CapDynamicEvalEvidence []CapEvidenceEntry

	// --- Transitive severity counts ---
	// Populated by evaluateTransitiveRisk in internal/intelligence after
	// the dep-tree walker resolves descendants. They drive the
	// sc.transitive_critical_vuln / sc.transitive_high_vuln /
	// sc.transitive_malware signals on the root re-evaluation.
	//
	// Each count is a distinct-CVE tally across descendants (deduped by
	// CVE ID where the evidence map carries one). MalwareCount counts
	// distinct descendants flagged sc.known_malicious. BlockedCount counts
	// distinct descendants whose own verdict is quarantine or replace.
	//
	// Zero for single-package evaluations (no transitive context).
	TransitiveCriticalCount int
	TransitiveHighCount     int
	TransitiveMediumCount   int
	TransitiveLowCount      int
	TransitiveMalwareCount  int
	TransitiveBlockedCount  int
}
