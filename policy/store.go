package policy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/tenancy"
)

// ErrPolicyNotFound indicates the requested policy does not exist.
var ErrPolicyNotFound = errors.New("policy not found")

// ErrDuplicatePolicy indicates a conflicting policy already exists.
var ErrDuplicatePolicy = errors.New("duplicate policy")

// ErrDuplicatePrecedence indicates a policy with the same precedence already exists.
var ErrDuplicatePrecedence = errors.New("duplicate policy precedence")

// ErrDuplicateName indicates a policy with the same display name already
// exists for the org. Surfaced through the (org_id, name) unique index
// (F12) — two policies sharing a name confused operators in the
// list_policies UI on staging.
var ErrDuplicateName = errors.New("duplicate policy name")

// Mode represents the policy action mode.
type Mode string

const (
	ModeAllow      Mode = "allow"
	ModeBlock      Mode = "block"
	ModeMonitor    Mode = "monitor"
	ModeQuarantine Mode = "quarantine"
	// ModeBlockAfterGrace is the Item-3b "block after a grace window" mode
	// (ADR-008). Behaviourally it is a BLOCK, with one carve-out gated
	// behind the `policy_grace_mode` feature flag: when the flag is ON,
	// a package that was already seen by this org BEFORE the policy's
	// created_at AND is still inside [created_at, created_at+grace_days]
	// has its block DOWNGRADED to monitor, giving operators a window to
	// remediate a pre-existing dependency before enforcement bites.
	//
	// CRITICAL (flag-off parity + keystone): when the flag is OFF the
	// evaluator maps this mode to a plain ModeBlock — no downgrade — so
	// shipping a `block_after_grace` policy without enabling the flag
	// NEVER weakens enforcement. The downgrade is ALSO suppressed for
	// known-malicious / vulnerable packages even with the flag ON, so an
	// in-grace package can never bypass a malware/vuln block. Both the
	// flag gate and the grace lookup are dependency-injected into the
	// evaluator (see Evaluator.WithGraceMode); a bare evaluator treats
	// this mode as a plain block.
	ModeBlockAfterGrace Mode = "block_after_grace"
)

// DefaultGraceDays is the grace window applied to a ModeBlockAfterGrace
// policy whose GraceDays override is nil. Per ADR-008 / BACKEND_PLAN the
// default window is 7 days.
const DefaultGraceDays = 7

// Kind discriminates the policy's role in evaluation. Empty is the
// historical default ("enforcement") — the evaluator runs the rule and
// the matching Mode (allow/block/monitor/quarantine) gates the install.
// "routing" is Wave-1 Agent B: the rule is consulted ONLY by the
// post-enforcement routing evaluator (internal/policy/routing.go) and
// dispatches a webhook to the resolved CODEOWNERS team. Routing rules
// never block — Mode is ignored for them.
type Kind string

const (
	KindEnforcement Kind = "" // legacy default
	KindRouting     Kind = "routing"
	// KindException marks an allow-mode policy created via the
	// /api/exceptions surface (or `chainsaw exception create`). It is a
	// load-bearing discriminator in the evaluator: a KindException rule
	// matches by Identifier (and Scope) ALONE — it deliberately does
	// not require Conditions.IsVulnerable to fire, which is the bug
	// that let malware-feed blocks ignore active exceptions. See the
	// matchesPolicy short-circuit in internal/policy/evaluator.go.
	KindException Kind = "exception"
)

// RoutingRule captures the Wave-1 Agent B routing-rule body. Either
// PathGlob or PackagePattern may be set (at least one is required when
// Kind=routing). Notify is a fixed enum — currently only "codeowners"
// is supported, which resolves owners via internal/codeowners/parser.go
// and dispatches via the standard webhook fan-out.
type RoutingRule struct {
	PathGlob       string `json:"pathGlob,omitempty" yaml:"pathGlob,omitempty"`
	PackagePattern string `json:"packagePattern,omitempty" yaml:"packagePattern,omitempty"`
	Notify         string `json:"notify,omitempty" yaml:"notify,omitempty"`
}

// Status represents the policy status.
type Status string

const (
	StatusEnabled  Status = "enabled"
	StatusDisabled Status = "disabled"
	// StatusPendingApproval is the Item-2 (ADR-007) approval-gating state.
	// A pending exception has been created but NOT yet approved; it is
	// NOT "enabled" so the evaluator (which only honours StatusEnabled
	// rules) and listPolicyExceptions (same filter) both naturally ignore
	// it — a pending exception therefore can NEVER bypass a block. This is
	// the keystone invariant: gating is purely additive on the existing
	// status free-text column (no CHECK constraint, zero DDL required).
	// The status is only written when the `exception_approval_gating`
	// flag is ON; with the flag OFF exceptions go live as StatusEnabled
	// on create exactly as before.
	StatusPendingApproval Status = "pending_approval"
)

// Identifier captures the target selector for a policy.
type Identifier struct {
	TargetPackageName    string `json:"targetPackageName,omitempty" yaml:"targetPackageName,omitempty"`
	TargetPackageRepo    string `json:"targetPackageRepo,omitempty" yaml:"targetPackageRepo,omitempty"`
	TargetPackageVersion string `json:"targetPackageVersion,omitempty" yaml:"targetPackageVersion,omitempty"` // semver pattern
}

// Conditions captures the rule conditions for policy evaluation.
type Conditions struct {
	IsVulnerable   *bool    `json:"isVulnerable,omitempty" yaml:"isVulnerable,omitempty"`     // nil=any, true=must be vulnerable, false=must not be vulnerable
	PackageAge     *int     `json:"packageAge,omitempty" yaml:"packageAge,omitempty"`         // days since the PACKAGE was first published, nil=any
	CooldownDays   *int     `json:"cooldownDays,omitempty" yaml:"cooldownDays,omitempty"`     // match if THIS VERSION was published within the last N days — publish-age quarantine; catches account-takeover / zero-hour novel versions of established packages; nil=off
	CVSSMin        *float64 `json:"cvssMin,omitempty" yaml:"cvssMin,omitempty"`               // minimum CVSS score (0-10)
	CVSSMax        *float64 `json:"cvssMax,omitempty" yaml:"cvssMax,omitempty"`               // maximum CVSS score (0-10)
	EPSSMin        *float64 `json:"epssMin,omitempty" yaml:"epssMin,omitempty"`               // minimum EPSS score (0-1)
	EPSSMax        *float64 `json:"epssMax,omitempty" yaml:"epssMax,omitempty"`               // maximum EPSS score (0-1)
	PackageLicense []string `json:"packageLicense,omitempty" yaml:"packageLicense,omitempty"` // allowed licenses, empty=all

	// Ecosystems narrows the rule to a specific subset of repository
	// formats (npm, pypi, maven, gomod, oci, cargo, ...). Empty list =
	// any ecosystem. Match is exact, lowercased — values match
	// EvaluationContext.RepositoryFormat which the proxy populates from
	// repository.Format. Used by the seeded SLSA baseline policy to
	// scope enforcement to Tier-1 ecosystems only, leaving formats
	// without standardised attestation channels (rubygems, composer,
	// cocoapods, cargo) unaffected.
	Ecosystems []string `json:"ecosystems,omitempty" yaml:"ecosystems,omitempty"`

	// Attestation-first conditions (the SLSA substrate). Use these to
	// require a specific build level, scope to allowed builders /
	// source repositories, demand a transparency-log entry, or refuse
	// answers served from stale Sigstore cache. They evaluate against
	// the per-version ProvenanceSection that the intelligence pipeline
	// hydrates from internal/provenance.

	// RequireSLSALevel is the minimum SLSA build level (1-4) the
	// verified attestation must claim. Rule fires when the context's
	// SLSALevel is below this. nil=any (don't constrain).
	RequireSLSALevel *int `json:"requireSlsaLevel,omitempty" yaml:"requireSlsaLevel,omitempty"`

	// RequireBuilderID is a substring allow-list against the OIDC
	// subject of the build (typically the GitHub Actions workflow URL
	// for keyless Sigstore signing). Rule fires when the verified
	// builder identity does not contain ANY of these substrings.
	// Empty list = any builder accepted.
	RequireBuilderID []string `json:"requireBuilderId,omitempty" yaml:"requireBuilderId,omitempty"`

	// RequireBuilderIssuer is a substring allow-list against the OIDC
	// issuer URL (e.g. "https://token.actions.githubusercontent.com").
	// Rule fires when the verified issuer does not contain ANY of
	// these substrings. Empty list = any issuer accepted.
	RequireBuilderIssuer []string `json:"requireBuilderIssuer,omitempty" yaml:"requireBuilderIssuer,omitempty"`

	// RequireSourceRepo is a substring allow-list against the
	// canonicalised source repository URL extracted from the cert.
	// Rule fires when the verified source repo does not contain ANY
	// of these substrings. Empty list = any source repo accepted.
	RequireSourceRepo []string `json:"requireSourceRepo,omitempty" yaml:"requireSourceRepo,omitempty"`

	// RequireTransparencyLog requires (or forbids) a public
	// transparency-log entry on the attestation. nil=any,
	// true=Rekor entry must exist, false=offline-signed only.
	RequireTransparencyLog *bool `json:"requireTransparencyLog,omitempty" yaml:"requireTransparencyLog,omitempty"`

	// ForbidCacheStale, when true, rejects decisions made from the
	// Sigstore last-known-good cache after Rekor/Fulcio became
	// unreachable. Operators with strict freshness requirements set
	// this; operators who prefer availability over freshness leave it
	// nil/false. nil=any.
	ForbidCacheStale *bool `json:"forbidCacheStale,omitempty" yaml:"forbidCacheStale,omitempty"`

	// RequireAttestation is a convenience matcher equivalent to
	// (HasProvenance=true AND RequireSLSALevel>=1). Useful for the
	// baseline "block packages without any verified attestation" rule
	// that ships seeded for Tier-1 ecosystems. nil=any.
	RequireAttestation *bool `json:"requireAttestation,omitempty" yaml:"requireAttestation,omitempty"`

	// Supply chain integrity conditions.
	HasProvenance              *bool    `json:"hasProvenance,omitempty" yaml:"hasProvenance,omitempty"`                           // nil=any, true=must have verified provenance
	IsSuspectedTyposquat       *bool    `json:"isSuspectedTyposquat,omitempty" yaml:"isSuspectedTyposquat,omitempty"`             // nil=any, true=suspected typosquat
	IsKnownMalicious           *bool    `json:"isKnownMalicious,omitempty" yaml:"isKnownMalicious,omitempty"`                     // nil=any, true=in OpenSSF malware DB
	TrustScoreMin              *int     `json:"trustScoreMin,omitempty" yaml:"trustScoreMin,omitempty"`                           // minimum trust score (0-100)
	TrustScoreMax              *int     `json:"trustScoreMax,omitempty" yaml:"trustScoreMax,omitempty"`                           // maximum trust score (0-100)
	ReservedNamespaces         []string `json:"reservedNamespaces,omitempty" yaml:"reservedNamespaces,omitempty"`                 // namespace patterns for dep confusion
	HasInstallScript           *bool    `json:"hasInstallScript,omitempty" yaml:"hasInstallScript,omitempty"`                     // nil=any, true=any lifecycle script declared in the manifest
	InstallScriptFetchesRemote *bool    `json:"installScriptFetchesRemote,omitempty" yaml:"installScriptFetchesRemote,omitempty"` // nil=any, true=install script body references curl/wget/fetch/subprocess/etc.

	// PublisherChanged fires when the incoming version's publisher/maintainer
	// set differs from the most recent prior persisted version's set. Catches
	// account-takeover-style supply-chain attacks (e.g. Axios v1.14.1 /
	// v0.30.4) before they show up in OpenSSF's malware feed. nil=any,
	// true=must have changed, false=must NOT have changed.
	PublisherChanged *bool `json:"publisherChanged,omitempty" yaml:"publisherChanged,omitempty"`

	// Version anomaly detection (PR 3). VersionAnomaly is the coarse boolean
	// switch — true fires when the metadiff helper reports any flag at all.
	// VersionAnomalyKinds narrows the match to a specific subset
	// (semver_regression, major_skip, timestamp_regression) — when set, the
	// evaluator requires an intersection between the policy kinds and the
	// context's VersionAnomalyFlags. Setting Kinds on its own is sufficient;
	// VersionAnomaly does not have to be true for kinds-based matching.
	VersionAnomaly      *bool    `json:"versionAnomaly,omitempty" yaml:"versionAnomaly,omitempty"`
	VersionAnomalyKinds []string `json:"versionAnomalyKinds,omitempty" yaml:"versionAnomalyKinds,omitempty"`

	// Hidden Unicode payload conditions (PR 8). HasHiddenUnicode is the
	// bool toggle; HiddenUnicodeKinds optionally narrows the match to a
	// subset of {"zero_width","bidi_override","tag"} using intersection
	// semantics (at least one matching kind must be present in the
	// scanner's Result.Kinds for the rule to fire).
	HasHiddenUnicode   *bool    `json:"hasHiddenUnicode,omitempty" yaml:"hasHiddenUnicode,omitempty"`     // nil=any, true=artifact had >=threshold suspect runes
	HiddenUnicodeKinds []string `json:"hiddenUnicodeKinds,omitempty" yaml:"hiddenUnicodeKinds,omitempty"` // subset of zero_width/bidi_override/tag

	// PublishVelocityAnomaly fires when the publisher of the incoming version
	// has published more than PublishVelocityThreshold24h versions (across any
	// package) in the last 24 hours. Counters Shai-Hulud style worm bursts.
	// The threshold defaults to 20 when PublishVelocityThreshold24h is nil.
	PublishVelocityAnomaly      *bool `json:"publishVelocityAnomaly,omitempty" yaml:"publishVelocityAnomaly,omitempty"`
	PublishVelocityThreshold24h *int  `json:"publishVelocityThreshold24h,omitempty" yaml:"publishVelocityThreshold24h,omitempty"`

	// Socket-gap Wave 1 — SPDX license taxonomy (see
	// SOCKET_GAP_IMPLEMENTATION_PLAN.md §10). Each bool is evaluated
	// against the Classify() output over the declared license
	// expression. nil=any, true=must match, false=must not.
	LicenseCopyleft            *bool `json:"licenseCopyleft,omitempty" yaml:"licenseCopyleft,omitempty"`
	LicenseNonPermissive       *bool `json:"licenseNonPermissive,omitempty" yaml:"licenseNonPermissive,omitempty"`
	LicenseExceptionPresent    *bool `json:"licenseExceptionPresent,omitempty" yaml:"licenseExceptionPresent,omitempty"`
	LicenseAmbiguousClassifier *bool `json:"licenseAmbiguousClassifier,omitempty" yaml:"licenseAmbiguousClassifier,omitempty"`
	LicenseUnidentified        *bool `json:"licenseUnidentified,omitempty" yaml:"licenseUnidentified,omitempty"`

	// DeprecatedByMaintainer fires when the upstream registry has
	// marked this version deprecated/yanked. Data source is
	// ecosystem-specific: npm versions[v].deprecated; PyPI yanked;
	// Cargo yanked.
	DeprecatedByMaintainer *bool `json:"deprecatedByMaintainer,omitempty" yaml:"deprecatedByMaintainer,omitempty"`

	// ShrinkwrapPresent (npm only) fires when the artifact contains
	// a bundled npm-shrinkwrap.json — a vector for hiding transitive
	// drift that bypasses lockfile-based dep review.
	ShrinkwrapPresent *bool `json:"shrinkwrapPresent,omitempty" yaml:"shrinkwrapPresent,omitempty"`

	// ManifestConfusion (npm only) fires when registry JSON
	// package.json fields (name, version, scripts, bin, main,
	// dependencies) diverge semantically from the tarball
	// package.json — a publisher-side metadata-tampering attack.
	ManifestConfusion *bool `json:"manifestConfusion,omitempty" yaml:"manifestConfusion,omitempty"`

	// Socket-gap Wave 2 — manifest hygiene (see
	// SOCKET_GAP_IMPLEMENTATION_PLAN.md §10). Computed by
	// internal/formats/depspec from the manifest's declared
	// dependencies list. Per-ecosystem support varies — see the
	// proxy compatibility matrix for the full grid.

	// GitDependency fires when any declared dep points at a git URL
	// (git+ssh://, github:, git: URLs in Cargo/Composer/Gemfile,
	// etc.) instead of a registry coordinate. Bypasses typical
	// dependency-review flows.
	GitDependency *bool `json:"gitDependency,omitempty" yaml:"gitDependency,omitempty"`

	// HTTPTarballDependency fires when any declared dep points at a
	// raw http(s) tarball URL (bypasses registry checksums).
	HTTPTarballDependency *bool `json:"httpTarballDependency,omitempty" yaml:"httpTarballDependency,omitempty"`

	// WildcardDependencyRange fires when a registry-sourced specifier
	// is unbounded (*, "", "latest", ">=0", "x.x.x", etc.) — the
	// upstream can ship anything without downstream review.
	WildcardDependencyRange *bool `json:"wildcardDependencyRange,omitempty" yaml:"wildcardDependencyRange,omitempty"`

	// BadDependencySemver fires when a registry-sourced specifier
	// fails to parse with the ecosystem's version grammar. Often a
	// fingerprint of a machine-generated manifest or a typo that
	// silently resolves to "latest".
	BadDependencySemver *bool `json:"badDependencySemver,omitempty" yaml:"badDependencySemver,omitempty"`

	// Socket-gap Wave 3 — Tier-2 source-code scanner conditions.
	// Each bool gates against the corresponding ArtifactScanSection
	// field hydrated by the Wave-3 intelligence providers (all ride
	// the Wave-0 shared ArtifactFileMap). Detection-only; firing does
	// not require any additional upstream fetch.

	// UsesEval fires when a source file in the artifact uses a
	// runtime dynamic-code-evaluation primitive (eval, Function ctor,
	// Python exec/compile, PHP eval, ...). Classic obfuscated-loader
	// pattern.
	UsesEval *bool `json:"usesEval,omitempty" yaml:"usesEval,omitempty"`

	// NetworkAccess fires when a source file references a network
	// primitive (fetch, http, net, urllib, reqwest, curl_init, ...).
	// Raises the severity bar for install-time review.
	NetworkAccess *bool `json:"networkAccess,omitempty" yaml:"networkAccess,omitempty"`

	// ShellAccess fires on child_process / subprocess / os.system /
	// Runtime.exec / system() / shell_exec references. Strong signal
	// for install-script exfiltration when combined with
	// HasInstallScript.
	ShellAccess *bool `json:"shellAccess,omitempty" yaml:"shellAccess,omitempty"`

	// FilesystemAccess fires on fs.* / open() / os.open / std::fs
	// references. Benign in application code, suspicious in a small
	// utility library.
	FilesystemAccess *bool `json:"filesystemAccess,omitempty" yaml:"filesystemAccess,omitempty"`

	// EnvVarAccess fires on process.env / os.environ / ENV[] /
	// os.Getenv references. Benign alone; combines with NetworkAccess
	// to detect secret-exfiltration payloads.
	EnvVarAccess *bool `json:"envVarAccess,omitempty" yaml:"envVarAccess,omitempty"`

	// NativeBinaryPresent fires when the artifact ships a compiled
	// native library (.node / .so / .dll / .dylib / .a / .lib) or a
	// build recipe (binding.gyp) that compiles one at install time.
	NativeBinaryPresent *bool `json:"nativeBinaryPresent,omitempty" yaml:"nativeBinaryPresent,omitempty"`

	// HighEntropyStrings fires when the artifact's source files
	// contain a candidate leaked secret — AWS access keys, GitHub
	// PATs, private-key blocks, or generic high-entropy assignments
	// tagged "secret"/"token"/"apikey". Detect-only (no live key
	// verification); modelled on the gitleaks default rule intent.
	HighEntropyStrings *bool `json:"highEntropyStrings,omitempty" yaml:"highEntropyStrings,omitempty"`

	// URLStrings fires when any http(s) URL appears in source files
	// outside the README / LICENSE / package-metadata allowlist.
	// Paired with NetworkAccess, pinpoints exfiltration endpoints.
	URLStrings *bool `json:"urlStrings,omitempty" yaml:"urlStrings,omitempty"`

	// MinifiedCode fires when any source file in the artifact looks
	// minified / obfuscated by heuristic (very long average line AND
	// high density of 1-2 character identifiers). Coarse signal;
	// benign on bundled web libraries, suspicious on utilities.
	MinifiedCode *bool `json:"minifiedCode,omitempty" yaml:"minifiedCode,omitempty"`

	// Socket-gap Wave 4 (see SOCKET_GAP_IMPLEMENTATION_PLAN.md §10).

	// TrivialPackage fires when the sum of source-code LOC across the
	// artifact is below TrivialPackageLOCThreshold (default 10). Catches
	// dependency-confusion / typosquat squatter stubs that ship only a
	// placeholder file. Rides the Wave-0 artifact map; no new network.
	TrivialPackage *bool `json:"trivialPackage,omitempty" yaml:"trivialPackage,omitempty"`

	// TooManyFiles fires when the artifact's file count exceeds the
	// built-in anomaly threshold (5000). No new network.
	TooManyFiles *bool `json:"tooManyFiles,omitempty" yaml:"tooManyFiles,omitempty"`

	// NonExistentAuthor fires when the declared author/maintainer
	// handle yields a 404 on the ecosystem's user endpoint. Requires a
	// registry RTT and is feature-flagged per ecosystem
	// (CHAINSAW_WAVE4_NONEXISTENT_AUTHOR_<ECO>=1).
	NonExistentAuthor *bool `json:"nonExistentAuthor,omitempty" yaml:"nonExistentAuthor,omitempty"`

	// FirstTimeCollaborator fires when the target version's uploader
	// handle is absent from the set of uploaders on all prior versions.
	// Feature-flagged per ecosystem
	// (CHAINSAW_WAVE4_FIRST_TIME_COLLABORATOR_<ECO>=1).
	FirstTimeCollaborator *bool `json:"firstTimeCollaborator,omitempty" yaml:"firstTimeCollaborator,omitempty"`

	// SuspiciousRepoStars fires when a GitHub repo URL present in the
	// package metadata has <5 stars OR was created less than 30 days
	// ago. Requires a GitHub API RTT and is feature-flagged
	// (CHAINSAW_WAVE4_SUSPICIOUS_REPO_STARS=1).
	SuspiciousRepoStars *bool `json:"suspiciousRepoStars,omitempty" yaml:"suspiciousRepoStars,omitempty"`

	// MaintainerAccountAgeDaysMax fires when the youngest publisher /
	// maintainer account on the incoming version is at most this many
	// days old. Detects fresh-account takeovers and ghost-maintainer
	// adds before the malware feeds catch up. Requires a registry RTT
	// and is feature-flagged per ecosystem
	// (CHAINSAW_WAVE4_MAINTAINER_AGE_<ECO>=1). nil = condition inert.
	MaintainerAccountAgeDaysMax *int `json:"maintainerAccountAgeDaysMax,omitempty" yaml:"maintainerAccountAgeDaysMax,omitempty"`

	// AI artifact conditions. Each gates against the corresponding
	// ArtifactScanSection field hydrated by the AI artifact providers
	// (provider_pickle, provider_modelcard, provider_agenttool). All
	// detect-only — they ride existing artifact bytes; no new network.

	// DangerousPickle fires when a pickle weight file imports a known-
	// dangerous module (os, subprocess, builtins.eval, runpy, ...).
	// Loading the file executes arbitrary code.
	DangerousPickle *bool `json:"dangerousPickle,omitempty" yaml:"dangerousPickle,omitempty"`

	// UnsafeSerializationFormat fires when the artifact ships pickle
	// weights without a safetensors alternative.
	UnsafeSerializationFormat *bool `json:"unsafeSerializationFormat,omitempty" yaml:"unsafeSerializationFormat,omitempty"`

	// ModelCardInjection fires when the model card contains hidden
	// unicode, jailbreak phrasing, embedded <script>, or large base64
	// in YAML frontmatter.
	ModelCardInjection *bool `json:"modelCardInjection,omitempty" yaml:"modelCardInjection,omitempty"`

	// AgentToolDangerousCapability fires when a declared MCP server /
	// agent tool exposes filesystem write, subprocess execution, or
	// arbitrary network egress to the model.
	AgentToolDangerousCapability *bool `json:"agentToolDangerousCapability,omitempty" yaml:"agentToolDangerousCapability,omitempty"`

	// MCPServerDeclared fires when the package self-declares an MCP
	// server / agent tool entry point. Inventory signal.
	MCPServerDeclared *bool `json:"mcpServerDeclared,omitempty" yaml:"mcpServerDeclared,omitempty"`

	// PromptTemplateInjection fires when a prompt-template artifact
	// (HF dataset tagged "prompt", *.prompt file, ...) contains
	// jailbreak / hidden-unicode tampering markers.
	PromptTemplateInjection *bool `json:"promptTemplateInjection,omitempty" yaml:"promptTemplateInjection,omitempty"`
}

// Scope captures the policy scope restrictions.
type Scope struct {
	TargetClient            []string `json:"targetClient,omitempty" yaml:"targetClient,omitempty"`                       // empty=all
	TargetGroup             []string `json:"targetGroup,omitempty" yaml:"targetGroup,omitempty"`                         // empty=all
	TargetRepos             []string `json:"targetRepos,omitempty" yaml:"targetRepos,omitempty"`                         // empty=all
	TargetRequestingCountry []string `json:"targetRequestingCountry,omitempty" yaml:"targetRequestingCountry,omitempty"` // empty=all
	TargetRequestingIP      []string `json:"targetRequestingIP,omitempty" yaml:"targetRequestingIP,omitempty"`           // empty=all, supports CIDR
}

// Policy represents a policy rule.
type Policy struct {
	ID          string     `json:"id" yaml:"id"`
	Name        string     `json:"name,omitempty" yaml:"name,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Precedence  int        `json:"precedence" yaml:"precedence"`
	Mode        Mode       `json:"mode" yaml:"mode"`
	Status      Status     `json:"status" yaml:"status"`
	CreatedAt   time.Time  `json:"createdAt" yaml:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt" yaml:"updatedAt"`
	Identifier  Identifier `json:"identifier" yaml:"identifier"`
	Conditions  Conditions `json:"conditions" yaml:"conditions"`
	Scope       Scope      `json:"scope" yaml:"scope"`
	// Decision/CVE/Note enrich exception-mode policies (Mode==ModeAllow with
	// IsVulnerable=true) so the VEX export can emit per-exception state. They
	// are nullable in the DB (TEXT, no DEFAULT) — empty strings on the wire
	// preserve back-compat with rows written before this column existed.
	Decision string `json:"decision,omitempty" yaml:"decision,omitempty"`
	CVE      string `json:"cve,omitempty" yaml:"cve,omitempty"`
	Note     string `json:"note,omitempty" yaml:"note,omitempty"`

	// Wave-1 Agent B fields. CreatedBy / ApproverID carry the per-row
	// provenance Agent C surfaces in the in-app exception inbox. Both
	// are nullable on the wire — pre-existing rows have no recorded
	// actor. Kind defaults to KindEnforcement (empty); KindRouting
	// flips the rule into routing-only mode (see internal/policy/routing.go).
	// Routing carries the rule body when Kind == KindRouting.
	CreatedBy  string       `json:"createdBy,omitempty" yaml:"createdBy,omitempty"`
	ApproverID string       `json:"approverId,omitempty" yaml:"approverId,omitempty"`
	Kind       Kind         `json:"kind,omitempty" yaml:"kind,omitempty"`
	Routing    *RoutingRule `json:"routing,omitempty" yaml:"routing,omitempty"`

	// ExpiresAt is an optional per-row expiry override for
	// KindException policies. When non-nil it WINS over the org-level
	// ExceptionAge default (settings.ExceptionAge): the rule is
	// considered expired once time.Now() crosses ExpiresAt. When nil,
	// the legacy createdAt + ExceptionAgeDays computation is used.
	// Persisted as `expires_at TIMESTAMPTZ NULL`.
	ExpiresAt *time.Time `json:"expiresAt,omitempty" yaml:"expiresAt,omitempty"`

	// GraceDays is the Item-3b (ADR-008) per-policy grace-window override
	// for ModeBlockAfterGrace rules. nil → DefaultGraceDays (7). Ignored
	// for every other mode. Persisted as `grace_days INTEGER NULL`
	// (additive migration; pre-existing rows read back nil → default).
	GraceDays *int `json:"graceDays,omitempty" yaml:"graceDays,omitempty"`
}

// EffectiveGraceDays returns the grace window for a ModeBlockAfterGrace
// policy: the GraceDays override when set to a positive value, otherwise
// DefaultGraceDays. A non-positive override is ignored (treated as
// unset) so a `0`/negative value can never collapse the grace window to
// "block immediately" by accident — operators disable grace by simply
// not using ModeBlockAfterGrace.
func (p Policy) EffectiveGraceDays() int {
	if p.GraceDays != nil && *p.GraceDays > 0 {
		return *p.GraceDays
	}
	return DefaultGraceDays
}

// nullableInt mirrors nullableString for *int so a nil pointer is
// written as SQL NULL. Used by the Item-3b grace_days column where NULL
// means "use the default grace window".
func nullableInt(n *int) any {
	if n == nil {
		return nil
	}
	return *n
}

// Store maintains policy entries inside Postgres.
type Store struct {
	sql   *pgstore.Store
	orgID string
}

// NewStore wires a policy store backed by Postgres.
func NewStore(db *pgstore.Store) (*Store, error) {
	if db == nil {
		return nil, errors.New("postgres store is required")
	}
	store := &Store{sql: db}
	if err := store.ensurePolicyIntegrity(); err != nil {
		return nil, err
	}
	return store, nil
}

// MaxPrecedence returns the highest precedence currently in use for the
// store's org, or 0 if no policies exist. Used by the REST handler to
// auto-default precedence to MAX+10 when callers omit it (F23 — neither
// the MCP propose_policy schema nor common scripts force callers to pick
// a precedence, and a bare `0` collides with the seeded baseline rules).
func (s *Store) MaxPrecedence() (int, error) {
	if s == nil || s.sql == nil {
		return 0, errors.New("policy store unavailable")
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)
	var max sql.NullInt64
	if err := s.sql.DB().QueryRow(`SELECT MAX(precedence) FROM policies WHERE org_id=?`, orgID).Scan(&max); err != nil {
		return 0, err
	}
	if !max.Valid {
		return 0, nil
	}
	return int(max.Int64), nil
}

// ForOrg scopes policy operations to a specific org.
func (s *Store) ForOrg(orgID string) *Store {
	if s == nil {
		return nil
	}
	next := *s
	next.orgID = tenancy.NormalizeOrgID(orgID)
	return &next
}

// List returns all policies sorted by precedence (ascending) then created_at (descending).
func (s *Store) List() ([]Policy, error) {
	if s == nil || s.sql == nil {
		return nil, errors.New("policy store unavailable")
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)
	rows, err := s.sql.DB().Query(`SELECT id, name, description, precedence, mode, status, created_at, updated_at, identifier, conditions, policy_scope, decision, cve, note, created_by, approver_id, kind, routing, expires_at, grace_days
		FROM policies WHERE org_id=? ORDER BY precedence ASC, created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []Policy
	for rows.Next() {
		policy, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	return policies, rows.Err()
}

// Get retrieves a policy by ID.
func (s *Store) Get(id string) (Policy, error) {
	if s == nil || s.sql == nil {
		return Policy{}, errors.New("policy store unavailable")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return Policy{}, ErrPolicyNotFound
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)
	row := s.sql.DB().QueryRow(`SELECT id, name, description, precedence, mode, status, created_at, updated_at, identifier, conditions, policy_scope, decision, cve, note, created_by, approver_id, kind, routing, expires_at, grace_days
		FROM policies WHERE org_id=? AND id=?`, orgID, id)
	return scanPolicy(row)
}

// Create persists a new policy.
func (s *Store) Create(policy Policy) (Policy, error) {
	if s == nil || s.sql == nil {
		return Policy{}, errors.New("policy store unavailable")
	}
	policy, err := normalizePolicy(policy)
	if err != nil {
		return Policy{}, err
	}
	if err := validatePolicy(policy); err != nil {
		return Policy{}, err
	}
	id, err := newID()
	if err != nil {
		return Policy{}, err
	}
	now := time.Now().UTC()
	policy.ID = id
	policy.Name = strings.TrimSpace(policy.Name)
	policy.Description = strings.TrimSpace(policy.Description)
	policy.CreatedAt = now
	policy.UpdatedAt = now
	parameterHash, err := PolicyParameterHash(policy)
	if err != nil {
		return Policy{}, err
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)
	if err := s.ensureNoPolicyConflicts(orgID, "", policy.Precedence, parameterHash); err != nil {
		return Policy{}, err
	}
	if err := s.ensureUniquePolicyName(orgID, "", policy.Name); err != nil {
		return Policy{}, err
	}

	identifierJSON, err := json.Marshal(policy.Identifier)
	if err != nil {
		return Policy{}, fmt.Errorf("marshal identifier: %w", err)
	}
	conditionsJSON, err := json.Marshal(policy.Conditions)
	if err != nil {
		return Policy{}, fmt.Errorf("marshal conditions: %w", err)
	}
	scopeJSON, err := json.Marshal(policy.Scope)
	if err != nil {
		return Policy{}, fmt.Errorf("marshal scope: %w", err)
	}
	routingJSON := ""
	if policy.Routing != nil {
		b, err := json.Marshal(policy.Routing)
		if err != nil {
			return Policy{}, fmt.Errorf("marshal routing: %w", err)
		}
		routingJSON = string(b)
	}

	_, err = s.sql.DB().Exec(`INSERT INTO policies(id, org_id, name, description, precedence, mode, status, created_at, updated_at, identifier, conditions, policy_scope, parameter_hash, decision, cve, note, created_by, approver_id, kind, routing, expires_at, grace_days)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		policy.ID, orgID, policy.Name, policy.Description, policy.Precedence, string(policy.Mode), string(policy.Status),
		policy.CreatedAt, policy.UpdatedAt, string(identifierJSON), string(conditionsJSON), string(scopeJSON), parameterHash,
		policy.Decision, policy.CVE, policy.Note,
		nullableString(policy.CreatedBy), nullableString(policy.ApproverID), string(policy.Kind), nullableString(routingJSON),
		nullableTime(policy.ExpiresAt), nullableInt(policy.GraceDays))
	if err != nil {
		return Policy{}, policyConflictError(err)
	}
	return policy, nil
}

// nullableString converts an empty string to a nil sql.NullString-like
// any so the driver writes SQL NULL (and pre-existing rows missing the
// column stay symmetric on read). Used for the Wave-1 Agent B columns
// where "" is semantically equivalent to "not set".
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableTime mirrors nullableString for *time.Time so a nil pointer
// (or zero-valued time) is written as SQL NULL. Used by the per-row
// exception expiry override column.
func nullableTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC()
}

// Update replaces an existing policy identified by id.
func (s *Store) Update(id string, policy Policy) (Policy, error) {
	if s == nil || s.sql == nil {
		return Policy{}, errors.New("policy store unavailable")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return Policy{}, ErrPolicyNotFound
	}
	policy, err := normalizePolicy(policy)
	if err != nil {
		return Policy{}, err
	}
	if err := validatePolicy(policy); err != nil {
		return Policy{}, err
	}

	now := time.Now().UTC()
	policy.ID = id
	policy.Name = strings.TrimSpace(policy.Name)
	policy.Description = strings.TrimSpace(policy.Description)
	policy.UpdatedAt = now
	parameterHash, err := PolicyParameterHash(policy)
	if err != nil {
		return Policy{}, err
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)
	if err := s.ensureNoPolicyConflicts(orgID, id, policy.Precedence, parameterHash); err != nil {
		return Policy{}, err
	}
	if err := s.ensureUniquePolicyName(orgID, id, policy.Name); err != nil {
		return Policy{}, err
	}

	identifierJSON, err := json.Marshal(policy.Identifier)
	if err != nil {
		return Policy{}, fmt.Errorf("marshal identifier: %w", err)
	}
	conditionsJSON, err := json.Marshal(policy.Conditions)
	if err != nil {
		return Policy{}, fmt.Errorf("marshal conditions: %w", err)
	}
	scopeJSON, err := json.Marshal(policy.Scope)
	if err != nil {
		return Policy{}, fmt.Errorf("marshal scope: %w", err)
	}
	routingJSON := ""
	if policy.Routing != nil {
		b, err := json.Marshal(policy.Routing)
		if err != nil {
			return Policy{}, fmt.Errorf("marshal routing: %w", err)
		}
		routingJSON = string(b)
	}

	res, err := s.sql.DB().Exec(`UPDATE policies SET name=?, description=?, precedence=?, mode=?, status=?, updated_at=?, identifier=?, conditions=?, policy_scope=?, parameter_hash=?, decision=?, cve=?, note=?, created_by=?, approver_id=?, kind=?, routing=?, expires_at=?, grace_days=? WHERE org_id=? AND id=?`,
		policy.Name, policy.Description, policy.Precedence, string(policy.Mode), string(policy.Status), now, string(identifierJSON), string(conditionsJSON), string(scopeJSON), parameterHash,
		policy.Decision, policy.CVE, policy.Note,
		nullableString(policy.CreatedBy), nullableString(policy.ApproverID), string(policy.Kind), nullableString(routingJSON),
		nullableTime(policy.ExpiresAt), nullableInt(policy.GraceDays),
		orgID, id)
	if err != nil {
		return Policy{}, policyConflictError(err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return Policy{}, ErrPolicyNotFound
	}

	// Fetch created_at from existing record
	var createdAt time.Time
	_ = s.sql.DB().QueryRow(`SELECT created_at FROM policies WHERE org_id=? AND id=?`, orgID, id).Scan(&createdAt)
	policy.CreatedAt = createdAt

	return policy, nil
}

// Renew resets the created_at timestamp of a policy to now, effectively
// restarting its exception expiry clock. Returns the updated policy.
func (s *Store) Renew(id string) (Policy, error) {
	if s == nil || s.sql == nil {
		return Policy{}, errors.New("policy store unavailable")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return Policy{}, ErrPolicyNotFound
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)
	now := time.Now().UTC()
	// Renew resets BOTH the creation clock (legacy ageDays-from-created
	// fallback) AND any per-row expires_at override — after renew the
	// row reverts to the org default ExceptionAge unless a subsequent
	// update sets a new explicit expiry. Without clearing expires_at
	// here, a renew would silently leave the original expiry intact.
	res, err := s.sql.DB().Exec(`UPDATE policies SET created_at=?, updated_at=?, expires_at=NULL WHERE org_id=? AND id=?`,
		now, now, orgID, id)
	if err != nil {
		return Policy{}, err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return Policy{}, ErrPolicyNotFound
	}
	return s.Get(id)
}

// RestoreRenewedAt rewinds a policy's created_at (and updated_at)
// timestamps to the supplied instant. Used by the undo service to
// reverse an exception.renew action: the forward mutation set
// created_at=now (resetting the expiry clock); the inverse must
// restore the OLD created_at the before_state snapshot captured.
//
// Distinct from Update because Update unconditionally rewrites
// updated_at=time.Now() (and validates / re-normalises the full
// policy payload). Here the only fields we touch are the two
// timestamps — every other column on the row was unchanged by Renew,
// so we leave them alone. Returns the refreshed row on success.
//
// Permission gating happens at the caller (undo.Service re-checks
// PermExceptionsManage at undo-apply time); this verb itself is a
// pure store-level operation.
func (s *Store) RestoreRenewedAt(id string, createdAt time.Time) (Policy, error) {
	if s == nil || s.sql == nil {
		return Policy{}, errors.New("policy store unavailable")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return Policy{}, ErrPolicyNotFound
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)
	createdAt = createdAt.UTC()
	res, err := s.sql.DB().Exec(`UPDATE policies SET created_at=?, updated_at=? WHERE org_id=? AND id=?`,
		createdAt, createdAt, orgID, id)
	if err != nil {
		return Policy{}, err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return Policy{}, ErrPolicyNotFound
	}
	return s.Get(id)
}

// Delete removes a policy by id.
func (s *Store) Delete(id string) error {
	if s == nil || s.sql == nil {
		return errors.New("policy store unavailable")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrPolicyNotFound
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)
	res, err := s.sql.DB().Exec(`DELETE FROM policies WHERE org_id=? AND id=?`, orgID, id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

// SetStatus updates the status of a policy.
func (s *Store) SetStatus(id string, status Status) error {
	if s == nil || s.sql == nil {
		return errors.New("policy store unavailable")
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return ErrPolicyNotFound
	}
	orgID := tenancy.NormalizeOrgID(s.orgID)
	res, err := s.sql.DB().Exec(`UPDATE policies SET status=?, updated_at=? WHERE org_id=? AND id=?`,
		string(status), time.Now().UTC(), orgID, id)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

type policyScanner interface {
	Scan(dest ...any) error
}

func scanPolicy(row policyScanner) (Policy, error) {
	var (
		policy                                    Policy
		name, description                         sql.NullString
		identifierJSON, conditionsJSON, scopeJSON sql.NullString
		decision, cve, note                       sql.NullString
		createdBy, approverID, kindStr            sql.NullString
		routingJSON                               sql.NullString
		expiresAt                                 sql.NullTime
		graceDays                                 sql.NullInt64
	)
	if err := row.Scan(&policy.ID, &name, &description, &policy.Precedence, &policy.Mode, &policy.Status,
		&policy.CreatedAt, &policy.UpdatedAt, &identifierJSON, &conditionsJSON, &scopeJSON,
		&decision, &cve, &note,
		&createdBy, &approverID, &kindStr, &routingJSON, &expiresAt, &graceDays); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Policy{}, ErrPolicyNotFound
		}
		return Policy{}, err
	}
	if name.Valid {
		policy.Name = name.String
	}
	if description.Valid {
		policy.Description = description.String
	}

	if identifierJSON.Valid && identifierJSON.String != "" {
		if err := json.Unmarshal([]byte(identifierJSON.String), &policy.Identifier); err != nil {
			return Policy{}, fmt.Errorf("unmarshal identifier: %w", err)
		}
	}
	if conditionsJSON.Valid && conditionsJSON.String != "" {
		if err := json.Unmarshal([]byte(conditionsJSON.String), &policy.Conditions); err != nil {
			return Policy{}, fmt.Errorf("unmarshal conditions: %w", err)
		}
	}
	if scopeJSON.Valid && scopeJSON.String != "" {
		if err := json.Unmarshal([]byte(scopeJSON.String), &policy.Scope); err != nil {
			return Policy{}, fmt.Errorf("unmarshal scope: %w", err)
		}
	}
	if decision.Valid {
		policy.Decision = decision.String
	}
	if cve.Valid {
		policy.CVE = cve.String
	}
	if note.Valid {
		policy.Note = note.String
	}
	if createdBy.Valid {
		policy.CreatedBy = createdBy.String
	}
	if approverID.Valid {
		policy.ApproverID = approverID.String
	}
	if kindStr.Valid && kindStr.String != "" {
		policy.Kind = Kind(kindStr.String)
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		policy.ExpiresAt = &t
	}
	if graceDays.Valid {
		g := int(graceDays.Int64)
		policy.GraceDays = &g
	}
	if routingJSON.Valid && routingJSON.String != "" {
		var rr RoutingRule
		if err := json.Unmarshal([]byte(routingJSON.String), &rr); err != nil {
			return Policy{}, fmt.Errorf("unmarshal routing: %w", err)
		}
		policy.Routing = &rr
	}

	return policy, nil
}

func validatePolicy(policy Policy) error {
	if policy.Kind == KindRouting {
		// Routing rules ride a separate evaluator (internal/policy/routing.go)
		// and never gate the install. Mode is ignored at evaluation time but
		// we still require it to be a recognised string so the existing
		// schema constraints stay satisfied; ModeMonitor is the canonical
		// no-op default. The routing body MUST carry at least one matcher,
		// otherwise the rule fires on every violation.
		if policy.Mode == "" {
			return errors.New("routing policy must set a mode (recommend 'monitor' — routing never blocks)")
		}
		if policy.Mode != ModeAllow && policy.Mode != ModeBlock && policy.Mode != ModeMonitor && policy.Mode != ModeQuarantine {
			return errors.New("invalid policy mode: must be 'allow', 'block', 'monitor', or 'quarantine'")
		}
		if policy.Routing == nil {
			return errors.New("routing policy requires a routing body")
		}
		if strings.TrimSpace(policy.Routing.PathGlob) == "" && strings.TrimSpace(policy.Routing.PackagePattern) == "" {
			return errors.New("routing policy requires at least one of pathGlob or packagePattern")
		}
		if policy.Routing.Notify == "" {
			policy.Routing.Notify = "codeowners"
		}
		if policy.Routing.Notify != "codeowners" {
			return fmt.Errorf("invalid routing notify channel %q: only 'codeowners' is supported", policy.Routing.Notify)
		}
		if policy.Status != StatusEnabled && policy.Status != StatusDisabled {
			return errors.New("invalid policy status: must be 'enabled' or 'disabled'")
		}
		return nil
	}
	if policy.Mode != ModeAllow && policy.Mode != ModeBlock && policy.Mode != ModeMonitor && policy.Mode != ModeQuarantine && policy.Mode != ModeBlockAfterGrace {
		return errors.New("invalid policy mode: must be 'allow', 'block', 'monitor', 'quarantine', or 'block_after_grace'")
	}
	// Item-2 (ADR-007) approval gating widens the legal status set with
	// 'pending_approval'. It is only ever WRITTEN when the
	// exception_approval_gating flag is on (see exceptions_api.go) — but
	// validatePolicy must accept it so an approve/deny round-trip (which
	// re-validates the policy) does not 400.
	if policy.Status != StatusEnabled && policy.Status != StatusDisabled && policy.Status != StatusPendingApproval {
		return errors.New("invalid policy status: must be 'enabled', 'disabled', or 'pending_approval'")
	}
	if !hasPolicyConstraint(policy) {
		return errors.New("policy must include at least one condition or scoped target")
	}
	if err := rejectStandaloneContextOnlyConditions(policy); err != nil {
		return err
	}
	switch policy.Decision {
	case "", "allow", "deny", "monitor":
		// valid: empty preserves back-compat for rows written before
		// this column existed.
	default:
		return fmt.Errorf("invalid decision %q: must be one of '', 'allow', 'deny', 'monitor'", policy.Decision)
	}
	return nil
}

func normalizePolicy(policy Policy) (Policy, error) {
	policy.Name = strings.TrimSpace(policy.Name)
	policy.Description = strings.TrimSpace(policy.Description)
	policy.Identifier.TargetPackageName = strings.TrimSpace(policy.Identifier.TargetPackageName)
	policy.Identifier.TargetPackageRepo = strings.TrimSpace(policy.Identifier.TargetPackageRepo)
	policy.Identifier.TargetPackageVersion = strings.TrimSpace(policy.Identifier.TargetPackageVersion)
	policy.Decision = strings.ToLower(strings.TrimSpace(policy.Decision))
	policy.CVE = strings.TrimSpace(policy.CVE)
	policy.Note = strings.TrimSpace(policy.Note)

	countries, err := normalizeCountryScope(policy.Scope.TargetRequestingCountry)
	if err != nil {
		return Policy{}, err
	}
	policy.Scope.TargetRequestingCountry = countries

	ips, err := normalizeIPScope(policy.Scope.TargetRequestingIP)
	if err != nil {
		return Policy{}, err
	}
	policy.Scope.TargetRequestingIP = ips

	return policy, nil
}

type policyHashPayload struct {
	Mode       Mode       `json:"mode"`
	Identifier Identifier `json:"identifier"`
	Conditions Conditions `json:"conditions"`
	Scope      Scope      `json:"scope"`
}

// PolicyParameterHash returns the stable behavioral hash used to deduplicate
// policies. It intentionally ignores user-defined metadata and lifecycle fields
// including name, description, precedence, status, ID, and timestamps.
func PolicyParameterHash(policy Policy) (string, error) {
	normalized, err := normalizePolicy(policy)
	if err != nil {
		return "", err
	}
	normalized.Conditions.PackageLicense = normalizeHashStrings(normalized.Conditions.PackageLicense)
	normalized.Conditions.ReservedNamespaces = normalizeHashStrings(normalized.Conditions.ReservedNamespaces)
	normalized.Conditions.VersionAnomalyKinds = normalizeHashStrings(normalized.Conditions.VersionAnomalyKinds)
	normalized.Conditions.HiddenUnicodeKinds = normalizeHashStrings(normalized.Conditions.HiddenUnicodeKinds)
	normalized.Scope.TargetClient = normalizeHashStrings(normalized.Scope.TargetClient)
	normalized.Scope.TargetGroup = normalizeHashStrings(normalized.Scope.TargetGroup)
	normalized.Scope.TargetRepos = normalizeHashStrings(normalized.Scope.TargetRepos)
	normalized.Scope.TargetRequestingCountry = normalizeHashStrings(normalized.Scope.TargetRequestingCountry)
	normalized.Scope.TargetRequestingIP = normalizeHashStrings(normalized.Scope.TargetRequestingIP)

	payload := policyHashPayload{
		Mode:       normalized.Mode,
		Identifier: normalized.Identifier,
		Conditions: normalized.Conditions,
		Scope:      normalized.Scope,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal policy hash payload: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func normalizeHashStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]string, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = trimmed
	}
	if len(seen) == 0 {
		return nil
	}
	result := make([]string, 0, len(seen))
	for _, value := range seen {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i]) < strings.ToLower(result[j])
	})
	return result
}

func (s *Store) ensureNoPolicyConflicts(orgID, exceptID string, precedence int, parameterHash string) error {
	if s == nil || s.sql == nil {
		return errors.New("policy store unavailable")
	}
	var existingID string
	err := s.sql.DB().QueryRow(`SELECT id FROM policies WHERE org_id=? AND precedence=? AND id<>? LIMIT 1`,
		orgID, precedence, exceptID).Scan(&existingID)
	if err == nil {
		return fmt.Errorf("%w: precedence %d is already used by policy %s", ErrDuplicatePrecedence, precedence, existingID)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	policies, err := s.ForOrg(orgID).List()
	if err != nil {
		return err
	}
	return duplicatePolicyParameterError(policies, exceptID, parameterHash)
}

// ensureUniquePolicyName fails fast (with ErrDuplicateName) when another
// row in the same org already uses this display name. The DB-level
// unique index is the authoritative guard; this pre-check is purely so
// the API returns a consistent CHW-4604 conflict instead of a generic
// driver error string. Empty name is exempt — see comment on
// idx_policies_org_name_unique.
func (s *Store) ensureUniquePolicyName(orgID, exceptID, name string) error {
	if s == nil || s.sql == nil {
		return errors.New("policy store unavailable")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	var existingID string
	err := s.sql.DB().QueryRow(`SELECT id FROM policies WHERE org_id=? AND name=? AND id<>? LIMIT 1`,
		orgID, name, exceptID).Scan(&existingID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: %q is already used by policy %s", ErrDuplicateName, name, existingID)
}

func duplicatePolicyParameterError(policies []Policy, exceptID, parameterHash string) error {
	for _, existing := range policies {
		if existing.ID == exceptID {
			continue
		}
		existingHash, err := PolicyParameterHash(existing)
		if err != nil {
			return err
		}
		if existingHash == parameterHash {
			return fmt.Errorf("%w: policy %s has the same effective parameters", ErrDuplicatePolicy, existing.ID)
		}
	}
	return nil
}

func policyConflictError(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "idx_policies_org_precedence_unique"):
		return fmt.Errorf("%w: precedence is already used", ErrDuplicatePrecedence)
	case strings.Contains(msg, "idx_policies_org_parameter_hash_unique"):
		return fmt.Errorf("%w: policy with the same effective parameters already exists", ErrDuplicatePolicy)
	case strings.Contains(msg, "idx_policies_org_name_unique"):
		return fmt.Errorf("%w: a policy with this name already exists", ErrDuplicateName)
	default:
		return err
	}
}

func (s *Store) ensurePolicyIntegrity() error {
	if s == nil || s.sql == nil {
		return errors.New("policy store unavailable")
	}
	if err := s.repairDuplicatePrecedence(); err != nil {
		return err
	}
	if err := s.backfillParameterHashes(); err != nil {
		return err
	}
	if err := s.repairDuplicateNames(); err != nil {
		return err
	}
	if _, err := s.sql.DB().Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_org_precedence_unique ON policies(org_id, precedence)`); err != nil {
		return fmt.Errorf("create policy precedence unique index: %w", err)
	}
	if _, err := s.sql.DB().Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_org_parameter_hash_unique ON policies(org_id, parameter_hash) WHERE parameter_hash <> ''`); err != nil {
		return fmt.Errorf("create policy parameter hash unique index: %w", err)
	}
	// F12 — Enforce unique (org_id, name) so two policies in the same org
	// can't share a display name. The repair pass above renames colliding
	// rows deterministically with a numeric suffix before the index goes
	// up; an empty name is exempt because the column allows '' for legacy
	// rows seeded before name became required and we don't want to invent
	// names for them at migration time.
	if _, err := s.sql.DB().Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_policies_org_name_unique ON policies(org_id, name) WHERE name <> ''`); err != nil {
		return fmt.Errorf("create policy name unique index: %w", err)
	}
	return nil
}

// repairDuplicateNames finds (org_id, name) collisions and renames the
// later rows in-place with a "(N)" suffix so the subsequent UNIQUE index
// can be created without an error. Idempotent: if the suffixed name also
// collides we increment N until a free slot is found, and rows already
// uniquely named are left untouched.
//
// Ordering: for a given (org_id, name), the row with the earliest
// created_at keeps the bare name. Ties break on id ASC for determinism.
// This matches operator intuition that the original policy keeps its
// label and copies are the ones that get suffixed.
func (s *Store) repairDuplicateNames() error {
	rows, err := s.sql.DB().Query(`SELECT org_id, id, name, created_at FROM policies WHERE name <> '' ORDER BY org_id, name, created_at ASC, id ASC`)
	if err != nil {
		return err
	}
	type nameRow struct {
		OrgID string
		ID    string
		Name  string
	}
	var all []nameRow
	for rows.Next() {
		var r nameRow
		var createdAt time.Time
		if err := rows.Scan(&r.OrgID, &r.ID, &r.Name, &createdAt); err != nil {
			rows.Close()
			return err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Build the set of names already taken per org so the suffix-search
	// avoids re-using a name that another row holds.
	taken := make(map[string]map[string]struct{}) // org_id → set of names
	for _, r := range all {
		if taken[r.OrgID] == nil {
			taken[r.OrgID] = make(map[string]struct{})
		}
		taken[r.OrgID][r.Name] = struct{}{}
	}

	// First pass: identify which rows need renaming. A row needs renaming
	// if a previous row in the sorted slice has the same (org_id, name).
	seen := make(map[string]map[string]struct{}) // org_id → first-seen names
	now := time.Now().UTC()
	for _, r := range all {
		if seen[r.OrgID] == nil {
			seen[r.OrgID] = make(map[string]struct{})
		}
		if _, dup := seen[r.OrgID][r.Name]; !dup {
			seen[r.OrgID][r.Name] = struct{}{}
			continue
		}
		// Find the next free " (N)" suffix.
		newName := ""
		for i := 1; ; i++ {
			candidate := fmt.Sprintf("%s (%d)", r.Name, i)
			if _, busy := taken[r.OrgID][candidate]; !busy {
				newName = candidate
				break
			}
		}
		taken[r.OrgID][newName] = struct{}{}
		seen[r.OrgID][newName] = struct{}{}
		if _, err := s.sql.DB().Exec(`UPDATE policies SET name=?, updated_at=? WHERE org_id=? AND id=?`,
			newName, now, r.OrgID, r.ID); err != nil {
			return fmt.Errorf("repair duplicate policy name for %s: %w", r.ID, err)
		}
	}
	return nil
}

type policyOrderRow struct {
	OrgID      string
	ID         string
	Precedence int
	CreatedAt  time.Time
}

func (s *Store) repairDuplicatePrecedence() error {
	rows, err := s.sql.DB().Query(`SELECT org_id, id, precedence, created_at FROM policies ORDER BY org_id, precedence ASC, created_at DESC, id ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	byOrg := make(map[string][]policyOrderRow)
	seen := make(map[string]map[int]struct{})
	duplicateOrgs := make(map[string]struct{})
	for rows.Next() {
		var row policyOrderRow
		if err := rows.Scan(&row.OrgID, &row.ID, &row.Precedence, &row.CreatedAt); err != nil {
			return err
		}
		byOrg[row.OrgID] = append(byOrg[row.OrgID], row)
		if seen[row.OrgID] == nil {
			seen[row.OrgID] = make(map[int]struct{})
		}
		if _, ok := seen[row.OrgID][row.Precedence]; ok {
			duplicateOrgs[row.OrgID] = struct{}{}
		}
		seen[row.OrgID][row.Precedence] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	now := time.Now().UTC()
	for orgID := range duplicateOrgs {
		for i, row := range byOrg[orgID] {
			nextPrecedence := (i + 1) * 10
			if row.Precedence == nextPrecedence {
				continue
			}
			if _, err := s.sql.DB().Exec(`UPDATE policies SET precedence=?, updated_at=? WHERE org_id=? AND id=?`,
				nextPrecedence, now, orgID, row.ID); err != nil {
				return fmt.Errorf("repair policy precedence for %s: %w", row.ID, err)
			}
		}
	}
	return nil
}

func (s *Store) backfillParameterHashes() error {
	policiesByOrg, err := s.listPoliciesForIntegrity()
	if err != nil {
		return err
	}
	for orgID, policies := range policiesByOrg {
		seen := make(map[string]string, len(policies))
		for _, pol := range policies {
			hash, err := PolicyParameterHash(pol)
			if err != nil {
				return err
			}
			value := hash
			if _, ok := seen[hash]; ok {
				value = ""
			} else {
				seen[hash] = pol.ID
			}
			if _, err := s.sql.DB().Exec(`UPDATE policies SET parameter_hash=? WHERE org_id=? AND id=?`,
				value, orgID, pol.ID); err != nil {
				return fmt.Errorf("backfill policy parameter hash for %s: %w", pol.ID, err)
			}
		}
	}
	return nil
}

func (s *Store) listPoliciesForIntegrity() (map[string][]Policy, error) {
	rows, err := s.sql.DB().Query(`SELECT id, name, description, precedence, mode, status, created_at, updated_at, identifier, conditions, policy_scope, org_id FROM policies ORDER BY org_id, precedence ASC, created_at DESC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string][]Policy)
	for rows.Next() {
		var (
			orgID                                     string
			policy                                    Policy
			name, description                         sql.NullString
			identifierJSON, conditionsJSON, scopeJSON sql.NullString
		)
		if err := rows.Scan(&policy.ID, &name, &description, &policy.Precedence, &policy.Mode, &policy.Status,
			&policy.CreatedAt, &policy.UpdatedAt, &identifierJSON, &conditionsJSON, &scopeJSON, &orgID); err != nil {
			return nil, err
		}
		if name.Valid {
			policy.Name = name.String
		}
		if description.Valid {
			policy.Description = description.String
		}
		if identifierJSON.Valid && identifierJSON.String != "" {
			if err := json.Unmarshal([]byte(identifierJSON.String), &policy.Identifier); err != nil {
				return nil, fmt.Errorf("unmarshal identifier: %w", err)
			}
		}
		if conditionsJSON.Valid && conditionsJSON.String != "" {
			if err := json.Unmarshal([]byte(conditionsJSON.String), &policy.Conditions); err != nil {
				return nil, fmt.Errorf("unmarshal conditions: %w", err)
			}
		}
		if scopeJSON.Valid && scopeJSON.String != "" {
			if err := json.Unmarshal([]byte(scopeJSON.String), &policy.Scope); err != nil {
				return nil, fmt.Errorf("unmarshal scope: %w", err)
			}
		}
		result[orgID] = append(result[orgID], policy)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func normalizeCountryScope(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" || isUnrestrictedScopeValue(value) {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	if len(normalized) == 0 {
		return nil, nil
	}
	return normalized, nil
}

func normalizeIPScope(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || isUnrestrictedScopeValue(value) {
			continue
		}
		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("invalid requesting IP/CIDR %q", value)
			}
			value = prefix.Masked().String()
		} else {
			addr, err := netip.ParseAddr(value)
			if err != nil {
				return nil, fmt.Errorf("invalid requesting IP/CIDR %q", value)
			}
			value = addr.Unmap().String()
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, value)
	}
	if len(normalized) == 0 {
		return nil, nil
	}
	return normalized, nil
}

func hasPolicyConstraint(policy Policy) bool {
	return hasPolicyIdentifier(policy.Identifier) || hasPolicyCondition(policy.Conditions) || hasPolicyScope(policy.Scope)
}

// rejectStandaloneContextOnlyConditions enforces that the noisy Wave-3
// codesmell signals (UsesEval, NetworkAccess, ShellAccess, FilesystemAccess,
// EnvVarAccess) cannot be used as the sole gate on a policy. Their estimated
// 60-85% FP rate on legitimate top-100 packages makes them alert-fatigue
// generators in isolation. They remain available as informational context on
// the Report and as inputs to trustscore / composite policies — they just
// must be paired with at least one other constraint.
func rejectStandaloneContextOnlyConditions(policy Policy) error {
	used := ConditionsUsedBy(policy.Conditions)
	if len(used) == 0 {
		return nil
	}
	contextOnlyUsed := make([]ConditionType, 0, len(used))
	hasGateableCondition := false
	for _, c := range used {
		if IsContextOnlyCondition(c) {
			contextOnlyUsed = append(contextOnlyUsed, c)
		} else {
			hasGateableCondition = true
		}
	}
	if len(contextOnlyUsed) == 0 || hasGateableCondition {
		return nil
	}
	// An identifier or scope is fine as a pairing — the context-only
	// condition is then narrowing an already-scoped policy rather than
	// firing globally.
	if hasPolicyIdentifier(policy.Identifier) || hasPolicyScope(policy.Scope) {
		return nil
	}
	names := make([]string, len(contextOnlyUsed))
	for i, c := range contextOnlyUsed {
		names[i] = string(c)
	}
	return fmt.Errorf("policy uses only context-only condition(s) %v as a standalone gate; these signals are too noisy to enforce alone — pair them with another condition, an identifier, or a scope, or use them via trustscore/composite expressions", names)
}

func hasPolicyIdentifier(identifier Identifier) bool {
	return hasMeaningfulValue(identifier.TargetPackageName) ||
		hasMeaningfulValue(identifier.TargetPackageRepo) ||
		hasMeaningfulValue(identifier.TargetPackageVersion)
}

func hasPolicyCondition(conditions Conditions) bool {
	if conditions.IsVulnerable != nil {
		return true
	}
	if conditions.PackageAge != nil {
		return true
	}
	if conditions.CVSSMin != nil || conditions.CVSSMax != nil {
		return true
	}
	if conditions.EPSSMin != nil || conditions.EPSSMax != nil {
		return true
	}
	if hasMeaningfulValues(conditions.PackageLicense) {
		return true
	}
	if conditions.HasProvenance != nil {
		return true
	}
	if conditions.IsSuspectedTyposquat != nil {
		return true
	}
	if conditions.IsKnownMalicious != nil {
		return true
	}
	if conditions.TrustScoreMin != nil || conditions.TrustScoreMax != nil {
		return true
	}
	if hasMeaningfulValues(conditions.ReservedNamespaces) {
		return true
	}
	if conditions.HasInstallScript != nil {
		return true
	}
	if conditions.InstallScriptFetchesRemote != nil {
		return true
	}
	if conditions.PublisherChanged != nil {
		return true
	}
	if conditions.VersionAnomaly != nil {
		return true
	}
	if hasMeaningfulValues(conditions.VersionAnomalyKinds) {
		return true
	}
	if conditions.HasHiddenUnicode != nil {
		return true
	}
	if hasMeaningfulValues(conditions.HiddenUnicodeKinds) {
		return true
	}
	if conditions.PublishVelocityAnomaly != nil {
		return true
	}
	if conditions.PublishVelocityThreshold24h != nil {
		return true
	}
	// Wave 1.
	if conditions.LicenseCopyleft != nil || conditions.LicenseNonPermissive != nil ||
		conditions.LicenseExceptionPresent != nil || conditions.LicenseAmbiguousClassifier != nil ||
		conditions.LicenseUnidentified != nil {
		return true
	}
	if conditions.DeprecatedByMaintainer != nil {
		return true
	}
	if conditions.ShrinkwrapPresent != nil || conditions.ManifestConfusion != nil {
		return true
	}
	// Wave 2.
	if conditions.GitDependency != nil || conditions.HTTPTarballDependency != nil ||
		conditions.WildcardDependencyRange != nil || conditions.BadDependencySemver != nil {
		return true
	}
	// Wave 3.
	if conditions.UsesEval != nil || conditions.NetworkAccess != nil ||
		conditions.ShellAccess != nil || conditions.FilesystemAccess != nil ||
		conditions.EnvVarAccess != nil || conditions.NativeBinaryPresent != nil ||
		conditions.HighEntropyStrings != nil || conditions.URLStrings != nil ||
		conditions.MinifiedCode != nil {
		return true
	}
	// Wave 4.
	if conditions.TrivialPackage != nil || conditions.TooManyFiles != nil ||
		conditions.NonExistentAuthor != nil ||
		conditions.FirstTimeCollaborator != nil ||
		conditions.SuspiciousRepoStars != nil {
		return true
	}
	// SLSA-substrate ecosystem narrowing + attestation requirement —
	// the Tier-1 baseline system policy uses these as its only
	// constraints, so without recognising them validatePolicy rejects
	// every system policy at boot.
	if hasMeaningfulValues(conditions.Ecosystems) {
		return true
	}
	if conditions.RequireAttestation != nil {
		return true
	}
	return false
}

func hasPolicyScope(scope Scope) bool {
	return hasMeaningfulValues(scope.TargetClient) ||
		hasMeaningfulValues(scope.TargetGroup) ||
		hasMeaningfulValues(scope.TargetRepos) ||
		hasMeaningfulValues(scope.TargetRequestingCountry) ||
		hasMeaningfulValues(scope.TargetRequestingIP)
}

func hasMeaningfulValues(values []string) bool {
	for _, value := range values {
		if hasMeaningfulValue(value) {
			return true
		}
	}
	return false
}

func hasMeaningfulValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && trimmed != "*" && !strings.EqualFold(trimmed, "all")
}

func newID() (string, error) {
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("generate policy id: %w", err)
	}
	return fmt.Sprintf("pol-%d-%s", time.Now().UTC().UnixNano(), hex.EncodeToString(buf[:])), nil
}

// CachedStore wraps a Store with a per-org in-memory policy cache.
// Policies change infrequently (admin operations only), so a short TTL
// eliminates redundant DB queries on the hot download path.
//
// E3: when an InvalidationBus is wired (see AttachInvalidationBus),
// every Invalidate call ALSO publishes to other replicas via NATS so
// stale per-replica caches converge in <100ms instead of waiting up
// to TTL seconds. The TTL fallback is preserved as belt-and-braces:
// if NATS is down, divergence is bounded by the TTL.
type CachedStore struct {
	inner *Store
	mu    sync.RWMutex
	cache map[string]cachedEntry
	ttl   time.Duration

	// busMu guards publisher (which may be reset at runtime). Reads
	// take an RLock, writes take a Lock.
	busMu     sync.RWMutex
	publisher *Publisher
}

type cachedEntry struct {
	policies []Policy
	loadedAt time.Time
}

const defaultPolicyCacheTTL = 15 * time.Second

// NewCachedStore creates a caching layer around a policy Store. When a
// package-level hook is registered via [OnCachedStoreInit] — typically
// by the server bootstrap — the hook is invoked synchronously with the
// freshly constructed CachedStore so it can wire the multi-replica
// invalidation bus. The hook is a seam, not policy: NewCachedStore
// remains callable (and returns a usable store) even with no hook
// registered.
func NewCachedStore(inner *Store, ttl time.Duration) *CachedStore {
	if ttl <= 0 {
		ttl = defaultPolicyCacheTTL
	}
	cs := &CachedStore{
		inner: inner,
		cache: make(map[string]cachedEntry),
		ttl:   ttl,
	}
	cachedStoreInitHookMu.RLock()
	hook := cachedStoreInitHook
	cachedStoreInitHookMu.RUnlock()
	if hook != nil {
		hook(cs)
	}
	return cs
}

// cachedStoreInitHook is the package-level factory seam
// [NewCachedStore] consults on every construction. It lets the server
// bootstrap attach the invalidation bus + subscriber + evaluator-cache
// extras without a direct import cycle and without expanding the
// internal/server package surface (the cached store is wholly internal
// to server.New today).
var (
	cachedStoreInitHookMu sync.RWMutex
	cachedStoreInitHook   func(*CachedStore)
)

// OnCachedStoreInit registers hook to be called once per CachedStore
// constructed via [NewCachedStore]. Pass nil to clear the hook (useful
// in tests). Calling this again replaces the previously-registered
// hook; we deliberately keep the slot single-valued so wiring
// responsibility stays in one place (cmd/chainsaw-proxy bootstrap).
func OnCachedStoreInit(hook func(*CachedStore)) {
	cachedStoreInitHookMu.Lock()
	cachedStoreInitHook = hook
	cachedStoreInitHookMu.Unlock()
}

// AttachInvalidationBus wires the multi-replica invalidation pub/sub.
// publisher is used by Invalidate to fan out; subscriber (when
// non-nil) is started here and routed to localInvalidate so inbound
// messages do NOT re-publish (which would loop).
//
// Pass a nil publisher and nil subscriber to detach (e.g. in tests).
// If subscriber.Start returns an error, the publisher is still
// installed — operators see the subscribe failure in the log but
// publishes from this replica still propagate to others.
//
// extras are additional per-org invalidators fired after localInvalidate
// for every inbound message — intended for downstream caches (e.g. the
// evaluator's eval cache) that must also evict when another replica
// edits a policy. Nil entries are skipped.
func (c *CachedStore) AttachInvalidationBus(ctx context.Context, publisher *Publisher, subscriber *Subscriber, extras ...func(orgID string)) error {
	if c == nil {
		return nil
	}
	c.busMu.Lock()
	c.publisher = publisher
	c.busMu.Unlock()
	if subscriber == nil {
		return nil
	}
	// Wire the subscriber's callback to localInvalidate (NOT
	// Invalidate) so an inbound message doesn't re-publish. Extras
	// run after localInvalidate so the primary policy cache clears
	// first; downstream caches see a consistent state on re-read.
	subscriber.callback = func(orgID string) {
		c.localInvalidate(orgID)
		for _, extra := range extras {
			if extra != nil {
				extra(orgID)
			}
		}
	}
	return subscriber.Start(ctx)
}

// Inner returns the underlying Store for direct access when needed.
func (c *CachedStore) Inner() *Store {
	return c.inner
}

// ListPolicies returns the cached policy list for an org, reloading from DB
// only when the cache entry is absent or expired.
func (c *CachedStore) ListPolicies(orgID string) ([]Policy, error) {
	orgID = tenancy.NormalizeOrgID(orgID)

	c.mu.RLock()
	if entry, ok := c.cache[orgID]; ok && time.Since(entry.loadedAt) < c.ttl {
		result := make([]Policy, len(entry.policies))
		copy(result, entry.policies)
		c.mu.RUnlock()
		return result, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.cache[orgID]; ok && time.Since(entry.loadedAt) < c.ttl {
		result := make([]Policy, len(entry.policies))
		copy(result, entry.policies)
		return result, nil
	}

	policies, err := c.inner.ForOrg(orgID).List()
	if err != nil {
		return nil, err
	}
	c.cache[orgID] = cachedEntry{policies: policies, loadedAt: time.Now()}

	result := make([]Policy, len(policies))
	copy(result, policies)
	return result, nil
}

// Invalidate removes the cached entry for a specific org and, when an
// InvalidationBus is attached, fans the eviction out to every other
// replica so they evict their local cache too. Errors from the bus
// are swallowed (logged via the publisher) — the local invalidation
// has already happened, and the TTL fallback bounds divergence.
func (c *CachedStore) Invalidate(orgID string) {
	c.localInvalidate(orgID)
	c.busMu.RLock()
	pub := c.publisher
	c.busMu.RUnlock()
	if pub != nil {
		// Best-effort fan-out. We deliberately do NOT block on the
		// network from a hot mutation path beyond a short timeout —
		// the TTL fallback covers us if the publish drops.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = pub.Invalidate(ctx, orgID)
	}
}

// localInvalidate evicts the per-org entry without re-publishing.
// Used by the subscriber callback so inbound messages don't loop.
func (c *CachedStore) localInvalidate(orgID string) {
	if c == nil {
		return
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	c.mu.Lock()
	delete(c.cache, orgID)
	c.mu.Unlock()
}

// InvalidateAll clears the entire cache. Local-only — does NOT fan
// out, because there is no "all" wildcard subject in the bus design
// and publishing per-org-key is impractical for a global flush.
func (c *CachedStore) InvalidateAll() {
	c.mu.Lock()
	c.cache = make(map[string]cachedEntry)
	c.mu.Unlock()
}
