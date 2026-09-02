// Package policy — proxy compatibility matrix (single source of truth).
//
// This file mirrors the matrix in POLICY_PROXY_MATRIX.md. When a policy rule
// references a condition that a given ecosystem's proxy doesn't populate, the
// rule is "silently inert" — it won't error, it just never fires. The matrix
// below lets both the UI and the evaluator reason about that up front:
//
//   - The UI queries GET /api/policies/support-matrix and renders an inline
//     warning next to unsupported condition inputs.
//   - The evaluator emits a `policy.rule.skipped` audit event when a rule is
//     skipped because its condition is ❌ for the context's ecosystem.
//
// Keeping this data in Go (rather than parsing the markdown at runtime) avoids
// a startup cost and pulls the support table into `go vet`/compilation. A
// drift test (proxy_matrix_test.go) asserts the table matches the markdown.
package policy

import "sort"

// SupportLevel categorises how well an ecosystem's proxy supports a condition.
type SupportLevel string

const (
	// SupportFull — the condition is evaluated for this ecosystem.
	SupportFull SupportLevel = "full"
	// SupportNone — the condition cannot fire for this ecosystem (silently inert).
	SupportNone SupportLevel = "none"
	// SupportPartial — supported in principle but the underlying signal is
	// empty or gated in practice (e.g. Swift license → SPDX mapping is
	// incomplete; OS-package provenance is wired but hash-chain walk is
	// deferred).
	SupportPartial SupportLevel = "partial"
)

// ConditionType names a column in the proxy compatibility matrix.
type ConditionType string

const (
	// ConditionScorecard is a documentation-only column: no Conditions
	// field maps to it, so ConditionsUsedBy can never emit it. It exists
	// so the matrix records that OpenSSF Scorecard is wired for no
	// ecosystem (every row is SupportNone). Giving it a Conditions field
	// would mean shipping a policy knob that can never fire.
	ConditionScorecard    ConditionType = "Scorecard"
	ConditionMalwareIndex ConditionType = "MalwareIndex"
	ConditionEPSS         ConditionType = "EPSS"
	ConditionCVE          ConditionType = "CVE"
	ConditionPackageAge   ConditionType = "PackageAge"
	// ConditionCooldown — the cooldownDays publish-age quarantine. It
	// reads the per-VERSION release date (EvaluationContext.VersionReleaseDate),
	// the same provenance-metadata dependency as ConditionPackageAge (which
	// reads the per-PACKAGE date). Support is therefore identical to
	// ConditionPackageAge for every ecosystem.
	ConditionCooldown                   ConditionType = "Cooldown"
	ConditionLicense                    ConditionType = "License"
	ConditionHasProvenance              ConditionType = "HasProvenance"
	ConditionTyposquat                  ConditionType = "Typosquat"
	ConditionCVSS                       ConditionType = "CVSS"
	ConditionReservedNamespaces         ConditionType = "ReservedNamespaces"
	ConditionHasInstallScript           ConditionType = "HasInstallScript"
	ConditionInstallScriptFetchesRemote ConditionType = "InstallScriptFetchesRemote"
	ConditionImportTimeExecution        ConditionType = "ImportTimeExecution"
	ConditionMaliciousIOC               ConditionType = "MaliciousIOC"
	ConditionBuildRsExecutes            ConditionType = "BuildRsExecutes"
	ConditionPublisherChanged           ConditionType = "PublisherChanged"
	ConditionVersionAnomaly             ConditionType = "VersionAnomaly"
	// ConditionHasHiddenUnicode — PR 8. Matches when the artifact's text
	// files contain zero-width, bidi-override, or tag-character payloads
	// above the configured threshold (CHAINSAW_HIDDEN_UNICODE_THRESHOLD).
	// The hiddenUnicodeKinds policy field optionally narrows this to a
	// subset of the three kinds using intersection semantics.
	ConditionHasHiddenUnicode       ConditionType = "HasHiddenUnicode"
	ConditionPublishVelocityAnomaly ConditionType = "PublishVelocityAnomaly"

	// Socket-gap Wave 1 (zero-fetch wins). See SOCKET_GAP_IMPLEMENTATION_PLAN.md §10.
	ConditionLicenseCopyleft            ConditionType = "LicenseCopyleft"
	ConditionLicenseNonPermissive       ConditionType = "LicenseNonPermissive"
	ConditionLicenseExceptionPresent    ConditionType = "LicenseExceptionPresent"
	ConditionLicenseAmbiguousClassifier ConditionType = "LicenseAmbiguousClassifier"
	ConditionLicenseUnidentified        ConditionType = "LicenseUnidentified"
	ConditionDeprecatedByMaintainer     ConditionType = "DeprecatedByMaintainer"
	ConditionShrinkwrapPresent          ConditionType = "ShrinkwrapPresent"
	ConditionManifestConfusion          ConditionType = "ManifestConfusion"

	// Socket-gap Wave 2 (manifest hygiene). All four read the same
	// parsed dep-specifier list from the manifest — see
	// internal/formats/depspec/. Tier-1; no new network calls.
	ConditionGitDependency           ConditionType = "GitDependency"
	ConditionHTTPTarballDependency   ConditionType = "HTTPTarballDependency"
	ConditionWildcardDependencyRange ConditionType = "WildcardDependencyRange"
	ConditionBadDependencySemver     ConditionType = "BadDependencySemver"

	// Socket-gap Wave 3 — Tier-2 source-code scanners (see
	// SOCKET_GAP_IMPLEMENTATION_PLAN.md §10). All nine ride the
	// Wave-0 shared artifact map. Detection-only signals; no new
	// network calls.
	ConditionUsesEval            ConditionType = "UsesEval"
	ConditionNetworkAccess       ConditionType = "NetworkAccess"
	ConditionShellAccess         ConditionType = "ShellAccess"
	ConditionFilesystemAccess    ConditionType = "FilesystemAccess"
	ConditionEnvVarAccess        ConditionType = "EnvVarAccess"
	ConditionNativeBinaryPresent ConditionType = "NativeBinaryPresent"
	ConditionHighEntropyStrings  ConditionType = "HighEntropyStrings"
	ConditionURLStrings          ConditionType = "URLStrings"
	ConditionMinifiedCode        ConditionType = "MinifiedCode"

	// Socket-gap Wave 4 (see SOCKET_GAP_IMPLEMENTATION_PLAN.md §10).
	// TrivialPackage / TooManyFiles ride the Wave-0 artifact map (no
	// new network). The remaining three require upstream calls and are
	// feature-flagged OFF by default; see internal/intelligence for the
	// env-var gates.
	ConditionTrivialPackage        ConditionType = "TrivialPackage"
	ConditionTooManyFiles          ConditionType = "TooManyFiles"
	ConditionNonExistentAuthor     ConditionType = "NonExistentAuthor"
	ConditionFirstTimeCollaborator ConditionType = "FirstTimeCollaborator"
	ConditionSuspiciousRepoStars   ConditionType = "SuspiciousRepoStars"
	ConditionMaintainerAccountAge  ConditionType = "MaintainerAccountAge"

	// AI artifacts (Wave 6). Each maps 1:1 onto a Conditions field
	// hydrated by the Tier-2 AI providers in
	// internal/intelligence/premium/provider_aiartifact.go
	// (pickle_scan / model_card / agent_tool). Support is narrow by
	// construction: pickle + model-card signals need model weights or a
	// model card, and the agent-tool signals need a package.json /
	// pyproject.toml entry point, so only huggingface, npm and pip
	// populate any of them.
	ConditionDangerousPickle              ConditionType = "DangerousPickle"
	ConditionUnsafeSerializationFormat    ConditionType = "UnsafeSerializationFormat"
	ConditionModelCardInjection           ConditionType = "ModelCardInjection"
	ConditionAgentToolDangerousCapability ConditionType = "AgentToolDangerousCapability"
	ConditionMCPServerDeclared            ConditionType = "MCPServerDeclared"
	ConditionPromptTemplateInjection      ConditionType = "PromptTemplateInjection"
)

// contextOnlyConditions enumerates Wave-3 codesmell signals whose base
// false-positive rate on legitimate top-100 packages is too high (60–85%) for
// them to be useful as standalone policy gates. They are still collected,
// surfaced on the Report, and may participate in composite/trustscore signals
// — but a policy whose ONLY constraint is one (or more) of these conditions
// is rejected at validation time, because in isolation it produces alert
// fatigue without real signal.
//
// The other four Wave-3 signals (NativeBinaryPresent, HighEntropyStrings,
// URLStrings, MinifiedCode) have lower FP rates and remain eligible as
// standalone gates.
var contextOnlyConditions = map[ConditionType]struct{}{
	ConditionUsesEval:         {},
	ConditionNetworkAccess:    {},
	ConditionShellAccess:      {},
	ConditionFilesystemAccess: {},
	ConditionEnvVarAccess:     {},
}

// IsContextOnlyCondition reports whether a condition is too noisy to be used
// as a standalone policy gate. Context-only conditions are still populated on
// the Report and may participate in composite expressions; they just can't be
// the sole constraint on a policy.
func IsContextOnlyCondition(c ConditionType) bool {
	_, ok := contextOnlyConditions[c]
	return ok
}

// AllConditions returns every matrix column in a stable order.
func AllConditions() []ConditionType {
	return []ConditionType{
		ConditionScorecard,
		ConditionMalwareIndex,
		ConditionEPSS,
		ConditionCVE,
		ConditionPackageAge,
		ConditionCooldown,
		ConditionLicense,
		ConditionHasProvenance,
		ConditionTyposquat,
		ConditionCVSS,
		ConditionReservedNamespaces,
		ConditionHasInstallScript,
		ConditionInstallScriptFetchesRemote,
		ConditionImportTimeExecution,
		ConditionMaliciousIOC,
		ConditionBuildRsExecutes,
		ConditionPublisherChanged,
		ConditionVersionAnomaly,
		ConditionHasHiddenUnicode,
		ConditionPublishVelocityAnomaly,
		ConditionLicenseCopyleft,
		ConditionLicenseNonPermissive,
		ConditionLicenseExceptionPresent,
		ConditionLicenseAmbiguousClassifier,
		ConditionLicenseUnidentified,
		ConditionDeprecatedByMaintainer,
		ConditionShrinkwrapPresent,
		ConditionManifestConfusion,
		ConditionGitDependency,
		ConditionHTTPTarballDependency,
		ConditionWildcardDependencyRange,
		ConditionBadDependencySemver,
		ConditionUsesEval,
		ConditionNetworkAccess,
		ConditionShellAccess,
		ConditionFilesystemAccess,
		ConditionEnvVarAccess,
		ConditionNativeBinaryPresent,
		ConditionHighEntropyStrings,
		ConditionURLStrings,
		ConditionMinifiedCode,
		ConditionTrivialPackage,
		ConditionTooManyFiles,
		ConditionNonExistentAuthor,
		ConditionFirstTimeCollaborator,
		ConditionSuspiciousRepoStars,
		// AI artifacts (Wave 6). P8-14: these six were declared as
		// ConditionType constants, carried a cell in EVERY SupportMatrix
		// row, and were emitted by ConditionsUsedBy — but were missing
		// here. Everything that enumerates the matrix through
		// AllConditions() was therefore blind to them: GET
		// /api/policies/support-matrix omitted the columns, so the UI
		// could not render its unsupported-condition warning, and
		// `chainsaw policy preflight` exited 0 declaring "every
		// condition supported" for a policy that used one.
		ConditionDangerousPickle,
		ConditionUnsafeSerializationFormat,
		ConditionModelCardInjection,
		ConditionAgentToolDangerousCapability,
		ConditionMCPServerDeclared,
		ConditionPromptTemplateInjection,
		// NOTE: ConditionMaintainerAccountAge is the ONE ConditionType
		// deliberately held out of AllConditions(). Read this before
		// "fixing" it either way:
		//
		//   - The original rationale recorded here — that it is a
		//     numeric-threshold condition, so "the per-ecosystem support
		//     matrix and POLICY_PROXY_MATRIX.md cells do not apply" — is
		//     FACTUALLY WRONG and has been since the constant landed.
		//     Every SupportMatrix row carries a
		//     ConditionMaintainerAccountAge cell, POLICY_PROXY_MATRIX.md
		//     has a "maintainer account age" column, and
		//     TestSupportMatrixMatchesMarkdown asserts the two agree.
		//     ConditionCooldown and ConditionPackageAge are numeric-
		//     threshold conditions too and both are listed above.
		//
		//   - So the exclusion is currently UNJUSTIFIED, not principled:
		//     it makes the support-matrix API and preflight blind to
		//     maintainerAccountAgeDaysMax in exactly the way P8-14
		//     describes for the six AI conditions.
		//
		// It is held out here only because the Phase-8 remediation plan
		// scoped this change to the six AI conditions. Adding it is
		// verdict-neutral for the same reason they were (detectUnsupported
		// reads ConditionsUsedBy, never AllConditions) and should be its
		// own follow-up. TestEveryEmittedConditionIsInAllConditions
		// carries it as the single documented exclusion, with this
		// reason attached.
	}
}

// Ecosystem names the row keys used in SupportMatrix. These match the proxy
// format constants in `internal/repository/manager.go` where possible; where a
// proxy serves multiple ecosystems under one format (e.g. pip / PyPI), the
// canonical registry name is used. See EcosystemForFormat for the mapping.
type Ecosystem string

const (
	EcoNPM         Ecosystem = "npm"
	EcoPyPI        Ecosystem = "pip"
	EcoMaven       Ecosystem = "maven"
	EcoCargo       Ecosystem = "cargo"
	EcoComposer    Ecosystem = "composer"
	EcoRubyGems    Ecosystem = "rubygems"
	EcoNuGet       Ecosystem = "nuget"
	EcoGo          Ecosystem = "go"
	EcoHuggingFace Ecosystem = "huggingface"
	EcoCocoaPods   Ecosystem = "cocoapods"
	EcoSwift       Ecosystem = "swift"
	EcoPub         Ecosystem = "pub"
	EcoDocker      Ecosystem = "docker"
	EcoAPT         Ecosystem = "apt"
	EcoYum         Ecosystem = "yum"
	EcoDNF         Ecosystem = "dnf"
)

// NOTE: gradle is intentionally NOT a distinct ecosystem here. Gradle
// resolves the same group:artifact/POM coordinate space as Maven — the
// proxy uses maven.NewResolver() for both formats (see
// internal/repository.resolverForFormat) — so gradle is an alias of the
// maven ecosystem, exactly as bun/yarn alias npm. EcosystemForFormat maps
// "gradle" → EcoMaven. The single canonical set is the 16 distinct
// proxied ecosystems by resolver identity; a reconciliation test
// (internal/repository) asserts this set equals resolverForFormat's.

// AllEcosystems returns every matrix row in the stable order used by the
// markdown, so drift tests can compare table ordering directly.
func AllEcosystems() []Ecosystem {
	return []Ecosystem{
		EcoNPM,
		EcoPyPI,
		EcoMaven,
		EcoCargo,
		EcoComposer,
		EcoRubyGems,
		EcoNuGet,
		EcoGo,
		EcoHuggingFace,
		EcoCocoaPods,
		EcoSwift,
		EcoPub,
		EcoDocker,
		EcoAPT,
		EcoYum,
		EcoDNF,
	}
}

// SupportMatrix is the canonical, in-code copy of POLICY_PROXY_MATRIX.md. Keys
// are (ecosystem, condition) — read via Support().
//
// Any change here must also be reflected in POLICY_PROXY_MATRIX.md. The
// TestSupportMatrixMatchesMarkdown drift test will fail otherwise.
var SupportMatrix = map[Ecosystem]map[ConditionType]SupportLevel{
	EcoNPM: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportFull,
		ConditionInstallScriptFetchesRemote: SupportFull,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportFull, // maintainers[].name
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportFull,
		ConditionPublishVelocityAnomaly:     SupportFull,
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportFull, // versions[v].deprecated
		ConditionShrinkwrapPresent:          SupportFull, // npm-shrinkwrap.json in tarball
		ConditionManifestConfusion:          SupportFull, // registry vs tarball package.json
		// Wave 2: depspec parser ships for npm (package.json).
		ConditionGitDependency:           SupportFull,
		ConditionHTTPTarballDependency:   SupportFull,
		ConditionWildcardDependencyRange: SupportFull,
		ConditionBadDependencySemver:     SupportFull,
		// Wave 3: source-code scanners all apply to npm tarballs.
		ConditionUsesEval:            SupportFull,
		ConditionNetworkAccess:       SupportFull,
		ConditionShellAccess:         SupportFull,
		ConditionFilesystemAccess:    SupportFull,
		ConditionEnvVarAccess:        SupportFull,
		ConditionNativeBinaryPresent: SupportFull,
		ConditionHighEntropyStrings:  SupportFull,
		ConditionURLStrings:          SupportFull,
		ConditionMinifiedCode:        SupportFull,
		// Wave 4: source-shipping ecosystem; RTT signals are feature-
		// flagged and start as Partial until the canary runs.
		ConditionTrivialPackage:        SupportFull,
		ConditionTooManyFiles:          SupportFull,
		ConditionNonExistentAuthor:     SupportPartial,
		ConditionFirstTimeCollaborator: SupportPartial,
		ConditionSuspiciousRepoStars:   SupportPartial,
		ConditionMaintainerAccountAge:  SupportPartial, // GitHub-account heuristic, opt-in, warns on every result
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone, // no pickle weights in npm tarballs
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportFull, // package.json mcpServers/bin/keywords
		ConditionMCPServerDeclared:            SupportFull,
		ConditionPromptTemplateInjection:      SupportFull,
	},
	EcoPyPI: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportFull,
		ConditionInstallScriptFetchesRemote: SupportFull,
		ConditionImportTimeExecution:        SupportFull,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportFull, // info.author_email + info.maintainer_email
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportFull,
		ConditionPublishVelocityAnomaly:     SupportFull,
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportFull, // yanked
		// P8-39 rail finding (same class as P8-58/P8-59, found by
		// TestSupportMatrixMatchesProviderCoverage rather than by hand):
		// shrinkwrapProvider is ecosystem-generic. ecosystemLockfiles
		// (provider_shrinkwrap.go:53-63) maps pip/pypi → Pipfile.lock, poetry.lock and Run walks the
		// shared artifact map for them exactly as it does for npm; only
		// the bundledDependencies suppression is npm-family-specific.
		// SupportNone made detectUnsupported skip the WHOLE policy: a
		// live fail-open on a signal that is genuinely produced.
		ConditionShrinkwrapPresent: SupportFull,
		ConditionManifestConfusion: SupportNone, // npm-only
		// Wave 2: depspec parser covers pyproject.toml (PEP 621 + Poetry)
		// and requirements.txt. All four signals apply.
		ConditionGitDependency:           SupportFull,
		ConditionHTTPTarballDependency:   SupportFull,
		ConditionWildcardDependencyRange: SupportFull,
		ConditionBadDependencySemver:     SupportFull,
		// Wave 3: PyPI sdists ship source.
		ConditionUsesEval:            SupportFull,
		ConditionNetworkAccess:       SupportFull,
		ConditionShellAccess:         SupportFull,
		ConditionFilesystemAccess:    SupportFull,
		ConditionEnvVarAccess:        SupportFull,
		ConditionNativeBinaryPresent: SupportFull,
		ConditionHighEntropyStrings:  SupportFull,
		ConditionURLStrings:          SupportFull,
		ConditionMinifiedCode:        SupportFull,
		// Wave 4: PyPI has a user page (HTML 404 probe) but no per-
		// release uploader field.
		ConditionTrivialPackage:    SupportFull,
		ConditionTooManyFiles:      SupportFull,
		ConditionNonExistentAuthor: SupportPartial,
		// P8-58: was SupportNone on the "no per-release uploader field"
		// rationale, which described the ORIGINAL network-fetching
		// implementation. firstTimeCollaboratorProvider now reads the
		// persisted publisher_set from the metadata store instead
		// (provider_wave4_rtt.go:340-353 records the widening), and
		// pip/pypi is in firstTimeCollabSupportedEcosystems. Leaving the
		// cell at SupportNone made detectUnsupported fire and
		// evaluator.go continue past the WHOLE policy — a rule an
		// operator wrote, against a signal that is genuinely hydrated,
		// silently stopped enforcing. Partial (not Full) because the
		// signal is behind CHAINSAW_WAVE4_FIRST_TIME_COLLABORATOR, the
		// same posture as npm/rubygems.
		ConditionFirstTimeCollaborator: SupportPartial,
		ConditionSuspiciousRepoStars:   SupportPartial,
		ConditionMaintainerAccountAge:  SupportPartial,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportFull, // pickle weights do ship inside sdists/wheels
		ConditionUnsafeSerializationFormat:    SupportFull,
		ConditionModelCardInjection:           SupportNone, // no model card in a PyPI distribution
		ConditionAgentToolDangerousCapability: SupportFull, // pyproject.toml [project.entry-points."mcp.server"]
		ConditionMCPServerDeclared:            SupportFull,
		ConditionPromptTemplateInjection:      SupportFull,
	},
	EcoMaven: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone, // no lifecycle-script concept
		ConditionInstallScriptFetchesRemote: SupportNone,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		// P8-70. Downgraded from ✅ to ⚠️ on 2026-09-02. The extractor
		// works — `developers[].id` → `<email>` → `<name>` via
		// `intelligence.MavenDeveloperPublisherIDs` — so the condition is
		// populated and a policy rule referencing it does fire. What it
		// is NOT is a publishing identity: the POM `<developers>` block
		// is prose the project author edits, and Maven Central's real
		// access control is Sonatype `groupId` namespace ownership,
		// which is nowhere in the POM. Measured on prod: 30 maven/gradle
		// coordinates fired this, 0 were takeovers. The risk signal was
		// therefore demoted for maven/gradle to the SevLow
		// `sc.pom_developer_list_changed`
		// (core/risk/registry_supplychain.go); leaving this cell at
		// SupportFull would have kept the UI telling policy authors the
		// condition means here what it means on npm.
		//
		// Deliberately NOT SupportNone: the matrix is documentation +
		// the `policy.rule.skipped` audit signal, and marking it ❌ would
		// tell an operator their explicit rule is inert when it still
		// evaluates. The honest level is "wired, but the underlying
		// signal is weaker than the column implies", which is exactly
		// what SupportPartial is defined as at the top of this file.
		ConditionPublisherChanged:           SupportPartial, // developers[].id — self-declared POM prose, not an ownership record (P8-70)
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportFull,
		ConditionPublishVelocityAnomaly:     SupportPartial, // developer IDs not always populated
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportNone, // no maintainer-deprecation flag
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
		// Wave 2: pom.xml has no git/http specifier concept (binary
		// resolution); parser covers version-range checks via
		// go-mvn-version. Maven-unique range forms like [1.0,) may
		// escape the grammar — hence Partial.
		ConditionGitDependency:           SupportNone,
		ConditionHTTPTarballDependency:   SupportNone,
		ConditionWildcardDependencyRange: SupportPartial,
		ConditionBadDependencySemver:     SupportPartial,
		// Wave 3: Maven jars ship .class files, not source — the
		// source-text scanners only fire when a -sources.jar is
		// proxied. NativeBinaryPresent fires reliably when a jar
		// embeds .so/.dll resources.
		ConditionUsesEval:            SupportPartial,
		ConditionNetworkAccess:       SupportPartial,
		ConditionShellAccess:         SupportPartial,
		ConditionFilesystemAccess:    SupportPartial,
		ConditionEnvVarAccess:        SupportPartial,
		ConditionNativeBinaryPresent: SupportFull,
		ConditionHighEntropyStrings:  SupportPartial,
		ConditionURLStrings:          SupportPartial,
		ConditionMinifiedCode:        SupportPartial,
		// Wave 4: Maven jars are classes not source — TrivialPackage
		// only fires when a -sources.jar is proxied. TooManyFiles still
		// counts archive entries reliably. No user endpoint → NonE is
		// ❌. No per-version uploader change → FirstTime ❌.
		// RepoStars reads scm.url from the POM when present.
		ConditionTrivialPackage:    SupportPartial,
		ConditionTooManyFiles:      SupportFull,
		ConditionNonExistentAuthor: SupportNone,
		// P8-58: see the pip row. maven/gradle are in
		// firstTimeCollabSupportedEcosystems — the provider reads the
		// persisted publisher_set, not a per-version uploader field, so
		// the "no per-version uploader change" rationale above no longer
		// applies to this cell.
		//
		// P8-70 (2026-09-02): stays ⚠️, and the reason narrowed. The
		// publisher_set this reads on maven/gradle is the POM
		// <developers> roster, so "first-time COLLABORATOR" is not what
		// a new entry means. The risk signal is now suppressed for POM
		// ecosystems (core/risk/registry_supplychain.go); the condition
		// remains evaluable for a policy author who wants the raw fact,
		// which is why this is ⚠️ and not ❌.
		ConditionFirstTimeCollaborator: SupportPartial,
		ConditionSuspiciousRepoStars:   SupportPartial,
		ConditionMaintainerAccountAge:  SupportNone,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
	// EcoPub (Dart/Flutter, pub.dev). A first-class proxied ecosystem
	// (own resolver/facet/transformer; internal/repository.FormatPub).
	// Tier-1 metadata signals are wired and verified against the code:
	// CVE/EPSS/CVSS via supportedCVEEcosystems (core/intelligence/
	// provider_cve.go), package-age/cooldown via fetchPubReleaseDate,
	// license via fetchPubLicense, publisher via fetchPubPublisherSet
	// (all internal/server/package_metadata.go), typosquat via the
	// enrolled "pub" corpus (core/typosquat). Malware is emerging: the
	// index only carries Dart entries once ossf/malicious-packages (or a
	// GHSA feed) publishes them — override-only today (core/malware/
	// sync.go pub coverage watch) — hence Partial. No provenance standard
	// for pub → HasProvenance None. Wave-2 depspec has no pubspec parser
	// (internal/formats/depspec has no pub.go) → all None. Wave-3/4
	// source scanners ride the ecosystem-agnostic shared artifact map;
	// pub ships Dart source but the scanners' patterns are not Dart-tuned
	// and pub-artifact scanning is unverified end-to-end → Partial (not
	// Full). UsesEval None (Dart has no runtime eval, like Swift/Go).
	EcoPub: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportPartial, // emerging Dart feed; override-only today
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull, // fetchPubReleaseDate
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull, // fetchPubLicense
		ConditionHasProvenance:              SupportNone, // no pub provenance standard
		ConditionTyposquat:                  SupportFull, // enrolled corpus (pubTopSeed)
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone, // no lifecycle-script concept
		ConditionInstallScriptFetchesRemote: SupportNone,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportFull, // fetchPubPublisherSet
		ConditionVersionAnomaly:             SupportFull, // pub is semver
		ConditionHasHiddenUnicode:           SupportFull, // Dart source is text
		ConditionPublishVelocityAnomaly:     SupportNone, // no per-version publisher metadata
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportFull, // runPub decodes retracted→Release.Yanked + isDiscontinued→Release.Deprecated
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
		// Wave 2: no pubspec.yaml dep-specifier parser yet.
		ConditionGitDependency:           SupportNone,
		ConditionHTTPTarballDependency:   SupportNone,
		ConditionWildcardDependencyRange: SupportNone,
		ConditionBadDependencySemver:     SupportNone,
		// Wave 3: shared artifact map runs over Dart source text, but
		// the scanners' regex heuristics are JS/Python-tuned and
		// pub-artifact scanning is not verified end-to-end → Partial.
		ConditionUsesEval:            SupportNone, // Dart has no runtime eval
		ConditionNetworkAccess:       SupportPartial,
		ConditionShellAccess:         SupportPartial,
		ConditionFilesystemAccess:    SupportPartial,
		ConditionEnvVarAccess:        SupportPartial,
		ConditionNativeBinaryPresent: SupportPartial,
		ConditionHighEntropyStrings:  SupportPartial,
		ConditionURLStrings:          SupportPartial,
		ConditionMinifiedCode:        SupportPartial,
		// Wave 4: TooManyFiles counts archive entries (ecosystem-
		// agnostic) → Full; TrivialPackage rides the artifact map →
		// Partial. No pub user-exists endpoint / per-version uploader.
		ConditionTrivialPackage:        SupportPartial,
		ConditionTooManyFiles:          SupportFull,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportPartial,
		ConditionMaintainerAccountAge:  SupportNone,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
	EcoCargo: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportNone, // no standard
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportFull,
		ConditionInstallScriptFetchesRemote: SupportFull,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportFull, // build.rs static scan ships for cargo crates
		// P8-59: the "not extracted in PR 2" comment outlived its fix.
		// supportedMetadiffEcosystems (provider_metadiff.go:88-91) covers
		// cargo — crates.io exposes a stable per-crate owner set via
		// api/v1/crates/{name}/owners — and cargo is also in
		// supportedRegistryEcosystems, so both the incoming publisher IDs
		// and the persisted baseline set are hydrated. SupportNone made
		// detectUnsupported skip the WHOLE policy: a live fail-open.
		ConditionPublisherChanged:           SupportFull,
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportFull,
		ConditionPublishVelocityAnomaly:     SupportNone, // no per-version publisher metadata
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportFull, // crate version "yanked"
		// P8-39 rail finding (same class as P8-58/P8-59, found by
		// TestSupportMatrixMatchesProviderCoverage rather than by hand):
		// shrinkwrapProvider is ecosystem-generic. ecosystemLockfiles
		// (provider_shrinkwrap.go:53-63) maps cargo → Cargo.lock and Run walks the
		// shared artifact map for them exactly as it does for npm; only
		// the bundledDependencies suppression is npm-family-specific.
		// SupportNone made detectUnsupported skip the WHOLE policy: a
		// live fail-open on a signal that is genuinely produced.
		ConditionShrinkwrapPresent: SupportFull,
		ConditionManifestConfusion: SupportNone,
		// Wave 2: Cargo.toml supports { git = "..." } (✅) but not raw
		// http tarballs (registry or git only).
		ConditionGitDependency:           SupportFull,
		ConditionHTTPTarballDependency:   SupportNone,
		ConditionWildcardDependencyRange: SupportFull,
		ConditionBadDependencySemver:     SupportFull,
		// Wave 3: crate tarballs ship .rs source.
		ConditionUsesEval:            SupportNone, // Rust has no runtime eval
		ConditionNetworkAccess:       SupportFull,
		ConditionShellAccess:         SupportFull,
		ConditionFilesystemAccess:    SupportFull,
		ConditionEnvVarAccess:        SupportFull,
		ConditionNativeBinaryPresent: SupportFull,
		ConditionHighEntropyStrings:  SupportFull,
		ConditionURLStrings:          SupportFull,
		ConditionMinifiedCode:        SupportFull,
		// Wave 4: crates-io has no user endpoint in scope and no
		// per-version uploader history in the index. RepoStars reads
		// Cargo.toml repository field.
		ConditionTrivialPackage:        SupportFull,
		ConditionTooManyFiles:          SupportFull,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportPartial,
		ConditionMaintainerAccountAge:  SupportPartial,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
	EcoComposer: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportNone, // no standard
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportFull,
		ConditionInstallScriptFetchesRemote: SupportFull,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportNone, // not extracted in PR 2
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportFull,
		ConditionPublishVelocityAnomaly:     SupportNone, // no per-version publisher metadata
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportNone,
		// P8-39 rail finding (same class as P8-58/P8-59, found by
		// TestSupportMatrixMatchesProviderCoverage rather than by hand):
		// shrinkwrapProvider is ecosystem-generic. ecosystemLockfiles
		// (provider_shrinkwrap.go:53-63) maps composer → composer.lock and Run walks the
		// shared artifact map for them exactly as it does for npm; only
		// the bundledDependencies suppression is npm-family-specific.
		// SupportNone made detectUnsupported skip the WHOLE policy: a
		// live fail-open on a signal that is genuinely produced.
		ConditionShrinkwrapPresent: SupportFull,
		ConditionManifestConfusion: SupportNone,
		// Wave 2: Composer specifier grammar has stability flags and
		// dev-<branch> tags outside Masterminds/semver — range/semver
		// cells start Partial until a dedicated composer grammar lands.
		ConditionGitDependency:           SupportFull,
		ConditionHTTPTarballDependency:   SupportFull,
		ConditionWildcardDependencyRange: SupportPartial,
		ConditionBadDependencySemver:     SupportPartial,
		// Wave 3: Composer packages ship PHP source.
		ConditionUsesEval:            SupportFull,
		ConditionNetworkAccess:       SupportFull,
		ConditionShellAccess:         SupportFull,
		ConditionFilesystemAccess:    SupportFull,
		ConditionEnvVarAccess:        SupportFull,
		ConditionNativeBinaryPresent: SupportFull,
		ConditionHighEntropyStrings:  SupportFull,
		ConditionURLStrings:          SupportFull,
		ConditionMinifiedCode:        SupportFull,
		// Wave 4: Composer has no user-exists endpoint in scope and
		// no per-version uploader change history. RepoStars reads
		// composer.json support.source.
		ConditionTrivialPackage:        SupportFull,
		ConditionTooManyFiles:          SupportFull,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportPartial,
		ConditionMaintainerAccountAge:  SupportPartial,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
	EcoRubyGems: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportFull,
		ConditionInstallScriptFetchesRemote: SupportFull,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportFull, // authors (comma-split)
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportFull,
		ConditionPublishVelocityAnomaly:     SupportFull,
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportNone, // rubygems yanked not extracted
		// P8-39 rail finding (same class as P8-58/P8-59, found by
		// TestSupportMatrixMatchesProviderCoverage rather than by hand):
		// shrinkwrapProvider is ecosystem-generic. ecosystemLockfiles
		// (provider_shrinkwrap.go:53-63) maps rubygems → Gemfile.lock and Run walks the
		// shared artifact map for them exactly as it does for npm; only
		// the bundledDependencies suppression is npm-family-specific.
		// SupportNone made detectUnsupported skip the WHOLE policy: a
		// live fail-open on a signal that is genuinely produced.
		ConditionShrinkwrapPresent: SupportFull,
		ConditionManifestConfusion: SupportNone,
		// Wave 2: Gemfile supports :git and :github refs (✅); no raw
		// http tarballs.
		ConditionGitDependency:           SupportFull,
		ConditionHTTPTarballDependency:   SupportNone,
		ConditionWildcardDependencyRange: SupportFull,
		ConditionBadDependencySemver:     SupportFull,
		// Wave 3: gems ship .rb source.
		ConditionUsesEval:            SupportFull,
		ConditionNetworkAccess:       SupportFull,
		ConditionShellAccess:         SupportFull,
		ConditionFilesystemAccess:    SupportFull,
		ConditionEnvVarAccess:        SupportFull,
		ConditionNativeBinaryPresent: SupportFull,
		ConditionHighEntropyStrings:  SupportFull,
		ConditionURLStrings:          SupportFull,
		ConditionMinifiedCode:        SupportFull,
		// Wave 4: RubyGems has a profile endpoint (partial), and the
		// versions API exposes per-version author — both RTT signals
		// supported but feature-flagged until canary.
		ConditionTrivialPackage:        SupportFull,
		ConditionTooManyFiles:          SupportFull,
		ConditionNonExistentAuthor:     SupportPartial,
		ConditionFirstTimeCollaborator: SupportPartial,
		ConditionSuspiciousRepoStars:   SupportPartial,
		ConditionMaintainerAccountAge:  SupportPartial,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
	EcoNuGet: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportFull, // legacy PowerShell tools/{install,uninstall,init}.ps1 hooks (walkNuGetHooks)
		ConditionInstallScriptFetchesRemote: SupportFull, // fetchesRemoteRE over the same PS hooks
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportFull, // authors (comma/semicolon-split)
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportFull,
		ConditionPublishVelocityAnomaly:     SupportFull,
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportNone,
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
		// Wave 2: NuGet .csproj / packages.config parsing deferred.
		ConditionGitDependency:           SupportNone,
		ConditionHTTPTarballDependency:   SupportNone,
		ConditionWildcardDependencyRange: SupportNone,
		ConditionBadDependencySemver:     SupportNone,
		// Wave 3: NuGet packages ship .dll (compiled) primarily.
		// Source-text scanners only fire when the .nupkg bundles
		// a src/ tree; NativeBinaryPresent fires reliably.
		ConditionUsesEval:            SupportPartial,
		ConditionNetworkAccess:       SupportPartial,
		ConditionShellAccess:         SupportPartial,
		ConditionFilesystemAccess:    SupportPartial,
		ConditionEnvVarAccess:        SupportPartial,
		ConditionNativeBinaryPresent: SupportFull,
		ConditionHighEntropyStrings:  SupportPartial,
		ConditionURLStrings:          SupportPartial,
		ConditionMinifiedCode:        SupportPartial,
		// Wave 4: NuGet packages are .dll — TrivialPackage only
		// fires on source-embedded .nupkg. No user-exists endpoint
		// in scope. RepoStars reads the .nuspec repository field.
		ConditionTrivialPackage:    SupportPartial,
		ConditionTooManyFiles:      SupportFull,
		ConditionNonExistentAuthor: SupportNone,
		// P8-58: see the pip row. nuget is in
		// firstTimeCollabSupportedEcosystems.
		ConditionFirstTimeCollaborator: SupportPartial,
		ConditionSuspiciousRepoStars:   SupportPartial,
		ConditionMaintainerAccountAge:  SupportNone,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
	EcoGo: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull, // PR 4: enrolled via curated seed list
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone, // no lifecycle-script concept
		ConditionInstallScriptFetchesRemote: SupportNone,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportNone, // no per-version publisher metadata
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportFull,
		ConditionPublishVelocityAnomaly:     SupportNone, // no per-version publisher metadata
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportNone,
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
		// Wave 2: go.mod requires always pin an exact version
		// (pseudo-version); no git/http specifiers and no wildcard
		// ranges. Only BadDependencySemver is meaningful.
		ConditionGitDependency:           SupportNone,
		ConditionHTTPTarballDependency:   SupportNone,
		ConditionWildcardDependencyRange: SupportNone,
		ConditionBadDependencySemver:     SupportFull,
		// Wave 3: Go modules ship .go source.
		ConditionUsesEval:            SupportNone, // Go has no runtime eval
		ConditionNetworkAccess:       SupportFull,
		ConditionShellAccess:         SupportFull,
		ConditionFilesystemAccess:    SupportFull,
		ConditionEnvVarAccess:        SupportFull,
		ConditionNativeBinaryPresent: SupportFull,
		ConditionHighEntropyStrings:  SupportFull,
		ConditionURLStrings:          SupportFull,
		ConditionMinifiedCode:        SupportFull,
		// Wave 4: Go modules ship source (TrivialPackage ✅). No user
		// endpoint; no per-version publisher signal. RepoStars from
		// module path github.com/... when applicable.
		ConditionTrivialPackage:        SupportFull,
		ConditionTooManyFiles:          SupportFull,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportPartial,
		ConditionMaintainerAccountAge:  SupportNone,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
	EcoHuggingFace: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportNone, // not extracted in PR 2
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportPartial, // text files only — model weights are binary and skipped
		ConditionPublishVelocityAnomaly:     SupportNone,    // no per-version publisher metadata
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportNone,
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
		// Wave 2: HuggingFace model repos have no dep-specifier concept.
		ConditionGitDependency:           SupportNone,
		ConditionHTTPTarballDependency:   SupportNone,
		ConditionWildcardDependencyRange: SupportNone,
		ConditionBadDependencySemver:     SupportNone,
		// Wave 3: HuggingFace artifacts are model weights — none of
		// the source scanners apply. Every cell is None.
		ConditionUsesEval:            SupportNone,
		ConditionNetworkAccess:       SupportNone,
		ConditionShellAccess:         SupportNone,
		ConditionFilesystemAccess:    SupportNone,
		ConditionEnvVarAccess:        SupportNone,
		ConditionNativeBinaryPresent: SupportNone,
		ConditionHighEntropyStrings:  SupportNone,
		ConditionURLStrings:          SupportNone,
		ConditionMinifiedCode:        SupportNone,
		// Wave 4: HuggingFace is model-weight territory — defer.
		ConditionTrivialPackage:        SupportNone,
		ConditionTooManyFiles:          SupportNone,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportNone,
		ConditionMaintainerAccountAge:  SupportPartial,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportFull, // pickle_scan over model weights
		ConditionUnsafeSerializationFormat:    SupportFull,
		ConditionModelCardInjection:           SupportFull,
		ConditionAgentToolDangerousCapability: SupportNone, // no package.json / pyproject.toml entry point
		ConditionMCPServerDeclared:            SupportNone, // no package.json / pyproject.toml entry point
		ConditionPromptTemplateInjection:      SupportFull, // datasets tagged `prompt`
	},
	EcoCocoaPods: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportNone, // no standard
		ConditionTyposquat:                  SupportFull, // PR 4: enrolled via curated seed list
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportNone,
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportFull,
		ConditionPublishVelocityAnomaly:     SupportNone, // no per-version publisher metadata
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportNone,
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
		// Wave 2: Podfile parser deferred.
		ConditionGitDependency:           SupportNone,
		ConditionHTTPTarballDependency:   SupportNone,
		ConditionWildcardDependencyRange: SupportNone,
		ConditionBadDependencySemver:     SupportNone,
		// Wave 3: CocoaPods ship source + (often) binary frameworks.
		// NativeBinaryPresent is downgraded to Partial because binary
		// frameworks are the NORM in CocoaPods — firing on every pod
		// would be too noisy to enforce on.
		ConditionUsesEval:            SupportNone, // Swift/ObjC: no runtime eval
		ConditionNetworkAccess:       SupportFull,
		ConditionShellAccess:         SupportFull,
		ConditionFilesystemAccess:    SupportFull,
		ConditionEnvVarAccess:        SupportFull,
		ConditionNativeBinaryPresent: SupportPartial,
		ConditionHighEntropyStrings:  SupportFull,
		ConditionURLStrings:          SupportFull,
		ConditionMinifiedCode:        SupportFull,
		// Wave 4: CocoaPods ship source; RepoStars from podspec
		// source url when github.com.
		ConditionTrivialPackage:        SupportFull,
		ConditionTooManyFiles:          SupportFull,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportPartial,
		ConditionMaintainerAccountAge:  SupportNone,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
	EcoSwift: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull, // via GHSA bridge
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportPartial,
		ConditionHasProvenance:              SupportPartial, // configurable
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportNone,
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportFull,
		ConditionPublishVelocityAnomaly:     SupportNone,    // no per-version publisher metadata
		ConditionLicenseCopyleft:            SupportPartial, // Swift SPDX coverage is incomplete
		ConditionLicenseNonPermissive:       SupportPartial,
		ConditionLicenseExceptionPresent:    SupportPartial,
		ConditionLicenseAmbiguousClassifier: SupportPartial,
		ConditionLicenseUnidentified:        SupportPartial,
		ConditionDeprecatedByMaintainer:     SupportNone,
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
		// Wave 2: Package.swift parser deferred.
		ConditionGitDependency:           SupportNone,
		ConditionHTTPTarballDependency:   SupportNone,
		ConditionWildcardDependencyRange: SupportNone,
		ConditionBadDependencySemver:     SupportNone,
		// Wave 3: Swift packages ship .swift source (when source
		// packages, not binary xcframeworks).
		ConditionUsesEval:            SupportNone,
		ConditionNetworkAccess:       SupportFull,
		ConditionShellAccess:         SupportFull,
		ConditionFilesystemAccess:    SupportFull,
		ConditionEnvVarAccess:        SupportFull,
		ConditionNativeBinaryPresent: SupportFull,
		ConditionHighEntropyStrings:  SupportFull,
		ConditionURLStrings:          SupportFull,
		ConditionMinifiedCode:        SupportFull,
		// Wave 4: Swift ships source (when source packages).
		ConditionTrivialPackage:        SupportFull,
		ConditionTooManyFiles:          SupportFull,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportPartial,
		ConditionMaintainerAccountAge:  SupportNone,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
	EcoDocker: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportNone,
		ConditionVersionAnomaly:             SupportNone, // Docker tags are not semver
		ConditionHasHiddenUnicode:           SupportNone, // PR 7 (layer text-file scan) is a separate PR not yet on this branch
		ConditionPublishVelocityAnomaly:     SupportNone, // no per-version publisher metadata
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportNone,
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
		// Wave 2: Docker images don't express deps as specifiers.
		ConditionGitDependency:           SupportNone,
		ConditionHTTPTarballDependency:   SupportNone,
		ConditionWildcardDependencyRange: SupportNone,
		ConditionBadDependencySemver:     SupportNone,
		// Wave 3: Docker images are binary layers — this scanner
		// family does not walk OCI layers. All None.
		ConditionUsesEval:            SupportNone,
		ConditionNetworkAccess:       SupportNone,
		ConditionShellAccess:         SupportNone,
		ConditionFilesystemAccess:    SupportNone,
		ConditionEnvVarAccess:        SupportNone,
		ConditionNativeBinaryPresent: SupportNone,
		ConditionHighEntropyStrings:  SupportNone,
		ConditionURLStrings:          SupportNone,
		ConditionMinifiedCode:        SupportNone,
		// Wave 4: Docker layers not walked — all None.
		ConditionTrivialPackage:        SupportNone,
		ConditionTooManyFiles:          SupportNone,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportNone,
		ConditionMaintainerAccountAge:  SupportPartial, // Docker Hub user endpoint
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
	EcoAPT: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportPartial,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportNone,
		ConditionCooldown:                   SupportNone, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull, // InRelease → Packages → .deb
		ConditionTyposquat:                  SupportNone, // low-risk
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportNone,
		ConditionVersionAnomaly:             SupportNone, // Debian-style versioning is non-semver
		ConditionHasHiddenUnicode:           SupportNone, // OS-package control files, not source
		ConditionPublishVelocityAnomaly:     SupportNone, // no per-version publisher metadata
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportNone,
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
		// Wave 2: OS packages don't carry manifest-level dep specifiers
		// in the chainsaw-visible request path.
		ConditionGitDependency:           SupportNone,
		ConditionHTTPTarballDependency:   SupportNone,
		ConditionWildcardDependencyRange: SupportNone,
		ConditionBadDependencySemver:     SupportNone,
		// Wave 3: APT packages are binary .deb blobs — source
		// scanners don't apply.
		ConditionUsesEval:            SupportNone,
		ConditionNetworkAccess:       SupportNone,
		ConditionShellAccess:         SupportNone,
		ConditionFilesystemAccess:    SupportNone,
		ConditionEnvVarAccess:        SupportNone,
		ConditionNativeBinaryPresent: SupportNone,
		ConditionHighEntropyStrings:  SupportNone,
		ConditionURLStrings:          SupportNone,
		ConditionMinifiedCode:        SupportNone,
		// Wave 4: OS-package scope out of reach — all None.
		ConditionTrivialPackage:        SupportNone,
		ConditionTooManyFiles:          SupportNone,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportNone,
		ConditionMaintainerAccountAge:  SupportNone,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
	EcoYum: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportPartial,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull, // repomd.xml → primary.xml → .rpm
		ConditionTyposquat:                  SupportNone, // low-risk
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportNone,
		ConditionVersionAnomaly:             SupportNone, // RPM epoch-version-release is non-semver
		ConditionHasHiddenUnicode:           SupportNone, // OS-package control files, not source
		ConditionPublishVelocityAnomaly:     SupportNone, // no per-version publisher metadata
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportNone,
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
		ConditionGitDependency:              SupportNone,
		ConditionHTTPTarballDependency:      SupportNone,
		ConditionWildcardDependencyRange:    SupportNone,
		ConditionBadDependencySemver:        SupportNone,
		// Wave 3: RPM packages are binary — source scanners N/A.
		ConditionUsesEval:            SupportNone,
		ConditionNetworkAccess:       SupportNone,
		ConditionShellAccess:         SupportNone,
		ConditionFilesystemAccess:    SupportNone,
		ConditionEnvVarAccess:        SupportNone,
		ConditionNativeBinaryPresent: SupportNone,
		ConditionHighEntropyStrings:  SupportNone,
		ConditionURLStrings:          SupportNone,
		ConditionMinifiedCode:        SupportNone,
		// Wave 4: OS-package scope out of reach — all None.
		ConditionTrivialPackage:        SupportNone,
		ConditionTooManyFiles:          SupportNone,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportNone,
		ConditionMaintainerAccountAge:  SupportNone,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
	EcoDNF: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportPartial,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionCooldown:                   SupportFull, // same metadata dep as PackageAge (per-version vs per-package release date)
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull, // repomd.xml → primary.xml → .rpm
		ConditionTyposquat:                  SupportNone, // low-risk
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
		ConditionImportTimeExecution:        SupportNone,
		ConditionMaliciousIOC:               SupportFull,
		ConditionBuildRsExecutes:            SupportNone, // build.rs is cargo-only
		ConditionPublisherChanged:           SupportNone,
		ConditionVersionAnomaly:             SupportNone, // RPM epoch-version-release is non-semver
		ConditionHasHiddenUnicode:           SupportNone, // OS-package control files, not source
		ConditionPublishVelocityAnomaly:     SupportNone, // no per-version publisher metadata
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportNone,
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
		ConditionGitDependency:              SupportNone,
		ConditionHTTPTarballDependency:      SupportNone,
		ConditionWildcardDependencyRange:    SupportNone,
		ConditionBadDependencySemver:        SupportNone,
		// Wave 3: RPM packages are binary — source scanners N/A.
		ConditionUsesEval:            SupportNone,
		ConditionNetworkAccess:       SupportNone,
		ConditionShellAccess:         SupportNone,
		ConditionFilesystemAccess:    SupportNone,
		ConditionEnvVarAccess:        SupportNone,
		ConditionNativeBinaryPresent: SupportNone,
		ConditionHighEntropyStrings:  SupportNone,
		ConditionURLStrings:          SupportNone,
		ConditionMinifiedCode:        SupportNone,
		// Wave 4: OS-package scope out of reach — all None.
		ConditionTrivialPackage:        SupportNone,
		ConditionTooManyFiles:          SupportNone,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportNone,
		ConditionMaintainerAccountAge:  SupportNone,
		// AI artifacts (Wave 6).
		ConditionDangerousPickle:              SupportNone,
		ConditionUnsafeSerializationFormat:    SupportNone,
		ConditionModelCardInjection:           SupportNone,
		ConditionAgentToolDangerousCapability: SupportNone,
		ConditionMCPServerDeclared:            SupportNone,
		ConditionPromptTemplateInjection:      SupportNone,
	},
}

// Support returns the support level for an (ecosystem, condition) pair. If
// either key is unknown, SupportFull is returned so unknown ecosystems don't
// surface spurious warnings in the UI.
func Support(ecosystem Ecosystem, condition ConditionType) SupportLevel {
	row, ok := SupportMatrix[ecosystem]
	if !ok {
		return SupportFull
	}
	level, ok := row[condition]
	if !ok {
		return SupportFull
	}
	return level
}

// IsUnsupported is a convenience wrapper returning true only for SupportNone.
// SupportPartial is treated as supported for the "silently inert" check — the
// condition is wired, it just may return empty results.
func IsUnsupported(ecosystem Ecosystem, condition ConditionType) bool {
	return Support(ecosystem, condition) == SupportNone
}

// EcosystemForFormat maps the `internal/repository` format strings (as stored
// on policies via Identifier.TargetPackageRepo → Repository.Format) to matrix
// row keys. Returns "" only for "raw" (no resolver, no package ecosystem) so
// callers can skip it.
//
// Alias folding: "gradle" → EcoMaven (shared maven.NewResolver / POM
// coordinate space), matching bun/yarn → EcoNPM. So a format:gradle repo's
// policies see the maven support row, which is correct — gradle artifacts
// ARE maven artifacts.
func EcosystemForFormat(format string) Ecosystem {
	switch format {
	case "npm", "bun", "yarn":
		return EcoNPM
	case "pip", "pypi":
		return EcoPyPI
	case "maven", "gradle":
		return EcoMaven
	case "pub":
		return EcoPub
	case "cargo":
		return EcoCargo
	case "composer":
		return EcoComposer
	case "rubygems":
		return EcoRubyGems
	case "nuget":
		return EcoNuGet
	case "go", "gomod":
		return EcoGo
	case "huggingface":
		return EcoHuggingFace
	case "cocoapods":
		return EcoCocoaPods
	case "swift":
		return EcoSwift
	case "docker", "oci":
		return EcoDocker
	case "apt":
		return EcoAPT
	case "yum":
		return EcoYum
	case "dnf":
		return EcoDNF
	default:
		return ""
	}
}

// ConditionsUsedBy returns the matrix condition columns that a given policy's
// Conditions struct actually references. Used by the evaluator to decide
// which cells to check for the silent-no-op audit event.
func ConditionsUsedBy(c Conditions) []ConditionType {
	used := make([]ConditionType, 0, 8)
	if c.IsVulnerable != nil || c.CVSSMin != nil || c.CVSSMax != nil {
		used = append(used, ConditionCVE)
	}
	if c.CVSSMin != nil || c.CVSSMax != nil {
		used = append(used, ConditionCVSS)
	}
	if c.EPSSMin != nil || c.EPSSMax != nil {
		used = append(used, ConditionEPSS)
	}
	if c.PackageAge != nil {
		used = append(used, ConditionPackageAge)
	}
	if c.CooldownDays != nil {
		used = append(used, ConditionCooldown)
	}
	if len(c.PackageLicense) > 0 {
		used = append(used, ConditionLicense)
	}
	if c.HasProvenance != nil {
		used = append(used, ConditionHasProvenance)
	}
	if c.IsSuspectedTyposquat != nil {
		used = append(used, ConditionTyposquat)
	}
	if c.IsKnownMalicious != nil {
		used = append(used, ConditionMalwareIndex)
	}
	if len(c.ReservedNamespaces) > 0 {
		used = append(used, ConditionReservedNamespaces)
	}
	if c.HasInstallScript != nil {
		used = append(used, ConditionHasInstallScript)
	}
	if c.InstallScriptFetchesRemote != nil {
		used = append(used, ConditionInstallScriptFetchesRemote)
	}
	// Each of these three has had a ConditionType and 16 SupportMatrix rows
	// since it landed, but no mapping here — so every consumer of
	// ConditionsUsedBy (the policy.rule.skipped audit event, `chainsaw policy
	// lint`, policy preflight) was blind to them.
	if c.ImportTimeExecution != nil {
		used = append(used, ConditionImportTimeExecution)
	}
	if c.MaliciousIOC != nil {
		used = append(used, ConditionMaliciousIOC)
	}
	if c.BuildRsExecutes != nil {
		used = append(used, ConditionBuildRsExecutes)
	}
	if c.PublisherChanged != nil {
		used = append(used, ConditionPublisherChanged)
	}
	if c.VersionAnomaly != nil || len(c.VersionAnomalyKinds) > 0 {
		used = append(used, ConditionVersionAnomaly)
	}
	if c.HasHiddenUnicode != nil || len(c.HiddenUnicodeKinds) > 0 {
		used = append(used, ConditionHasHiddenUnicode)
	}
	// PublishVelocityThreshold24h is a knob on the bool condition; we only
	// attribute the used column to the bool toggle so threshold-only policies
	// (which cannot fire on their own) don't count.
	if c.PublishVelocityAnomaly != nil {
		used = append(used, ConditionPublishVelocityAnomaly)
	}
	if c.LicenseCopyleft != nil {
		used = append(used, ConditionLicenseCopyleft)
	}
	if c.LicenseNonPermissive != nil {
		used = append(used, ConditionLicenseNonPermissive)
	}
	if c.LicenseExceptionPresent != nil {
		used = append(used, ConditionLicenseExceptionPresent)
	}
	if c.LicenseAmbiguousClassifier != nil {
		used = append(used, ConditionLicenseAmbiguousClassifier)
	}
	if c.LicenseUnidentified != nil {
		used = append(used, ConditionLicenseUnidentified)
	}
	if c.DeprecatedByMaintainer != nil {
		used = append(used, ConditionDeprecatedByMaintainer)
	}
	if c.ShrinkwrapPresent != nil {
		used = append(used, ConditionShrinkwrapPresent)
	}
	if c.ManifestConfusion != nil {
		used = append(used, ConditionManifestConfusion)
	}
	if c.GitDependency != nil {
		used = append(used, ConditionGitDependency)
	}
	if c.HTTPTarballDependency != nil {
		used = append(used, ConditionHTTPTarballDependency)
	}
	if c.WildcardDependencyRange != nil {
		used = append(used, ConditionWildcardDependencyRange)
	}
	if c.BadDependencySemver != nil {
		used = append(used, ConditionBadDependencySemver)
	}
	// Wave 3 — Tier-2 source-code scanners.
	if c.UsesEval != nil {
		used = append(used, ConditionUsesEval)
	}
	if c.NetworkAccess != nil {
		used = append(used, ConditionNetworkAccess)
	}
	if c.ShellAccess != nil {
		used = append(used, ConditionShellAccess)
	}
	if c.FilesystemAccess != nil {
		used = append(used, ConditionFilesystemAccess)
	}
	if c.EnvVarAccess != nil {
		used = append(used, ConditionEnvVarAccess)
	}
	if c.NativeBinaryPresent != nil {
		used = append(used, ConditionNativeBinaryPresent)
	}
	if c.HighEntropyStrings != nil {
		used = append(used, ConditionHighEntropyStrings)
	}
	if c.URLStrings != nil {
		used = append(used, ConditionURLStrings)
	}
	if c.MinifiedCode != nil {
		used = append(used, ConditionMinifiedCode)
	}
	// Wave 4 — trivial packages + anomaly counters + RTT signals.
	if c.TrivialPackage != nil {
		used = append(used, ConditionTrivialPackage)
	}
	if c.TooManyFiles != nil {
		used = append(used, ConditionTooManyFiles)
	}
	if c.NonExistentAuthor != nil {
		used = append(used, ConditionNonExistentAuthor)
	}
	if c.FirstTimeCollaborator != nil {
		used = append(used, ConditionFirstTimeCollaborator)
	}
	if c.SuspiciousRepoStars != nil {
		used = append(used, ConditionSuspiciousRepoStars)
	}
	if c.MaintainerAccountAgeDaysMax != nil {
		used = append(used, ConditionMaintainerAccountAge)
	}
	// AI artifacts (Wave 6).
	if c.DangerousPickle != nil {
		used = append(used, ConditionDangerousPickle)
	}
	if c.UnsafeSerializationFormat != nil {
		used = append(used, ConditionUnsafeSerializationFormat)
	}
	if c.ModelCardInjection != nil {
		used = append(used, ConditionModelCardInjection)
	}
	if c.AgentToolDangerousCapability != nil {
		used = append(used, ConditionAgentToolDangerousCapability)
	}
	if c.MCPServerDeclared != nil {
		used = append(used, ConditionMCPServerDeclared)
	}
	if c.PromptTemplateInjection != nil {
		used = append(used, ConditionPromptTemplateInjection)
	}
	// Trust score is a composite signal derived from the others; it doesn't
	// map directly to a matrix column, so we don't check it here.
	return dedupeConditions(used)
}

func dedupeConditions(in []ConditionType) []ConditionType {
	if len(in) <= 1 {
		return in
	}
	seen := make(map[ConditionType]struct{}, len(in))
	out := make([]ConditionType, 0, len(in))
	for _, c := range in {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}
