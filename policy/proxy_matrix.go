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
	ConditionScorecard                  ConditionType = "Scorecard"
	ConditionMalwareIndex               ConditionType = "MalwareIndex"
	ConditionEPSS                       ConditionType = "EPSS"
	ConditionCVE                        ConditionType = "CVE"
	ConditionPackageAge                 ConditionType = "PackageAge"
	ConditionLicense                    ConditionType = "License"
	ConditionHasProvenance              ConditionType = "HasProvenance"
	ConditionTyposquat                  ConditionType = "Typosquat"
	ConditionCVSS                       ConditionType = "CVSS"
	ConditionReservedNamespaces         ConditionType = "ReservedNamespaces"
	ConditionHasInstallScript           ConditionType = "HasInstallScript"
	ConditionInstallScriptFetchesRemote ConditionType = "InstallScriptFetchesRemote"
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
		ConditionLicense,
		ConditionHasProvenance,
		ConditionTyposquat,
		ConditionCVSS,
		ConditionReservedNamespaces,
		ConditionHasInstallScript,
		ConditionInstallScriptFetchesRemote,
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
		// NOTE: ConditionMaintainerAccountAge is intentionally NOT in
		// AllConditions(). It is a numeric-threshold condition rather
		// than a boolean signal column, so the per-ecosystem support
		// matrix and POLICY_PROXY_MATRIX.md cells do not apply. The
		// constant exists for ConditionsUsedBy() / DSL telemetry only.
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
	EcoGradle      Ecosystem = "gradle"
	EcoCargo       Ecosystem = "cargo"
	EcoComposer    Ecosystem = "composer"
	EcoRubyGems    Ecosystem = "rubygems"
	EcoNuGet       Ecosystem = "nuget"
	EcoGo          Ecosystem = "go"
	EcoHuggingFace Ecosystem = "huggingface"
	EcoCocoaPods   Ecosystem = "cocoapods"
	EcoSwift       Ecosystem = "swift"
	EcoDocker      Ecosystem = "docker"
	EcoAPT         Ecosystem = "apt"
	EcoYum         Ecosystem = "yum"
	EcoDNF         Ecosystem = "dnf"
)

// AllEcosystems returns every matrix row in the stable order used by the
// markdown, so drift tests can compare table ordering directly.
func AllEcosystems() []Ecosystem {
	return []Ecosystem{
		EcoNPM,
		EcoPyPI,
		EcoMaven,
		EcoGradle,
		EcoCargo,
		EcoComposer,
		EcoRubyGems,
		EcoNuGet,
		EcoGo,
		EcoHuggingFace,
		EcoCocoaPods,
		EcoSwift,
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
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportFull,
		ConditionInstallScriptFetchesRemote: SupportFull,
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
	},
	EcoPyPI: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportFull,
		ConditionInstallScriptFetchesRemote: SupportFull,
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
		ConditionShrinkwrapPresent:          SupportNone, // npm-only concept
		ConditionManifestConfusion:          SupportNone, // npm-only
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
		// release uploader field — FirstTimeCollaborator is ❌.
		ConditionTrivialPackage:        SupportFull,
		ConditionTooManyFiles:          SupportFull,
		ConditionNonExistentAuthor:     SupportPartial,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportPartial,
	},
	EcoMaven: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone, // no lifecycle-script concept
		ConditionInstallScriptFetchesRemote: SupportNone,
		ConditionPublisherChanged:           SupportFull, // developers[].id / email
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
		ConditionTrivialPackage:        SupportPartial,
		ConditionTooManyFiles:          SupportFull,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportPartial,
	},
	EcoGradle: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone, // no lifecycle-script concept
		ConditionInstallScriptFetchesRemote: SupportNone,
		ConditionPublisherChanged:           SupportFull, // POM developers[].id / email
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportFull,
		ConditionPublishVelocityAnomaly:     SupportPartial, // developer IDs not always populated
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportNone,
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
		// Wave 2: gradle build files are Groovy/Kotlin DSL; we don't
		// parse them here. Gradle projects that publish poms go through
		// the Maven path — same Partial classification.
		ConditionGitDependency:           SupportNone,
		ConditionHTTPTarballDependency:   SupportNone,
		ConditionWildcardDependencyRange: SupportPartial,
		ConditionBadDependencySemver:     SupportPartial,
		// Wave 3: same Partial pattern as Maven — jar artifacts
		// carry .class rather than source; source scanners only
		// fire on the occasional -sources.jar.
		ConditionUsesEval:            SupportPartial,
		ConditionNetworkAccess:       SupportPartial,
		ConditionShellAccess:         SupportPartial,
		ConditionFilesystemAccess:    SupportPartial,
		ConditionEnvVarAccess:        SupportPartial,
		ConditionNativeBinaryPresent: SupportFull,
		ConditionHighEntropyStrings:  SupportPartial,
		ConditionURLStrings:          SupportPartial,
		ConditionMinifiedCode:        SupportPartial,
		// Wave 4: same Partial pattern as Maven for TrivialPackage;
		// TooManyFiles works over archive contents.
		ConditionTrivialPackage:        SupportPartial,
		ConditionTooManyFiles:          SupportFull,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportPartial,
	},
	EcoCargo: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportNone, // no standard
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportFull,
		ConditionInstallScriptFetchesRemote: SupportFull,
		ConditionPublisherChanged:           SupportNone, // not extracted in PR 2
		ConditionVersionAnomaly:             SupportFull,
		ConditionHasHiddenUnicode:           SupportFull,
		ConditionPublishVelocityAnomaly:     SupportNone, // no per-version publisher metadata
		ConditionLicenseCopyleft:            SupportFull,
		ConditionLicenseNonPermissive:       SupportFull,
		ConditionLicenseExceptionPresent:    SupportFull,
		ConditionLicenseAmbiguousClassifier: SupportFull,
		ConditionLicenseUnidentified:        SupportFull,
		ConditionDeprecatedByMaintainer:     SupportFull, // crate version "yanked"
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
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
	},
	EcoComposer: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportNone, // no standard
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportFull,
		ConditionInstallScriptFetchesRemote: SupportFull,
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
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
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
	},
	EcoRubyGems: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportFull,
		ConditionInstallScriptFetchesRemote: SupportFull,
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
		ConditionShrinkwrapPresent:          SupportNone,
		ConditionManifestConfusion:          SupportNone,
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
	},
	EcoNuGet: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone, // no lifecycle-script concept
		ConditionInstallScriptFetchesRemote: SupportNone,
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
		ConditionTrivialPackage:        SupportPartial,
		ConditionTooManyFiles:          SupportFull,
		ConditionNonExistentAuthor:     SupportNone,
		ConditionFirstTimeCollaborator: SupportNone,
		ConditionSuspiciousRepoStars:   SupportPartial,
	},
	EcoGo: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull, // PR 4: enrolled via curated seed list
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone, // no lifecycle-script concept
		ConditionInstallScriptFetchesRemote: SupportNone,
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
	},
	EcoHuggingFace: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
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
	},
	EcoCocoaPods: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportNone, // no standard
		ConditionTyposquat:                  SupportFull, // PR 4: enrolled via curated seed list
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
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
	},
	EcoSwift: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull, // via GHSA bridge
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportPartial,
		ConditionHasProvenance:              SupportPartial, // configurable
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
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
	},
	EcoDocker: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportFull,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull,
		ConditionTyposquat:                  SupportFull,
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
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
	},
	EcoAPT: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportPartial,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportNone,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull, // InRelease → Packages → .deb
		ConditionTyposquat:                  SupportNone, // low-risk
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
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
	},
	EcoYum: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportPartial,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull, // repomd.xml → primary.xml → .rpm
		ConditionTyposquat:                  SupportNone, // low-risk
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
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
	},
	EcoDNF: {
		ConditionScorecard:                  SupportNone,
		ConditionMalwareIndex:               SupportPartial,
		ConditionEPSS:                       SupportFull,
		ConditionCVE:                        SupportFull,
		ConditionPackageAge:                 SupportFull,
		ConditionLicense:                    SupportFull,
		ConditionHasProvenance:              SupportFull, // repomd.xml → primary.xml → .rpm
		ConditionTyposquat:                  SupportNone, // low-risk
		ConditionCVSS:                       SupportFull,
		ConditionReservedNamespaces:         SupportFull,
		ConditionHasInstallScript:           SupportNone,
		ConditionInstallScriptFetchesRemote: SupportNone,
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
// row keys. Returns "" for formats that don't participate in the matrix
// (raw, bun, yarn) so callers can skip them.
func EcosystemForFormat(format string) Ecosystem {
	switch format {
	case "npm":
		return EcoNPM
	case "pip", "pypi":
		return EcoPyPI
	case "maven":
		return EcoMaven
	case "gradle":
		return EcoGradle
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
