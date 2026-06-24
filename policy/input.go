package policy

import (
	"encoding/json"
	"strings"
	"time"
)

// SurfaceTag identifies the enforcement surface evaluating a policy.
// Authors can write `input.surface == "pr"` in Rego to scope rules.
// The same value is what policyengine.Decide stamps on the input
// before invoking the DSL — every surface produces the same shape;
// only this string differs.
type SurfaceTag string

const (
	SurfacePR      SurfaceTag = "pr"      // GitHub-Actions PR check
	SurfaceProxy   SurfaceTag = "proxy"   // registry proxy fetch
	SurfacePublish SurfaceTag = "publish" // pre-publish gate
	SurfacePromote SurfaceTag = "promote" // env→env promotion gate
	SurfaceDeploy  SurfaceTag = "deploy"  // k8s admission webhook
	SurfaceRuntime SurfaceTag = "runtime" // package-manager install hook
)

// AllSurfaces enumerates every supported enforcement surface in a
// stable order. Useful for the demo "fire one rule on six places"
// matrix and for round-trip tests.
func AllSurfaces() []SurfaceTag {
	return []SurfaceTag{
		SurfacePR,
		SurfaceProxy,
		SurfacePublish,
		SurfacePromote,
		SurfaceDeploy,
		SurfaceRuntime,
	}
}

// Input is the canonical JSON document fed to the OPA engine. Every
// surface produces this shape — missing fields stay zero-valued. The
// JSON tags here ARE the contract: changes need a corresponding bump
// to `schema/input.schema.json` and any in-tree Rego rules.
//
// Field naming follows the `EvaluationContext` source-of-truth in
// evaluator.go but is written in lowerCamelCase so Rego authors don't
// have to remember Go conventions. MarshalInput translates between
// the two — Go callers keep using EvaluationContext, Rego authors
// see clean idiomatic keys.
type Input struct {
	// Surface is "pr"|"proxy"|"publish"|"promote"|"deploy"|"runtime".
	Surface SurfaceTag `json:"surface"`

	// Identity coordinates.
	Repository       string `json:"repository,omitempty"`
	RepositoryFormat string `json:"ecosystem,omitempty"`
	PackageName      string `json:"package,omitempty"`
	PackageVersion   string `json:"version,omitempty"`

	// Caller / network identity.
	ClientID          string   `json:"clientId,omitempty"`
	ClientGroups      []string `json:"clientGroups,omitempty"`
	RequestingIP      string   `json:"requestingIp,omitempty"`
	RequestingCountry string   `json:"requestingCountry,omitempty"`

	// Package metadata.
	IsInternal         bool     `json:"isInternal,omitempty"`
	PackageReleaseDate string   `json:"releaseDate,omitempty"` // RFC3339 or empty
	LicenseSPDX        string   `json:"licenseSpdx,omitempty"`
	LicenseTags        []string `json:"licenseTags,omitempty"`

	// Vulnerability metadata.
	IsVulnerable bool     `json:"isVulnerable,omitempty"`
	CVSSScore    float64  `json:"cvss,omitempty"`
	EPSSScore    float64  `json:"epss,omitempty"`
	CVEs         []string `json:"cves,omitempty"`

	// Supply-chain integrity metadata.
	HasProvenance        bool   `json:"hasProvenance,omitempty"`
	ProvenanceStatus     string `json:"provenanceStatus,omitempty"`
	IsSuspectedTyposquat bool   `json:"isSuspectedTyposquat,omitempty"`
	IsKnownMalicious     bool   `json:"isKnownMalicious,omitempty"`
	TrustScore           int    `json:"trustScore,omitempty"`
	PublisherChanged     bool   `json:"publisherChanged,omitempty"`

	// Attestation context (SLSA / Sigstore).
	SLSALevel                  int    `json:"slsaLevel,omitempty"`
	AttestationBuilderID       string `json:"attestationBuilderId,omitempty"`
	AttestationIssuer          string `json:"attestationIssuer,omitempty"`
	AttestationSourceRepo      string `json:"attestationSourceRepo,omitempty"`
	AttestationTransparencyLog string `json:"attestationTransparencyLog,omitempty"`
	AttestationCacheStale      bool   `json:"attestationCacheStale,omitempty"`

	// Install-script signals.
	HasInstallScript           bool `json:"hasInstallScript,omitempty"`
	InstallScriptFetchesRemote bool `json:"installScriptFetchesRemote,omitempty"`

	// Version anomaly.
	VersionAnomaly      bool     `json:"versionAnomaly,omitempty"`
	VersionAnomalyFlags []string `json:"versionAnomalyFlags,omitempty"`

	// Hidden Unicode.
	HasHiddenUnicode   bool     `json:"hasHiddenUnicode,omitempty"`
	HiddenUnicodeKinds []string `json:"hiddenUnicodeKinds,omitempty"`

	// Publish velocity.
	PublishVelocity24h int `json:"publishVelocity24h,omitempty"`

	// Wave 1 — license / yanked / shrinkwrap / manifest confusion.
	DeprecatedByMaintainer bool `json:"deprecatedByMaintainer,omitempty"`
	ShrinkwrapPresent      bool `json:"shrinkwrapPresent,omitempty"`
	ManifestConfusion      bool `json:"manifestConfusion,omitempty"`

	// Wave 2 — manifest hygiene.
	GitDependency           bool `json:"gitDependency,omitempty"`
	HTTPTarballDependency   bool `json:"httpTarballDependency,omitempty"`
	WildcardDependencyRange bool `json:"wildcardDependencyRange,omitempty"`
	BadDependencySemver     bool `json:"badDependencySemver,omitempty"`

	// Wave 3 — code-smell scanners.
	UsesEval            bool `json:"usesEval,omitempty"`
	NetworkAccess       bool `json:"networkAccess,omitempty"`
	ShellAccess         bool `json:"shellAccess,omitempty"`
	FilesystemAccess    bool `json:"filesystemAccess,omitempty"`
	EnvVarAccess        bool `json:"envVarAccess,omitempty"`
	NativeBinaryPresent bool `json:"nativeBinaryPresent,omitempty"`
	HighEntropyStrings  bool `json:"highEntropyStrings,omitempty"`
	URLStrings          bool `json:"urlStrings,omitempty"`
	MinifiedCode        bool `json:"minifiedCode,omitempty"`

	// Wave 4.
	TrivialPackage    bool `json:"trivialPackage,omitempty"`
	TooManyFiles      bool `json:"tooManyFiles,omitempty"`
	NonExistentAuthor bool `json:"nonExistentAuthor,omitempty"`
	// FirstTimeCollaborator is *bool to preserve three-state at the
	// policy/Rego boundary. nil → field omitted from JSON (rules can't
	// match an unknown via plain equality); &true / &false serialize
	// as the literal boolean.
	FirstTimeCollaborator    *bool `json:"firstTimeCollaborator,omitempty"`
	SuspiciousRepoStars      bool  `json:"suspiciousRepoStars,omitempty"`
	MaintainerAccountAgeDays int   `json:"maintainerAccountAgeDays,omitempty"`

	// AI artifact signals.
	ArtifactSubtype              string `json:"artifactSubtype,omitempty"`
	DangerousPickle              bool   `json:"dangerousPickle,omitempty"`
	UnsafeSerializationFormat    bool   `json:"unsafeSerializationFormat,omitempty"`
	ModelCardInjection           bool   `json:"modelCardInjection,omitempty"`
	AgentToolDangerousCapability bool   `json:"agentToolDangerousCapability,omitempty"`
	MCPServerDeclared            bool   `json:"mcpServerDeclared,omitempty"`
	PromptTemplateInjection      bool   `json:"promptTemplateInjection,omitempty"`

	ChecksumUnavailable bool `json:"checksumUnavailable,omitempty"`
}

// MarshalInput projects an EvaluationContext + surface tag onto the
// canonical OPA input shape and JSON-encodes it. Used by both the
// chainsaw policy facade (live decisions) and the `chainsaw policy
// eval` CLI (offline rule authoring).
func MarshalInput(surface SurfaceTag, ctx EvaluationContext) ([]byte, error) {
	in := ContextToInput(surface, ctx)
	return json.Marshal(in)
}

// ContextToInput is the pure-data projection used by MarshalInput.
// Exposed so the dsl package can hand the typed struct directly to
// OPA via rego.EvalInput rather than going round-trip through JSON.
func ContextToInput(surface SurfaceTag, ctx EvaluationContext) Input {
	releaseDate := ""
	if ctx.PackageReleaseDate != nil && !ctx.PackageReleaseDate.IsZero() {
		releaseDate = ctx.PackageReleaseDate.UTC().Format(time.RFC3339)
	}
	return Input{
		Surface:                      surface,
		Repository:                   ctx.Repository,
		RepositoryFormat:             strings.ToLower(ctx.RepositoryFormat),
		PackageName:                  ctx.PackageName,
		PackageVersion:               ctx.PackageVersion,
		ClientID:                     ctx.ClientID,
		ClientGroups:                 ctx.ClientGroups,
		RequestingIP:                 ctx.RequestingIP,
		RequestingCountry:            ctx.RequestingCountry,
		IsInternal:                   ctx.IsInternalPackage,
		PackageReleaseDate:           releaseDate,
		LicenseSPDX:                  ctx.LicenseSPDX,
		LicenseTags:                  ctx.LicenseTags,
		IsVulnerable:                 ctx.IsVulnerable,
		CVSSScore:                    ctx.CVSSScore,
		EPSSScore:                    ctx.EPSSScore,
		CVEs:                         ctx.CVEs,
		HasProvenance:                ctx.HasProvenance,
		ProvenanceStatus:             ctx.ProvenanceStatus,
		IsSuspectedTyposquat:         ctx.IsSuspectedTyposquat,
		IsKnownMalicious:             ctx.IsKnownMalicious,
		TrustScore:                   ctx.TrustScore,
		PublisherChanged:             ctx.PublisherChanged,
		SLSALevel:                    ctx.SLSALevel,
		AttestationBuilderID:         ctx.AttestationBuilderID,
		AttestationIssuer:            ctx.AttestationIssuer,
		AttestationSourceRepo:        ctx.AttestationSourceRepo,
		AttestationTransparencyLog:   ctx.AttestationTransparencyLog,
		AttestationCacheStale:        ctx.AttestationCacheStale,
		HasInstallScript:             ctx.HasInstallScript,
		InstallScriptFetchesRemote:   ctx.InstallScriptFetchesRemote,
		VersionAnomaly:               ctx.VersionAnomaly,
		VersionAnomalyFlags:          ctx.VersionAnomalyFlags,
		HasHiddenUnicode:             ctx.HasHiddenUnicode,
		HiddenUnicodeKinds:           ctx.HiddenUnicodeKinds,
		PublishVelocity24h:           ctx.PublishVelocity24h,
		DeprecatedByMaintainer:       ctx.DeprecatedByMaintainer,
		ShrinkwrapPresent:            ctx.ShrinkwrapPresent,
		ManifestConfusion:            ctx.ManifestConfusion,
		GitDependency:                ctx.GitDependency,
		HTTPTarballDependency:        ctx.HTTPTarballDependency,
		WildcardDependencyRange:      ctx.WildcardDependencyRange,
		BadDependencySemver:          ctx.BadDependencySemver,
		UsesEval:                     ctx.UsesEval,
		NetworkAccess:                ctx.NetworkAccess,
		ShellAccess:                  ctx.ShellAccess,
		FilesystemAccess:             ctx.FilesystemAccess,
		EnvVarAccess:                 ctx.EnvVarAccess,
		NativeBinaryPresent:          ctx.NativeBinaryPresent,
		HighEntropyStrings:           ctx.HighEntropyStrings,
		URLStrings:                   ctx.URLStrings,
		MinifiedCode:                 ctx.MinifiedCode,
		TrivialPackage:               ctx.TrivialPackage,
		TooManyFiles:                 ctx.TooManyFiles,
		NonExistentAuthor:            ctx.NonExistentAuthor,
		FirstTimeCollaborator:        ctx.FirstTimeCollaborator,
		SuspiciousRepoStars:          ctx.SuspiciousRepoStars,
		MaintainerAccountAgeDays:     ctx.MaintainerAccountAgeDays,
		ArtifactSubtype:              ctx.ArtifactSubtype,
		DangerousPickle:              ctx.DangerousPickle,
		UnsafeSerializationFormat:    ctx.UnsafeSerializationFormat,
		ModelCardInjection:           ctx.ModelCardInjection,
		AgentToolDangerousCapability: ctx.AgentToolDangerousCapability,
		MCPServerDeclared:            ctx.MCPServerDeclared,
		PromptTemplateInjection:      ctx.PromptTemplateInjection,
		ChecksumUnavailable:          ctx.ChecksumUnavailable,
	}
}
