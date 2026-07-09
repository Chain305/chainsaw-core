// Package supplychain holds the legacy supply-chain check result type
// and ancillary helpers that survive Phase D's orchestrator retirement.
//
// CheckResult is the long-lived contract between the proxy hot path and
// the policy evaluator — it's the shape the evaluator reads when
// deciding whether a request flows. Post-Phase-D, this type is produced
// by projecting intelligence.Report.SupplyChain / .Scan / .Vulnerabilities
// via Report.ToLegacyCheckResult (internal/intelligence/adapters.go).
// The orchestrator struct that used to produce it has been retired.
package supplychain

import "github.com/chain305/chainsaw-core/trustscore"

// CheckResult captures the outcome of the synchronous supply-chain
// checks for a single package version. Consumed by the policy evaluator
// and the audit/BOM emitters.
type CheckResult struct {
	// Malware check result.
	IsKnownMalicious bool
	MalwareID        string
	MalwareSummary   string

	// Typosquat detection result.
	IsSuspectedTyposquat bool
	TyposquatConfidence  string
	TyposquatSimilarTo   string

	// Install-script static-scan result (populated when an install-
	// script classification is available from the persisted metadata
	// store, or when ScanArtifact is invoked inline).
	HasInstallScript           bool
	InstallScriptFetchesRemote bool
	// ImportTimeExecution: Python package runs malicious behavior at
	// import/install time (pysource provider). PyPI-only.
	ImportTimeExecution bool
	// MaliciousIOC: source embeds an exfil sink host or a coupled stealer
	// string (iocscan provider). Cross-ecosystem.
	MaliciousIOC bool
	// InstallScriptKind is the text enum persisted to
	// package_metadata.install_script_kind — one of
	// "none" | "present" | "fetches_remote" | "eval_encoded" |
	// "mutates_dependency" | "" (unscanned).
	InstallScriptKind string

	// PublisherChanged is true when the incoming version's publisher set
	// differs from the most recent prior version's persisted set. Empty
	// diffs, first-seen packages, and ecosystems without extractors leave
	// this false (silent no-op).
	PublisherChanged bool
	// PublisherSetAdded and PublisherSetRemoved are populated when
	// PublisherChanged is true — persisted for audit / UI surfaces.
	PublisherSetAdded   []string
	PublisherSetRemoved []string

	// Version anomaly. VersionAnomaly is true iff VersionAnomalyFlags
	// is non-empty. Flags come from metadiff.VersionSequenceFlags —
	// one or more of "semver_regression", "major_skip",
	// "timestamp_regression".
	VersionAnomaly      bool
	VersionAnomalyFlags []string

	// Hidden-Unicode scanner result. HiddenUnicodeHits is the total
	// suspect-rune count across the artifact's text files;
	// HasHiddenUnicode is true when it meets or exceeds
	// CHAINSAW_HIDDEN_UNICODE_THRESHOLD. HiddenUnicodeKinds is the
	// deduplicated, sorted union of detected kinds (subset of
	// {"zero_width","bidi_override","tag"}).
	HasHiddenUnicode   bool
	HiddenUnicodeHits  int
	HiddenUnicodeKinds []string

	// SignalBag carries the full signal bundle for downstream reporting
	// (BOM entries, etc.) so callers don't each have to reach into the
	// underlying scanner state to reconstruct them.
	SignalBag map[string]any

	// Trust score (sync portion only).
	TrustScore trustscore.Score

	// PublishVelocity24h is the trailing-24h count of versions published
	// by any publisher overlapping the incoming version's publisher set.
	// Zero when unknown.
	PublishVelocity24h int
}

// Signals returns a flat map of boolean supply-chain signals. Callers
// use this for structured logging / audit events so they don't have to
// keep re-deriving the same booleans from the richer fields. Keys match
// the JSON field names on policy.Conditions so log entries can be
// correlated with matched rules.
func (r CheckResult) Signals() map[string]bool {
	return map[string]bool{
		"isKnownMalicious":           r.IsKnownMalicious,
		"isSuspectedTyposquat":       r.IsSuspectedTyposquat,
		"hasInstallScript":           r.HasInstallScript,
		"installScriptFetchesRemote": r.InstallScriptFetchesRemote,
		"importTimeExecution":        r.ImportTimeExecution,
		"maliciousIOC":               r.MaliciousIOC,
		"publisherChanged":           r.PublisherChanged,
	}
}

// VersionAnomalyHistoryDepth is the number of prior versions the version
// anomaly check inspects when building its input sequence. Five is a
// comfortable upper bound: enough to catch a backdating attack even when
// the attacker spreads it across a couple of decoy releases, small
// enough that the Postgres read stays sub-millisecond.
const VersionAnomalyHistoryDepth = 5

// InstallScriptFiles bundles the raw file bodies the install-script
// detector needs, one per supported ecosystem. Kept in the supplychain
// package (as opposed to moved to internal/installscripts) because the
// proxy's artifact-walker in internal/server/artifact_inspection.go
// populates this shape before handing it off to the install-script
// scanner, and that walker is legacy code we don't want to churn.
type InstallScriptFiles struct {
	// npm
	PackageJSON []byte
	// pip
	SetupPy       []byte
	PyprojectToml []byte
	// rubygems
	Gemspec []byte
	// cargo
	CargoToml []byte
	BuildRS   []byte
	// composer
	ComposerJSON []byte
}
