// Package trustscore is the LEGACY single-integer trust-score implementation.
//
// Compute() and the Breakdown JSON it produces are retained ONLY for the
// per-signal explanation that the UI and audit-log render line-by-line.
// They are NOT authoritative for SupplyChain.TrustScore — internal/risk
// (Risk-V2) is. Do not consume Compute()'s integer Total for policy /
// risk decisions; read it through risk.Evaluation.RolledUp.Overall (which
// is what intelligence.ComputeTrustScore writes into the score field) or
// from SupplyChain.TrustScore directly.
//
// The Breakdown shape is a stable contract: downstream consumers parse the
// per-signal integers (malwareCheck, vulnStatus, ...) for display. Adding
// fields is fine; renaming or removing them is not without a migration.
package trustscore

import (
	"encoding/json"
	"time"
)

// Score represents a composite trust score for a package version.
type Score struct {
	// Total is the aggregate score (0-100). -100 = known malicious.
	Total int `json:"total"`
	// Breakdown shows per-signal contributions.
	Breakdown Breakdown `json:"breakdown"`
	// ComputedAt is when the score was calculated.
	ComputedAt time.Time `json:"computedAt"`
	// IsComplete is true when all signals (including async) have been computed.
	IsComplete bool `json:"isComplete"`
}

// Breakdown shows the contribution of each signal to the trust score.
type Breakdown struct {
	MalwareCheck int `json:"malwareCheck"` // 0 or -100
	VulnStatus   int `json:"vulnStatus"`   // 0 to +20
	// Provenance is the legacy "verified attestation" delta (+25).
	// Populated only when AttestationFirst is false. When
	// AttestationFirst is true this stays 0 and AttestationBase /
	// SLSALevelBonus carry the contribution instead.
	Provenance int `json:"provenance"` // 0 or +25 (legacy mode)
	// AttestationBase is the substrate base contribution under the
	// attestation-first reframe: +70 when the package has a verified
	// attestation (any SLSA level), +30 when it doesn't. Populated
	// only when Signals.AttestationFirst is true. The 40-point gap
	// shifts provenance from "tiebreaker" to "primary trust control".
	AttestationBase int `json:"attestationBase,omitempty"`
	// SLSALevelBonus rewards higher SLSA build levels on top of
	// AttestationBase: L1=+0, L2=+5, L3=+10, L4=+15. Populated only
	// when Signals.AttestationFirst is true and the package has a
	// verified attestation with a known level.
	SLSALevelBonus    int `json:"slsaLevelBonus,omitempty"`
	LicenseCompliance int `json:"licenseCompliance"` // 0 or +10
	PackageAge        int `json:"packageAge"`        // 0 or +10
	TyposquatCheck    int `json:"typosquatCheck"`    // -30 to +10
	// SourceRepo combines the legacy "source repo present" bit with the
	// PR 11 repo-liveness classification: +10 ok, 0 unknown/no repo,
	// -10 archived/missing, -20 ownership_mismatch. RepoLinkStatus on
	// Signals drives the signed value; absent a status the factor falls
	// back to the legacy +10/0 behaviour so downstream callers that
	// haven't wired the enricher continue to see the same number.
	SourceRepo       int `json:"sourceRepo"`
	VersionCount     int `json:"versionCount"`     // 0 or +10
	ChecksumVerified int `json:"checksumVerified"` // 0 or +5
	// SignatureVerified is the upstream-signature bonus, separate from
	// ChecksumVerified. ChecksumVerified only proves the bytes match
	// the registry's declared digest (a bit-flip check — both halves
	// come from the attacker-controlled registry). SignatureVerified
	// reflects a real cryptographic verification (sigstore today; PGP
	// TODO) against an independent trust root. +5 when verified, 0
	// otherwise. No penalty for "false" — that's a separate signal
	// path and would double-count with provenance.
	SignatureVerified int `json:"signatureVerified"` // 0 or +5
	// RepoLinkStatus echoes the classification that produced the
	// SourceRepo delta so UI breakdowns and audits can display it
	// without re-reading metadata. Empty when the enricher hasn't run.
	RepoLinkStatus string `json:"repoLinkStatus,omitempty"`
	// InstallScript: additive penalty for a lifecycle script.
	// -5 for hasInstallScript, -20 for installScriptFetchesRemote
	// (fetches_remote wins over hasInstallScript — they're not
	// double-counted; the total is clamped at -20 on the install-script
	// axis).
	InstallScript          int `json:"installScript"`          // 0 to -25
	ImportTimeExecution    int `json:"importTimeExecution"`    // 0 or -30 (PyPI import-time malicious exec)
	MaliciousIOC           int `json:"maliciousIoc"`           // 0 or -30 (embedded exfil host / coupled stealer string)
	PublisherChanged       int `json:"publisherChanged"`       // 0 or -25 (account-takeover signal)
	VersionAnomaly         int `json:"versionAnomaly"`         // 0 to -30 (−15 per flag, capped)
	HiddenUnicode          int `json:"hiddenUnicode"`          // 0 or -20 (PR 8)
	PublishVelocityAnomaly int `json:"publishVelocityAnomaly"` // 0 or -20 (default threshold)
	// KnownExploitedCVE: -25 when at least one of the package's CVEs
	// appears in the CISA KEV catalog (provider_kev). Pairs additively
	// with VulnStatus rather than replacing it, so a known-exploited
	// vulnerability is materially worse than an unexploited one of the
	// same CVSS.
	KnownExploitedCVE int `json:"knownExploitedCVE"` // 0 or -25
	// DangerousPickleOpcode: -30 when PickleScan flagged a code-exec
	// gadget (REDUCE/GLOBAL with dangerous targets) in a model artifact.
	// Heaviest of the AI-artifact penalties because the gadget executes
	// on load.
	DangerousPickleOpcode int `json:"dangerousPickleOpcode"` // 0 or -30
	// ModelCardInjection: -10 when the model card text contains
	// prompt-injection markers. Smaller than the other AI penalties
	// because injection isn't direct compromise — it's a downstream
	// risk to anyone who feeds the card to an LLM.
	ModelCardInjection int `json:"modelCardInjection"` // 0 or -10
	// AgentToolDangerousCapability: -15 when an MCP server manifest
	// claims dangerous capabilities (file_write / shell / code_exec /
	// network) without verified provenance.
	AgentToolDangerousCapability int `json:"agentToolDangerousCapability"` // 0 or -15
	// TyposquatOwnBytesCoupling: -20 when the package is BOTH a suspected
	// typosquat AND trips at least one own-bytes signal (install-script /
	// import-time exec / malicious IOC / hidden-unicode). The conjunction
	// is a far stronger verdict than either alone — a name-confusion
	// candidate that also ships a suspicious payload is near-certainly a
	// dependency-confusion / typosquat attack, not a coincidence. The extra
	// penalty pushes the coupled case below the block line even when the
	// individual signals are individually mild (detection-roadmap item 2).
	TyposquatOwnBytesCoupling int `json:"typosquatOwnBytesCoupling"` // 0 or -20
}

// BreakdownJSON returns the breakdown as a JSON string suitable for DB storage.
func (s Score) BreakdownJSON() string {
	b, _ := json.Marshal(s.Breakdown)
	return string(b)
}

// Signals captures the input data used to compute a trust score.
type Signals struct {
	// Sync signals — available immediately on cache miss.
	IsKnownMalicious     bool
	IsVulnerable         bool
	MaxCVSS              float64 // 0-10
	LicenseSPDX          string  // empty = unknown
	VersionReleaseDate   *time.Time
	IsSuspectedTyposquat bool
	TyposquatConfidence  string // "high", "medium", "low"
	ChecksumVerified     bool
	// SignatureVerified is the upstream-signature verdict projected
	// from Provenance by provider_signature_verify.go. true awards a
	// +5 bonus on top of any ChecksumVerified bonus. false / unknown
	// awards nothing — the latter is the common case for ecosystems
	// without provenance support today.
	SignatureVerified bool

	// Install-script signals — additive penalty.
	HasInstallScript           bool
	InstallScriptFetchesRemote bool

	// ImportTimeExecution flags a Python package that runs malicious behavior
	// at import/install time (top-level obfuscated decode-and-exec, import-time
	// credential exfil, or a download-and-execute top-level shell). High-
	// confidence-malicious; carries a heavy own-bytes penalty.
	ImportTimeExecution bool

	// ImportTimeKind is the dominant import-time shape the pysource detector
	// reported (e.g. "obfuscated_exec", "import_time_exfil", "top_level_shell").
	// The scorer reads it to apply a LIGHTER penalty to the advisory
	// "obfuscated_exec_bare" kind — a bare decode-and-exec with no send/recon/
	// harvest/exfil co-marker, the legitimate plugin/bytecode-loader shape —
	// so that signal alone does not drive a package below the block line
	// (detection-roadmap item 3). Empty preserves the full penalty.
	ImportTimeKind string

	// MaliciousIOC flags a package whose source embeds a high-confidence
	// indicator of compromise (an exfil sink host — Discord/Telegram/Slack
	// webhook, paste/anon-file drop, tunnel, OOB host — or a stealer string
	// coupled with a network send). Near-certain malware; heavy penalty.
	MaliciousIOC bool

	// PublishVelocityAnomaly flags a version whose publisher set pushed more
	// than the default 20 versions in the trailing 24h — Shai-Hulud style
	// worm tell. A dedicated bool keeps the trust-score package decoupled
	// from the policy package's threshold constant; the caller (orchestrator
	// or pipeline) computes the bool using its own threshold of record.
	PublishVelocityAnomaly bool

	// Async signals — filled in by background enrichment.
	HasProvenance    bool
	ProvenanceStatus string // "verified", "missing", etc.
	// SLSALevel is the SLSA build level (1-4) the verified attestation
	// claims, or 0 when no level is known. Used by the
	// attestation-first scoring reframe to award an extra bonus on top
	// of the substrate base. Ignored when AttestationFirst is false.
	SLSALevel int
	// AttestationFirst, when true, switches Compute to the SLSA-substrate
	// reframe: base 70 with verified attestation vs. base 30 without,
	// plus a per-level bonus. When false (default), Compute uses the
	// legacy +25 additive provenance bonus. Operators flip this via
	// the trustscore.attestation_first setting once the SLSA writer
	// path is producing reliable values for their deployment.
	AttestationFirst bool
	HasSourceRepo    bool
	// RepoLinkStatus comes from the PR 11 repo-liveness enricher:
	// "ok", "archived", "missing", "ownership_mismatch", "unknown", or
	// empty (enricher hasn't run). When non-empty it overrides the
	// binary HasSourceRepo delta with a signed contribution.
	RepoLinkStatus string
	VersionCount   int // number of known versions of this package

	// PublisherChanged is true when the incoming version's publisher set
	// differs from the most recent prior version. Contributes a -25 delta.
	PublisherChanged bool

	// VersionAnomalyFlags — per-kind flags produced by
	// metadiff.VersionSequenceFlags. Each flag contributes -15; the sum
	// is clamped to -30 so two or more flags produce the maximum penalty
	// without stacking further.
	VersionAnomalyFlags []string

	// Hidden-Unicode payload signal (PR 8). True when the scanner found
	// at least CHAINSAW_HIDDEN_UNICODE_THRESHOLD suspect runes in the
	// artifact's text files. Contributes -20 to the trust score.
	HasHiddenUnicode bool

	// KnownExploitedCVE is true when at least one CVE on this package
	// appears in the CISA Known Exploited Vulnerabilities (KEV) catalog
	// — populated by provider_kev. Contributes -25 additively with the
	// CVSS-derived VulnStatus, so an exploited CVE is strictly worse
	// than an unexploited one at the same severity.
	KnownExploitedCVE bool

	// DangerousPickleOpcode is true when PickleScan flagged a code-exec
	// gadget in a model artifact (REDUCE/GLOBAL pointing at exec, eval,
	// os.system, etc.). Contributes -30 — the heaviest AI-artifact
	// penalty because the gadget executes on torch.load.
	DangerousPickleOpcode bool

	// ModelCardInjection is true when the model card README contains
	// prompt-injection markers (ignore-previous-instructions, jailbreak
	// patterns, etc.). Contributes -10.
	ModelCardInjection bool

	// AgentToolDangerousCapability is true when an MCP server manifest
	// declares dangerous capabilities (file_write, shell, code_exec,
	// network) without verified provenance. Contributes -15.
	AgentToolDangerousCapability bool
}

// ownBytesSignalFired reports whether any OWN-BYTES detection signal fired —
// the artifact-content signals that reveal a payload, as opposed to
// name/metadata signals. Used by the typosquat coupling: a typosquat name is
// suggestive on its own, but a typosquat name PLUS a payload signal is the
// dependency-confusion attack shape. The set deliberately covers the
// install-script / import-time-exec / embedded-IOC / hidden-unicode axes
// (detection-roadmap item 2); pickle/model-card/agent-tool AI signals are
// own-bytes too and are included for completeness.
func ownBytesSignalFired(s Signals) bool {
	return s.HasInstallScript ||
		s.InstallScriptFetchesRemote ||
		s.ImportTimeExecution ||
		s.MaliciousIOC ||
		s.HasHiddenUnicode ||
		s.DangerousPickleOpcode ||
		s.ModelCardInjection ||
		s.AgentToolDangerousCapability
}

// Compute calculates a trust score from the provided signals.
func Compute(signals Signals) Score {
	var b Breakdown

	// Malware: instant kill.
	if signals.IsKnownMalicious {
		b.MalwareCheck = -100
		return Score{
			Total:      0,
			Breakdown:  b,
			ComputedAt: time.Now(),
			IsComplete: true,
		}
	}

	// Vulnerability status: 0 to +20, scaled inversely by CVSS.
	if !signals.IsVulnerable {
		b.VulnStatus = 20
	} else if signals.MaxCVSS < 4.0 {
		b.VulnStatus = 10 // low severity
	} else if signals.MaxCVSS < 7.0 {
		b.VulnStatus = 5 // medium severity
	}
	// high/critical severity: 0

	// Provenance contribution. Two modes:
	//
	//   - Legacy (AttestationFirst=false): +25 additive when verified.
	//     Maximum sum-of-positive-signals stays at 100, provenance
	//     remains one factor among many.
	//
	//   - Attestation-first (AttestationFirst=true): the SLSA substrate
	//     reframe. Verified attestation seeds a 70-point base; lack of
	//     attestation seeds a 30-point floor. SLSA level adds 0/5/10/15
	//     on top. The 40-point gap demotes "no attestation" packages to
	//     a sub-50 score even when every other signal is positive,
	//     matching the "block-by-default for Tier-1 ecosystems" stance
	//     the seeded baseline policy expresses.
	if signals.AttestationFirst {
		if signals.HasProvenance && signals.ProvenanceStatus == "verified" {
			b.AttestationBase = 70
			switch {
			case signals.SLSALevel >= 4:
				b.SLSALevelBonus = 15
			case signals.SLSALevel == 3:
				b.SLSALevelBonus = 10
			case signals.SLSALevel == 2:
				b.SLSALevelBonus = 5
			default:
				// L1 or unknown level — base only.
			}
		} else {
			b.AttestationBase = 30
		}
	} else if signals.HasProvenance && signals.ProvenanceStatus == "verified" {
		b.Provenance = 25
	}

	// License compliance.
	if signals.LicenseSPDX != "" {
		b.LicenseCompliance = 10
	}

	// Package age (> 30 days).
	if signals.VersionReleaseDate != nil {
		age := time.Since(*signals.VersionReleaseDate)
		if age > 30*24*time.Hour {
			b.PackageAge = 10
		}
	}

	// Typosquat check.
	if signals.IsSuspectedTyposquat {
		switch signals.TyposquatConfidence {
		case "high":
			b.TyposquatCheck = -30
		case "medium":
			b.TyposquatCheck = -20
		case "low":
			b.TyposquatCheck = -10
		default:
			b.TyposquatCheck = -15
		}
	} else {
		b.TyposquatCheck = 10
	}

	// Source repo + liveness (PR 11).
	// When the enricher has run (RepoLinkStatus non-empty), we use the
	// classification directly. Otherwise fall back to the legacy binary:
	// +10 if a source repo URL is known, 0 otherwise.
	b.RepoLinkStatus = signals.RepoLinkStatus
	switch signals.RepoLinkStatus {
	case "ok":
		b.SourceRepo = 10
	case "unknown":
		b.SourceRepo = 0
	case "archived", "missing":
		b.SourceRepo = -10
	case "ownership_mismatch":
		b.SourceRepo = -20
	default:
		// Empty — enricher hasn't run. Preserve pre-PR-11 behaviour.
		if signals.HasSourceRepo {
			b.SourceRepo = 10
		}
	}

	// Multiple versions.
	if signals.VersionCount >= 3 {
		b.VersionCount = 10
	} else if signals.VersionCount >= 2 {
		b.VersionCount = 5
	}

	// Checksum verified. NB: this is a bit-flip canary, not a security
	// boundary — see provider_checksum.go header for the
	// circular-verification caveat. The real upstream-signature
	// verdict is SignatureVerified below.
	if signals.ChecksumVerified {
		b.ChecksumVerified = 5
	}

	// Signature verified — real cryptographic verification against an
	// independent trust root (sigstore today; PGP TODO). +5 bonus,
	// dovetails with the SLSA bonuses above. No penalty for "false"
	// because the failure case is already reflected in ProvenanceStatus.
	if signals.SignatureVerified {
		b.SignatureVerified = 5
	}

	// Install-script penalty. FetchesRemote is the stronger signal so
	// it supersedes the plain hasInstallScript penalty rather than
	// stacking (otherwise a remote-fetch package would take a -25 hit,
	// which is heavier than the research-calibrated -20).
	if signals.InstallScriptFetchesRemote {
		b.InstallScript = -20
	} else if signals.HasInstallScript {
		b.InstallScript = -5
	}

	// Import-time execution (PyPI): obfuscated decode-and-exec / import-time
	// exfil / download-and-execute shell that runs the instant the package is
	// imported or built. High-confidence-malicious — heaviest own-bytes hit.
	//
	// Exception: a BARE obfuscated decode-and-exec ("obfuscated_exec_bare") —
	// one with no send/recon/harvest/exfil co-marker — is the legitimate
	// plugin/bytecode-loader shape. It still contributes a penalty (obfuscation
	// in a published package is a real tell), but a LIGHTER one so it cannot,
	// alone, drive a package below the block line. A real dropper that decodes
	// AND sends/exfils is reported under the strong "obfuscated_exec" kind and
	// keeps the full -30 (detection-roadmap item 3).
	if signals.ImportTimeExecution {
		if signals.ImportTimeKind == "obfuscated_exec_bare" {
			b.ImportTimeExecution = -10
		} else {
			b.ImportTimeExecution = -30
		}
	}

	// Embedded IOC (exfil sink host / coupled stealer string): near-certain
	// malware regardless of code shape. Heavy penalty.
	if signals.MaliciousIOC {
		b.MaliciousIOC = -30
	}

	// Publisher changed (account-takeover signal): -25 when the incoming
	// version was published by a different maintainer set than the prior
	// version. Tuneable per the plan; starts aggressive because this is a
	// high-signal indicator of Axios-style takeovers.
	if signals.PublisherChanged {
		b.PublisherChanged = -25
	}

	// Version anomaly penalty: -15 per metadiff flag, capped at -30.
	// Two or more flags therefore produce the maximum penalty without
	// stacking further (Axios-style regression + timestamp = same
	// penalty as a single major skip + regression).
	if n := len(signals.VersionAnomalyFlags); n > 0 {
		penalty := n * -15
		if penalty < -30 {
			penalty = -30
		}
		b.VersionAnomaly = penalty
	}

	// Hidden Unicode payload (PR 8).
	if signals.HasHiddenUnicode {
		b.HiddenUnicode = -20
	}

	// Publish velocity anomaly — Shai-Hulud style worm burst tell. The
	// caller decides the threshold of record (orchestrator / policy) and
	// passes a pre-computed bool here so this package stays decoupled from
	// the policy threshold constant.
	if signals.PublishVelocityAnomaly {
		b.PublishVelocityAnomaly = -20
	}

	// Known-exploited (CISA KEV) — additive on top of VulnStatus so an
	// exploited CVE is strictly worse than an unexploited one of the
	// same severity. -25 is calibrated against CVSS-7.0+ (which already
	// zeroes VulnStatus) so KEV alone takes a vulnerable package well
	// below 50.
	if signals.KnownExploitedCVE {
		b.KnownExploitedCVE = -25
	}

	// AI artifact: dangerous pickle opcode — model carries a code-exec
	// gadget that fires on torch.load. Severe.
	if signals.DangerousPickleOpcode {
		b.DangerousPickleOpcode = -30
	}

	// AI artifact: model card prompt-injection. Lower magnitude — this
	// is a downstream risk to consumers, not direct compromise.
	if signals.ModelCardInjection {
		b.ModelCardInjection = -10
	}

	// MCP server manifest claiming dangerous capability without verified
	// provenance.
	if signals.AgentToolDangerousCapability {
		b.AgentToolDangerousCapability = -15
	}

	// Typosquat × own-bytes coupling (detection-roadmap item 2). A package
	// that is BOTH a suspected typosquat AND trips an own-bytes signal is a
	// far stronger verdict than either alone: a name-confusion candidate that
	// also ships a suspicious payload (an install script, an import-time exec,
	// an embedded IOC, or hidden-unicode) is near-certainly a
	// dependency-confusion / typosquat attack, not a coincidence. The
	// individual penalties above already fire; this adds a fixed conjunction
	// penalty so the coupled case lands below the block line even when each
	// signal alone is mild (e.g. low-confidence typosquat + a bare install
	// script). We do NOT require the own-bytes signal to be "strong" — the
	// whole point is that the COMBINATION is what's dispositive.
	if signals.IsSuspectedTyposquat && ownBytesSignalFired(signals) {
		b.TyposquatOwnBytesCoupling = -20
	}

	total := b.MalwareCheck + b.VulnStatus + b.Provenance +
		b.AttestationBase + b.SLSALevelBonus +
		b.LicenseCompliance +
		b.PackageAge + b.TyposquatCheck + b.SourceRepo + b.VersionCount + b.ChecksumVerified + b.SignatureVerified +
		b.InstallScript + b.ImportTimeExecution + b.MaliciousIOC + b.PublisherChanged + b.VersionAnomaly + b.HiddenUnicode + b.PublishVelocityAnomaly +
		b.KnownExploitedCVE + b.DangerousPickleOpcode + b.ModelCardInjection + b.AgentToolDangerousCapability +
		b.TyposquatOwnBytesCoupling

	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}

	isComplete := signals.HasProvenance || signals.ProvenanceStatus != ""

	return Score{
		Total:      total,
		Breakdown:  b,
		ComputedAt: time.Now(),
		IsComplete: isComplete,
	}
}
