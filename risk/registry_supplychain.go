package risk

import "fmt"

// Supply-chain-category signal IDs. This is the category with the highest
// weight in CategoryWeights because these signals indicate active attack
// patterns (malware, takeovers, typosquats) rather than latent flaws.
const (
	SignalSCKnownMalicious        = "sc.known_malicious"
	SignalSCTyposquatHigh         = "sc.typosquat_high"
	SignalSCTyposquatMedium       = "sc.typosquat_medium"
	SignalSCTyposquatLow          = "sc.typosquat_low"
	SignalSCPublisherChanged      = "sc.publisher_changed"
	SignalSCInstallScriptNetwork  = "sc.install_script_fetches_remote"
	SignalSCInstallScriptOnly     = "sc.install_script_only"
	SignalSCHiddenUnicode         = "sc.hidden_unicode"
	SignalSCRepoOwnershipMismatch = "sc.repo_ownership_mismatch"
	SignalSCRepoArchived          = "sc.repo_archived"
	SignalSCRepoMissing           = "sc.repo_missing"
	SignalSCProvenanceVerified    = "sc.provenance_verified"
	SignalSCReservedNamespace     = "sc.reserved_namespace_violation"
	SignalSCPublishVelocity       = "sc.publish_velocity_anomaly"
	SignalSCSLSALevelBonus        = "sc.slsa_level_bonus"
	SignalSCSignatureVerified     = "sc.signature_verified"

	// URL-dependency signals — fire when package.json deps resolve to
	// git or raw HTTP(S) URLs, bypassing the registry hash chain.
	// Projection wiring is deferred; fields stay zero-valued until then.
	SignalSCGitURLDependency  = "sc.git_url_dependency"
	SignalSCHTTPURLDependency = "sc.http_url_dependency"

	// Wave-4 RTT signals projected from r.Scan.* into risk.Input.
	SignalSCSuspiciousRepoStars            = "sc.suspicious_repo_stars"
	SignalSCFirstTimeCollaborator          = "sc.first_time_collaborator"
	SignalSCMaintainerAccountVeryYoung     = "sc.maintainer_account_very_young"
	SignalSCMaintainerAccountYoung         = "sc.maintainer_account_young"
	SignalSCMaintainerAccountSomewhatYoung = "sc.maintainer_account_somewhat_young"
	SignalSCNonExistentAuthor              = "sc.non_existent_author"

	// Transitive-closure signals — fire on the root package when one or
	// more descendants in the dep tree carry critical / high / malware
	// findings. Populated by evaluateTransitiveRisk in
	// internal/intelligence and projected into risk.Input.Transitive*Count
	// before the root's second evaluation runs. Mirrors Socket's
	// "transitive_vulnerabilities" summary line.
	SignalSCTransitiveCriticalVuln = "sc.transitive_critical_vuln"
	SignalSCTransitiveHighVuln     = "sc.transitive_high_vuln"
	SignalSCTransitiveMalware      = "sc.transitive_malware"
)

func init() {
	// Instant-block: known malicious. Weight is sentinel (-1000); the
	// evaluator short-circuits to Overall=0 / Verdict=Quarantine when this
	// signal fires — we still register it with a weight for consistency
	// but the evaluator does not simply add it.
	register(Signal{
		ID:          SignalSCKnownMalicious,
		Category:    CategorySupplyChain,
		Severity:    SevCritical,
		Weight:      -1000,
		Title:       "Known-malicious package",
		Description: "Matched a curated malware index entry. Short-circuits evaluation.",
		// Pain 9 P2: the -1000 sentinel is what triggers the
		// quarantine short-circuit in evaluator.go. Allowing an
		// admin to override this weight (positive or merely smaller-
		// magnitude) would silently disable instant-block on
		// confirmed malware — a hole big enough that it must be
		// closed at the validation layer, not at the operator's
		// discretion. NotTunable: requests via /api/risk/overrides
		// are rejected.
		NotTunable: true,
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.IsKnownMalicious {
				return false, "", nil
			}
			return true, "This package is on the known-malicious index — do not install.",
				map[string]any{"malwareId": in.MalwareID, "summary": in.MalwareSummary}
		},
	})

	// MaxImpact tier: HIGH-confidence harmful (30-40). High-severity matched
	// signal — strong evidence of attack pattern but not RCE-grade.
	register(Signal{
		ID:        SignalSCTyposquatHigh,
		Category:  CategorySupplyChain,
		Severity:  SevHigh,
		Weight:    -40,
		MaxImpact: 30,
		Title:     "Likely typosquat (high confidence)",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.IsSuspectedTyposquat || in.TyposquatConfidence != "high" {
				return false, "", nil
			}
			return true, "Name is highly similar to a popular package.",
				map[string]any{"similarTo": in.TyposquatSimilarTo}
		},
	})

	// MaxImpact tier: MEDIUM-confidence soft signal — NO ceiling. The -20
	// weight already drops the supply_chain category to 80 (and overall
	// near 93 in an otherwise-clean package). A medium-confidence soft
	// signal must not cascade into a near-quarantine score by itself —
	// the rebalance from MaxImpact:35 → no-ceiling fixes the jose@5.10.0
	// regression where a single medium-confidence hit collapsed overall
	// from 92 to 35.
	register(Signal{
		ID:       SignalSCTyposquatMedium,
		Category: CategorySupplyChain,
		Severity: SevMedium,
		Weight:   -20,
		Title:    "Possible typosquat (medium confidence)",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.IsSuspectedTyposquat || in.TyposquatConfidence != "medium" {
				return false, "", nil
			}
			return true, "Name is similar to a popular package.",
				map[string]any{"similarTo": in.TyposquatSimilarTo}
		},
	})

	register(Signal{
		ID:       SignalSCTyposquatLow,
		Category: CategorySupplyChain,
		Severity: SevLow,
		Weight:   -8,
		Title:    "Name similarity to popular package (low confidence)",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.IsSuspectedTyposquat || in.TyposquatConfidence != "low" {
				return false, "", nil
			}
			return true, "Name is weakly similar to a popular package.",
				map[string]any{"similarTo": in.TyposquatSimilarTo}
		},
	})

	// Publisher-change alone is a strong signal (account takeover is the
	// common cause). Compound rule in compound.go amplifies it when a new
	// install script is also introduced in the same version.
	// MaxImpact tier: HIGH-confidence harmful (30-40). Account takeover is
	// the dominant cause of publisher changes; only the compound rule
	// (with install-script) escalates to instant-block grade.
	register(Signal{
		ID:          SignalSCPublisherChanged,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -25,
		MaxImpact:   40,
		Title:       "Publisher changed from previous version",
		Description: "The maintainer set for this version differs from the previous version — common signature of account takeover.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.PublisherChanged {
				return false, "", nil
			}
			return true, "Publisher identity changed between versions.", nil
		},
	})

	// MaxImpact tier: HIGH-confidence harmful (30-40). Install-time
	// network egress is high-confidence harmful — fetch-and-exec is a
	// known malware pattern.
	register(Signal{
		ID:          SignalSCInstallScriptNetwork,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -25,
		MaxImpact:   40,
		Title:       "Install script makes network calls",
		Description: "The package's install/postinstall script fetches remote content at install time.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.InstallScriptFetchesRemote {
				return false, "", nil
			}
			return true, "Install-time lifecycle script fetches remote content.", nil
		},
	})

	// Plain install script (no network). Low weight — many legitimate
	// packages use postinstall for native builds — but it compounds with
	// publisher-change (see compound.go).
	register(Signal{
		ID:       SignalSCInstallScriptOnly,
		Category: CategorySupplyChain,
		Severity: SevLow,
		Weight:   -5,
		Title:    "Install lifecycle script present",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.HasInstallScript || in.InstallScriptFetchesRemote {
				return false, "", nil
			}
			return true, "Package has an install/postinstall script.", nil
		},
	})

	// MaxImpact tier: MEDIUM-confidence harmful (50-60). Bidi/invisible
	// Unicode is a known concealment vector but appears benignly (e.g.,
	// internationalised tests) often enough to keep the ceiling soft.
	register(Signal{
		ID:          SignalSCHiddenUnicode,
		Category:    CategorySupplyChain,
		Severity:    SevMedium,
		Weight:      -20,
		MaxImpact:   60,
		Title:       "Hidden Unicode in source",
		Description: "Source files contain invisible or bidirectional Unicode that can hide malicious code from review.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.HasHiddenUnicode {
				return false, "", nil
			}
			return true, "Source contains invisible/bidi Unicode code points.", nil
		},
	})

	// MaxImpact tier: HIGH-confidence harmful (30-40). Mismatched repo
	// ownership is a typosquat-kit fingerprint — high-severity claim.
	register(Signal{
		ID:          SignalSCRepoOwnershipMismatch,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -20,
		MaxImpact:   40,
		Title:       "Source repo ownership mismatch",
		Description: "Registry-advertised source repo is owned by a different account than the publisher — common in typosquat kits.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.RepoLinkStatus != "ownership_mismatch" {
				return false, "", nil
			}
			return true, "Declared source repo owner does not match the publisher.", nil
		},
	})

	// MaxImpact tier: MEDIUM-confidence harmful (50-60). Archived repos
	// are not actively maintained but the package itself can still be
	// fine — keep the ceiling soft.
	register(Signal{
		ID:        SignalSCRepoArchived,
		Category:  CategorySupplyChain,
		Severity:  SevMedium,
		Weight:    -12,
		MaxImpact: 60,
		Title:     "Source repo archived",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.RepoLinkStatus != "archived" {
				return false, "", nil
			}
			return true, "Source repository is archived (read-only).", nil
		},
	})

	// MaxImpact tier: MEDIUM-confidence harmful (50-60). Missing repo is
	// a transparency degradation — medium severity matches the policy.
	register(Signal{
		ID:        SignalSCRepoMissing,
		Category:  CategorySupplyChain,
		Severity:  SevMedium,
		Weight:    -12,
		MaxImpact: 60,
		Title:     "Source repo missing",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.RepoLinkStatus != "missing" {
				return false, "", nil
			}
			return true, "Declared source repository is unreachable or deleted.", nil
		},
	})

	// Positive signal — reward verifiable provenance.
	register(Signal{
		ID:          SignalSCProvenanceVerified,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      +15,
		Title:       "Verified build provenance",
		Description: "Package has verifiable sigstore/SLSA provenance attestation.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.HasProvenance || in.ProvenanceStatus != "verified" {
				return false, "", nil
			}
			return true, "Verified provenance attestation present.", nil
		},
	})

	register(Signal{
		ID:          SignalSCReservedNamespace,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -25,
		Title:       "Reserved namespace violation",
		Description: "Package name shadows an internal/private namespace — possible dependency-confusion bait.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.ReservedNamespaceViolation {
				return false, "", nil
			}
			return true, "Package name squats a reserved namespace.", nil
		},
	})

	// SLSA build-level bonus on top of the bare provenance-verified reward.
	// Mirrors the legacy trustscore.SLSALevelBonus contribution: L2=+5,
	// L3=+10, L4=+15. Only fires when provenance is verified — otherwise
	// the level number is meaningless.
	register(Signal{
		ID:          SignalSCSLSALevelBonus,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      0, // dynamic — overridden in computeCategoryScores
		Title:       "SLSA build level bonus",
		Description: "Verified attestation claims a higher SLSA build level (L2/L3/L4) — additional reward beyond bare provenance.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.HasProvenance || in.ProvenanceStatus != "verified" {
				return false, "", nil
			}
			if in.SLSALevel < 2 {
				return false, "", nil
			}
			return true, "Verified attestation claims a higher SLSA level.",
				map[string]any{"slsaLevel": in.SLSALevel}
		},
	})

	// Cryptographic-signature reward (sigstore today; PGP TODO). Distinct
	// from ChecksumVerified (a bit-flip canary against the registry's own
	// digest) and from HasProvenance (presence of a provenance document) —
	// this is verification against an independent trust root.
	register(Signal{
		ID:          SignalSCSignatureVerified,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      +5,
		Title:       "Upstream signature verified",
		Description: "Cryptographic verification against an independent trust root succeeded.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.SignatureVerified {
				return false, "", nil
			}
			return true, "Upstream signature verified against independent trust root.", nil
		},
	})

	// MaxImpact tier: MEDIUM-confidence harmful (50-60). Anomalous
	// publish velocity is a Shai-Hulud-style worm signature; medium
	// severity by itself, escalated by other supply-chain signals.
	register(Signal{
		ID:          SignalSCPublishVelocity,
		Category:    CategorySupplyChain,
		Severity:    SevMedium,
		Weight:      -15,
		MaxImpact:   55,
		Title:       "Abnormal publish velocity",
		Description: "Publisher set pushed an unusually high number of releases in the trailing 24h — Shai-Hulud worm signature.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.PublishVelocityAnomaly {
				return false, "", nil
			}
			return true, "Publisher has pushed an abnormal number of versions recently.", nil
		},
	})

	// --- Wave-4 RTT signals ---------------------------------------------
	// SuspiciousRepoStars is a composite-AND result (low stars + young
	// repo + young maintainer all true). High confidence by construction,
	// so a heavy weight is justified.
	// MaxImpact tier: HIGH-confidence harmful (30-40). The composite-AND
	// evidence (low stars + young repo + young maintainer) is high
	// confidence by construction.
	register(Signal{
		ID:          SignalSCSuspiciousRepoStars,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -25,
		MaxImpact:   40,
		Title:       "Suspicious repo: low stars + young repo + young maintainer",
		Description: "All three of: repo star count below threshold, repo created recently, maintainer account very young.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.SuspiciousRepoStars {
				return false, "", nil
			}
			return true, "Repo and maintainer composite checks all flagged.", nil
		},
	})

	register(Signal{
		ID:          SignalSCFirstTimeCollaborator,
		Category:    CategorySupplyChain,
		Severity:    SevMedium,
		Weight:      -15,
		Title:       "First-time collaborator on this package",
		Description: "Publisher has never previously contributed to this package.",
		Fires: func(in Input) (bool, string, map[string]any) {
			// Three-state: only &true fires; nil and &false stay dormant.
			if in.FirstTimeCollaborator == nil || !*in.FirstTimeCollaborator {
				return false, "", nil
			}
			return true, "Publisher has not previously contributed to this package.", nil
		},
	})

	// Account-age tiers — only one fires (the most-young matching tier),
	// gated by 0 = unknown.
	// MaxImpact tier: HIGH-confidence harmful (30-40). Brand-new
	// maintainer accounts (<30 days) are the dominant typosquat-publisher
	// pattern.
	register(Signal{
		ID:          SignalSCMaintainerAccountVeryYoung,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -25,
		MaxImpact:   40,
		Title:       "Maintainer account very young (<30 days)",
		Description: "The youngest maintainer account is less than 30 days old.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.MaintainerAccountAgeDays <= 0 || in.MaintainerAccountAgeDays >= 30 {
				return false, "", nil
			}
			return true, "Youngest maintainer account is brand new.",
				map[string]any{"days": in.MaintainerAccountAgeDays}
		},
	})

	register(Signal{
		ID:          SignalSCMaintainerAccountYoung,
		Category:    CategorySupplyChain,
		Severity:    SevMedium,
		Weight:      -15,
		Title:       "Maintainer account young (<90 days)",
		Description: "The youngest maintainer account is less than 90 days old.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.MaintainerAccountAgeDays < 30 || in.MaintainerAccountAgeDays >= 90 {
				return false, "", nil
			}
			return true, "Youngest maintainer account is recent.",
				map[string]any{"days": in.MaintainerAccountAgeDays}
		},
	})

	register(Signal{
		ID:          SignalSCMaintainerAccountSomewhatYoung,
		Category:    CategorySupplyChain,
		Severity:    SevLow,
		Weight:      -5,
		Title:       "Maintainer account under 6 months",
		Description: "The youngest maintainer account is less than 180 days old.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.MaintainerAccountAgeDays < 90 || in.MaintainerAccountAgeDays >= 180 {
				return false, "", nil
			}
			return true, "Youngest maintainer account is under six months.",
				map[string]any{"days": in.MaintainerAccountAgeDays}
		},
	})

	// MaxImpact tier: HIGH-confidence harmful (30-40). A declared author
	// that doesn't resolve is a strong fake-identity signal.
	register(Signal{
		ID:          SignalSCNonExistentAuthor,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -20,
		MaxImpact:   40,
		Title:       "Declared author does not exist on registry",
		Description: "The package's declared author email/name does not resolve to a real registry account.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.NonExistentAuthor {
				return false, "", nil
			}
			return true, "Author identity does not resolve to a registry account.", nil
		},
	})

	// Git-URL dependency: the resolved version bypasses the registry hash
	// chain entirely (no integrity hash, no npm audit coverage).
	register(Signal{
		ID:          SignalSCGitURLDependency,
		Category:    CategorySupplyChain,
		Severity:    SevLow,
		Weight:      -8,
		Title:       "Git URL dependency",
		Description: "A package.json dependency resolves to a git URL (git+https://, git+ssh://, git://, github:user/repo) and bypasses the registry hash chain.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.HasGitURLDep {
				return false, "", nil
			}
			return true, "Dependency resolved via git URL — bypasses registry integrity hash.",
				map[string]any{"deps": in.GitURLDeps}
		},
	})

	// Raw HTTP(S)-tarball dependency: fetched at install time from an
	// arbitrary host, not the npm/yarn registry, so no lockfile hash covers
	// it.  Registry URLs (registry.npmjs.org, registry.yarnpkg.com) are
	// excluded — those are normal resolved tarballs.
	register(Signal{
		ID:          SignalSCHTTPURLDependency,
		Category:    CategorySupplyChain,
		Severity:    SevLow,
		Weight:      -8,
		Title:       "HTTP(S) tarball URL dependency",
		Description: "A package.json dependency resolves to a raw http:// or https:// tarball URL outside the standard npm/yarn registries.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.HasHTTPURLDep {
				return false, "", nil
			}
			return true, "Dependency resolved via raw HTTP(S) URL — not covered by registry integrity hash.",
				map[string]any{"deps": in.HTTPURLDeps}
		},
	})

	// --- Transitive-closure signals -----------------------------------
	// Fire when the transitive dep-walker (internal/intelligence's
	// evaluateTransitiveRisk) has populated the Transitive*Count fields
	// on the root's second-pass risk.Input. Critical and Malware ride at
	// SevCritical so they participate in the critical-signal
	// verdict-promotion path in evaluator.go; High is SevHigh.
	//
	// Malware uses the -1000 sentinel so a descendant on the
	// known-malicious index instantly quarantines the parent through the
	// same short-circuit code path as a directly-malicious root.
	register(Signal{
		ID:          SignalSCTransitiveCriticalVuln,
		Category:    CategorySupplyChain,
		Severity:    SevCritical,
		Weight:      -40,
		MaxImpact:   30,
		Title:       "Transitive critical vulnerability",
		Description: "One or more critical-severity CVEs are reachable through the dependency closure.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.TransitiveCriticalCount <= 0 {
				return false, "", nil
			}
			return true, fmt.Sprintf("%d critical CVE(s) reachable via dependencies.", in.TransitiveCriticalCount),
				map[string]any{"count": in.TransitiveCriticalCount}
		},
	})

	register(Signal{
		ID:          SignalSCTransitiveHighVuln,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -20,
		MaxImpact:   50,
		Title:       "Transitive high-severity vulnerability",
		Description: "One or more high-severity CVEs are reachable through the dependency closure.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.TransitiveHighCount <= 0 {
				return false, "", nil
			}
			return true, fmt.Sprintf("%d high-severity CVE(s) reachable via dependencies.", in.TransitiveHighCount),
				map[string]any{"count": in.TransitiveHighCount}
		},
	})

	register(Signal{
		ID:          SignalSCTransitiveMalware,
		Category:    CategorySupplyChain,
		Severity:    SevCritical,
		Weight:      -1000,
		MaxImpact:   0,
		NotTunable:  true,
		Title:       "Malware in transitive closure",
		Description: "A descendant in the dependency closure is flagged on the known-malicious index.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.TransitiveMalwareCount <= 0 {
				return false, "", nil
			}
			return true, fmt.Sprintf("%d malicious descendant(s) reachable via dependencies.", in.TransitiveMalwareCount),
				map[string]any{"count": in.TransitiveMalwareCount}
		},
	})
}
