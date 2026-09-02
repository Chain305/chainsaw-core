package risk

import "fmt"

// Supply-chain-category signal IDs. This is the category with the highest
// weight in CategoryWeights because these signals indicate active attack
// patterns (malware, takeovers, typosquats) rather than latent flaws.
const (
	SignalSCKnownMalicious   = "sc.known_malicious"
	SignalSCTyposquatHigh    = "sc.typosquat_high"
	SignalSCTyposquatMedium  = "sc.typosquat_medium"
	SignalSCTyposquatLow     = "sc.typosquat_low"
	SignalSCPublisherChanged = "sc.publisher_changed"
	// SignalSCPOMDeveloperListChanged is the POM-ecosystem (maven/gradle)
	// counterpart of sc.publisher_changed. Same underlying fact, different
	// claim: see the registration below and P8-70.
	SignalSCPOMDeveloperListChanged = "sc.pom_developer_list_changed"
	SignalSCInstallScriptNetwork    = "sc.install_script_fetches_remote"
	SignalSCInstallScriptOnly       = "sc.install_script_only"
	SignalSCHiddenUnicode           = "sc.hidden_unicode"
	SignalSCRepoOwnershipMismatch   = "sc.repo_ownership_mismatch"
	SignalSCRepoArchived            = "sc.repo_archived"
	SignalSCRepoMissing             = "sc.repo_missing"
	SignalSCProvenanceVerified      = "sc.provenance_verified"
	SignalSCReservedNamespace       = "sc.reserved_namespace_violation"
	SignalSCPublishVelocity         = "sc.publish_velocity_anomaly"
	SignalSCSLSALevelBonus          = "sc.slsa_level_bonus"
	SignalSCSignatureVerified       = "sc.signature_verified"

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
	//
	// SevCritical, not SevHigh — and the severity is load-bearing, not
	// cosmetic. The ceiling of 30 pins overall to EXACTLY thresholdQuarantine
	// when this fires alone, and resolveVerdict's band-1 test is strict
	// (`overall < thresholdQuarantine`), so 30 falls through into band 2.
	// Band 2 has one and only one way back out: the critical-signal
	// escalation, driven by hasCriticalSignal. At SevHigh this signal took
	// neither path and resolved to bare Warn — a high-confidence typosquat
	// could never produce a blocking verdict, which is the whole point of
	// detecting one. Its two ceiling-30 peers (vuln.cvss_critical,
	// sc.transitive_critical_vuln) both already ride SevCritical for exactly
	// this reason; this signal was the odd one out.
	//
	// The other two candidate fixes are wrong. Relaxing the band test to
	// `<=` moves the boundary for every package whose organic rollup happens
	// to land on the integer 30, with no signal-level attribution, and
	// cascades into blockedNodes for transitive parents. Dropping the
	// ceiling to 29 would trip UpgradePromotionEligible's bottom-band gate
	// for the OTHER ceiling-30 signals and silently delete "upgrade to X"
	// from a critical CVE that has a published fix.
	//
	// The severity change cannot interact with upgrade promotion: supply_chain
	// is vetoed outright by upgradeVetoCategories, and UpgradePromotionEligible
	// additionally requires a vulnerability-category deficit that a lone
	// typosquat never produces. See TestTyposquatHighCannotPromoteToUpgradeAvailable.
	register(Signal{
		ID:        SignalSCTyposquatHigh,
		Category:  CategorySupplyChain,
		Severity:  SevCritical,
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
	//
	// P8-70 (epoch 12): this claim — "signature of account takeover" — is an
	// access-control claim, and it only holds where the publisher set is
	// sourced from something the registry ENFORCES. On maven/gradle it is
	// not: both sides of the diff are read out of the POM `<developers>`
	// block, which is prose the author types into the artifact. Adding a
	// committer, dropping one, or renaming the sponsoring company
	// (`lightbend` -> `akka`) rewrites it without any account changing
	// hands. Measured on prod, 2026-09-01/02: 30 maven/gradle coordinates
	// carried publisherChanged=true; after the epoch-11 extractor fix 11
	// still did, and the true-positive count across all 30 was ZERO.
	// The blast radius was not hypothetical either — Wave S (2026-05-23)
	// 403'd every `mvn` invocation in the smoke org off this signal.
	//
	// So for POM ecosystems the FACT is kept and the CLAIM is dropped: the
	// firing moves to SignalSCPOMDeveloperListChanged below (SevLow, -5, no
	// MaxImpact ceiling) which says only what the data supports. Do NOT
	// "simplify" this by deleting the guard and re-widening the SevHigh
	// signal; TestPublisherChangedDemotion_* pin both halves.
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
			if IsPOMMaintainerEco(in.Ecosystem) {
				return false, "", nil
			}
			return true, "Publisher identity changed between versions.", nil
		},
	})

	// The POM-ecosystem context signal. Deliberately NOT a takeover claim:
	// the POM `<developers>` block is self-declared documentation, so all
	// this reports is that the declared list moved between the two versions
	// compared. SevLow / -5 matches the other "worth showing, never worth
	// blocking on" entries in the registry (sc.install_script_only,
	// maint.single_maintainer). It carries NO MaxImpact: a ceiling is a
	// claim that this signal alone is enough to hold a package below a
	// verdict band, which is exactly the claim P8-70 refuted.
	//
	// It also deliberately does NOT feed CompoundSCTakeoverSignature — see
	// the guard and comment in compound.go. Routing it there would put the
	// -55 takeover weight back on POM prose through the side door.
	register(Signal{
		ID:          SignalSCPOMDeveloperListChanged,
		Category:    CategorySupplyChain,
		Severity:    SevLow,
		Weight:      -5,
		Title:       "Declared developer list changed",
		Description: "The POM <developers> block differs from the previous version. This block is self-declared documentation, not a registry-enforced publishing identity, so a change here is context — commonly a committer added or removed, or a sponsor rename — and not evidence of account takeover.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.PublisherChanged {
				return false, "", nil
			}
			if !IsPOMMaintainerEco(in.Ecosystem) {
				return false, "", nil
			}
			return true, "Declared <developers> list differs from the previous version.", nil
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
	//
	// maxImpactWarnTop (59), not a literal 60. This is Trojan Source
	// detection: the offline guard hard-blocks on it while the server, with
	// the ceiling sitting exactly on thresholdWarn, could not produce so
	// much as a warning — `60 < 60` is false, band 2 is skipped and the
	// verdict is ALLOW. See P8-02.
	register(Signal{
		ID:          SignalSCHiddenUnicode,
		Category:    CategorySupplyChain,
		Severity:    SevMedium,
		Weight:      -20,
		MaxImpact:   maxImpactWarnTop,
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
	// fine — keep the ceiling soft. maxImpactWarnTop (59) rather than a
	// literal 60: a ceiling ON thresholdWarn resolves to ALLOW, which makes
	// the ceiling decorative. See P8-02.
	register(Signal{
		ID:        SignalSCRepoArchived,
		Category:  CategorySupplyChain,
		Severity:  SevMedium,
		Weight:    -12,
		MaxImpact: maxImpactWarnTop,
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
	// maxImpactWarnTop (59) rather than a literal 60: a ceiling ON
	// thresholdWarn resolves to ALLOW. See P8-02.
	register(Signal{
		ID:        SignalSCRepoMissing,
		Category:  CategorySupplyChain,
		Severity:  SevMedium,
		Weight:    -12,
		MaxImpact: maxImpactWarnTop,
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

	// MaxImpact tier: HIGH-confidence harmful (30-40). Dependency-confusion
	// bait is an attack pattern, not a hygiene problem — a public name that
	// shadows a private namespace exists to be resolved by mistake.
	//
	// The ceiling was MISSING, which is not the same as a deliberate
	// no-ceiling call: a signal that declares no MaxImpact contributes no
	// cap at all, so this scored strictly more leniently than its own exact
	// peers — sc.publisher_changed, sc.install_script_network,
	// sc.suspicious_repo_stars and sc.maintainer_account_very_young all sit
	// at the same severity and the same -25 weight with MaxImpact 40, and
	// sc.repo_ownership_mismatch is LIGHTER (-20) and still ceilings at 40.
	// Same omission shape as the vuln.cvss_critical bug: see
	// TestVulnSeverityLadderIsMonotonic for how that one inverted the ladder.
	register(Signal{
		ID:          SignalSCReservedNamespace,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -25,
		MaxImpact:   40,
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
			// P8-70, same root cause as sc.publisher_changed above and
			// P8-11's maint.single_maintainer. This signal is computed by
			// firstTimeCollaboratorProvider from exactly the same two
			// fields — prior publisher_set vs Report.People.PublisherIDs —
			// and on maven/gradle both are the POM `<developers>` roster.
			// The sentence it renders ("publisher has never previously
			// CONTRIBUTED to this package") is false by construction there:
			// a name appearing in <developers> for the first time means the
			// project edited a documentation block, not that a new account
			// pushed the artifact. Whatever a new POM name is, it is not a
			// first-time PUBLISHER, so the signal has nothing to measure.
			//
			// The fact that the declared list moved is still reported —
			// SignalSCPOMDeveloperListChanged above carries it once. Firing
			// both would double-count one POM edit.
			//
			// This is belt-and-braces today: maven/gradle sit in
			// firstTimeCollabSupportedEcosystems
			// (internal/intelligence/premium/provider_wave4_rtt.go) but the
			// provider is env-gated off for them in prod, so the field is
			// nil and the guard above already returns. It exists so that
			// turning CHAINSAW_WAVE4_FIRST_TIME_COLLABORATOR on cannot
			// silently reintroduce the class.
			if IsPOMMaintainerEco(in.Ecosystem) {
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
