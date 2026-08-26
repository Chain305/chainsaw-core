package risk

const (
	SignalLicMissing         = "lic.missing"
	SignalLicPolicyBlocked   = "lic.policy_blocked"
	SignalLicChangedFromPrev = "lic.changed_from_previous_version"
	SignalLicSPDXPresent     = "lic.spdx_present"

	// Socket-gap Wave 1 — SPDX taxonomy. Signal IDs match the
	// LicenseTag string constants so the classifier output can be
	// compared directly.
	SignalLicCopyleft            = "license.copyleft"
	SignalLicNonPermissive       = "license.non_permissive"
	SignalLicExceptionPresent    = "license.exception_present"
	SignalLicAmbiguousClassifier = "license.ambiguous_classifier"
	SignalLicUnidentified        = "license.unidentified"
)

func init() {
	register(Signal{
		ID:          SignalLicMissing,
		Category:    CategoryLicense,
		Severity:    SevMedium,
		Weight:      -15,
		Title:       "No license declared",
		Description: "Package does not declare a license — ambiguous legal standing for downstream use.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.LicenseSPDX != "" {
				return false, "", nil
			}
			return true, "Package does not declare a license.", nil
		},
	})

	// Policy-driven — the upstream caller (intelligence package) is
	// responsible for setting LicensePolicyBlocked based on its org's
	// allow/deny list. Deferred per-org weight overrides are v2 work;
	// this signal just fires on the pre-computed bool.
	register(Signal{
		ID:          SignalLicPolicyBlocked,
		Category:    CategoryLicense,
		Severity:    SevHigh,
		Weight:      -30,
		Title:       "License blocked by policy",
		Description: "Declared license is on the org's block list (e.g., strong-copyleft for a commercial use-case).",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.LicensePolicyBlocked {
				return false, "", nil
			}
			return true, "License is blocked by policy.",
				map[string]any{"license": in.LicenseSPDX}
		},
	})

	register(Signal{
		ID:          SignalLicChangedFromPrev,
		Category:    CategoryLicense,
		Severity:    SevMedium,
		Weight:      -15,
		Title:       "License changed from previous version",
		Description: "This version declares a different license than the previous version — often benign but worth review.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.LicenseChangedFromPrev {
				return false, "", nil
			}
			return true, "License differs from the previous version.",
				map[string]any{"license": in.LicenseSPDX}
		},
	})

	register(Signal{
		ID:       SignalLicSPDXPresent,
		Category: CategoryLicense,
		Severity: SevInfo,
		Weight:   +5,
		Title:    "SPDX license declared",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.LicenseSPDX == "" {
				return false, "", nil
			}
			return true, "Package declares an SPDX license.",
				map[string]any{"license": in.LicenseSPDX}
		},
	})

	// Wave 1 classifier-derived signals. Each reads the shared
	// Input.LicenseTags slice populated by the risk projection.
	// ── LICENCE STRENGTH IS TIERED, AND IT IS TIERED WITH TWO SIGNALS ──
	//
	// These two used to be a flat -20 each, and license.non_permissive is
	// by its own definition the SUPERSET of license.copyleft, so every
	// copyleft package paid BOTH: -40. Three consequences, all wrong:
	//
	//   * MPL-2.0 (-40) was penalised exactly twice as hard as BUSL-1.1
	//     (-20), when BUSL is the one that can forbid your business
	//     outright and MPL is the one that asks nothing of your own files.
	//   * AGPL-3.0 and MPL-2.0 priced identically, at -40.
	//   * -40 of licence deficit beats the -20 of a single vuln.cvss_high,
	//     so UpgradePromotionEligible's dominance test refused to promote
	//     ANY copyleft package with a CVE that had a published fix. The
	//     user was told "review before use" while the engine was holding a
	//     SafeVersion it had already computed. certifi 2023.7.22 (MPL-2.0
	//     + CVE-2024-39689) is the filed case.
	//
	// Note the dominance test is `d >= vuln` — a TIE also refuses — so
	// merely deleting the duplicate would have left licence at 20 against
	// vuln's 20 and changed nothing. The weights had to move as well.
	//
	// The scheme, and it is a strict ordering:
	//
	//   weak copyleft        -10   MPL / EPL / CDDL / LGPL / MS-RL
	//   source-available     -20   BUSL / ELv2 / RSAL / Confluent / CC
	//   strong copyleft      -30   GPL / AGPL / OSL / SSPL / Sleepycat
	//
	// It is built out of TWO signals rather than three so the registry
	// keeps its published signal count, its five license.* policy
	// conditions, and both tag names exactly as they are:
	//
	//   license.copyleft       -10, fires on the copyleft tag, unchanged
	//                          firing set. The base price every copyleft
	//                          licence pays: you may not modify-and-close,
	//                          and you must carry the notice.
	//   license.non_permissive -20, fires on the non-permissive tag EXCEPT
	//                          when the strength is weak copyleft. It
	//                          prices the obligation that reaches YOUR OWN
	//                          code — and weak copyleft, by construction,
	//                          does not: MPL/EPL/CDDL confine reciprocity
	//                          to the dependency's own files and LGPL to
	//                          linkage, so an unmodified library consumer
	//                          inherits nothing. Strong copyleft and
	//                          source-available both do reach the
	//                          consumer, and both keep paying it.
	//
	// So the signal's firing set is a strict subset of its TAG's, on
	// purpose. The TAG is untouched: core/policy's LicenseNonPermissive
	// condition still sees the superset, because narrowing a policy
	// predicate would be an enforcement change and this is a scoring fix.
	registerLicenseTagSignal(SignalLicCopyleft, SevMedium, -10,
		"Copyleft license",
		"Declared license is copyleft (GPL / AGPL / LGPL / MPL / CDDL / OSL).",
		LicenseTagCopyleft)
	registerNonPermissiveSignal()
	registerLicenseTagSignal(SignalLicExceptionPresent, SevInfo, -5,
		"License carries a WITH exception",
		"Declared expression contains a WITH <exception> clause — review the exception text.",
		LicenseTagExceptionPresent)
	registerLicenseTagSignal(SignalLicAmbiguousClassifier, SevLow, -10,
		"Ambiguous license expression",
		"License expression combines multiple distinct license families — operator choice required.",
		LicenseTagAmbiguous)
	registerLicenseTagSignal(SignalLicUnidentified, SevMedium, -15,
		"Unidentified license",
		"License expression is NOASSERTION, empty, or not recognisable as SPDX.",
		LicenseTagUnidentified)
}

// registerNonPermissiveSignal registers license.non_permissive with the
// weak-copyleft suppression described at its call site. It is written out
// rather than routed through registerLicenseTagSignal because it is the one
// tag signal whose firing set is deliberately NARROWER than its tag.
//
// The suppression reads LicenseStrengthOf(in.LicenseSPDX) rather than a
// sixth LicenseTag: adding a tag would change the wire shape of
// policy.Input.LicenseTags and the tag/condition drift rails that Wave A
// built, for a distinction that only the scorer needs.
func registerNonPermissiveSignal() {
	const desc = "Declared license is copyleft or source-available (BUSL, SSPL, Commons Clause, ELv2)."
	register(Signal{
		ID:          SignalLicNonPermissive,
		Category:    CategoryLicense,
		Severity:    SevMedium,
		Weight:      -20,
		Title:       "Non-permissive license",
		Description: desc,
		Fires: func(in Input) (bool, string, map[string]any) {
			present := false
			for _, t := range in.LicenseTags {
				if t == LicenseTagNonPermissive {
					present = true
					break
				}
			}
			if !present {
				return false, "", nil
			}
			// Weak copyleft is already priced by license.copyleft and
			// imposes nothing on the consumer's own source. Suppressing
			// here is what removes the -40 double count.
			if LicenseStrengthOf(in.LicenseSPDX) == LicenseStrengthWeakCopyleft {
				return false, "", nil
			}
			return true, desc, map[string]any{
				"license": in.LicenseSPDX,
				"tag":     string(LicenseTagNonPermissive),
			}
		},
	})
}

func registerLicenseTagSignal(id string, sev Severity, weight float64, title, desc string, tag LicenseTag) {
	register(Signal{
		ID:          id,
		Category:    CategoryLicense,
		Severity:    sev,
		Weight:      weight,
		Title:       title,
		Description: desc,
		Fires: func(in Input) (bool, string, map[string]any) {
			for _, t := range in.LicenseTags {
				if t == tag {
					return true, desc, map[string]any{"license": in.LicenseSPDX, "tag": string(tag)}
				}
			}
			return false, "", nil
		},
	})
}
