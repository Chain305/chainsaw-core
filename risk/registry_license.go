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
	registerLicenseTagSignal(SignalLicCopyleft, SevMedium, -20,
		"Copyleft license",
		"Declared license is copyleft (GPL / AGPL / LGPL / MPL / CDDL / OSL).",
		LicenseTagCopyleft)
	registerLicenseTagSignal(SignalLicNonPermissive, SevMedium, -20,
		"Non-permissive license",
		"Declared license is copyleft or source-available (BUSL, SSPL, Commons Clause, ELv2).",
		LicenseTagNonPermissive)
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
