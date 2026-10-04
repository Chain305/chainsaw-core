package risk

import "strings"

const (
	SignalLicMissing = "lic.missing"
	// lic.policy_blocked is DEREGISTERED — deliberately, and the constant is
	// gone with it rather than left as a tempting re-registration.
	//
	// It was registered at SevHigh / weight -30 and could never fire:
	// ProjectToRiskInput assigns Input.LicensePolicyBlocked a literal
	// `false` on every scan. So `GET /api/v1/intel/signals` advertised
	// licence blocking as an available risk signal, and an operator
	// building policy on it would have waited forever for a signal the
	// engine cannot emit.
	//
	// It could not be wired either: there is no licence allow/deny config
	// anywhere in the product to wire it TO. The sibling artefact tells the
	// same story — errcodes CHW-2003 ("not on the allowed list for this
	// repository") is registered and raised by nothing. Two descriptions of
	// a feature that was never built.
	//
	// The capability is NOT lost. Blocking on licence is real and supported
	// through the policy DSL's ConditionLicenseCopyleft / NonPermissive /
	// ExceptionPresent / AmbiguousClassifier / Unidentified, none of which
	// is context-only. This signal was a parallel path that never got
	// built, and a signal that cannot fire is worse than no signal: it
	// reads as coverage.
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
			// An empty licence we never managed to READ is not a
			// declaration of none. See Input.LicenseDataUnavailable.
			if in.LicenseSPDX != "" || in.LicenseDataUnavailable {
				return false, "", nil
			}
			return true, "Package does not declare a license.", nil
		},
	})

	// Observed at WEIGHT 0. The projection (intelligence.projectLicenseDiff)
	// fires only when this version adds a copyleft / non-permissive class
	// the prior version we hold lacked. "Prior" is the most recently
	// COLLECTED other version, not the semver predecessor, which is why the
	// title says "a version we hold". It earns a weight once it has been
	// priced against the corpus, not before.
	register(Signal{
		ID:          SignalLicChangedFromPrev,
		Category:    CategoryLicense,
		Severity:    SevMedium,
		Weight:      0,
		Title:       "Licence became more restrictive than a version we hold",
		Description: "This version declares a copyleft or non-permissive licence that the previously scanned version did not.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.LicenseChangedFromPrev {
				return false, "", nil
			}
			return true, "Licence is more restrictive than a version we hold.",
				map[string]any{
					"license":      in.LicenseSPDX,
					"priorLicense": in.LicensePriorSPDX,
					"priorVersion": in.LicensePriorVersion,
				}
		},
	})

	register(Signal{
		ID:       SignalLicSPDXPresent,
		Category: CategoryLicense,
		Severity: SevInfo,
		Weight:   +5,
		Title:    "SPDX license declared",
		Fires: func(in Input) (bool, string, map[string]any) {
			// A licence identified from LICENSE-file text was inferred,
			// not declared; this +5 rewards the declaration.
			if in.LicenseSPDX == "" || in.LicenseFromFile {
				return false, "", nil
			}
			// A non-empty string is not an SPDX expression. Registries
			// hand us licence URLs constantly — NuGet's `licenseUrl`
			// yields values like
			// "https://raw.github.com/JamesNK/Newtonsoft.Json/master/LICENSE.md"
			// — and firing on any non-empty value made this signal
			// award +5 for "declares an SPDX license" on the SAME row
			// where license.unidentified fired -15 for the same field
			// not being recognisable as SPDX. Measured on production:
			// 339 rows across six ecosystems carried both at once, and
			// the package page rendered the contradiction to operators.
			//
			// Defer to the classifier that owns the question. It is the
			// same predicate license.unidentified keys on, so the two
			// signals can no longer disagree about one string.
			for _, tag := range Classify(in.LicenseSPDX) {
				if tag == LicenseTagUnidentified {
					return false, "", nil
				}
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
	registerAmbiguousSignal()
	registerUnidentifiedSignal()
}

// registerAmbiguousSignal registers license.ambiguous_classifier without
// one case its tag still covers: a combination whose every licence is
// permissive. An OR ("MIT OR Apache-2.0") hands the CONSUMER a choice they
// can take as it stands; an AND ("Apache-2.0 AND MIT") asks no choice at
// all, only that every grant's notice is kept. Neither leaves the operator
// anything to resolve. The OR form cost -10 on most Rust crates (16 of 43
// rev5 firings, 7 more as crates.io's "MIT/Apache-2.0"); the AND form on
// aiohttp and numpy in the server FP corpus.
//
// Still fired: any copyleft or source-available licence in the expression
// (which branch you take, or what you combine with, changes your
// obligations), NOASSERTION mixed in, and anything unrecognised. The TAG is
// untouched for core/policy's LicenseAmbiguousClassifier condition, for
// the reason given on registerUnidentifiedSignal.
func registerAmbiguousSignal() {
	const desc = "License expression combines multiple distinct license families — operator choice required."
	register(Signal{
		ID:          SignalLicAmbiguousClassifier,
		Category:    CategoryLicense,
		Severity:    SevLow,
		Weight:      -10,
		Title:       "Ambiguous license expression",
		Description: desc,
		Fires: func(in Input) (bool, string, map[string]any) {
			if IsAllPermissive(in.LicenseSPDX) {
				return false, "", nil
			}
			for _, t := range in.LicenseTags {
				if t == LicenseTagAmbiguous {
					return true, desc, map[string]any{"license": in.LicenseSPDX, "tag": string(LicenseTagAmbiguous)}
				}
			}
			return false, "", nil
		},
	})
}

// registerUnidentifiedSignal registers license.unidentified with one
// exclusion its tag does not make: an EMPTY expression. Classify("") tags
// Unidentified, and lic.missing (-15) already fires on exactly that case,
// so an undeclared licence paid -30 for one fact. On corpus-v1-rev4 that
// was 441 of the 553 rows this signal fired on.
//
// Like license.non_permissive below, the firing set is narrower than the
// TAG on purpose: core/policy's LicenseUnidentified condition still sees
// the empty expression as unidentified, because narrowing a policy
// predicate is an enforcement change and this is a scoring fix.
func registerUnidentifiedSignal() {
	const desc = "License expression is NOASSERTION or not recognisable as SPDX."
	register(Signal{
		ID:          SignalLicUnidentified,
		Category:    CategoryLicense,
		Severity:    SevMedium,
		Weight:      -15,
		Title:       "Unidentified license",
		Description: desc,
		Fires: func(in Input) (bool, string, map[string]any) {
			if strings.TrimSpace(in.LicenseSPDX) == "" {
				return false, "", nil
			}
			for _, t := range in.LicenseTags {
				if t == LicenseTagUnidentified {
					return true, desc, map[string]any{"license": in.LicenseSPDX, "tag": string(LicenseTagUnidentified)}
				}
			}
			return false, "", nil
		},
	})
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
