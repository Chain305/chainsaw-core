package risk

// registry_wave1.go registers the three non-license Socket-gap Wave 1
// signals. Kept in its own file so the commit boundary is legible.

const (
	SignalSCDeprecatedByMaintainer = "sc.deprecated_by_maintainer"
	SignalSCShrinkwrapPresent      = "sc.shrinkwrap_present"
	SignalSCManifestConfusion      = "sc.manifest_confusion"
)

func init() {
	register(Signal{
		ID:       SignalSCDeprecatedByMaintainer,
		Category: CategorySupplyChain,
		Severity: SevMedium,
		Weight:   -15,
		// MaxImpact tier: MEDIUM-confidence harmful (50-60), matching its
		// peer sc.repo_archived. maxImpactWarnTop (59) rather than a
		// literal 60 for the P8-02 reason: a ceiling ON thresholdWarn
		// resolves to ALLOW and is decorative.
		//
		// ADDED 2026-09-13. Its absence was a calibration inconsistency,
		// not a deliberate leniency. Compare the two SevMedium
		// supply-chain siblings before this change:
		//
		//   sc.repo_archived              weight -12, ceiling 59 → warn
		//   sc.deprecated_by_maintainer   weight -15, no ceiling → allow
		//
		// The STRONGER claim scored more leniently. repo_archived is an
		// inference ("the repo looks read-only"); this signal is the
		// maintainer stating in the registry that the version should not
		// be used. An absent MaxImpact contributes no cap at all, which
		// registry_supplychain_test.go already warns about in prose, and
		// docs/ARCHITECTURE.md#architecture-package-intelligence puts Medium-confidence
		// signals in the 50-59 band — so the old shape was also out of
		// compliance with the project's own published calibration policy.
		//
		// Scope is deliberately narrow: this is the ONLY change made for
		// the "suspicious tier is empty" finding. Category weights are NOT
		// touched (CategoryMaintenance is 0.15, so every maintenance
		// signal firing at once moves the score at most 15 points against
		// a warn band 40 points down — arithmetically unable to reach
		// warn, which is why re-weighting was the wrong lever), and
		// maint.no_recent_release is deliberately NOT ceilinged: "no
		// release in two years" describes a large share of the stable long
		// tail, and a finished library is not suspicious.
		MaxImpact:   maxImpactWarnTop,
		Title:       "Deprecated by maintainer",
		Description: "Registry reports this version is deprecated (npm) or yanked (PyPI/Cargo).",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.DeprecatedByMaintainer {
				return false, "", nil
			}
			msg := "Maintainer has deprecated this version."
			if in.DeprecationReason != "" {
				msg = "Maintainer deprecation: " + in.DeprecationReason
			}
			return true, msg, map[string]any{"reason": in.DeprecationReason}
		},
	})

	register(Signal{
		ID:       SignalSCShrinkwrapPresent,
		Category: CategorySupplyChain,
		Severity: SevLow,
		Weight:   -10,
		// COPY IS NOT npm-ONLY. The producing provider's coverage map,
		// intelligence.ecosystemLockfiles, covers five ecosystems —
		// npm-family, pypi/pip, composer, cargo and rubygems — so a
		// title naming npm-shrinkwrap.json was factually wrong on four
		// of them (a Rust crate shipping Cargo.lock rendered as
		// "Bundled npm-shrinkwrap.json"). Keep this wording in step
		// with that map, not with npm.
		Title:       "Bundled dependency lockfile",
		Description: "Artifact ships a pinned dependency lockfile (npm-shrinkwrap.json, package-lock.json, Pipfile.lock, poetry.lock, composer.lock, Cargo.lock or Gemfile.lock) — hides transitive deps from consumer review.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.ShrinkwrapPresent {
				return false, "", nil
			}
			return true, "Artifact bundles a dependency lockfile — review the pinned transitive deps.", nil
		},
	})

	register(Signal{
		ID:          SignalSCManifestConfusion,
		Category:    CategorySupplyChain,
		Severity:    SevHigh,
		Weight:      -45,
		Title:       "Registry/tarball manifest mismatch",
		Description: "Registry JSON package.json and tarball package.json diverge semantically.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.ManifestConfusion {
				return false, "", nil
			}
			return true, "Registry-side package.json differs from the tarball — possible metadata-tampering attack.",
				map[string]any{"divergentFields": in.ManifestConfusionFields}
		},
	})
}
