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
		ID:          SignalSCDeprecatedByMaintainer,
		Category:    CategorySupplyChain,
		Severity:    SevMedium,
		Weight:      -15,
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
