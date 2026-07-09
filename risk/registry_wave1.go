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
		ID:          SignalSCShrinkwrapPresent,
		Category:    CategorySupplyChain,
		Severity:    SevLow,
		Weight:      -10,
		Title:       "Bundled npm-shrinkwrap.json",
		Description: "Artifact ships an npm-shrinkwrap.json — hides transitive deps from consumer review.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if !in.ShrinkwrapPresent {
				return false, "", nil
			}
			return true, "Tarball contains npm-shrinkwrap.json — review bundled transitive deps.", nil
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
