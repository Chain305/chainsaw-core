package risk

import (
	"fmt"
	"time"
)

// registry_maintenance_state.go holds the registry-native maintenance facts
// that no older signal expresses. Most of them do not need one: every
// registry's "do not use this version" (npm deprecated, PyPI/Cargo yanked,
// NuGet unlisted or deprecated, Go retract or module Deprecated:, Packagist
// abandoned, PyPI PEP 792 project-status, pub retracted) is folded onto
// ReleaseSection.Yanked / .Deprecated by the registry provider and fires
// sc.deprecated_by_maintainer, and "no release in two years" is
// maint.no_recent_release. What is left is the fact that names its own
// replacement and that the package manager follows by itself.

const SignalMaintRelocated = "maint.relocated"

func init() {
	register(Signal{
		ID:       SignalMaintRelocated,
		Category: CategoryMaintenance,
		Severity: SevLow,
		// Weight 0 and no MaxImpact: a relocation cannot move a verdict.
		// Maven resolves a relocated coordinate to its target without the
		// user doing anything, and the maintainer who wrote it named the
		// replacement, so the claim here is "this coordinate has moved",
		// never "do not use it". Routing it through Release.Deprecated
		// would have ceilinged it to warn via sc.deprecated_by_maintainer
		// and flagged every build still on an old coordinate
		// (mysql:mysql-connector-java -> com.mysql:mysql-connector-j).
		Weight:      0,
		Title:       "Coordinate relocated",
		Description: "The Maven POM declares a <relocation>: this coordinate has moved and the build resolves the named target instead.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.RelocatedTo == "" {
				return false, "", nil
			}
			return true, "Relocated to " + in.RelocatedTo + ".",
				map[string]any{"relocatedTo": in.RelocatedTo}
		},
	})
}

// SignalSCReleaseAfterDormancy: this version came out after the package had
// published nothing for DormancyGapThreshold. The ctx (PyPI, 2022) takeover
// was exactly this — eight years silent, then a backdoored release from an
// account recovered through an expired maintainer domain — and expired
// domains, Go repojacking and MavenGate all make the dormant package the
// target. Weight 0 because recall cannot be measured yet: every malicious
// corpus row lost its timeline when the registry deleted it. Benign base rate
// at 2 years (2026-10-03): 5 of 443 dated corpus releases, 237 of 5,379 dated
// prod reports.
const SignalSCReleaseAfterDormancy = "sc.release_after_dormancy"

// DormancyGapThreshold is the silence that makes a release notable.
const DormancyGapThreshold = 2 * 365 * 24 * time.Hour

func init() {
	register(Signal{
		ID:          SignalSCReleaseAfterDormancy,
		Category:    CategorySupplyChain,
		Severity:    SevInfo,
		Weight:      0,
		Title:       "Release after long dormancy",
		Description: "This version was published more than two years after the previous release.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.VersionPublishedAt == nil || in.PriorReleaseAt == nil || in.PriorReleaseVersion == "" {
				return false, "", nil
			}
			gap := in.VersionPublishedAt.Sub(*in.PriorReleaseAt)
			if gap < DormancyGapThreshold {
				return false, "", nil
			}
			days := int(gap.Hours() / 24)
			return true, fmt.Sprintf("Published %d days after the previous release (%s).", days, in.PriorReleaseVersion),
				map[string]any{
					"gapDays":         days,
					"priorVersion":    in.PriorReleaseVersion,
					"priorReleasedAt": in.PriorReleaseAt.UTC().Format(time.RFC3339),
				}
		},
	})
}

// SignalMaintOutdatedVersion is the version-age fact: the PINNED version is
// over two years old and a newer non-prerelease version exists.
// maint.no_recent_release is the package-level twin — this one fires on a
// maintained package pinned to an old release (deep_cloneable 1.6.0 from 2013
// while 3.x ships), which package-level staleness correctly cannot.
const SignalMaintOutdatedVersion = "maint.outdated_version"

// OutdatedVersionThreshold matches NoRecentReleaseThreshold so the two
// staleness facts use one definition of "old".
const OutdatedVersionThreshold = NoRecentReleaseThreshold

func init() {
	register(Signal{
		ID:       SignalMaintOutdatedVersion,
		Category: CategoryMaintenance,
		Severity: SevInfo,
		// Weight 0 and no MaxImpact, for the reason registry_maintenance.go
		// gives for staleness: age is our inference, not a registry
		// statement, and most of the benign long tail pins old versions.
		Weight:      0,
		Title:       "Outdated version",
		Description: "This version was published over two years ago and a newer non-prerelease version exists.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.VersionPublishedAt == nil || in.NewerVersion == "" || in.NewerVersionAt == nil {
				return false, "", nil
			}
			if time.Since(*in.VersionPublishedAt) < OutdatedVersionThreshold {
				return false, "", nil
			}
			return true, "Published " + in.VersionPublishedAt.UTC().Format("2006-01-02") +
					"; newer version " + in.NewerVersion + " published " + in.NewerVersionAt.UTC().Format("2006-01-02") + ".",
				map[string]any{
					"versionPublishedAt": in.VersionPublishedAt.UTC().Format(time.RFC3339),
					"newerVersion":       in.NewerVersion,
					"newerVersionAt":     in.NewerVersionAt.UTC().Format(time.RFC3339),
				}
		},
	})
}
