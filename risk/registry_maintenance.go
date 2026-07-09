package risk

import (
	"os"
	"strings"
	"time"
)

const (
	SignalMaintAbandonedRepo    = "maint.abandoned_repo"
	SignalMaintNoRecentRelease  = "maint.no_recent_release"
	SignalMaintVeryNewPackage   = "maint.very_new_package"
	SignalMaintSingleMaintainer = "maint.single_maintainer"
	SignalMaintHealthyCadence   = "maint.healthy_cadence"
	SignalMaintUnpopularPackage = "maint.unpopular_package"
)

// Download-count thresholds for maint.unpopular_package.
// Packages below these counts have very low community adoption;
// the signal is informational only (SevInfo, weight 0).
const (
	UnpopularNPMWeeklyThreshold  = 100 // npm downloads/week
	UnpopularPyPIWeeklyThreshold = 50  // PyPI downloads/week
)

// Thresholds — exported so tests and docs can reference the exact cutoffs
// rather than hardcoding durations in two places.
const (
	AbandonedRepoThreshold    = 365 * 24 * time.Hour     // 12mo without commits
	NoRecentReleaseThreshold  = 2 * 365 * 24 * time.Hour // 24mo without a release
	VeryNewPackageThreshold   = 30 * 24 * time.Hour      // <30 days old
	VeryNewPackageMaxVersions = 3                        // AND version count <= 3
	HealthyCadenceMaxAge      = 90 * 24 * time.Hour      // latest release within 90d
	HealthyCadenceMinVersions = 5                        // AND >=5 historical versions
)

func init() {
	register(Signal{
		ID:          SignalMaintAbandonedRepo,
		Category:    CategoryMaintenance,
		Severity:    SevHigh,
		Weight:      -25,
		Title:       "Source repository looks abandoned",
		Description: "No commits to the source repo in over 12 months.",
		Fires: func(in Input) (bool, string, map[string]any) {
			// RepoArchived is *bool: explicit-true short-circuits (a known
			// archived repo can't be "abandoned" — it's intentional). Both
			// false and nil fall through; nil means we couldn't probe and
			// the abandonment decision falls back to LastRepoCommitAt
			// alone.
			if in.LastRepoCommitAt == nil {
				return false, "", nil
			}
			if in.RepoArchived != nil && *in.RepoArchived {
				return false, "", nil
			}
			if time.Since(*in.LastRepoCommitAt) < AbandonedRepoThreshold {
				return false, "", nil
			}
			return true, "No commits in over a year.",
				map[string]any{"lastCommitAt": in.LastRepoCommitAt.UTC().Format(time.RFC3339)}
		},
	})

	register(Signal{
		ID:          SignalMaintNoRecentRelease,
		Category:    CategoryMaintenance,
		Severity:    SevMedium,
		Weight:      -15,
		Title:       "No recent releases",
		Description: "Latest release is over 24 months old.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.LatestReleaseAt == nil {
				return false, "", nil
			}
			if time.Since(*in.LatestReleaseAt) < NoRecentReleaseThreshold {
				return false, "", nil
			}
			return true, "No releases in the last two years.",
				map[string]any{"latestReleaseAt": in.LatestReleaseAt.UTC().Format(time.RFC3339)}
		},
	})

	register(Signal{
		ID:          SignalMaintVeryNewPackage,
		Category:    CategoryMaintenance,
		Severity:    SevMedium,
		Weight:      -10,
		Title:       "Very new package",
		Description: "Package is less than 30 days old with few historical versions.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.PublishedAt == nil {
				return false, "", nil
			}
			if time.Since(*in.PublishedAt) > VeryNewPackageThreshold {
				return false, "", nil
			}
			if in.VersionCount > VeryNewPackageMaxVersions {
				return false, "", nil
			}
			return true, "Package is brand-new with very few prior versions.",
				map[string]any{"versionCount": in.VersionCount}
		},
	})

	register(Signal{
		ID:          SignalMaintSingleMaintainer,
		Category:    CategoryMaintenance,
		Severity:    SevLow,
		Weight:      -5,
		Title:       "Single maintainer",
		Description: "Only one maintainer — bus-factor and takeover-target risk.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.MaintainerCount != 1 {
				return false, "", nil
			}
			return true, "Package has only one maintainer.", nil
		},
	})

	// Positive signal.
	register(Signal{
		ID:          SignalMaintHealthyCadence,
		Category:    CategoryMaintenance,
		Severity:    SevInfo,
		Weight:      +10,
		Title:       "Healthy release cadence",
		Description: "Recent release within 90 days and a history of >=5 versions.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.LatestReleaseAt == nil {
				return false, "", nil
			}
			if time.Since(*in.LatestReleaseAt) > HealthyCadenceMaxAge {
				return false, "", nil
			}
			if in.VersionCount < HealthyCadenceMinVersions {
				return false, "", nil
			}
			return true, "Recent releases and a track record of historical versions.", nil
		},
	})

	// Informational: very low weekly download counts suggest minimal community
	// adoption. This is not a direct security risk but correlates with
	// unmaintained / obscure packages that receive less community scrutiny.
	// Weight 0: purely informational. In air-gap mode or on fetch error the
	// field is nil and the signal stays dormant (fail-open).
	// When the fetcher could not obtain a count (network error / offline),
	// the projection layer sets WeeklyDownloads to a sentinel and the signal
	// fires with SevUnknown — this is handled below by emitting a separate
	// "unknown" firing when WeeklyDownloads == &unknownDownloads.
	register(Signal{
		ID:       SignalMaintUnpopularPackage,
		Category: CategoryMaintenance,
		Severity: SevInfo, // overridden to SevUnknown in the Fires func when data is absent
		Weight:   0,
		Title:    "Very low download count",
		Description: "The package receives very few weekly downloads (npm <100/wk, PyPI <50/wk), " +
			"suggesting minimal community adoption. " +
			"When download data is unavailable the signal fires with severity 'unknown'.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.WeeklyDownloads == nil {
				return false, "", nil
			}
			dl := *in.WeeklyDownloads
			// Sentinel value -1 means "fetch failed / air-gap" — emit unknown.
			if dl == unknownDownloadsSentinel {
				msg := "Weekly download count unavailable (air-gap or fetch error)."
				// When CHAINSAW_OFFLINE=1 is set, the operator intentionally
				// disabled upstream fetches — distinguish that from a real
				// fetch failure so the message isn't misleading.
				if isOfflineForSignal() {
					msg = "Weekly download data unavailable (offline mode)."
				}
				return true, msg,
					map[string]any{"severity_override": string(SevUnknown)}
			}
			eco := in.Ecosystem
			switch {
			case isNPMEco(eco) && dl < UnpopularNPMWeeklyThreshold:
				return true, "Package has very few weekly downloads on npm.",
					map[string]any{"weekly_downloads": dl, "threshold": UnpopularNPMWeeklyThreshold}
			case isPyPIEco(eco) && dl < UnpopularPyPIWeeklyThreshold:
				return true, "Package has very few weekly downloads on PyPI.",
					map[string]any{"weekly_downloads": dl, "threshold": UnpopularPyPIWeeklyThreshold}
			}
			return false, "", nil
		},
	})
}

// unknownDownloadsSentinel is written by the fetcher to WeeklyDownloads when
// the registry API was unreachable (network error or CHAINSAW_OFFLINE=1). The
// Fires function converts it to a SevUnknown emission rather than suppressing
// the signal entirely.
const unknownDownloadsSentinel = -1

func isNPMEco(eco string) bool {
	switch eco {
	case "npm", "yarn", "bun", "pnpm":
		return true
	}
	return false
}

func isPyPIEco(eco string) bool {
	switch eco {
	case "pip", "pypi":
		return true
	}
	return false
}

// isOfflineForSignal reports whether CHAINSAW_OFFLINE is set to a truthy
// value. Mirrors intelligence.isOffline but is duplicated here to avoid an
// import cycle between risk and intelligence.
func isOfflineForSignal() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("CHAINSAW_OFFLINE")))
	switch v {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}
