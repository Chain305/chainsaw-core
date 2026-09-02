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
			// VersionDataAvailable IS the guard this signal was always
			// missing. Input.VersionDataAvailable's own doc comment says it
			// "Prevents the maint.very_new_package false-positive that fires
			// when the sparse proxy-driven store returns 0 versions for a
			// popular package" — and until now NOTHING in core/risk read the
			// field. It was declared, projected, unit-tested for being set,
			// and consulted by nobody, so the false positive it names was
			// live: this signal's second clause treats "we have no version
			// history" as "there is no version history", which is the one
			// reading the flag exists to forbid.
			//
			// Dormant, not firing, is the right posture. A −10 maintenance
			// signal asserted on absent facts is the shape of claim this
			// engine must not make; the package is still scored by every
			// other signal, and the sparse-store path
			// (premium/provider_maintenance.go's GetPackageVersionHistory
			// fallback) recovers the count as soon as history exists.
			if !in.VersionDataAvailable {
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
			// P8-11: on Maven/Gradle the maintainer list is derived from the
			// POM `<developers>` block, which an author fills in by hand.
			// Whatever it is, it is not a headcount: plenty of large,
			// well-staffed projects list exactly one developer, and
			// spring-core-6.1.0.pom is one of them, which is why this fired
			// on Spring Framework. A count of 1 there carries no bus-factor
			// information, so the signal has nothing to measure.
			//
			// Note the open disagreement next door: `runMaven`
			// (`provider_registrymetadata.go:1605-1607`) calls the same block
			// a publisher identity, "since Sonatype keys publisher accounts
			// on the developer email", and `sc.publisher_changed` for maven
			// is built on that being true. This signal only needs the weaker
			// claim — that the entry COUNT is meaningless — which holds
			// either way. The stronger question is filed as P8-70; do not
			// resolve it by copying either comment.
			if isPOMMaintainerEco(in.Ecosystem) {
				return false, "", nil
			}
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

// isPOMMaintainerEco reports whether this ecosystem's maintainer list comes
// from a POM `<developers>` block. Those entries are self-declared prose
// rather than an access-control list — `runMaven`'s `<developers>` loop
// (`core/intelligence/provider_registrymetadata.go:1609`) maps them onto
// PeopleSection.Maintainers deliberately, because the People panel has
// nothing better to show, but a count taken off them does not mean what
// MaintainerCount means everywhere else. See P8-11.
//
// P8-70 widened the scope of this predicate beyond the maintainer COUNT.
// The same `<developers>` block is also the only source of maven/gradle
// publisher identity (`intelligence.MavenDeveloperPublisherIDs`), so it
// gates three signals now: maint.single_maintainer (P8-11),
// sc.publisher_changed / sc.pom_developer_list_changed and
// sc.first_time_collaborator (both P8-70), plus the
// CompoundSCTakeoverSignature rule in compound.go. The name says
// "Maintainer" for history; read it as "this ecosystem's People data is
// POM prose". Every caller wants the same answer, so keep it one function
// — a second, subtly different ecosystem list is how the two halves of
// P8-70 drifted apart in the first place.
//
// LOWERCASE THE INPUT. `risk.Input.Ecosystem` is the RAW caller-supplied
// string: `risk_projection.go:153` copies `r.Identity.Ecosystem` through
// untouched and the HTTP handlers (`api_v1_intel.go`, `admin_intelligence.go`)
// build the key without folding case. The provider side DOES normalise —
// `provider_registrymetadata.go:217` runs `normalizeEcosystemKey` before
// dispatching to `runMaven` — so a request for ecosystem "Maven" populates
// Maintainers from the POM but would miss a case-sensitive guard here, and the
// false positive would survive on exactly the `/api/v1/intel/packages/...`
// surface it was reported from. That asymmetry is the residual of P8-33, which
// normalised the `Supports()` lookup layer and left the stored value raw.
func isPOMMaintainerEco(eco string) bool {
	switch strings.ToLower(strings.TrimSpace(eco)) {
	case "maven", "gradle":
		return true
	// "maven-central" is a chainsaw PROXY REPO NAME, not an ecosystem token
	// (`internal/simulate/riskweights.go:274` draws that distinction
	// explicitly), so nothing should route it here. Kept as a cheap guard
	// against a repo-name leaking into the ecosystem field, not because it
	// is a real coordinate shape.
	case "maven-central":
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
