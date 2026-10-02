package risk

import (
	"fmt"
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
//
// Registries publish different windows, so each threshold is per ecosystem
// AND per window (risk.Input.DownloadsWindow); a count in a window with no
// threshold never fires. npm and PyPI are the original rules, unchanged.
// The rest were set 2026-09-30 against real counts for the 1,885-row
// corpus-v1-rev4, where the "benign" stratum is deliberately obscure (npm
// benign median: 6 a week; the npm rule fires on 176 of 205). Each new rule
// was held to fire on no larger a share of benign packages than npm's:
//
//   - crates.io, 90 days  < 100 — about 8 a week, an order below npm's
//     floor. Fires on 51/104 benign crates.
//   - Packagist, month    < 50 — about 12 a week. Fires on 75/108 benign
//     packages; Packagist volumes are small and most corpus packages
//     reported 0 for the month.
//   - RubyGems, all time  < 500 — every published gem accrues a few hundred
//     downloads from mirrors alone (corpus minimum 537), so under 500 means
//     nobody beyond the mirrors. Fires on 0/111 benign gems.
//   - NuGet, all time     < 500 — corpus benign minimum 247. Fires on 1/112.
//
// An all-time total cannot be scaled to a week (it depends on age), which
// is why those two are floors rather than conversions.
const (
	UnpopularNPMWeeklyThreshold     = 100 // npm downloads/week
	UnpopularPyPIWeeklyThreshold    = 50  // PyPI downloads/week
	UnpopularCargo90DayThreshold    = 100 // crates.io recent_downloads (90 days)
	UnpopularComposerMonthThreshold = 50  // Packagist downloads/month
	UnpopularRubyGemsTotalThreshold = 500 // RubyGems all-time downloads
	UnpopularNuGetTotalThreshold    = 500 // NuGet all-time downloads
)

// unpopularThreshold returns the threshold and registry label for a count
// in window on eco; ok=false when there is no rule for that pair.
func unpopularThreshold(eco, window string) (threshold int, registry string, ok bool) {
	switch {
	case isNPMEco(eco) && window == "week":
		return UnpopularNPMWeeklyThreshold, "npm", true
	case isPyPIEco(eco) && window == "week":
		return UnpopularPyPIWeeklyThreshold, "PyPI", true
	case eco == "cargo" && window == "90d":
		return UnpopularCargo90DayThreshold, "crates.io", true
	case eco == "composer" && window == "month":
		return UnpopularComposerMonthThreshold, "Packagist", true
	case eco == "rubygems" && window == "total":
		return UnpopularRubyGemsTotalThreshold, "RubyGems", true
	case eco == "nuget" && window == "total":
		return UnpopularNuGetTotalThreshold, "NuGet", true
	}
	return 0, "", false
}

// downloadsWindowPhrase renders a window for the alert text.
var downloadsWindowPhrase = map[string]string{
	"week":  "weekly downloads",
	"month": "downloads in the last month",
	"90d":   "downloads in the last 90 days",
	"total": "downloads in total",
}

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

// REFUSED, 2026-09-13: the signals in this file deliberately do NOT carry a
// MaxImpact ceiling, so none of them can on its own produce an adverse
// verdict. That is the intended behaviour, not an oversight, and not the F-2
// gap that was fixed elsewhere.
//
// The labelled-corpus eval (docs/REPORTS.md#labelled-corpus-eval-2026-09-13, F-2)
// found 0 of 9 "suspicious" rows scoring adverse. The fix was to ceiling
// sc.deprecated_by_maintainer in registry_wave1.go — a first-party MAINTAINER
// DECLARATION we are merely repeating. It was NOT to ceiling anything here,
// and the distinction is the whole point:
//
//   - "npm says this version is deprecated" is a fact the registry publishes
//     and that `npm install` already prints. Repeating it cannot be wrong.
//   - "no release since 2013" is OUR INFERENCE that absence means neglect,
//     and it is wrong constantly. A finished, stable, correct library stops
//     getting releases because it is DONE. pypi distribute (2013), pypi nose
//     (2015) and rubygems rails-observers (2017) sit in the corpus labelled
//     "suspicious" and this engine scores them `allow` — which is the right
//     answer.
//
// There is also arithmetic behind it: CategoryMaintenance carries weight 0.15
// (category.go), so driving maintenance from 100 to 0 costs at most 15 points,
// while the warn band starts 40 points down (thresholdWarn = 60). Every signal
// in this file firing at once still cannot reach warn. Ceilings, not weights,
// are the only lever here — which is exactly why reaching for one must be a
// deliberate decision about evidence, not a reflex about severity.
//
// Before ceilinging anything in this file, re-run the labelled-corpus eval and
// show the false-positive rate on the benign set. It was 0/40 when this was
// written, and that number is what makes the public package-intelligence
// surface publishable at all.

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

	// Info, weight 0 since 2026-10-02 (was medium, -15). Re-scored at -15,
	// -10, -5 and 0 over 18,309 rows (corpus-v1, the top-400 stratum, 16,024
	// prod reports): 0 verdict changes, 0 of 600 malicious rows fired, 55% of
	// benign rows did — finished libraries, now including 20 of the top 70 Go
	// modules once Go release dates became observable. A takeover publish
	// resets LatestReleaseAt, so staleness cannot precede one. socket.dev's
	// "unmaintained" is 5 years, low, off by default. Still shown as a fact;
	// archived repos (sc.repo_archived), stale commits (maint.abandoned_repo)
	// and maintainer deprecations keep the penalty. NoRecentReleaseThreshold
	// is shared with maint.outdated_version and is deliberately unchanged.
	register(Signal{
		ID:          SignalMaintNoRecentRelease,
		Category:    CategoryMaintenance,
		Severity:    SevInfo,
		Weight:      0,
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
			if IsPOMMaintainerEco(in.Ecosystem) {
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
		Severity: SevInfo, // the unknown arm overrides this to SevUnknown via evidence; see applySignalOverrides
		Weight:   0,
		Title:    "Very low download count",
		Description: "The package has very few downloads (npm <100/wk, PyPI <50/wk, crates.io <100 in 90 days, " +
			"Packagist <50/month, RubyGems and NuGet <500 in total), suggesting minimal community adoption. " +
			"When download data is unavailable the signal fires with severity 'unknown'.",
		Fires: func(in Input) (bool, string, map[string]any) {
			// Downloads carries its window; WeeklyDownloads is the
			// fallback for reports written before it existed.
			counted, window := in.Downloads, in.DownloadsWindow
			if counted == nil {
				counted, window = in.WeeklyDownloads, "week"
			}
			if counted == nil {
				return false, "", nil
			}
			dl := *counted
			// Sentinel value -1 means "fetch failed / air-gap" — emit unknown.
			if dl == unknownDownloadsSentinel {
				msg := "Weekly download count unavailable (air-gap or fetch error)."
				if window != "week" {
					msg = "Download count unavailable (air-gap or fetch error)."
				}
				// When CHAINSAW_OFFLINE=1 is set, the operator intentionally
				// disabled upstream fetches — distinguish that from a real
				// fetch failure so the message isn't misleading.
				if isOfflineForSignal() {
					msg = "Weekly download data unavailable (offline mode)."
				}
				// title_override, not just the detail line. The registered
				// title is "Very low download count"; on THIS arm we did
				// not measure the count at all, and a page that renders
				// the title beside a MAINTENANCE badge states as fact the
				// thing the detail says we failed to fetch. Reported on
				// lodash — tens of millions of weekly downloads, shown as
				// low adoption because the fetch failed.
				return true, msg, map[string]any{
					"severity_override": string(SevUnknown),
					"title_override":    "Download count unavailable",
				}
			}
			threshold, registry, ok := unpopularThreshold(in.Ecosystem, window)
			if !ok || dl >= threshold {
				return false, "", nil
			}
			ev := map[string]any{"downloads": dl, "window": window, "threshold": threshold}
			if window == "week" {
				ev["weekly_downloads"] = dl // the key this signal has always carried
			}
			return true, fmt.Sprintf("Package has very few %s on %s.", downloadsWindowPhrase[window], registry), ev
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

// IsPOMMaintainerEco reports whether this ecosystem's maintainer list comes
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
// gates these signals: maint.single_maintainer (P8-11),
// sc.publisher_changed / sc.pom_developer_list_changed (P8-70; the
// sc.first_time_collaborator signal it also gated is deleted), plus the
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
// EXPORTED because core/cli needs the same list for the `--fail-on` severity
// map. Duplicating the ecosystem set there would recreate precisely the defect
// P8-70 was: two sides of one question reading different definitions and
// silently disagreeing. One list, four consumers.
func IsPOMMaintainerEco(eco string) bool {
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
