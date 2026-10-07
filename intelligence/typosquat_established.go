package intelligence

import (
	"fmt"
	"time"
)

// establishedTyposquatWeeklyDownloads is the candidate's OWN weekly download
// count at or above which a name-similarity hit is not a typosquat.
//
// Why 100,000. A squat's traffic is the typo traffic it steals from its
// target, a small fraction of the target's. Across every typosquat-flagged
// row in production (2026-10-06, 85 high/medium rows) the busiest real squat
// was `expres` at 8,167/week; the false positives this clears start at
// `csrf` 1.28M and run to `gaxios` 130M, with `mpath`/`mquery` at ~7.5M. The
// threshold sits more than 10x above the strongest squat and 10x below the
// smallest of those. It does not reach `chan` (25,517/week, a 2013 package
// flagged against `chai`): no download line separates it from squat traffic
// without also clearing squats.
const establishedTyposquatWeeklyDownloads = 100_000

// establishedTyposquat90DayDownloads is the same line for crates.io, which
// publishes only a 90-day count (DownloadWindow90Days), so the weekly rule
// above could never clear a crate.
//
// Why 75,000. The busiest crates.io squat on record, faster_log (a fast_log
// lookalike, deleted 2025-09-24), drew 7,181 downloads over its whole ~4
// month life; 75,000 is more than 10x that even if all of it had landed in
// one 90-day window. The production false positives it clears start at
// termbg (94,361) and include typedmap (204,545, flagged against type-map,
// quarantined in the feldera/feldera scan 2026-10-07) and actix-ws (542,767).
// It does not reach s2-common (42,887) or dbsp (24,227): no line separates
// those from squat traffic with the same margin.
const establishedTyposquat90DayDownloads = 75_000

// establishedTyposquatMinVersions and establishedTyposquatMinAge are the
// release-history line, for a real package whose download count no line can
// separate from squat traffic.
//
// Why 50 versions over 2 years. Registries delete squats within weeks to
// months of discovery, and a squat ships what it needs to look plausible:
// across every typosquat-flagged row in production (2026-10-07) the real and
// suspected squats carry 1 (chalkk, lodahs), 5 (expres), 6 (chan), 27
// (bmp-ts) and 28 (avada) versions, and the deleted malicious rows carry no
// history at all. The false positive this exists for is dbsp, Feldera's
// incremental-computation engine: 299 versions since 2023-08-23 and 24,227
// downloads per 90 days, quarantined as a squat of dasp. The age half stops a
// burst of 50 publishes in one week from qualifying; s2-common (60 versions,
// first published 2026-01) stays flagged for that reason.
const (
	establishedTyposquatMinVersions = 50
	establishedTyposquatMinAge      = 2 * 365 * 24 * time.Hour
)

// WarnTyposquatClearedEstablished records a typosquat hit that was cleared
// because the candidate is itself heavily installed. The message keeps the
// lookalike and the count, so the clearing stays explainable after the
// SupplyChain fields are reset.
const WarnTyposquatClearedEstablished = "typosquat_cleared_established"

// clearEstablishedTyposquat resets a "suspected" typosquat verdict to clean
// when the candidate meets its registry window's established download line
// (100,000 a week on npm/PyPI, 75,000 per 90 days on crates.io), or has a
// long release history (establishedHistory).
//
// It runs after every provider has finished because the typosquat provider is
// name-only and runs in parallel with the registry metadata that carries the
// download count. It edits the REPORT, not just the risk input: the UI, the
// policy condition isSuspectedTyposquat, supply-chain alerts, the SBOM export
// and the stored is_typosquat column all read SupplyChain.TyposquatStatus.
//
// The name-only sibling (core/typosquat, establishedCandidate) clears names on
// the reviewed download ranking; this one covers popular names below that
// cut, such as echarts and nprogress, whenever the count is known. A missing
// count (nil) or a failed fetch (-1) clears nothing. Each registry window has
// its own line (establishedDownloads).
func clearEstablishedTyposquat(r *Report, now time.Time) {
	sc := &r.SupplyChain
	if sc.TyposquatStatus != "suspected" {
		return
	}
	var why string
	if count, window, ok := establishedDownloads(r.Maintenance); ok {
		why = fmt.Sprintf("%d downloads per %s", count, window)
	} else if n, since, ok := establishedHistory(r, now); ok {
		why = fmt.Sprintf("%d versions since %s", n, since.Format("2006-01-02"))
	} else {
		return
	}
	r.Observation.Warnings = append(r.Observation.Warnings, Warning{
		Provider: "typosquat",
		Code:     WarnTyposquatClearedEstablished,
		Message: fmt.Sprintf("name resembles %q (%s confidence); cleared: %s",
			sc.TyposquatSimilarTo, sc.TyposquatConfidence, why),
		At: now,
	})
	sc.TyposquatStatus = "clean"
	sc.TyposquatConfidence = ""
	sc.TyposquatSimilarTo = ""
}

// establishedDownloads reports the candidate's download count and window when
// it meets that window's established line. Only the measured windows have a
// line: Packagist's month and the RubyGems/NuGet all-time totals clear nothing
// until squat traffic there is measured too.
func establishedDownloads(m MaintenanceSection) (int, string, bool) {
	if d := m.Downloads; d != nil && d.Window == DownloadWindow90Days {
		return d.Count, d.Window, d.Count >= establishedTyposquat90DayDownloads
	}
	if d := m.WeeklyDownloads; d != nil && *d >= establishedTyposquatWeeklyDownloads {
		return *d, DownloadWindowWeek, true
	}
	return 0, "", false
}

// establishedHistory reports the version count and first publish when the
// candidate has at least establishedTyposquatMinVersions releases and its
// first was at least establishedTyposquatMinAge before now. An unknown first
// publish clears nothing.
//
// The count is projectedVersionCount, not Maintenance.VersionCount: the
// latter has only a premium writer, so a core build holding the full
// timeline would read 0.
func establishedHistory(r *Report, now time.Time) (int, time.Time, bool) {
	n := projectedVersionCount(r)
	if r.Maintenance.FirstPublishedAt == nil || n < establishedTyposquatMinVersions {
		return 0, time.Time{}, false
	}
	first := *r.Maintenance.FirstPublishedAt
	return n, first, now.Sub(first) >= establishedTyposquatMinAge
}
