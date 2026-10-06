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

// WarnTyposquatClearedEstablished records a typosquat hit that was cleared
// because the candidate is itself heavily installed. The message keeps the
// lookalike and the count, so the clearing stays explainable after the
// SupplyChain fields are reset.
const WarnTyposquatClearedEstablished = "typosquat_cleared_established"

// clearEstablishedTyposquat resets a "suspected" typosquat verdict to clean
// when the candidate has at least establishedTyposquatWeeklyDownloads weekly
// downloads.
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
// count (nil) or a failed fetch (-1) clears nothing.
func clearEstablishedTyposquat(r *Report, now time.Time) {
	sc := &r.SupplyChain
	if sc.TyposquatStatus != "suspected" {
		return
	}
	d := r.Maintenance.WeeklyDownloads
	if d == nil || *d < establishedTyposquatWeeklyDownloads {
		return
	}
	r.Observation.Warnings = append(r.Observation.Warnings, Warning{
		Provider: "typosquat",
		Code:     WarnTyposquatClearedEstablished,
		Message: fmt.Sprintf("name resembles %q (%s confidence); cleared: %d weekly downloads",
			sc.TyposquatSimilarTo, sc.TyposquatConfidence, *d),
		At: now,
	})
	sc.TyposquatStatus = "clean"
	sc.TyposquatConfidence = ""
	sc.TyposquatSimilarTo = ""
}
