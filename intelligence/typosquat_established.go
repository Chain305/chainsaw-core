package intelligence

import (
	"fmt"
	"time"

	"github.com/chain305/chainsaw-core/risk"
)

// The establishment lines live in core/risk (established.go), where the
// established-package damper uses them too; one definition, so the
// typosquat clear and the damper cannot disagree about which packages are
// established. The measurements behind each line are documented there.
const (
	establishedTyposquatWeeklyDownloads = risk.EstablishedWeeklyDownloads
	establishedTyposquat90DayDownloads  = risk.Established90DayDownloads
	establishedTyposquatMinVersions     = risk.EstablishedMinVersions
)

// WarnTyposquatClearedEstablished records a typosquat hit that was cleared
// because the candidate is itself established. The message keeps the
// lookalike and the reason, so the clearing stays explainable after the
// SupplyChain fields are reset.
const WarnTyposquatClearedEstablished = "typosquat_cleared_established"

// clearEstablishedTyposquat resets a "suspected" typosquat verdict to clean
// when the candidate is established (risk.EstablishedReason: 100,000 weekly
// downloads on npm/PyPI, 75,000 per 90 days on crates.io, or 50 versions
// over two years). A typosquat claim about an established package is wrong
// rather than weak, so this clears it outright; the damper in core/risk only
// halves the other hygiene signals.
//
// It runs after every provider has finished because the typosquat provider is
// name-only and runs in parallel with the registry metadata that carries the
// download count and release history. It edits the REPORT, not just the risk
// input: the UI, the policy condition isSuspectedTyposquat, supply-chain
// alerts, the SBOM export and the stored is_typosquat column all read
// SupplyChain.TyposquatStatus.
//
// The name-only sibling (core/typosquat, establishedCandidate) clears names on
// the reviewed download ranking; this one covers everything the registry
// metadata can establish. Missing data, or a failed fetch (-1), clears
// nothing.
func clearEstablishedTyposquat(r *Report, now time.Time) {
	sc := &r.SupplyChain
	if sc.TyposquatStatus != "suspected" {
		return
	}
	m := r.Maintenance
	why := risk.EstablishedReason(downloadsCount(m.Downloads), downloadsWindow(m.Downloads),
		m.WeeklyDownloads, projectedVersionCount(r), m.FirstPublishedAt, now)
	if why == "" {
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
