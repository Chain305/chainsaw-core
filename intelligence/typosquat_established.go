package intelligence

import (
	"fmt"
	"strings"
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

// The long-lived lines. Registries delete a squat once it is reported, and
// squats are reported in days to months; jeIlyfish (PyPI, 2018-12 to
// 2019-12) is the famous outlier at about a year. Rev6 stratum E (2026-10-10)
// quarantined 11 benign packages one edit from a popular name, every one on
// its registry since 2010-2018: jamespath (the original Ruby JMESPath, 2013),
// litc, redrock, bst, set_version, hacs, pwsgi, pyisa, tta, and rage, whose
// owner also publishes the age crate it "squats". None is popular enough for
// the download lines, and only rage has a long release history.
//
// Both halves are required. The package age is the survival evidence; the
// version age stops a sleeper, a lookalike name registered years ago that
// ships its payload in a fresh release, from inheriting that evidence.
//
// The ages themselves are risk.EstablishedLongLived* so that the offline
// guard's table clear (core/cli/guard_established.go) decides the SAME line
// with the SAME numbers — the guard had no copy of any clear rule at all and
// blocked 28 established packages before this shared definition existed.

// WarnTyposquatClearedEstablished records a typosquat hit that was cleared
// because the candidate is itself established. The message keeps the
// lookalike and the reason, so the clearing stays explainable after the
// SupplyChain fields are reset.
const WarnTyposquatClearedEstablished = "typosquat_cleared_established"

// clearEstablishedTyposquat resets a "suspected" typosquat verdict to clean
// when the candidate is established (risk.EstablishedReason: 100,000 weekly
// downloads on npm/PyPI, 75,000 per 90 days on crates.io, or 50 versions
// over two years) or long-lived (longLivedReason). A typosquat claim about an established package is wrong
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
		why = longLivedReason(r, now)
	}
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

// longLivedReason reports why a candidate has outlived any squat, or "" when
// it has not: its first release is at least five years old and the scanned
// version at least one. Missing dates and NuGet's 1900 unlisted sentinel
// prove nothing. npm's "0.0.1-security" holding package is excluded: it is
// what npm leaves behind when it removes a squat, so its age is the removal
// date, not survival.
//
// The AGE LINE ITSELF is risk.EstablishedClear — the one definition the
// offline guard's table clear also calls — so the server and the guard
// cannot diverge on the numbers again. What stays here is the half the guard
// table cannot express: the report-specific exclusions (the sentinel year,
// the holding-package version suffix) and the mapping of Report fields onto
// an EstablishedRow. Deliberately still NOT in the damper
// (risk.EstablishedReason): the damper softens every hygiene signal, and age
// alone does not make a package well-kept, only not a squat.
func longLivedReason(r *Report, now time.Time) string {
	first, pub := r.Maintenance.FirstPublishedAt, r.Release.PublishedAt
	if first == nil || pub == nil || first.Year() <= 1901 || pub.Year() <= 1901 {
		return ""
	}
	if strings.HasSuffix(strings.ToLower(r.Identity.Version), "-security") {
		return ""
	}
	// WeeklyDownloads 0 and VersionCount 0 mean this row can only clear
	// through the long-lived line — exactly the question being asked.
	reason, cleared := risk.EstablishedClear(risk.EstablishedRow{
		FirstPublished: *first,
		LastPublished:  *pub,
	}, now)
	if !cleared {
		return ""
	}
	return reason
}
