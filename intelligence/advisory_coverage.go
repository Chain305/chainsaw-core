package intelligence

// advisory_coverage.go closes P8-05: seven ecosystems floored at ALLOW
// because nothing ever looked for a vulnerability in them.
//
// THE DEFECT. huggingface, swift, cocoapods, docker, apt, yum and dnf have
// no bucket in supportedOSVEcosystems, so osvProvider.Supports returns
// false and scanner.go skips it with a bare `continue` — no warning, no
// ProviderTiming, no trace. Vulnerabilities.ScannedAt therefore stays nil,
// SignalsUnavailable stays false, every category starts at
// risk.categoryBase = 100, and resolveVerdict returns
// VerdictAllow — "Package shows no blocking risk signals." The vendor's
// evidence: 27 apt/yum/dnf runs returned a BYTE-IDENTICAL
// `ALLOW 96 (A) / Vulnerability 100 A (0 findings)`, including openssl
// 3.0.2, openssl 1.1.1k, nginx 1.14.1 and bash 4.4.20. Proof it is a
// constant and not a measurement: Alamofire 5.8.0 scores 96 under swift
// and 100 under cocoapods.
//
// The malware provider next door refuses this exact pattern on purpose —
// a lookup that always misses "would silently stamp 'clean' — worse than
// admitting no coverage". The advisory path did what the malware path
// forbids.
//
// TRAP 1 — EMITTING THE WARNING ALONE CHANGES NO VERDICT.
// ProjectToRiskInput has no branch on WarnUnsupported, so an emission site
// with no projection arm is inert. Both halves ship together: the emission
// here and the third unavailability return in risk_projection.go.
//
// TRAP 2 — THE OBVIOUS EMISSION INVERTS THE OPT-IN COVERAGE GATE, AND THIS
// FILE IS ARRANGED SO IT CANNOT. WarnUnsupported ("ecosystem_unsupported")
// is already in core/coverage's notApplicableCodes → StatusNotApplicable →
// Gate never blocks on it. Today a skipped provider leaves NO
// ProviderTimings entry, and coverage/gate.go treats an ABSENT entry as
// StatusUnavailable → Block. So an operator with `core/coverage` opted in
// and mode: closed is ALREADY refusing these pulls, and attributing the
// new warning to a mapped provider name would turn that from blocking to
// affirmatively non-blocking — a silent fail-open on the one feature whose
// entire purpose is to fail closed.
//
// The emission is therefore attributed to `advisory`, a pseudo-provider
// that is deliberately NOT a key of coverage.go's providerToSource map.
// LedgerFromReport skips warnings whose provider it does not recognise, so
// the coverage ledger this wave produces is byte-identical to the one
// before it: no operator's gate changes direction, in either direction.
// TestAdvisoryCoverageWarningDoesNotTouchTheLedger pins that.
//
// The alternative — a new StatusUncovered that Gate treats as blocking —
// was considered and REJECTED for this wave. It would make apt/yum/dnf/
// swift/docker/cocoapods/huggingface a NEW hard block for every opted-in
// org, which is a strictly larger enforcement change than the one this
// wave is measuring, needs its own flip count, and per the plan needs a
// founder decision, a docs/COVERAGE_SOURCES.md row and a release note. It
// is a separable follow-up, and separating it is the point: this change
// moves the VERDICT (allow → unknown, which maps to Monitored, not
// Blocked) and leaves the GATE exactly where it was.
//
// WHY THE TEST IS EVIDENCE-BASED AND NOT `Supports()`-BASED. Keying on
// "the OSV provider does not support this ecosystem" alone would blind the
// Trivy/cveProvider lane, which genuinely covers docker on the proxy path
// (vulnerability_metadata rows written out-of-band by the image scanner).
// The condition below is "no advisory feed structurally covers this
// ecosystem AND no lane produced a scan", so a docker image Trivy really
// did scan keeps its score and one nobody scanned stops pretending.

import "time"

// advisoryCoverageWarningProvider is the Warning.Provider value for the
// no-advisory-source stamp. It is not a real provider — the finding is
// about the ABSENCE of one — so it is named for what it describes.
//
// It must stay OUT of coverage.go's providerToSource map. See trap 2 in
// the file header; TestAdvisoryCoverageWarningDoesNotTouchTheLedger fails
// if it is ever added.
const advisoryCoverageWarningProvider = "advisory"

// ecosystemsWithoutAdvisorySource is the complement of
// supportedOSVEcosystems over the ecosystems this build can be asked
// about. Derived rather than hand-listed so adding an OSV bucket removes
// an ecosystem from the uncovered set with no second edit.
//
// `pub` is deliberately NOT here: it gained OSV coverage in Phase 7 Wave
// 7 and is in supportedOSVEcosystems, so the derivation excludes it
// automatically. That is the whole reason this is derived.
func ecosystemHasAdvisorySource(ecosystem string) bool {
	_, ok := supportedOSVEcosystems[normalizeEcosystemKey(ecosystem)]
	return ok
}

// knownEcosystems is the DOMAIN over which the complement above is taken:
// the ecosystems this build can be asked about at all.
//
// It exists because the complement was previously taken over EVERY string,
// which made a value that is not an ecosystem — a repository NAME — look
// like an uncovered ecosystem. In the 2026-08-25 production export that is
// `maven-hosted`, `npmjs-hosted`, `rubygems-hosted` and `crates-hosted`: an
// org's own hosted registries. The packages under them are ordinary maven,
// npm, rubygems and cargo packages and they DO have advisory coverage, so
// "no advisory source in this build covers ecosystem maven-hosted" is a
// false statement about coverage. It is evidence of a ROUTING bug, and the
// fix for a routing bug belongs where the routing happens.
//
// PHASE 7 WAVE 6 ADJUDICATED THIS EXACT CLASS and the precedent is binding
// (docs/plan_qa_phase7_remediation.md, "Wave 6 — the maven-hosted ecosystem,
// correctly diagnosed"):
//
//   - `maven-hosted` is a repository NAME, not an ecosystem. The
//     `repositories` table carries name and format separately and the
//     deployment names hosted repos `<format>-<flavour>`.
//   - `osv.CanonicalEcosystem("maven-hosted") == ""` is CORRECT and
//     load-bearing; teaching the canonicaliser about it would make a
//     repo-name leak look SUPPORTED instead of failing loudly, and would
//     not generalise.
//   - The right fix is upstream: the ecosystem must carry `repo.Format`.
//
// So nothing here maps a name to a format, and nothing here parses one.
// Parsing could not work even in principle: the production names are
// `npmjs-hosted` (format `npm`), `crates-hosted` (format `cargo`) and
// `rubygems-hosted` (format `rubygems`), so the prefix is not the format.
// Name to format is a database fact.
//
// What this map does is narrower, and note what it does NOT do: it does not
// let the row off. A report whose ecosystem is a repository name was scanned
// by NOTHING — every provider's Supports() rejected the string — so its
// ALLOW 96 was a constant and Unknown is the correct verdict. Suppressing
// the marker would be a fail-open — the P8-34 refutation test
// (TestUnrecognisedEcosystemIsNotSilentlyScored) exists to catch exactly
// that, and it does.
//
// What the map decides is the WORDING, which is the part that was false.
// "No advisory source in this build covers ecosystem maven-hosted" tells an
// operator that Maven is unsupported, which is untrue and unactionable.
// "maven-hosted is not an ecosystem, it looks like a repository name" tells
// them the routing is wrong, which is both true and fixable — and the fix
// is the one Wave 6 named, upstream, in the code that populates the field.
//
// Derived from the provider Supports() tables rather than hand-listed, for
// the reason Wave 6 gave when it found two hand-maintained copies of the
// same fact: an ecosystem added to any provider joins the domain with no
// second edit. supportedCVEEcosystems is the widest of them and is what
// carries apt/yum/dnf/swift; the others are unioned so a future ecosystem
// wired into only one lane still counts.
//
// TestRepositoryNamesAreNotEcosystems pins that no repository name is a
// member of any of the source maps.
var knownEcosystems = func() map[string]struct{} {
	out := make(map[string]struct{}, 32)
	for _, src := range []map[string]struct{}{
		supportedCVEEcosystems,
		supportedRegistryEcosystems,
		supportedOSVEcosystems,
		definitiveMalwareWhitelist,
		adjacentSuspectWhitelist,
	} {
		for eco := range src {
			out[normalizeEcosystemKey(eco)] = struct{}{}
		}
	}
	return out
}()

// isKnownEcosystem reports whether the string names an ecosystem this build
// can be asked about, as opposed to a repository name, an empty string, or
// any other value that reached Key.Ecosystem by mistake.
func isKnownEcosystem(ecosystem string) bool {
	_, ok := knownEcosystems[normalizeEcosystemKey(ecosystem)]
	return ok
}

// noAdvisorySourceMessage is the Warning.Message for the stamp. Two shapes,
// because there are two different facts and only one of them is about
// advisory coverage. See knownEcosystems.
func noAdvisorySourceMessage(ecosystem string) string {
	eco := normalizeEcosystemKey(ecosystem)
	if isKnownEcosystem(eco) {
		return "no advisory source in this build covers ecosystem " + eco
	}
	if eco == "" {
		return "no ecosystem was recorded for this coordinate, so no provider ran"
	}
	return "\"" + eco + "\" is not an ecosystem this build recognises, so no " +
		"provider ran; if it is a repository name the ecosystem field should " +
		"carry the repository FORMAT instead"
}

// markNoAdvisoryCoverage stamps WarnUnsupported on a merged Report whose
// ecosystem has no advisory source AND whose vulnerability section was
// never populated by any lane. Reports whether it stamped.
//
// Called post-merge, before ComputeTrustScoreForOrg, because the second
// half of the condition is a fact about the MERGED report: the OSV lane is
// structurally absent, but the Trivy-backed cveProvider may still have
// supplied rows, and a coordinate that really was scanned must keep its
// score.
//
// Idempotent — a Report already carrying the code is left alone, so the
// refresh path does not accumulate duplicates.
func markNoAdvisoryCoverage(r *Report, at time.Time) bool {
	if r == nil {
		return false
	}
	if ecosystemHasAdvisorySource(r.Identity.Ecosystem) {
		return false
	}
	// A vulnerability lane DID answer for this coordinate. ScannedAt is
	// the tree's existing "a CVE scan actually completed" marker — the
	// same discriminator risk_projection.go uses for VulnDataAvailable —
	// so this is the one fact that distinguishes "docker image Trivy
	// scanned" from "docker image nobody scanned".
	if r.Vulnerabilities.ScannedAt != nil {
		return false
	}
	for _, w := range r.Observation.Warnings {
		if w.Code == WarnUnsupported {
			return false
		}
	}
	r.Observation.Warnings = append(r.Observation.Warnings, Warning{
		Provider: advisoryCoverageWarningProvider,
		Code:     WarnUnsupported,
		Message:  noAdvisorySourceMessage(r.Identity.Ecosystem),
		At:       at,
	})
	return true
}

// noAdvisorySourceReason is the operator-facing explanation attached to
// the unavailable evaluation, and the third arm of ProjectToRiskInput's
// unavailability set.
//
// Phrased as a clause to match its two siblings: it is rendered inside
// UnavailableEvaluation's summary sentence, so no leading capital, no
// trailing period, no em dash.
//
// It says "no advisory source", not "unsupported ecosystem", because the
// rest of the scan DID run — registry metadata, malware, provenance and
// typosquat all have coverage for several of these ecosystems. What is
// missing is the vulnerability lane specifically, and telling the operator
// that is what lets them decide whether they care.
func noAdvisorySourceReason(r *Report) (string, bool) {
	for _, w := range r.Observation.Warnings {
		if w.Code != WarnUnsupported {
			continue
		}
		// Two facts, two clauses. Claiming a COVERAGE gap for a string
		// that is not an ecosystem is false — `maven-hosted` packages are
		// ordinary Maven packages with full advisory coverage — and it
		// points the reader at the wrong thing to fix. The verdict is the
		// same either way: nothing ran, so nothing is known.
		if !isKnownEcosystem(r.Identity.Ecosystem) {
			return "the recorded ecosystem is not one this build recognises, " +
				"so no provider ran at all; this is a routing problem — most " +
				"likely a repository NAME where the repository FORMAT belongs " +
				"— and not a statement about what this build can cover", true
		}
		return "no advisory source in this build covers this ecosystem, " +
			"so no vulnerability was looked for; this is a coverage gap, " +
			"not a clean result", true
	}
	return "", false
}
