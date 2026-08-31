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
//
// P9 P0-C — `ScannedAt != nil` WAS NECESSARY BUT NOT SUFFICIENT, AND
// COCOAPODS FELL THROUGH THE GAP FOR A WHOLE EPOCH.
//
// The paragraph above is right about docker and wrong about the shape of
// the discriminator, and cocoapods is where the difference showed. Live
// production at matcherEpoch 8, written 2026-08-31:
//
//	apt / dnf / yum / huggingface / swift : unknown        (fixed)
//	docker                                : 71 unknown, 19 allow 95-97
//	cocoapods                             :  8 unknown, 61 allow 97-100
//
// The 61 are the same defect this file was written to close, one layer
// down. `internal/hooks.selectTrivialTarget` has an explicit `cocoapods`
// case, so a pod pulled through the proxy IS handed to the vendored Trivy
// scanner; `internal/server.recordTrivialVulnerabilityMetadata` then
// writes a vulnerability_metadata row for it, clean or not; and
// provider_cve.go stamps `Vulnerabilities.ScannedAt` off the mere
// existence of that row. Nothing in that chain ever established that the
// trivy-db bundle HAS a cocoapods bucket. An empty answer from a lane
// that could not have answered was recorded as "scanned, nothing found"
// and graded ALLOW 100 — precisely the thing the malware provider next
// door refuses on purpose, and precisely what this file's own header
// calls "worse than admitting no coverage".
//
// swift and huggingface escaped only by accident: selectTrivialTarget has
// no case for either, so no row is ever written and ScannedAt stays nil.
// They are not fixed, they are unrouted. The tester's published proof —
// swift Alamofire 5.8.0 vs cocoapods Alamofire 5.8.0, same package, two
// ecosystems, two verdicts — is that accident, not a working control.
//
// TWO REJECTED FIXES, AND WHY.
//
//	(a) Gate the early return on ScannerDBDigest naming a scanner whose
//	    advisory DB covers the ecosystem. Rejected: the digest is a
//	    free-form string minted by the ROOT module and unreadable from
//	    here — an OCI layer sha that rotates on every trivy-db refresh
//	    (server_lifecycle.go currentTrivyDBDigest), the literal
//	    "docker-eol-v1" (docker_metadata.go), "osv-bundle" (provider_osv.go),
//	    and "" on every legacy row. Deciding coverage by sniffing it is
//	    the same string-sniff antipattern the plan condemns in the
//	    `registry.npmjs.org` 404 detector, and it answers a rotating value,
//	    not a fact.
//
//	(b) Narrow supportedCVEEcosystems to drop cocoapods/swift/huggingface.
//	    Rejected as a FAIL-OPEN. cveProvider is a pure READER: its
//	    whitelist means "if a row exists for this coordinate, read it",
//	    not "this ecosystem has advisory coverage". Dropping an ecosystem
//	    there discards rows that DO carry findings — and both of those
//	    ecosystems can carry them. The vendored engine has a first-class
//	    ecosystem.Cocoapods bucket with a rubygems comparer wired in
//	    internal/vulnscan/internal/detector/driver.go:108-111, and GHSA
//	    publishes a Swift ecosystem that vulnsrc/vulnerability.go:255-258
//	    normalises package names for. Refusing to read a positive row
//	    would turn a real CVE into VerdictUnknown. It also silently
//	    shrinks knownEcosystems below (that domain is derived from these
//	    maps) and breaks the L-02 premise guard in provider_osv_test.go,
//	    whose comment says in terms: do not just update the assertions.
//
// WHAT SHIPPED INSTEAD: NAME THE MISSING FACT.
//
// `ScannedAt` answers "did a lane run". Nothing answered "did a lane that
// could have found something run", so the one discriminator was carrying
// two questions and could only answer the first. That second fact now has
// its own table, scannerAdvisedEcosystems, next to the first — and the
// early return needs BOTH: a completed scan AND a reason to believe the
// scan could have produced a finding.
//
// The second half is a disjunction, not a whitelist test, because the
// asymmetry matters and this codebase already has a name for it. An empty
// result from an unverified lane is absence of evidence (isDefiniteAbsence,
// report.go) and must not be read as evidence of absence. A NON-empty
// result is evidence of presence and is dispositive whatever the table
// says — so a cocoapods row that really does carry a CVE keeps its
// verdict and can still block. Only the empty answer is downgraded, and
// only to Unknown (Monitored), never to Blocked.
//
// KNOWN AND DELIBERATE CONSERVATISM. A genuinely-scanned, genuinely-clean
// cocoapods pod now reads Unknown rather than ALLOW 100. That is the
// honest answer while nobody has verified the bundle actually ships a
// cocoapods bucket, and it is one line to undo the day somebody does:
// add the ecosystem to scannerAdvisedEcosystems with the evidence. The
// table is the place that claim gets recorded, which is the point of
// having it.

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

// scannerAdvisedEcosystems is the second fact P0-C had to add: of the
// ecosystems with no OSV bucket, which ones does the Trivy-backed scanner
// lane STRUCTURALLY advise on — i.e. for which of them does an empty
// result mean "looked and found nothing" rather than "could not look"?
//
// Membership is a claim about two things at once, and an entry needs
// both:
//
//  1. the proxy actually routes the format to a scanner
//     (internal/hooks.selectTrivialTarget for registry pulls,
//     the docker layer scanner for image pulls), and
//  2. the advisory database that scanner consults actually has a bucket
//     for the resulting ecosystem.
//
// DOCKER IS THE ONLY MEMBER, and it earns it on both counts. Image pulls
// go through hooks.OCIInspector, which extracts real installed packages
// out of the layers (apk / dpkg / rpm sqlite+BDB+ndb) and looks each one
// up through hooks.AdvisoryDB against the OS buckets upstream trivy-db
// genuinely ships — "alpine 3.18", "debian 12", "Red Hat CPE" and the
// rest, enumerated in internal/trivydb/updater.go's Phase-4 note. A clean
// docker row is a real negative.
//
// NOT MEMBERS, and none of them is an oversight:
//
//   - cocoapods — routed (selectTrivialTarget has the case) but the
//     bundle's cocoapods bucket is unverified. Routed-but-unverified is
//     exactly the state that produced 61 ALLOW 97-100 rows, so it is the
//     state this table exists to exclude.
//   - swift, huggingface — no case in selectTrivialTarget at all, so
//     nothing is routed and no row is ever written. They read Unknown
//     today because they are UNROUTED, not because they are covered.
//   - apt, yum, dnf — same: trivy-db has excellent Debian/RHEL coverage,
//     but no repository-format case routes an apt/yum/dnf pull into it,
//     and there is no distro-release context to key the lookup on. Adding
//     them here would grade an unrouted ecosystem as scanned.
//
// This is hand-listed and not derived, unlike knownEcosystems below, and
// that is deliberate: there is nothing in this module to derive it FROM.
// It asserts what a third-party bundle contains and what a different Go
// module routes, neither of which core/intelligence can observe. A
// derivation would have to invent the fact it claims to read.
//
// TestScannerAdvisedEcosystemsIsAJustifiedSubset pins the shape.
var scannerAdvisedEcosystems = map[string]struct{}{
	"docker": {},
}

// ecosystemHasScannerAdvisorySource reports whether a completed scan in
// this ecosystem is capable of having produced a finding.
func ecosystemHasScannerAdvisorySource(ecosystem string) bool {
	_, ok := scannerAdvisedEcosystems[normalizeEcosystemKey(ecosystem)]
	return ok
}

// vulnerabilityScanCouldHaveFound reports whether this report's completed
// vulnerability scan is worth anything as a NEGATIVE. Two ways to qualify:
//
//   - the ecosystem is one the scanner lane structurally advises on, so
//     an empty result is a real "nothing found"; or
//   - the scan is not empty. Evidence of presence is dispositive no
//     matter what the coverage table claims — a lane that surfaced a CVE
//     for this coordinate demonstrably could look at it, and downgrading
//     that to Unknown would be a fail-open that costs a block.
//
// The asymmetry is the whole point, and it is the isDefiniteAbsence
// doctrine applied in the only direction it holds: absence of evidence is
// not evidence of absence, but presence of evidence is.
//
// A veto-emptied section (recomputeVulnAggregates in scanner.go leaves
// ScannedAt set with the CVE list cleared) reads as empty here and so
// takes the conservative arm. That is a knowing residual: it costs an
// Unknown on a coordinate a contributor positively cleared, which is the
// safe direction, and ClearedCVEs is a per-contributor merge channel
// rather than a persisted fact of the merged report, so keying on it here
// would be keying on something that is usually already gone.
func vulnerabilityScanCouldHaveFound(r *Report) bool {
	if ecosystemHasScannerAdvisorySource(r.Identity.Ecosystem) {
		return true
	}
	return r.Vulnerabilities.IsVulnerable || len(r.Vulnerabilities.CVEs) > 0
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

// noAdvisorySourceMessage is the Warning.Message for the stamp. THREE
// shapes, because there are three different facts and only one of them is
// about advisory coverage in the plain sense. See knownEcosystems for the
// repository-name shape, and the P0-C section of the file header for the
// scanned-but-unverified one.
//
// The wording matters for the same reason Wave 6 said it does: the verdict
// is Unknown in all three cases, but the sentence tells an operator which
// thing to go and fix, and a sentence that names the wrong thing is worse
// than useless. "No vulnerability was looked for" is TRUE of an unrouted
// ecosystem and FALSE of a cocoapods pod that Trivy really did open — for
// that one the gap is the database, not the scan.
func noAdvisorySourceMessage(r *Report) string {
	eco := normalizeEcosystemKey(r.Identity.Ecosystem)
	if isKnownEcosystem(eco) {
		if r.Vulnerabilities.ScannedAt != nil {
			return "a vulnerability scan completed for ecosystem " + eco +
				" but no advisory database in this build is known to cover it, " +
				"so the empty result is not a clean result"
		}
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
// never populated by a lane that could have found something. Reports
// whether it stamped.
//
// Called post-merge, before ComputeTrustScoreForOrg, because the second
// half of the condition is a fact about the MERGED report: the OSV lane is
// structurally absent, but the Trivy-backed cveProvider may still have
// supplied rows, and a coordinate that really was scanned must keep its
// score.
//
// "Really was scanned" is two facts, not one — see
// vulnerabilityScanCouldHaveFound. A row exists is the first; the lane
// that wrote it had a bucket for this ecosystem, or actually found
// something, is the second.
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
	// A vulnerability lane DID answer for this coordinate, AND the answer
	// is worth something.
	//
	// ScannedAt is the tree's existing "a CVE scan actually completed"
	// marker — the same discriminator risk_projection.go uses for
	// VulnDataAvailable — and it is necessary here. It is NOT sufficient,
	// and P0-C is the bill for treating it as if it were: provider_cve.go
	// stamps it off the mere existence of a vulnerability_metadata row, so
	// a scanner with no advisory bucket for the ecosystem stamped "scanned"
	// over an answer it was never able to give. See the P0-C section of the
	// file header for the 61 cocoapods rows that produced.
	if r.Vulnerabilities.ScannedAt != nil && vulnerabilityScanCouldHaveFound(r) {
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
		Message:  noAdvisorySourceMessage(r),
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
		// Three facts, three clauses. Claiming a COVERAGE gap for a string
		// that is not an ecosystem is false — `maven-hosted` packages are
		// ordinary Maven packages with full advisory coverage — and it
		// points the reader at the wrong thing to fix. The verdict is the
		// same in all three cases: nothing usable is known.
		if !isKnownEcosystem(r.Identity.Ecosystem) {
			return "the recorded ecosystem is not one this build recognises, " +
				"so no provider ran at all; this is a routing problem — most " +
				"likely a repository NAME where the repository FORMAT belongs " +
				"— and not a statement about what this build can cover", true
		}
		// P0-C. A scan DID run here, so "no vulnerability was looked for"
		// would be false and would send the operator to check the routing,
		// which is fine. What is missing is the advisory data behind the
		// scanner, and an empty answer from a database with no bucket for
		// this ecosystem carries no information either way.
		if r.Vulnerabilities.ScannedAt != nil {
			return "a vulnerability scan completed, but no advisory database " +
				"in this build is known to cover this ecosystem, so the empty " +
				"result carries no information; this is a coverage gap in the " +
				"advisory data, not a clean result", true
		}
		return "no advisory source in this build covers this ecosystem, " +
			"so no vulnerability was looked for; this is a coverage gap, " +
			"not a clean result", true
	}
	return "", false
}
