package intelligence

// P8-05 — an ecosystem with no advisory source must resolve to
// VerdictUnknown, never VerdictAllow.
//
// Plus the P8-57 rail, which this change makes load-bearing: an Unknown
// evaluation's Overall 0 must never be projected as a KNOWN trust score.

import (
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/coverage"
	"github.com/chain305/chainsaw-core/risk"
)

// uncoveredEcosystems is the seven the vendor measured, spelled as a
// literal rather than derived, so that the derivation in
// ecosystemHasAdvisorySource is checked against an independent statement
// of the same fact rather than against itself.
var uncoveredEcosystems = []string{
	"huggingface", "swift", "cocoapods", "docker", "apt", "yum", "dnf",
}

func newUncoveredReport(eco, pkg, ver string) *Report {
	r := &Report{}
	r.Identity.Ecosystem = eco
	r.Identity.Package = pkg
	r.Identity.Version = ver
	// Load it with the packument-level facts these scans really do
	// collect. Without the fix these are exactly what produced the
	// 96-100 A grades: real maintainer and release data, and a
	// vulnerability category that nothing ever looked at.
	r.Maintenance.MaintainerCount = 3
	r.Maintenance.Stars = 900
	r.Metadata.LicenseExpression = "Apache-2.0"
	return r
}

func TestUncoveredEcosystemResolvesToUnknown(t *testing.T) {
	at := time.Unix(0, 0)
	for _, eco := range uncoveredEcosystems {
		t.Run(eco, func(t *testing.T) {
			r := newUncoveredReport(eco, "openssl", "3.0.2")
			if !markNoAdvisoryCoverage(r, at) {
				t.Fatalf("%s has no OSV bucket but was not marked", eco)
			}
			ev := risk.EvaluatePackage(ProjectToRiskInput(r), risk.Options{})
			if ev.Verdict != risk.VerdictUnknown {
				t.Fatalf("verdict = %q (overall %d), want unknown — "+
					"27 apt/yum/dnf runs returned a byte-identical ALLOW 96 (A) "+
					"because nothing ever looked for a vulnerability",
					ev.Verdict, ev.RolledUp.Overall)
			}
		})
	}
}

// The other side of the rail: an ecosystem WITH an advisory source must be
// untouched, including pub, which gained OSV coverage in Phase 7 Wave 7
// and is not part of this group.
func TestCoveredEcosystemIsNotMarked(t *testing.T) {
	at := time.Unix(0, 0)
	for _, eco := range []string{"npm", "pypi", "pip", "maven", "gradle",
		"cargo", "rubygems", "nuget", "composer", "go", "gomod", "pub",
		"yarn", "bun", "NPM", "PyPI"} {
		r := newUncoveredReport(eco, "left-pad", "1.0.0")
		if markNoAdvisoryCoverage(r, at) {
			t.Errorf("%s has an advisory source but was marked uncovered", eco)
		}
	}
}

// A docker coordinate a vulnerability lane REALLY scanned keeps its
// score. This is what stops the fix blinding the Trivy-backed cveProvider
// on the proxy path, where images do get scanned out of band:
// hooks.OCIInspector extracts the installed apk/dpkg/rpm packages out of
// the layers and looks each one up against the OS buckets upstream
// trivy-db genuinely ships, so a clean docker row is a real negative.
func TestScannedDockerCoordinateIsNotMarked(t *testing.T) {
	at := time.Unix(0, 0)
	r := newUncoveredReport("docker", "nginx", "1.14.1")
	scanned := at
	r.Vulnerabilities.ScannedAt = &scanned
	if markNoAdvisoryCoverage(r, at) {
		t.Error("a scanned docker coordinate was marked uncovered — the " +
			"Trivy image lane would be blinded")
	}
}

// ---------------------------------------------------------------------------
// P9 P0-C — the cocoapods regression, seeded from the LIVE SHAPE
// ---------------------------------------------------------------------------

// newLiveCocoapodsShape reproduces what production actually persisted: the
// exact row class behind `cocoapods: 8 unknown, 61 allow 97-100` at
// matcherEpoch 8, written 2026-08-31 05:45.
//
// Every field here is load-bearing and matches a fact in the chain:
//
//   - ecosystem cocoapods, which HAS a case in
//     internal/hooks.selectTrivialTarget, so the proxy really did route
//     the pull to the vendored Trivy scanner;
//   - ScannedAt set, because internal/server.recordTrivialVulnerabilityMetadata
//     wrote a vulnerability_metadata row for the result and
//     provider_cve.go stamps ScannedAt off that row's existence;
//   - zero CVEs and IsVulnerable false, because the scanner had no
//     cocoapods bucket to answer from and so returned clean;
//   - NO ecosystem_unsupported warning, which is what the production
//     export showed and what proves the marker never fired.
//
// The package is the tester's published proof: swift Alamofire 5.8.0
// against cocoapods Alamofire 5.8.0, same package, two ecosystems, two
// verdicts. Only the accident that selectTrivialTarget has no `swift`
// case made the swift half look correct.
func newLiveCocoapodsShape(at time.Time) *Report {
	r := newUncoveredReport("cocoapods", "Alamofire", "5.8.0")
	scanned := at
	r.Vulnerabilities.ScannedAt = &scanned
	r.Vulnerabilities.IsVulnerable = false
	r.Vulnerabilities.CVEs = nil
	return r
}

// The regression itself. A clean scan from a lane with no advisory bucket
// for the ecosystem is absence of evidence, not evidence of absence, and
// must resolve to Unknown rather than to the ALLOW 97-100 production has
// been serving.
func TestCleanScanWithoutAStructuralAdvisorySourceIsUncovered(t *testing.T) {
	at := time.Unix(0, 0)
	r := newLiveCocoapodsShape(at)

	// Precondition: this is the state that used to take the early return.
	if r.Vulnerabilities.ScannedAt == nil {
		t.Fatal("precondition: the live shape carries a completed scan")
	}
	for _, w := range r.Observation.Warnings {
		if w.Code == WarnUnsupported {
			t.Fatal("precondition: the live rows carry NO ecosystem_unsupported stamp")
		}
	}

	if !markNoAdvisoryCoverage(r, at) {
		t.Fatal("cocoapods + ScannedAt + zero CVEs was not marked — this is " +
			"the live shape of the 61 production rows grading ALLOW 97-100 " +
			"off a scanner with no cocoapods bucket (P9 P0-C)")
	}

	ev := risk.EvaluatePackage(ProjectToRiskInput(r), risk.Options{})
	if ev.Verdict != risk.VerdictUnknown {
		t.Fatalf("verdict = %q (overall %d), want unknown", ev.Verdict, ev.RolledUp.Overall)
	}
	if ev.RolledUp.Overall >= 95 {
		t.Fatalf("overall = %d — an unlooked-at coordinate must not grade in "+
			"the 95-100 band the defect produced", ev.RolledUp.Overall)
	}

	// Wording, on the Wave 6 precedent: the verdict is Unknown either way,
	// but the sentence has to send the operator at the right thing. A scan
	// DID run here, so the unrouted-ecosystem clause would be false and
	// would point at the routing instead of at the advisory data.
	reason, ok := noAdvisorySourceReason(r)
	if !ok {
		t.Fatal("no reason attached to the unavailable evaluation")
	}
	if strings.Contains(reason, "no vulnerability was looked for") {
		t.Errorf("reason says nothing was looked for, but a scan completed "+
			"for this coordinate — that sends the operator to the routing "+
			"when the gap is the advisory database: %q", reason)
	}
	if !strings.Contains(reason, "advisory database") {
		t.Errorf("reason does not name the advisory database as the gap: %q", reason)
	}
	if !strings.Contains(reason, "not a clean result") {
		t.Errorf("reason drops the load-bearing 'not a clean result': %q", reason)
	}
}

// The fail-open rail on the fix. Evidence of PRESENCE is dispositive
// whatever the coverage table says: a lane that surfaced a CVE for this
// coordinate demonstrably could look at it, so the marker must keep its
// hands off and the finding must survive to the verdict. Without this
// disjunct the fix would convert every real cocoapods/swift CVE into
// VerdictUnknown and cost a block.
func TestScanWithFindingsIsNeverMarkedUncovered(t *testing.T) {
	at := time.Unix(0, 0)
	for _, eco := range uncoveredEcosystems {
		t.Run(eco, func(t *testing.T) {
			r := newUncoveredReport(eco, "Alamofire", "5.8.0")
			scanned := at
			r.Vulnerabilities.ScannedAt = &scanned
			r.Vulnerabilities.IsVulnerable = true
			r.Vulnerabilities.CVEs = []string{"CVE-2021-23337"}
			r.Vulnerabilities.CVSSScore = 7.2

			if markNoAdvisoryCoverage(r, at) {
				t.Fatalf("%s coordinate with a real CVE was marked uncovered — "+
					"that converts a finding into Unknown and loses the block", eco)
			}
			ev := risk.EvaluatePackage(ProjectToRiskInput(r), risk.Options{})
			if ev.Verdict == risk.VerdictUnknown {
				t.Fatalf("%s coordinate with a real CVE resolved to unknown", eco)
			}
		})
	}
}

// The table is a claim about a third-party bundle's contents and about
// what a DIFFERENT Go module routes, so nothing here can derive it and
// nothing here can check it. What this test can do is stop it growing
// quietly: every member must be an ecosystem that reached this file
// because OSV does not cover it, and the three ecosystems the defect ran
// through must stay out until somebody produces the evidence.
func TestScannerAdvisedEcosystemsIsAJustifiedSubset(t *testing.T) {
	for eco := range scannerAdvisedEcosystems {
		if ecosystemHasAdvisorySource(eco) {
			t.Errorf("%q has an OSV bucket, so it never reaches the "+
				"scanner-advised test — remove the row", eco)
		}
		if !isKnownEcosystem(eco) {
			t.Errorf("%q is not an ecosystem this build recognises", eco)
		}
	}

	if !ecosystemHasScannerAdvisorySource("docker") {
		t.Error("docker left scannerAdvisedEcosystems — hooks.OCIInspector " +
			"extracts real apk/dpkg/rpm packages and looks them up against " +
			"trivy-db's OS buckets, so clean docker rows are real negatives " +
			"and dropping it re-blinds the image lane")
	}

	// Routed but unverified (cocoapods), and unrouted (swift,
	// huggingface, apt, yum, dnf). None of them may be added without
	// first establishing BOTH that the format is routed to a scanner and
	// that the scanner's database has a bucket for it.
	for _, eco := range []string{
		"cocoapods", "swift", "huggingface", "apt", "yum", "dnf",
	} {
		if ecosystemHasScannerAdvisorySource(eco) {
			t.Errorf("%q was added to scannerAdvisedEcosystems. A clean scan "+
				"in that ecosystem now grades as a real negative again — "+
				"which is the P9 P0-C defect. Add it only with evidence that "+
				"the format is routed (internal/hooks.selectTrivialTarget) "+
				"AND that the advisory bundle has a bucket for it", eco)
		}
	}
}

// Casing is not a bypass. Key.Ecosystem arrives verbatim from a URL path
// segment, a lockfile parser or a policy row, and P8-33 was an entire
// provider lane lost to a `PyPI`-cased coordinate.
func TestScannerAdvisedEcosystemsIsCaseInsensitive(t *testing.T) {
	for _, eco := range []string{"Docker", "DOCKER", " docker "} {
		if !ecosystemHasScannerAdvisorySource(eco) {
			t.Errorf("%q did not match the scanner-advised table", eco)
		}
	}
	at := time.Unix(0, 0)
	for _, eco := range []string{"CocoaPods", "COCOAPODS"} {
		r := newUncoveredReport(eco, "Alamofire", "5.8.0")
		scanned := at
		r.Vulnerabilities.ScannedAt = &scanned
		if !markNoAdvisoryCoverage(r, at) {
			t.Errorf("%q escaped the marker on casing alone", eco)
		}
	}
}

func TestMarkNoAdvisoryCoverageIsIdempotent(t *testing.T) {
	at := time.Unix(0, 0)
	r := newUncoveredReport("apt", "openssl", "3.0.2")
	if !markNoAdvisoryCoverage(r, at) {
		t.Fatal("first mark did not stamp")
	}
	if markNoAdvisoryCoverage(r, at) {
		t.Fatal("second mark stamped again — refresh ticks would accumulate duplicates")
	}
	n := 0
	for _, w := range r.Observation.Warnings {
		if w.Code == WarnUnsupported {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d WarnUnsupported warnings, want 1", n)
	}
}

// TRAP 2, pinned. The whole point of attributing the warning to a
// pseudo-provider is that the coverage LEDGER is unchanged by this wave.
// If `advisory` is ever added to providerToSource, an operator running
// `core/coverage` with mode: closed silently flips from BLOCKING these
// pulls (absent ProviderTimings entry → StatusUnavailable) to
// affirmatively NOT blocking them (ecosystem_unsupported →
// StatusNotApplicable). That is a fail-open on the one feature whose
// entire purpose is to fail closed.
func TestAdvisoryCoverageWarningDoesNotTouchTheLedger(t *testing.T) {
	if _, mapped := providerToSource[advisoryCoverageWarningProvider]; mapped {
		t.Fatalf("%q is mapped in providerToSource — emitting WarnUnsupported "+
			"under it INVERTS the opt-in fail-closed coverage gate from "+
			"blocking to non-blocking (P8-05, trap 2)",
			advisoryCoverageWarningProvider)
	}

	at := time.Unix(0, 0)
	r := newUncoveredReport("apt", "openssl", "3.0.2")
	r.Observation.CollectedAt = at
	before := LedgerFromReport(r)
	markNoAdvisoryCoverage(r, at)
	after := LedgerFromReport(r)

	if len(before) != len(after) {
		t.Fatalf("ledger size changed %d → %d", len(before), len(after))
	}
	for src, e := range after {
		if before[src] != e {
			t.Errorf("ledger entry for %s changed: %+v → %+v", src, before[src], e)
		}
	}

	// And the code itself still classifies as not-applicable, so even a
	// future accidental mapping is one review away rather than silent.
	if got := coverage.StatusForWarnCode(WarnUnsupported); got != coverage.StatusNotApplicable {
		t.Errorf("StatusForWarnCode(%q) = %q, want not_applicable", WarnUnsupported, got)
	}
}

// P8-34 — "no ecosystem validation exists on the intel path at all, which
// is why apt/yum/dnf were accepted silently and returned constants".
//
// REFUTED AS A SEPARATE FIX, and this test is the evidence. The symptom
// the finding names — an ecosystem this server cannot advise on being
// accepted and answered with a constant — is closed by P8-05 for EVERY
// unrecognised string, not merely for apt/yum/dnf: ecosystemHasAdvisorySource
// is a whitelist, so anything outside it (including a typo, a name from a
// newer CLI, and a name that is not an ecosystem at all) takes the
// unavailability arm and returns VerdictUnknown with a reason.
//
// Adding a 400 on top would be a REGRESSION against a Phase-7 decision,
// not an improvement. Phase 7 Wave 5 established store-and-mark over
// refuse for precisely this class: the proxy hot path, the refresher and
// the dependency enqueuer all re-request a coordinate they failed to get,
// so a hard error on a coordinate that will not become valid is an
// infinite retry with an upstream fetch attached to each turn. A marked
// Unknown row terminates the loop and stays queryable; a 400 gives the
// caller no verdict, no row and no reason.
func TestUnrecognisedEcosystemIsNotSilentlyScored(t *testing.T) {
	at := time.Unix(0, 0)
	for _, eco := range []string{
		"apt", "yum", "dnf", // the three the finding named
		"nodejs", "python", "ruby", // plausible user typos for real ones
		"definitely-not-an-ecosystem", "", "  ",
	} {
		r := newUncoveredReport(eco, "openssl", "3.0.2")
		if !markNoAdvisoryCoverage(r, at) {
			t.Errorf("%q was accepted with no advisory source and no marker", eco)
			continue
		}
		ev := risk.EvaluatePackage(ProjectToRiskInput(r), risk.Options{})
		if ev.Verdict != risk.VerdictUnknown {
			t.Errorf("%q resolved to %q — an ecosystem this build cannot advise "+
				"on must never return a scored constant", eco, ev.Verdict)
		}
	}
}

// ---------------------------------------------------------------------------
// P8-57 — the Unknown-0 leak rail
// ---------------------------------------------------------------------------

// No path may present an unevaluated coordinate's 0 as a KNOWN trust
// score. A known 0 matches every trustScoreMax rule ever written, so if a
// writer for package_metadata.trust_score is ever wired, a leaked 0 would
// mass-block exactly the population P8-04 and P8-05 just created.
//
// BOTH disjuncts of the guard are covered. The original expression was
// `r.Risk == nil || r.Risk.Verdict != VerdictUnknown`, and the first
// disjunct — no evaluation at all — also returned known=true on a zero
// score.
func TestUnknownEvaluationNeverProjectsAKnownTrustScore(t *testing.T) {
	cases := []struct {
		name      string
		build     func() *Report
		wantKnown bool
	}{
		{
			name: "unknown verdict with a zero score",
			build: func() *Report {
				r := newUncoveredReport("apt", "openssl", "3.0.2")
				markNoAdvisoryCoverage(r, time.Unix(0, 0))
				ComputeTrustScoreForOrg(r, "org-test")
				return r
			},
		},
		{
			name: "no evaluation at all with a zero score",
			build: func() *Report {
				// Risk stays nil — a Report assembled but never evaluated.
				return newUncoveredReport("apt", "openssl", "3.0.2")
			},
		},
		{
			name: "no evaluation but a real legacy total",
			build: func() *Report {
				r := newUncoveredReport("npm", "left-pad", "1.0.0")
				r.SupplyChain.TrustScore = 74
				return r
			},
			wantKnown: true,
		},
		{
			name: "a genuine zero from a real evaluation stays known",
			build: func() *Report {
				r := newUncoveredReport("npm", "evil", "1.0.0")
				r.SupplyChain.MalwareStatus = "malicious"
				r.SupplyChain.MalwareID = "MAL-1"
				ComputeTrustScoreForOrg(r, "org-test")
				return r
			},
			wantKnown: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.build()
			meta := r.ToLegacyPackageMetadata("repo")
			if meta == nil {
				t.Fatal("ToLegacyPackageMetadata returned nil")
			}
			if meta.TrustScoreKnown != tc.wantKnown {
				t.Fatalf("TrustScoreKnown = %v (score %d, risk %v), want %v",
					meta.TrustScoreKnown, meta.TrustScore, r.Risk != nil, tc.wantKnown)
			}
			if !tc.wantKnown && meta.TrustScore != 0 {
				t.Fatalf("precondition: this case is about a ZERO score, got %d",
					meta.TrustScore)
			}
		})
	}
}

// trustscore.go writes eval.RolledUp.Overall into SupplyChain.TrustScore
// unconditionally, including the Unknown 0. That is what makes the guard
// above the only thing standing between an unevaluated coordinate and a
// hard 0 on the policy surface — pinned here so the guard cannot be
// deleted as "unreachable".
func TestUnknownEvaluationDoesWriteAZeroTrustScore(t *testing.T) {
	r := newUncoveredReport("apt", "openssl", "3.0.2")
	markNoAdvisoryCoverage(r, time.Unix(0, 0))
	ComputeTrustScoreForOrg(r, "org-test")
	if r.Risk == nil || r.Risk.Verdict != risk.VerdictUnknown {
		t.Fatalf("precondition: want an Unknown evaluation, got %+v", r.Risk)
	}
	if r.SupplyChain.TrustScore != 0 {
		t.Fatalf("SupplyChain.TrustScore = %d, want 0 — if this stops being 0 "+
			"the rail above is guarding the wrong field", r.SupplyChain.TrustScore)
	}
}
