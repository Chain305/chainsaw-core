package intelligence

// P8-05 must not fire on chainsaw's own hosted-repository pseudo-ecosystems.
//
// ecosystemHasAdvisorySource is the complement of supportedOSVEcosystems.
// Taken over EVERY string, that complement includes values that are not
// ecosystems at all — repository NAMES. The 2026-08-25 production export
// carries four of them in the ecosystem column: `maven-hosted`,
// `npmjs-hosted`, `rubygems-hosted`, `crates-hosted`. Those are an org's
// own hosted registries; the packages under them are ordinary maven, npm,
// rubygems and cargo packages, and they DO have advisory coverage. Stamping
// "no advisory source in this build covers ecosystem maven-hosted" turns
// every such upload into NOT EVALUATED and pushes the org's scan to exit 2
// on a claim that is simply untrue.
//
// PRECEDENT: Phase 7 Wave 6 (docs/plan_qa_phase7_remediation.md). It ruled
// that `maven-hosted` is a repository NAME, that
// osv.CanonicalEcosystem("maven-hosted") == "" is CORRECT, and that
// teaching the canonicaliser about it would be the WRONG fix — it would
// make a repo-name leak look supported instead of failing loudly and would
// not generalise. The right fix is upstream: the ecosystem must carry
// repo.Format.
//
// This wave therefore does two things and neither of them is a name-to-
// format mapping:
//
//  1. Fixes the leak where it enters. Refresher.refreshRow and its server
//     wiring both fell back to the repository NAME when the format could
//     not be resolved; they now yield the empty string. A hosted-repo
//     upload carries `maven`, gets scanned, and is never stamped at all.
//  2. Stops the stamp making a COVERAGE claim about a string that is not
//     an ecosystem. It still STAMPS — a report nothing scanned must not
//     grade ALLOW, and TestUnrecognisedEcosystemIsNotSilentlyScored pins
//     that — but the reason says the true thing: the routing is wrong, not
//     that Maven is uncovered.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/metadata"
	"github.com/chain305/chainsaw-core/risk"
)

// hostedPseudoEcosystems are verbatim from the production export.
var hostedPseudoEcosystems = []string{
	"maven-hosted", "npmjs-hosted", "rubygems-hosted", "crates-hosted",
}

func TestHostedRepositoryNamesAreNotReportedAsACoverageGap(t *testing.T) {
	at := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	for _, eco := range hostedPseudoEcosystems {
		t.Run(eco, func(t *testing.T) {
			r := &Report{}
			r.Identity.Ecosystem = eco
			r.Identity.Package = "com.chainsaw.wave-aa:probe"
			r.Identity.Version = "0.0.1"

			// Still stamped, and still Unknown: nothing scanned this
			// report, so its ALLOW would be a constant. Suppressing the
			// marker would be a fail-open.
			if !markNoAdvisoryCoverage(r, at) {
				t.Fatalf("%q was not stamped — every provider rejects the "+
					"string, so the report has no facts and must not grade "+
					"ALLOW off a constant", eco)
			}
			ev := risk.EvaluatePackage(ProjectToRiskInput(r), risk.Options{})
			if ev == nil || ev.Verdict != risk.VerdictUnknown {
				t.Fatalf("%q did not resolve to unknown", eco)
			}

			// But the CLAIM must be true. These are ordinary maven / npm /
			// rubygems / cargo packages and every one of those ecosystems
			// has full advisory coverage, so "no advisory source covers
			// this ecosystem" is false and points at the wrong fix.
			reason, ok := noAdvisorySourceReason(r)
			if !ok {
				t.Fatalf("%q produced no reason", eco)
			}
			if strings.Contains(reason, "coverage gap") {
				t.Fatalf("%q is reported as a COVERAGE gap. It is a repository "+
					"NAME; the packages under it have full advisory coverage. "+
					"reason=%q", eco, reason)
			}
			if !strings.Contains(reason, "routing") {
				t.Fatalf("%q must be reported as a routing problem so the "+
					"reader fixes repo.Name -> repo.Format; reason=%q", eco, reason)
			}
			for _, w := range r.Observation.Warnings {
				if w.Code == WarnUnsupported && strings.Contains(w.Message, "covers ecosystem") {
					t.Fatalf("the warning message still claims a coverage gap "+
						"for %q: %q", eco, w.Message)
				}
			}
		})
	}
}

// An unresolved refresher row carries no ecosystem at all. It is still
// stamped — nothing ran, so nothing is known — but the reason must not
// claim a coverage gap for an ecosystem that was never named.
func TestEmptyEcosystemIsReportedAsUnrouted(t *testing.T) {
	r := &Report{}
	r.Identity.Package = "whatever"
	r.Identity.Version = "1.0.0"
	if !markNoAdvisoryCoverage(r, time.Now()) {
		t.Fatal("an unrouted row was not stamped, so it would grade ALLOW off a constant")
	}
	reason, ok := noAdvisorySourceReason(r)
	if !ok || strings.Contains(reason, "coverage gap") {
		t.Fatalf("empty ecosystem reported as a coverage gap: ok=%v reason=%q", ok, reason)
	}
}

// The rail in the other direction for the WORDING: a genuinely uncovered
// ecosystem must still be reported as a coverage gap, or narrowing the
// claim would have blurred the one it exists to make.
func TestGenuinelyUncoveredEcosystemsAreReportedAsACoverageGap(t *testing.T) {
	at := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	for _, eco := range []string{"huggingface", "swift", "cocoapods", "docker", "apt", "yum", "dnf"} {
		t.Run(eco, func(t *testing.T) {
			r := &Report{}
			r.Identity.Ecosystem = eco
			r.Identity.Package = "openssl"
			r.Identity.Version = "3.0.2"
			if !markNoAdvisoryCoverage(r, at) {
				t.Fatalf("%q was not stamped", eco)
			}
			reason, ok := noAdvisorySourceReason(r)
			if !ok || !strings.Contains(reason, "coverage gap") {
				t.Fatalf("%q is a real coverage gap and must say so: ok=%v reason=%q",
					eco, ok, reason)
			}
		})
	}
}

// The rail in the other direction: the seven genuinely uncovered
// ecosystems P8-05 exists for must still be stamped. Narrowing the domain
// must not become a way to fall back to the ALLOW floor.
func TestGenuinelyUncoveredEcosystemsAreStillStamped(t *testing.T) {
	at := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	for _, eco := range []string{
		"huggingface", "swift", "cocoapods", "docker", "apt", "yum", "dnf",
	} {
		t.Run(eco, func(t *testing.T) {
			r := &Report{}
			r.Identity.Ecosystem = eco
			r.Identity.Package = "openssl"
			r.Identity.Version = "3.0.2"
			if !markNoAdvisoryCoverage(r, at) {
				t.Fatalf("%q has no advisory source in this build and no lane "+
					"produced a scan, so it must not floor at ALLOW", eco)
			}
		})
	}
}

// And the covered ecosystems are untouched, so the domain narrowing did not
// quietly widen the stamp.
func TestCoveredEcosystemsAreNeverStamped(t *testing.T) {
	at := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	for _, eco := range []string{
		"npm", "yarn", "bun", "pip", "pypi", "maven", "gradle", "cargo",
		"rubygems", "nuget", "composer", "go", "pub",
	} {
		t.Run(eco, func(t *testing.T) {
			r := &Report{}
			r.Identity.Ecosystem = eco
			r.Identity.Package = "left-pad"
			r.Identity.Version = "1.3.0"
			if markNoAdvisoryCoverage(r, at) {
				t.Fatalf("%q has an OSV bucket and must never be stamped", eco)
			}
		})
	}
}

// The leak itself: Refresher.refreshRow used to substitute the repository
// NAME for the ecosystem whenever the resolver was nil or could not resolve
// the row. That is how `maven-hosted` reached Key.Ecosystem in the first
// place, and Phase 7 Wave 6 already ruled the ecosystem must carry
// repo.Format. An unresolvable row now carries no ecosystem at all.
func TestRefresherNeverSubstitutesRepositoryNameForEcosystem(t *testing.T) {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		resolver EcosystemResolver
	}{
		{"no resolver wired", nil},
		{"resolver cannot resolve the repo", func(string) string { return "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := &fakeMetadataSource{
				rows: []metadata.PackageMetadataRow{{
					OrgID: "org1",
					PackageMetadata: metadata.PackageMetadata{
						Repository: "maven-hosted",
						Package:    "com.chainsaw.wave-aa:probe",
						Version:    "0.0.1",
						UpdatedAt:  now.Add(-48 * time.Hour), // stale -> rescanned
					},
				}},
			}
			svc := &fakeService{}
			ref := NewRefresher(RefresherConfig{
				Service:           svc,
				Metadata:          src,
				MaxStaleness:      24 * time.Hour,
				Concurrency:       1,
				PageSize:          10,
				EcosystemResolver: tc.resolver,
			})
			ref.now = func() time.Time { return now }
			ref.RunOnce(context.Background())

			svc.mu.Lock()
			seen := append([]Request(nil), svc.seen...)
			svc.mu.Unlock()
			if len(seen) == 0 {
				t.Fatal("the stale row was not scanned at all")
			}
			for _, req := range seen {
				if req.Key.Ecosystem == "maven-hosted" {
					t.Fatalf("the repository NAME was passed as the ecosystem. "+
						"Downstream reads that as a fact about the package: "+
						"P8-05 turns it into \"no advisory source covers this "+
						"ecosystem\", which is false for a hosted Maven repo. "+
						"req=%+v", req.Key)
				}
				if req.Key.Ecosystem != "" {
					t.Fatalf("expected an unresolved row to carry no ecosystem, got %q",
						req.Key.Ecosystem)
				}
			}
		})
	}
}
