package intelligence

import (
	"testing"
	"time"
)

func TestComputeTrustScore_PopulatedReportYieldsNonZero(t *testing.T) {
	// Build a "good citizen" report: license known, no malware, verified
	// provenance, source repo set, checksum verified, multiple versions.
	past := time.Now().Add(-120 * 24 * time.Hour)
	tr := true
	report := &Report{
		Release: ReleaseSection{
			PublishedAt: &past,
		},
		URLs: URLSection{
			SourceRepoURL: "https://github.com/example/pkg",
		},
		Artifact: ArtifactSection{
			Digests: ArtifactDigest{
				SHA256:   "deadbeef",
				Verified: true,
			},
		},
		Metadata: MetadataSection{
			LicenseExpression: "MIT",
		},
		Provenance: ProvenanceSection{
			Status:    "verified",
			Available: true,
			Verified:  true,
		},
		SupplyChain: SupplyChainSection{
			MalwareStatus:   "clean",
			TyposquatStatus: "clean",
			RepoLinkStatus:  "ok",
			// No publisher change, no velocity anomaly.
			PublisherChanged: boolPtr(false),
		},
		Vulnerabilities: VulnSection{IsVulnerable: false},
		Scan: ArtifactScanSection{
			Performed:         true,
			InstallScriptKind: "none",
			HasInstallScript:  false,
		},
	}
	_ = tr

	ComputeTrustScore(report)

	if report.SupplyChain.TrustScore <= 0 {
		t.Fatalf("expected positive score for clean package, got %d", report.SupplyChain.TrustScore)
	}
	// The legacy per-signal breakdown used to be asserted here. It was
	// removed 2026-09-04 (P9F-307) — write-only fossil. The signal
	// contributions it carried are covered directly in
	// core/trustscore/score_test.go; what this test owns is the composite.
	if report.Risk == nil {
		t.Fatalf("expected report.Risk to be populated by the risk-V2 evaluator")
	}
}

func TestComputeTrustScore_MaliciousReportLowScore(t *testing.T) {
	report := &Report{
		SupplyChain: SupplyChainSection{
			MalwareStatus: "malicious",
			MalwareID:     "MAL-2025-0001",
		},
	}
	ComputeTrustScore(report)
	// A malicious package scores 0. The -100 MalwareCheck contribution
	// that drives the legacy blend to the same place is asserted in
	// core/trustscore/score_test.go, against trustscore.Compute directly.
	if report.SupplyChain.TrustScore != 0 {
		t.Fatalf("expected score 0 for malicious package, got %d", report.SupplyChain.TrustScore)
	}
}

func TestComputeTrustScore_NilReportIsSafe(t *testing.T) {
	// Must not panic.
	ComputeTrustScore(nil)
}

func TestComputeTrustScore_EmptyReportHandled(t *testing.T) {
	report := &Report{}
	ComputeTrustScore(report)
	// Empty report: no malware, no typosquat, etc. trustscore.Compute
	// assigns +20 VulnStatus, +10 TyposquatCheck, so Total should be
	// non-negative.
	if report.SupplyChain.TrustScore < 0 {
		t.Fatalf("empty report should not produce negative score, got %d", report.SupplyChain.TrustScore)
	}
}

// TestComputeTrustScore_InstallScriptFetchesRemoteHurtsScore checks that a
// remote-fetching install script costs the package points.
//
// It used to assert `"installScript":-20` inside the legacy breakdown
// STRING on the report. That field is gone (P9F-307), and the string match
// was the wrong assertion anyway: it pinned the legacy blend, not the
// composite the policy evaluator actually gates on. Now it compares the
// served score against an otherwise-identical clean report.
func TestComputeTrustScore_InstallScriptFetchesRemoteHurtsScore(t *testing.T) {
	build := func(fetchesRemote bool) *Report {
		r := &Report{
			Identity: IdentitySection{Ecosystem: "npm", Package: "acme", Version: "1.0.0"},
			Scan:     ArtifactScanSection{Performed: true},
		}
		if fetchesRemote {
			r.Scan.HasInstallScript = true
			r.Scan.InstallScriptFetches = true
			r.Scan.InstallScriptKind = "fetches_remote"
		}
		return r
	}

	clean := build(false)
	dirty := build(true)
	ComputeTrustScore(clean)
	ComputeTrustScore(dirty)

	if dirty.SupplyChain.TrustScore >= clean.SupplyChain.TrustScore {
		t.Fatalf("a remote-fetching install script must lower the composite score: "+
			"with=%d, without=%d", dirty.SupplyChain.TrustScore, clean.SupplyChain.TrustScore)
	}
}

func boolPtr(b bool) *bool { return &b }

// TestComputeTrustScore_RiskV2IsAuthoritative locks in the post-cutover
// contract: v2 always runs, report.Risk is populated, and the score field
// comes from risk.Evaluation.RolledUp.Overall — not from
// legacy.Compute().Total. (The legacy breakdown JSON that used to ride
// along on the report was removed 2026-09-04; see P9F-307.)
func TestComputeTrustScore_RiskV2IsAuthoritative(t *testing.T) {
	past := time.Now().Add(-200 * 24 * time.Hour)
	report := &Report{
		Identity: IdentitySection{Ecosystem: "npm", Package: "acme", Version: "1.2.3"},
		Release:  ReleaseSection{PublishedAt: &past},
		URLs:     URLSection{SourceRepoURL: "https://github.com/example/acme"},
		Artifact: ArtifactSection{
			Digests: ArtifactDigest{SHA256: "deadbeef", Verified: true},
		},
		Metadata: MetadataSection{LicenseExpression: "MIT"},
		Provenance: ProvenanceSection{
			Status: "verified", Available: true, Verified: true, SLSALevel: 3,
		},
		SupplyChain: SupplyChainSection{
			MalwareStatus:   "clean",
			TyposquatStatus: "clean",
			RepoLinkStatus:  "ok",
		},
		Vulnerabilities: VulnSection{IsVulnerable: false},
		Scan:            ArtifactScanSection{Performed: true},
	}

	ComputeTrustScore(report)

	if report.Risk == nil {
		t.Fatalf("expected report.Risk to be populated by Risk-V2")
	}
	if report.Risk.EngineVersion == "" {
		t.Fatalf("expected EngineVersion to be stamped on Evaluation")
	}
	if report.SupplyChain.TrustScore != report.Risk.RolledUp.Overall {
		t.Fatalf("score field should mirror Risk-V2 RolledUp.Overall: score=%d v2=%d",
			report.SupplyChain.TrustScore, report.Risk.RolledUp.Overall)
	}
}

// TestComputeTrustScore_OrgWeightsResolverChangesScore confirms the
// per-org weight override seam is wired into the v2 hot path: a
// non-default weights map produces a different score from the default.
func TestComputeTrustScore_OrgWeightsResolverChangesScore(t *testing.T) {
	prev := OrgWeightsResolver
	t.Cleanup(func() { OrgWeightsResolver = prev })

	build := func() *Report {
		scannedAt := time.Now()
		return &Report{
			Identity: IdentitySection{Ecosystem: "npm", Package: "acme", Version: "1.0.0"},
			Metadata: MetadataSection{LicenseExpression: "MIT"},
			// ScannedAt non-nil → VulnDataAvailable=true → vuln category
			// participates in the rollup and the per-org weight override
			// has visible effect on the result.
			//
			// The CVE sits in the medium tier deliberately. risk's
			// vuln.cvss_critical / vuln.cvss_high declare a MaxImpact
			// ceiling, and a ceiling pins overall to a fixed value
			// regardless of category weight — a ceilinged fixture would
			// mask the override seam this test exists to prove.
			Vulnerabilities: VulnSection{IsVulnerable: true, CVSSScore: 6.0, ScannedAt: &scannedAt},
		}
	}

	OrgWeightsResolver = func(string) map[string]float64 { return nil }
	r1 := build()
	ComputeTrustScore(r1)

	OrgWeightsResolver = func(string) map[string]float64 {
		return map[string]float64{
			"vulnerability": 0.50,
			"supply_chain":  0.20,
			"maintenance":   0.15,
			"license":       0.075,
			"quality":       0.075,
		}
	}
	r2 := build()
	ComputeTrustScore(r2)

	if r1.SupplyChain.TrustScore == r2.SupplyChain.TrustScore {
		t.Fatalf("override should change score (default=%d, override=%d)",
			r1.SupplyChain.TrustScore, r2.SupplyChain.TrustScore)
	}
}
