package intelligence

import (
	"strings"
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
	if report.SupplyChain.TrustScoreBreakdown == "" {
		t.Fatalf("expected breakdown JSON to be populated")
	}
	if !strings.Contains(report.SupplyChain.TrustScoreBreakdown, "malwareCheck") {
		t.Fatalf("breakdown JSON should contain malwareCheck key: %s", report.SupplyChain.TrustScoreBreakdown)
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
	// trustscore.Compute clamps malicious packages to Total=0 (with a
	// -100 MalwareCheck in the breakdown).
	if report.SupplyChain.TrustScore != 0 {
		t.Fatalf("expected score 0 for malicious package, got %d", report.SupplyChain.TrustScore)
	}
	if !strings.Contains(report.SupplyChain.TrustScoreBreakdown, "-100") {
		t.Fatalf("breakdown should include -100 malware penalty, got %s", report.SupplyChain.TrustScoreBreakdown)
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
	if report.SupplyChain.TrustScoreBreakdown == "" {
		t.Fatalf("expected breakdown JSON for empty report")
	}
}

func TestComputeTrustScore_InstallScriptFetchesRemoteHurtsScore(t *testing.T) {
	report := &Report{
		Scan: ArtifactScanSection{
			Performed:            true,
			HasInstallScript:     true,
			InstallScriptFetches: true,
			InstallScriptKind:    "fetches_remote",
		},
	}
	ComputeTrustScore(report)
	if !strings.Contains(report.SupplyChain.TrustScoreBreakdown, `"installScript":-20`) {
		t.Fatalf("expected installScript penalty -20, got %s", report.SupplyChain.TrustScoreBreakdown)
	}
}

func boolPtr(b bool) *bool { return &b }

// TestComputeTrustScore_RiskV2IsAuthoritative locks in the post-cutover
// contract: v2 always runs, report.Risk is populated, the legacy
// breakdown JSON still flows through, and the score field comes from
// risk.Evaluation.RolledUp.Overall — not from legacy.Compute().Total.
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
	if report.SupplyChain.TrustScoreBreakdown == "" {
		t.Fatalf("legacy Breakdown JSON must still be populated for explanation paths")
	}
	if !strings.Contains(report.SupplyChain.TrustScoreBreakdown, "malwareCheck") {
		t.Fatalf("breakdown should contain legacy per-signal keys, got %s",
			report.SupplyChain.TrustScoreBreakdown)
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
			Vulnerabilities: VulnSection{IsVulnerable: true, CVSSScore: 9.0, ScannedAt: &scannedAt},
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
