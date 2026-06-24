package trustscore

import (
	"testing"
	"time"
)

func TestComputeKnownMalicious(t *testing.T) {
	score := Compute(Signals{IsKnownMalicious: true})
	if score.Total != 0 {
		t.Errorf("expected 0 for known malicious, got %d", score.Total)
	}
	if score.Breakdown.MalwareCheck != -100 {
		t.Errorf("expected -100 malware check, got %d", score.Breakdown.MalwareCheck)
	}
}

func TestComputeCleanPackage(t *testing.T) {
	releaseDate := time.Now().Add(-60 * 24 * time.Hour)
	score := Compute(Signals{
		LicenseSPDX:        "MIT",
		VersionReleaseDate: &releaseDate,
		HasProvenance:      true,
		ProvenanceStatus:   "verified",
		HasSourceRepo:      true,
		VersionCount:       10,
		ChecksumVerified:   true,
	})
	if score.Total != 100 {
		t.Errorf("expected 100 for clean package with all signals, got %d", score.Total)
	}
}

func TestComputeSuspectedTyposquat(t *testing.T) {
	score := Compute(Signals{
		IsSuspectedTyposquat: true,
		TyposquatConfidence:  "high",
	})
	if score.Breakdown.TyposquatCheck != -30 {
		t.Errorf("expected -30 typosquat penalty for high confidence, got %d", score.Breakdown.TyposquatCheck)
	}
}

func TestComputeVulnerable(t *testing.T) {
	score := Compute(Signals{
		IsVulnerable: true,
		MaxCVSS:      9.5,
	})
	if score.Breakdown.VulnStatus != 0 {
		t.Errorf("expected 0 vuln status for critical CVSS, got %d", score.Breakdown.VulnStatus)
	}

	score = Compute(Signals{
		IsVulnerable: true,
		MaxCVSS:      3.0,
	})
	if score.Breakdown.VulnStatus != 10 {
		t.Errorf("expected 10 vuln status for low CVSS, got %d", score.Breakdown.VulnStatus)
	}
}

func TestComputeNewPackage(t *testing.T) {
	releaseDate := time.Now().Add(-5 * 24 * time.Hour)
	score := Compute(Signals{
		VersionReleaseDate: &releaseDate,
	})
	if score.Breakdown.PackageAge != 0 {
		t.Errorf("expected 0 age score for 5-day-old package, got %d", score.Breakdown.PackageAge)
	}
}

// TestComputeRepoLinkStatusDeltas locks in the per-classification
// contribution table defined by PR 11. A regression here would
// silently shift trust-scores across every cached package on the next
// enrichment pass.
func TestComputeRepoLinkStatusDeltas(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		status    string
		hasRepo   bool // legacy signal; tested only when status is empty
		wantDelta int
	}{
		{"ok", "ok", false, 10},
		{"unknown", "unknown", false, 0},
		{"archived", "archived", false, -10},
		{"missing", "missing", false, -10},
		{"ownership_mismatch", "ownership_mismatch", false, -20},
		{"empty status + repo present falls back to legacy +10", "", true, 10},
		{"empty status + no repo is zero", "", false, 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			score := Compute(Signals{
				RepoLinkStatus: tc.status,
				HasSourceRepo:  tc.hasRepo,
			})
			if score.Breakdown.SourceRepo != tc.wantDelta {
				t.Errorf("SourceRepo delta for status=%q hasRepo=%v: got %d, want %d",
					tc.status, tc.hasRepo, score.Breakdown.SourceRepo, tc.wantDelta)
			}
			if tc.status != "" && score.Breakdown.RepoLinkStatus != tc.status {
				t.Errorf("Breakdown.RepoLinkStatus: got %q, want %q",
					score.Breakdown.RepoLinkStatus, tc.status)
			}
		})
	}
}

// TestComputeRepoLinkOwnershipMismatchDoesNotFloorBelowZero — the
// ownership_mismatch delta is -20 but the overall score clamp ensures
// the total never goes below 0 for a non-malware package. Regression
// here would let a single factor collapse trust to negative numbers
// and break downstream comparisons.
func TestComputeRepoLinkOwnershipMismatchDoesNotFloorBelowZero(t *testing.T) {
	t.Parallel()
	score := Compute(Signals{RepoLinkStatus: "ownership_mismatch"})
	if score.Total < 0 {
		t.Errorf("total must be clamped to >= 0, got %d", score.Total)
	}
}

// cleanBaseSignals returns a Signals fixture that scores 100. Tests for
// new penalty bits flip a single field on this baseline and assert the
// score moves by exactly the documented delta — that's how we lock in
// "additive only, no interaction with existing weights".
func cleanBaseSignals() Signals {
	t := time.Now().Add(-60 * 24 * time.Hour)
	return Signals{
		LicenseSPDX:        "MIT",
		VersionReleaseDate: &t,
		HasProvenance:      true,
		ProvenanceStatus:   "verified",
		HasSourceRepo:      true,
		VersionCount:       10,
		ChecksumVerified:   true,
	}
}

// TestComputeKnownExploitedCVE — KEV match must dock the score by 25
// and surface the contribution in the Breakdown so the audit log can
// show it. We assert against a clean baseline so the delta is unambiguous.
func TestComputeKnownExploitedCVE(t *testing.T) {
	t.Parallel()
	base := Compute(cleanBaseSignals())
	if base.Total != 100 {
		t.Fatalf("baseline expected 100, got %d", base.Total)
	}

	s := cleanBaseSignals()
	s.KnownExploitedCVE = true
	got := Compute(s)
	if got.Breakdown.KnownExploitedCVE != -25 {
		t.Errorf("KnownExploitedCVE breakdown: got %d, want -25", got.Breakdown.KnownExploitedCVE)
	}
	if got.Total != base.Total-25 {
		t.Errorf("score should drop by 25 vs baseline: base=%d got=%d", base.Total, got.Total)
	}
}

// TestComputeKnownExploitedCVEStacksWithVuln — a vulnerable package
// that's also in KEV must take BOTH penalties (CVSS-driven VulnStatus
// loss + the KEV -25). The bug being fixed was that exploited and
// non-exploited CVEs scored identically.
func TestComputeKnownExploitedCVEStacksWithVuln(t *testing.T) {
	t.Parallel()
	exploited := Compute(Signals{
		IsVulnerable:      true,
		MaxCVSS:           9.5,
		KnownExploitedCVE: true,
	})
	notExploited := Compute(Signals{
		IsVulnerable: true,
		MaxCVSS:      9.5,
	})
	if exploited.Total >= notExploited.Total {
		t.Errorf("exploited CVE must score lower than non-exploited at same CVSS: exploited=%d notExploited=%d",
			exploited.Total, notExploited.Total)
	}
	if exploited.Breakdown.KnownExploitedCVE != -25 {
		t.Errorf("expected -25 KEV delta, got %d", exploited.Breakdown.KnownExploitedCVE)
	}
}

func TestComputeDangerousPickleOpcode(t *testing.T) {
	t.Parallel()
	base := Compute(cleanBaseSignals())
	s := cleanBaseSignals()
	s.DangerousPickleOpcode = true
	got := Compute(s)
	if got.Breakdown.DangerousPickleOpcode != -30 {
		t.Errorf("DangerousPickleOpcode breakdown: got %d, want -30", got.Breakdown.DangerousPickleOpcode)
	}
	if got.Total != base.Total-30 {
		t.Errorf("score should drop by 30: base=%d got=%d", base.Total, got.Total)
	}

	// Absence: no contribution.
	clean := Compute(cleanBaseSignals())
	if clean.Breakdown.DangerousPickleOpcode != 0 {
		t.Errorf("clean baseline must not penalise: got %d", clean.Breakdown.DangerousPickleOpcode)
	}
}

func TestComputeModelCardInjection(t *testing.T) {
	t.Parallel()
	base := Compute(cleanBaseSignals())
	s := cleanBaseSignals()
	s.ModelCardInjection = true
	got := Compute(s)
	if got.Breakdown.ModelCardInjection != -10 {
		t.Errorf("ModelCardInjection breakdown: got %d, want -10", got.Breakdown.ModelCardInjection)
	}
	if got.Total != base.Total-10 {
		t.Errorf("score should drop by 10: base=%d got=%d", base.Total, got.Total)
	}
}

func TestComputeAgentToolDangerousCapability(t *testing.T) {
	t.Parallel()
	base := Compute(cleanBaseSignals())
	s := cleanBaseSignals()
	s.AgentToolDangerousCapability = true
	got := Compute(s)
	if got.Breakdown.AgentToolDangerousCapability != -15 {
		t.Errorf("AgentToolDangerousCapability breakdown: got %d, want -15", got.Breakdown.AgentToolDangerousCapability)
	}
	if got.Total != base.Total-15 {
		t.Errorf("score should drop by 15: base=%d got=%d", base.Total, got.Total)
	}
}

func TestComputeSignatureVerifiedAddsBonus(t *testing.T) {
	// A modest baseline well below the 100-point clamp so the +5 delta
	// is observable. The clamp would mask a smaller-than-baseline test.
	baseSignals := Signals{
		LicenseSPDX:    "MIT",
		IsVulnerable:   true,
		MaxCVSS:        5.0,
		RepoLinkStatus: "unknown",
	}
	base := Compute(baseSignals)

	withSig := baseSignals
	withSig.SignatureVerified = true
	got := Compute(withSig)

	if got.Breakdown.SignatureVerified != 5 {
		t.Errorf("Breakdown.SignatureVerified = %d, want 5", got.Breakdown.SignatureVerified)
	}
	if got.Total != base.Total+5 {
		t.Errorf("score should rise by exactly 5: base=%d got=%d", base.Total, got.Total)
	}
	// SignatureVerified=false / unset must not penalise — it's a
	// "not known" signal, separate from any provenance penalty.
	zeroed := baseSignals
	zeroed.SignatureVerified = false
	if Compute(zeroed).Breakdown.SignatureVerified != 0 {
		t.Error("SignatureVerified=false must contribute 0, not a penalty")
	}
}
