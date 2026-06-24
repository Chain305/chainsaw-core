package trustscore

import "testing"

// baseAttestationFirstSignals returns Signals representing a clean
// package: no malware, not vulnerable, license known, plenty of versions,
// repo link OK. Tests flip individual fields to assert the
// attestation-first reframe in isolation.
func baseAttestationFirstSignals() Signals {
	return Signals{
		AttestationFirst: true,
		LicenseSPDX:      "MIT",
		HasSourceRepo:    true,
		RepoLinkStatus:   "ok",
		VersionCount:     5,
		ChecksumVerified: true,
	}
}

func TestAttestationFirstWithoutAttestationFloorsAt30(t *testing.T) {
	got := Compute(baseAttestationFirstSignals())
	if got.Breakdown.AttestationBase != 30 {
		t.Errorf("AttestationBase = %d, want 30 (no attestation floor)", got.Breakdown.AttestationBase)
	}
	if got.Breakdown.Provenance != 0 {
		t.Errorf("legacy Provenance = %d, want 0 in attestation-first mode", got.Breakdown.Provenance)
	}
	if got.Breakdown.SLSALevelBonus != 0 {
		t.Errorf("SLSALevelBonus = %d, want 0 without verified attestation", got.Breakdown.SLSALevelBonus)
	}
}

func TestAttestationFirstVerifiedRaisesBaseTo70(t *testing.T) {
	s := baseAttestationFirstSignals()
	s.HasProvenance = true
	s.ProvenanceStatus = "verified"
	got := Compute(s)
	if got.Breakdown.AttestationBase != 70 {
		t.Errorf("AttestationBase = %d, want 70 (verified attestation)", got.Breakdown.AttestationBase)
	}
	// Without an explicit SLSA level, the bonus is 0 (treated as L1).
	if got.Breakdown.SLSALevelBonus != 0 {
		t.Errorf("SLSALevelBonus = %d, want 0 (no level set = L1)", got.Breakdown.SLSALevelBonus)
	}
}

func TestAttestationFirstSLSALevelBonus(t *testing.T) {
	cases := []struct {
		level int
		bonus int
	}{
		{1, 0},
		{2, 5},
		{3, 10},
		{4, 15},
		{5, 15}, // future-proof: cap at L4 bonus
		{0, 0},
	}
	for _, tc := range cases {
		s := baseAttestationFirstSignals()
		s.HasProvenance = true
		s.ProvenanceStatus = "verified"
		s.SLSALevel = tc.level
		got := Compute(s)
		if got.Breakdown.SLSALevelBonus != tc.bonus {
			t.Errorf("level=%d: SLSALevelBonus = %d, want %d",
				tc.level, got.Breakdown.SLSALevelBonus, tc.bonus)
		}
	}
}

func TestAttestationFirst40PointGap(t *testing.T) {
	// The substrate base is 70 (verified) vs 30 (missing) — a 40-point
	// gap, vs the legacy mode's 25-point gap. This is the load-bearing
	// reframe and a regression here would silently soften the
	// SLSA-substrate stance.
	withVerified := baseAttestationFirstSignals()
	withVerified.HasProvenance = true
	withVerified.ProvenanceStatus = "verified"
	withVerified.SLSALevel = 1 // base only, no bonus
	without := baseAttestationFirstSignals()

	gap := Compute(withVerified).Breakdown.AttestationBase - Compute(without).Breakdown.AttestationBase
	if gap != 40 {
		t.Errorf("base gap = %d, want 40 (substrate reframe)", gap)
	}
}

func TestLegacyModePreservesProvenanceContribution(t *testing.T) {
	// Drift guard: with AttestationFirst=false (default), the legacy
	// +25 contribution still fires on verified provenance.
	s := Signals{
		HasProvenance:    true,
		ProvenanceStatus: "verified",
	}
	got := Compute(s)
	if got.Breakdown.Provenance != 25 {
		t.Errorf("legacy Provenance = %d, want 25", got.Breakdown.Provenance)
	}
	if got.Breakdown.AttestationBase != 0 {
		t.Errorf("AttestationBase = %d, want 0 in legacy mode", got.Breakdown.AttestationBase)
	}
}

func TestAttestationFirstMalwareStillKills(t *testing.T) {
	// Malware short-circuits to -100 regardless of mode.
	s := baseAttestationFirstSignals()
	s.HasProvenance = true
	s.ProvenanceStatus = "verified"
	s.SLSALevel = 4
	s.IsKnownMalicious = true
	got := Compute(s)
	if got.Total != 0 {
		t.Errorf("Total = %d, want 0 (clamped after malware -100)", got.Total)
	}
	if got.Breakdown.MalwareCheck != -100 {
		t.Errorf("MalwareCheck = %d, want -100", got.Breakdown.MalwareCheck)
	}
}

func TestAttestationFirstClampedTo100(t *testing.T) {
	// All-positive signals + L4 attestation should clamp at 100.
	s := baseAttestationFirstSignals()
	s.HasProvenance = true
	s.ProvenanceStatus = "verified"
	s.SLSALevel = 4
	s.PublishVelocityAnomaly = false
	got := Compute(s)
	if got.Total != 100 {
		t.Errorf("Total = %d, want 100 (clamped). breakdown=%+v", got.Total, got.Breakdown)
	}
}
