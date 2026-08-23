package risk

import "testing"

// evalWith builds a minimal Evaluation carrying a verdict, a score and a
// fired-signal set filed into the category buckets exactly the way
// computeCategoryScores and instantBlock file them. UpgradePromotionEligible
// reads nothing else.
func evalWith(verdict Verdict, overall int, fired ...FiredSignal) *Evaluation {
	cats := make(map[Category]CategoryScore, len(CategoryWeights))
	for _, f := range fired {
		cs := cats[f.Category]
		cs.DataAvailable = true
		cs.FiredSignals = append(cs.FiredSignals, f)
		cats[f.Category] = cs
	}
	score := Score{Overall: overall, Categories: cats}
	return &Evaluation{Verdict: verdict, DirectScore: score, RolledUp: score}
}

func vulnSig(id string, w float64) FiredSignal {
	return FiredSignal{ID: id, Category: CategoryVulnerability, Severity: SevHigh, Weight: w}
}

// TestUpgradePromotionEligible_HappyPath is the shape the promotion is FOR:
// a band-2 CVE-driven package with nothing else wrong.
func TestUpgradePromotionEligible_HappyPath(t *testing.T) {
	ev := evalWith(VerdictWarn, 40,
		vulnSig(SignalVulnCVSSHigh, -20),
		FiredSignal{ID: SignalVulnFixAvailable, Category: CategoryVulnerability, Severity: SevInfo, Weight: +5},
	)
	if !UpgradePromotionEligible(ev) {
		t.Fatalf("a band-2 CVE-driven evaluation must be eligible for promotion")
	}
}

// TestUpgradePromotionEligible_BottomBandRefused is gate (c). A sub-30
// score is not a "just upgrade" case no matter how good the fix data is.
// vuln.kev carries MaxImpact 20, so this is also the KEV rule.
func TestUpgradePromotionEligible_BottomBandRefused(t *testing.T) {
	for _, overall := range []int{0, 20, ThresholdQuarantine - 1} {
		ev := evalWith(VerdictQuarantine, overall, vulnSig(SignalVulnKEV, -60))
		if UpgradePromotionEligible(ev) {
			t.Errorf("overall=%d was promoted out of the bottom band", overall)
		}
	}
	// Exactly at the threshold is in-band and eligible — the boundary is
	// pinned so a future edit to thresholdQuarantine cannot silently
	// widen or narrow the promotion window.
	ev := evalWith(VerdictQuarantine, ThresholdQuarantine, vulnSig(SignalVulnCVSSCritical, -35))
	if !UpgradePromotionEligible(ev) {
		t.Errorf("overall=%d (== ThresholdQuarantine) should be eligible", ThresholdQuarantine)
	}
}

// TestUpgradePromotionEligible_RolledUpAlsoGates: a node whose direct
// score is comfortable but whose transitive rollup dropped it into band 1
// must not be promoted on the strength of the direct score.
func TestUpgradePromotionEligible_RolledUpAlsoGates(t *testing.T) {
	ev := evalWith(VerdictQuarantine, 45, vulnSig(SignalVulnCVSSHigh, -20))
	ev.RolledUp.Overall = 10
	if UpgradePromotionEligible(ev) {
		t.Fatalf("a rolled-up bottom-band score must refuse promotion")
	}
}

// TestUpgradePromotionEligible_VetoedCategories is gate (b): a newer
// version of a malicious/typosquatted/tampered package is not a safe one.
// The gate is keyed on category so signals added to those registries
// later inherit it.
func TestUpgradePromotionEligible_VetoedCategories(t *testing.T) {
	cases := []struct {
		name string
		sig  FiredSignal
	}{
		{"malware", FiredSignal{ID: SignalSCKnownMalicious, Category: CategorySupplyChain, Severity: SevCritical, Weight: -1000}},
		{"typosquat", FiredSignal{ID: SignalSCTyposquatHigh, Category: CategorySupplyChain, Severity: SevHigh, Weight: -40}},
		{"install hook", FiredSignal{ID: SignalSCInstallScriptNetwork, Category: CategorySupplyChain, Severity: SevHigh, Weight: -30}},
		{"checksum mismatch", FiredSignal{ID: SignalQualChecksumMismatch, Category: CategoryQuality, Severity: SevCritical, Weight: -1000}},
		{"compound takeover", FiredSignal{ID: CompoundSCTakeoverSignature, Category: CategorySupplyChain, Severity: SevCritical, Weight: -55, Compound: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := evalWith(VerdictQuarantine, 40, vulnSig(SignalVulnCVSSHigh, -20), c.sig)
			if UpgradePromotionEligible(ev) {
				t.Fatalf("%s contributed to the score but promotion was allowed", c.sig.ID)
			}
		})
	}
}

// TestUpgradePromotionEligible_PositiveSupplyChainSignalIsNotAVeto: the
// veto is on RISK contributions, not on the category appearing at all. A
// verified checksum or verified provenance must not suppress a legitimate
// upgrade recommendation.
func TestUpgradePromotionEligible_PositiveSupplyChainSignalIsNotAVeto(t *testing.T) {
	ev := evalWith(VerdictWarn, 40,
		vulnSig(SignalVulnCVSSHigh, -20),
		FiredSignal{ID: SignalQualChecksumVerified, Category: CategoryQuality, Severity: SevInfo, Weight: +5},
	)
	if !UpgradePromotionEligible(ev) {
		t.Fatalf("a positive quality signal must not veto promotion")
	}
}

// TestUpgradePromotionEligible_DominanceRequired: maintenance and license
// are not vetoes, but they cannot be the DRIVER. "Just upgrade" is wrong
// advice for a package whose real problem is that nobody maintains it.
func TestUpgradePromotionEligible_DominanceRequired(t *testing.T) {
	maint := func(w float64) FiredSignal {
		return FiredSignal{ID: "maint.x", Category: CategoryMaintenance, Severity: SevMedium, Weight: w}
	}
	if UpgradePromotionEligible(evalWith(VerdictWarn, 40, vulnSig(SignalVulnCVSSHigh, -20), maint(-25))) {
		t.Errorf("maintenance-dominant risk was promoted")
	}
	if UpgradePromotionEligible(evalWith(VerdictWarn, 40, vulnSig(SignalVulnCVSSHigh, -20), maint(-20))) {
		t.Errorf("a tie is not dominance and must not be promoted")
	}
	if !UpgradePromotionEligible(evalWith(VerdictWarn, 40, vulnSig(SignalVulnCVSSHigh, -20), maint(-5))) {
		t.Errorf("vulnerability-dominant risk with minor maintenance noise should be eligible")
	}
}

// TestUpgradePromotionEligible_NoVulnerabilityDeficit: nothing to upgrade
// away from.
func TestUpgradePromotionEligible_NoVulnerabilityDeficit(t *testing.T) {
	ev := evalWith(VerdictWarn, 40,
		FiredSignal{ID: "maint.x", Category: CategoryMaintenance, Severity: SevMedium, Weight: -20},
	)
	if UpgradePromotionEligible(ev) {
		t.Fatalf("no negative vulnerability signal fired; promotion must be refused")
	}
}

// TestUpgradePromotionEligible_NonPromotableVerdicts: Allow has nothing to
// improve and Unknown never ran. Neither may be laundered into advice.
func TestUpgradePromotionEligible_NonPromotableVerdicts(t *testing.T) {
	for _, v := range []Verdict{VerdictAllow, VerdictUnknown, VerdictUpgradeAvailable, Verdict("")} {
		ev := evalWith(v, 40, vulnSig(SignalVulnCVSSHigh, -20))
		if UpgradePromotionEligible(ev) {
			t.Errorf("verdict %q must not be promotable", v)
		}
	}
	if UpgradePromotionEligible(nil) {
		t.Errorf("nil evaluation must not be promotable")
	}
}
