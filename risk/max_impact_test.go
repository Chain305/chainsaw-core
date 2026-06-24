package risk

import "testing"

// TestMaxImpactCeiling_LoneTyposquatHigh verifies that a lone typosquat-high
// signal pins overall to its declared MaxImpact, addressing the score-shift
// regression where the SupplyChain category weight (0.35) prevented a -40
// signal from dragging overall below 65.
func TestMaxImpactCeiling_LoneTyposquatHigh(t *testing.T) {
	in := Input{
		Ecosystem:            "npm",
		Package:              "lodahs",
		Version:              "1.0.0",
		LicenseSPDX:          "MIT",
		IsSuspectedTyposquat: true,
		TyposquatConfidence:  "high",
	}
	eval := EvaluatePackage(in, Options{})
	sig, ok := Registry[SignalSCTyposquatHigh]
	if !ok {
		t.Fatalf("typosquat-high signal not registered")
	}
	if eval.RolledUp.Overall > sig.MaxImpact {
		t.Errorf("overall=%d should be capped at MaxImpact=%d when typosquat-high fires alone",
			eval.RolledUp.Overall, sig.MaxImpact)
	}
}

// TestMaxImpactCeiling_BypassedWhenCompoundFires confirms that compound rules
// (multi-signal elevation) bypass the per-signal ceiling — the takeover
// compound's ceiling-bypassing additive deficit, plus its Critical severity
// in resolveVerdict, ensures verdict escalates past plain Warn even though
// the numerical overall may not be lower than a tightly-ceilinged primitive.
func TestMaxImpactCeiling_BypassedWhenCompoundFires(t *testing.T) {
	in := Input{
		Ecosystem:        "npm",
		Package:          "axios-like",
		Version:          "2.0.0",
		LicenseSPDX:      "MIT",
		PublisherChanged: true,
		HasInstallScript: true,
	}
	eval := EvaluatePackage(in, Options{})
	if eval.Verdict == VerdictAllow {
		t.Errorf("takeover compound must not Allow: verdict=%q overall=%d",
			eval.Verdict, eval.RolledUp.Overall)
	}
	if eval.Verdict == VerdictWarn {
		t.Errorf("takeover compound (Critical) must not be bare Warn: verdict=%q overall=%d",
			eval.Verdict, eval.RolledUp.Overall)
	}
}

// TestNewWave4Signals_FireAndContribute confirms each of the four new RTT
// signals projects from Input → fired primitive on the expected condition.
func TestNewWave4Signals_FireAndContribute(t *testing.T) {
	tt := []struct {
		name string
		in   Input
		want string
	}{
		{
			name: "SuspiciousRepoStars",
			in:   Input{LicenseSPDX: "MIT", SuspiciousRepoStars: true},
			want: SignalSCSuspiciousRepoStars,
		},
		{
			name: "FirstTimeCollaborator true",
			in:   Input{LicenseSPDX: "MIT", FirstTimeCollaborator: ptrBool(true)},
			want: SignalSCFirstTimeCollaborator,
		},
		{
			name: "MaintainerAccountAge very young",
			in:   Input{LicenseSPDX: "MIT", MaintainerAccountAgeDays: 7},
			want: SignalSCMaintainerAccountVeryYoung,
		},
		{
			name: "NonExistentAuthor",
			in:   Input{LicenseSPDX: "MIT", NonExistentAuthor: true},
			want: SignalSCNonExistentAuthor,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			fired := runPrimitiveSignals(tc.in, nil)
			if _, ok := fired[tc.want]; !ok {
				t.Errorf("expected %s to fire; fired=%v", tc.want, keys(fired))
			}
		})
	}
}

// TestFirstTimeCollaborator_NilDoesNotFire — sparse-data path; nil should
// never fire (we don't penalise on missing data).
func TestFirstTimeCollaborator_NilDoesNotFire(t *testing.T) {
	in := Input{LicenseSPDX: "MIT", FirstTimeCollaborator: nil}
	fired := runPrimitiveSignals(in, nil)
	if _, ok := fired[SignalSCFirstTimeCollaborator]; ok {
		t.Errorf("nil FirstTimeCollaborator should not fire signal")
	}
}

func ptrBool(b bool) *bool { return &b }

func keys(m map[string]FiredSignal) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
