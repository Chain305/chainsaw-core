package policy

import "testing"

// TestInKEVCondition pins the inKev matcher, including its fail-closed arm.
//
// Break it like this: delete the `cond.InKEV` block in matchesConditions —
// "listed" stops matching; or drop the KEVUnavailable term — "no catalog,
// vulnerable" stops matching, which is the fail-open this condition must not
// have.
func TestInKEVCondition(t *testing.T) {
	tr, fa := true, false
	for _, tc := range []struct {
		name string
		cond Conditions
		ctx  EvaluationContext
		want bool
	}{
		{"listed", Conditions{InKEV: &tr}, EvaluationContext{IsVulnerable: true, InKEV: true}, true},
		{"not listed", Conditions{InKEV: &tr}, EvaluationContext{IsVulnerable: true}, false},
		{"no catalog, vulnerable: fails closed", Conditions{InKEV: &tr}, EvaluationContext{IsVulnerable: true, KEVUnavailable: true}, true},
		{"no catalog, clean package: no match", Conditions{InKEV: &tr}, EvaluationContext{KEVUnavailable: true}, false},
		{"inKev=false, listed", Conditions{InKEV: &fa}, EvaluationContext{IsVulnerable: true, InKEV: true}, false},
		{"inKev=false, not listed", Conditions{InKEV: &fa}, EvaluationContext{IsVulnerable: true}, true},
		// KEV is independent of CVSS: a low score still matches.
		{"listed at CVSS 5.3", Conditions{IsVulnerable: &tr, InKEV: &tr}, EvaluationContext{IsVulnerable: true, CVSSScore: 5.3, InKEV: true}, true},
	} {
		if got := matchesConditions(tc.ctx, tc.cond); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
	if used := ConditionsUsedBy(Conditions{InKEV: &tr}); len(used) != 1 || used[0] != ConditionCVE {
		t.Errorf("ConditionsUsedBy(inKev) = %v, want [%s]: inKev reads the CVE list", used, ConditionCVE)
	}
}

// TestSeededKEVRuleRefusesLowScoreExploited runs the REAL seed set
// (configs/seed.yaml + demo policies) plus an org's cvssMin 7 rule over
// CVE-2023-44487 (HTTP/2 Rapid Reset): KEV-listed, GitHub MODERATE, and 6.9
// after GitHub-band scoring — below the cvssMin rule. The seeded KEV rule
// must refuse it; without the KEV rule the verdict is monitor.
func TestSeededKEVRuleRefusesLowScoreExploited(t *testing.T) {
	seven := 7.0
	tr := true
	pols := atkBWith(t, "Block high and critical CVEs", Conditions{IsVulnerable: &tr, CVSSMin: &seven})
	ctx := EvaluationContext{
		OrgID: "org-1", RepositoryFormat: "golang", PackageName: "golang.org/x/net", PackageVersion: "0.16.0",
		IsVulnerable: true, CVSSScore: 6.9, CVEs: []string{"CVE-2023-44487"}, InKEV: true,
	}
	res := atkBEval(t, pols, ctx)
	if res.Action != ModeBlock || res.MatchedPolicy == nil || res.MatchedPolicy.Conditions.InKEV == nil {
		t.Fatalf("KEV-listed CVE at CVSS 6.9: got %s by %+v, want block by the seeded KEV rule", res.Action, res.MatchedPolicy)
	}

	// Same package, not KEV-listed: the cvssMin rule does not fire at 6.9 and
	// nothing else blocks it.
	ctx.InKEV = false
	if res := atkBEval(t, pols, ctx); res.Action == ModeBlock {
		t.Fatalf("non-KEV CVE at CVSS 6.9 blocked by %+v; the KEV rule over-matched", res.MatchedPolicy)
	}

	// No KEV catalog loaded: fail closed.
	ctx.KEVUnavailable = true
	if res := atkBEval(t, pols, ctx); res.Action != ModeBlock {
		t.Fatalf("no KEV catalog, vulnerable package: got %s, want block (fail closed)", res.Action)
	}
}
