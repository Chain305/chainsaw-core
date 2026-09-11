package intelligence

import (
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// TestVerdictRankUnknownFoldIsUnreachable pins the reachability argument
// that makes verdictRank's `return 0` tail safe.
//
// verdictRank ranks VerdictUnknown equal to VerdictAllow, which
// core/risk/evaluation.go:24-42 forbids in general. It is safe at its one
// call site only because the dangerous combination — a clean root that an
// unevaluable transitive pass should have pulled down — cannot be
// constructed. That argument rests on two properties of EvaluatePackage,
// and this test is what stops a refactor from quietly removing either.
//
// If this test fails, verdictRank's tail must become `return -1` (the
// shape recallVerdictRank already uses) and the comment above it is
// wrong.
func TestVerdictRankUnknownFoldIsUnreachable(t *testing.T) {
	// Property 1: with SignalsUnavailable=false, Unknown is unreachable.
	//
	// This is the load-bearing half. rootEval and secondEval are both
	// EvaluatePackage over the same Input (only Transitive*Count differs),
	// so if an evaluable Input can never yield Unknown, then a root of
	// Allow can never be paired with a second of Unknown.
	t.Run("evaluable input never yields unknown", func(t *testing.T) {
		for _, in := range evaluableInputs() {
			ev := risk.EvaluatePackage(in, risk.Options{})
			if ev == nil {
				t.Fatalf("EvaluatePackage returned nil for %+v", in)
			}
			if ev.Verdict == risk.VerdictUnknown {
				t.Errorf("SignalsUnavailable=false produced VerdictUnknown for %+v — "+
					"verdictRank's fold is now reachable and must become return -1", in)
			}
		}
	})

	// Property 2: with SignalsUnavailable=true, Allow is unreachable.
	//
	// The mirror image. If an unevaluable Input could yield Allow, the
	// two evaluations could disagree in the other direction and the
	// "both take the same branch" half of the argument would fail.
	t.Run("unevaluable input never yields allow", func(t *testing.T) {
		for _, in := range evaluableInputs() {
			in.SignalsUnavailable = true
			ev := risk.EvaluatePackage(in, risk.Options{})
			if ev == nil {
				t.Fatalf("EvaluatePackage returned nil for %+v", in)
			}
			if ev.Verdict == risk.VerdictAllow {
				t.Errorf("SignalsUnavailable=true produced VerdictAllow for %+v — "+
					"an outage would be reported as a clean bill of health", in)
			}
		}
	})

	// Property 3: the overlay condition itself. Drive the actual
	// comparison verdictRank feeds, over every pair the two properties
	// above permit, and assert the overlay never discards a known verdict
	// in favour of an unknown one.
	t.Run("overlay never replaces a known verdict with unknown", func(t *testing.T) {
		for _, base := range evaluableInputs() {
			for _, unavailable := range []bool{false, true} {
				rootIn := base
				rootIn.SignalsUnavailable = unavailable
				secondIn := rootIn
				// The only mutation the production path makes between
				// the two evaluations.
				secondIn.TransitiveCriticalCount = 3
				secondIn.TransitiveMalwareCount = 1

				rootEval := risk.EvaluatePackage(rootIn, risk.Options{})
				secondEval := risk.EvaluatePackage(secondIn, risk.Options{})

				overlayWins := verdictRank(secondEval.Verdict) > verdictRank(rootEval.Verdict)
				if overlayWins && secondEval.Verdict == risk.VerdictUnknown {
					t.Errorf("overlay would replace %q with unknown (unavailable=%v, input %+v)",
						rootEval.Verdict, unavailable, base)
				}
				// The case the filed concern was about.
				if rootEval.Verdict == risk.VerdictAllow && secondEval.Verdict == risk.VerdictUnknown {
					t.Errorf("constructed the supposedly-unreachable pair root=allow second=unknown "+
						"(unavailable=%v, input %+v) — verdictRank's comment is now wrong",
						unavailable, base)
				}
			}
		}
	})
}

// evaluableInputs spans the verdict bands: clean, warn-ish, high-risk,
// malicious, and typosquat. All carry SignalsUnavailable=false; callers
// flip it where the property under test needs it.
func evaluableInputs() []risk.Input {
	base := func() risk.Input {
		return risk.Input{
			Ecosystem: "npm",
			Package:   "left-pad",
			Version:   "1.3.0",
		}
	}
	var out []risk.Input

	out = append(out, base()) // clean

	malicious := base()
	malicious.IsKnownMalicious = true
	out = append(out, malicious)

	typo := base()
	typo.IsSuspectedTyposquat = true
	out = append(out, typo)

	vuln := base()
	vuln.MaxCVSS = 9.8
	vuln.IsVulnerable = true
	out = append(out, vuln)

	mid := base()
	mid.MaxCVSS = 5.0
	mid.IsVulnerable = true
	out = append(out, mid)

	return out
}
