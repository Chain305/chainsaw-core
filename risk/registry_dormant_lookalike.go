package risk

import "fmt"

// SignalSCDormantLookalikeRelease: the server cleared a typosquat hit because
// the package is established on a package-wide line (weekly downloads or
// release history), but the scanned release is under a year old and came
// after at least DormancyGapThreshold of silence. Those lines describe the
// package's past, not this release; a lookalike that qualified long ago and
// then ships after years of silence is the sleeper the clear would otherwise
// wave through (the ctx takeover shape, on a lookalike name).
//
// Warn, not a re-flag: 38 of 46 production orgs run the seeded
// isSuspectedTyposquat block rule, so leaving the hit suspected would block
// (owner decision 2026-10-22, docs/PLANS_INTELLIGENCE.md#plan-server-established-version-gate).
// The ceiling is maxImpactWarnTop so it can warn and never quarantine on its
// own. Not DampEstablished: it only ever fires on established packages, so
// the damper would erase it everywhere.
const SignalSCDormantLookalikeRelease = "sc.dormant_lookalike_release"

func init() {
	register(Signal{
		ID:          SignalSCDormantLookalikeRelease,
		Category:    CategorySupplyChain,
		Severity:    SevMedium,
		Weight:      -20,
		MaxImpact:   maxImpactWarnTop,
		Title:       "Lookalike name, fresh release after long dormancy",
		Description: "The name resembles a popular package. The typosquat flag was cleared because the package is established, but this release came more than two years after the previous one.",
		Fires: func(in Input) (bool, string, map[string]any) {
			if in.DormantLookalikeSimilarTo == "" {
				return false, "", nil
			}
			return true, fmt.Sprintf("Name resembles %q; cleared as established, but this release came %d days after the previous one (%s).",
					in.DormantLookalikeSimilarTo, in.DormantLookalikeGapDays, in.DormantLookalikePriorVersion),
				map[string]any{
					"similarTo":    in.DormantLookalikeSimilarTo,
					"confidence":   in.DormantLookalikeConfidence,
					"priorVersion": in.DormantLookalikePriorVersion,
					"gapDays":      in.DormantLookalikeGapDays,
				}
		},
	})
}
