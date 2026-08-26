package risk

import (
	"sort"
	"testing"
)

// This file pins the invariant that P8-02 violated at BOTH band boundaries.
//
// The rule is NOT "no signal's MaxImpact may equal a threshold" — the values
// are deliberate calibration. The rule the engine actually relies on is:
//
//	A declared MaxImpact is a policy claim of the form "this signal, fired
//	alone, holds the package at or below N". The claim is only enforceable
//	if the verdict that comes out is at least as bad as the band N names.
//	Concretely, with the bands [0, 30) blocking / [30, 60) warn / [60, 100]
//	allow:
//	  - a ceiling at or below ThresholdQuarantine claims blocking grade, so
//	    the lone-fire verdict must be quarantine (or another blocking-grade
//	    resolution when the caller supplied an upgrade/alternative);
//	  - a ceiling at or below ThresholdWarn claims "not clean", so the
//	    lone-fire verdict must never be allow.
//
// Both band tests in resolveVerdict are strict `<`, so a ceiling landing
// EXACTLY on a threshold falls through into the weaker band. That is how
// five signals shipped unable to reach the verdict their ceiling claimed:
// sc.typosquat_high (30, SevHigh, no critical escalation → bare warn) and
// the four SevMedium 60-ceiling signals (qual.version_anomaly,
// sc.hidden_unicode, sc.repo_archived, sc.repo_missing → allow).
//
// Three earlier reviewers reasoned from SCORES and got the answer wrong.
// This test drives the real EvaluatePackage and asserts on VERDICTS.

// loneFireFixtures maps every Registry signal that declares a MaxImpact
// ceiling to an Input that fires that signal and nothing else negative.
// TestEveryCeilingedSignalHasALoneFireFixture fails when a new ceilinged
// signal is registered without a fixture, so the invariant below cannot be
// silently skipped by adding a signal.
//
// LicenseSPDX is set on every fixture so lic.missing / license.unidentified
// do not join the fired set. sc.transitive_malware is absent by design: its
// MaxImpact is 0 (no cap at all) and it enforces through the -1000
// instant-block sentinel, which short-circuits before resolveVerdict.
func loneFireFixtures() map[string]Input {
	base := func() Input {
		return Input{Ecosystem: "npm", Package: "p", Version: "1.0.0", LicenseSPDX: "MIT"}
	}
	withVuln := func(cvss float64, kev bool) Input {
		in := base()
		in.IsVulnerable = true
		in.VulnDataAvailable = true
		in.MaxCVSS = cvss
		in.KnownExploited = kev
		in.CVEs = []string{"CVE-2024-0001"}
		return in
	}
	set := func(f func(*Input)) Input {
		in := base()
		f(&in)
		return in
	}

	return map[string]Input{
		// --- vulnerability -------------------------------------------------
		SignalVulnKEV:          withVuln(9.5, true),
		SignalVulnCVSSCritical: withVuln(9.8, false),
		SignalVulnCVSSHigh:     withVuln(7.5, false),

		// --- AI artifact ---------------------------------------------------
		SignalAIDangerousPickle: set(func(in *Input) {
			in.Ecosystem = "huggingface"
			in.DangerousPickleOpcode = true
			in.DangerousPickleFiles = []string{"weights.pkl"}
		}),
		SignalAIAgentToolDangerous: set(func(in *Input) {
			in.AgentToolDangerousCapability = true
			in.AgentToolCapabilities = []string{"subprocess"}
		}),

		// --- quality -------------------------------------------------------
		SignalQualVersionAnomaly: set(func(in *Input) {
			in.VersionAnomalyFlags = []string{"timestamp_regression"}
		}),

		// --- supply chain --------------------------------------------------
		SignalSCTyposquatHigh: set(func(in *Input) {
			in.Package = "lodahs"
			in.IsSuspectedTyposquat = true
			in.TyposquatConfidence = "high"
			in.TyposquatSimilarTo = "lodash"
		}),
		SignalSCPublisherChanged: set(func(in *Input) {
			// No install script — sc.takeover_signature must not fire, or
			// the compound bypasses applyMaxImpactCeiling entirely.
			in.PublisherChanged = true
		}),
		SignalSCInstallScriptNetwork: set(func(in *Input) {
			in.InstallScriptFetchesRemote = true
		}),
		SignalSCHiddenUnicode: set(func(in *Input) {
			in.HasHiddenUnicode = true
		}),
		SignalSCRepoOwnershipMismatch: set(func(in *Input) {
			in.RepoLinkStatus = "ownership_mismatch"
		}),
		SignalSCRepoArchived: set(func(in *Input) {
			in.RepoLinkStatus = "archived"
		}),
		SignalSCRepoMissing: set(func(in *Input) {
			in.RepoLinkStatus = "missing"
		}),
		SignalSCReservedNamespace: set(func(in *Input) {
			in.ReservedNamespaceViolation = true
		}),
		SignalSCPublishVelocity: set(func(in *Input) {
			in.PublishVelocityAnomaly = true
		}),
		SignalSCSuspiciousRepoStars: set(func(in *Input) {
			in.SuspiciousRepoStars = true
		}),
		SignalSCMaintainerAccountVeryYoung: set(func(in *Input) {
			in.MaintainerAccountAgeDays = 10
		}),
		SignalSCNonExistentAuthor: set(func(in *Input) {
			in.NonExistentAuthor = true
		}),
		SignalSCTransitiveCriticalVuln: set(func(in *Input) {
			in.TransitiveCriticalCount = 1
		}),
		SignalSCTransitiveHighVuln: set(func(in *Input) {
			in.TransitiveHighCount = 1
		}),
	}
}

// verdictRank orders the verdicts from "clean" to "blocking" so the
// invariant can require "at least this bad" without pinning the exact
// resolution — a caller that supplies SafeUpgradeVersion or Alternative
// legitimately gets upgrade_available / replace instead of quarantine, and
// both are blocking-grade at the proxy.
func verdictRank(v Verdict) int {
	switch v {
	case VerdictAllow:
		return 0
	case VerdictWarn:
		return 1
	case VerdictUpgradeAvailable, VerdictReplace, VerdictQuarantine:
		return 2
	default: // VerdictUnknown — never produced by these fixtures.
		return -1
	}
}

// requiredRankForCeiling maps a declared MaxImpact onto the weakest verdict
// that still honours the claim. The comparison is INCLUSIVE of the
// threshold, which is the whole point: resolveVerdict's band tests are
// exclusive, so a ceiling sitting exactly on a threshold is a claim about
// the tighter band while the score lands in the looser one.
func requiredRankForCeiling(maxImpact int) (int, string) {
	switch {
	case maxImpact <= ThresholdQuarantine:
		return 2, "blocking-grade (quarantine / upgrade_available / replace)"
	case maxImpact <= ThresholdWarn:
		return 1, "at least warn"
	default:
		return 0, "unconstrained"
	}
}

// negativeFired returns the ids of every fired signal that SUBTRACTS from a
// category score. Positive/info credits (lic.spdx_present, checksum
// verified, provenance) are ignored — they cannot move a package into a
// worse band and their presence does not make a fixture impure.
func negativeFired(ev *Evaluation) []string {
	var out []string
	for _, cs := range ev.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			if f.Weight < 0 {
				out = append(out, f.ID)
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestEveryCeilingedSignalHasALoneFireFixture is the completeness half.
// Without it, a future signal declaring MaxImpact 60 would simply not be
// covered by the invariant below and would reintroduce the defect silently.
func TestEveryCeilingedSignalHasALoneFireFixture(t *testing.T) {
	fixtures := loneFireFixtures()
	for id, sig := range Registry {
		if sig.MaxImpact <= 0 {
			continue
		}
		if _, ok := fixtures[id]; !ok {
			t.Errorf("signal %q declares MaxImpact %d but has no lone-fire fixture in loneFireFixtures(); "+
				"add one so TestCeilingedSignalRebutsItsOwnBand can check it", id, sig.MaxImpact)
		}
	}
	for id := range fixtures {
		if _, ok := Registry[id]; !ok {
			t.Errorf("loneFireFixtures has an entry for %q, which is not in Registry", id)
		}
	}
}

// TestCeilingedSignalRebutsItsOwnBand is the invariant that would have
// caught all five P8-02 signals. It drives the real evaluator and asserts on
// verdicts, not scores.
func TestCeilingedSignalRebutsItsOwnBand(t *testing.T) {
	fixtures := loneFireFixtures()
	ids := make([]string, 0, len(fixtures))
	for id := range fixtures {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		sig, ok := Registry[id]
		if !ok {
			continue // reported by the completeness test above
		}
		t.Run(id, func(t *testing.T) {
			ev := EvaluatePackage(fixtures[id], Options{})

			// The fixture must isolate the signal, or the assertion below
			// is measuring something else's ceiling.
			got := negativeFired(ev)
			if len(got) != 1 || got[0] != id {
				t.Fatalf("fixture for %s does not fire it alone: negative signals = %v", id, got)
			}

			wantRank, wantDesc := requiredRankForCeiling(sig.MaxImpact)
			if verdictRank(ev.Verdict) < wantRank {
				t.Errorf("%s declares MaxImpact %d (thresholds: quarantine %d, warn %d) but firing it alone "+
					"yields overall=%d verdict=%q — the ceiling claims %s. A ceiling that lands exactly on a "+
					"band threshold falls through to the weaker band because resolveVerdict's tests are strict `<`; "+
					"fix the SIGNAL (severity or ceiling), never the band test.",
					id, sig.MaxImpact, ThresholdQuarantine, ThresholdWarn,
					ev.RolledUp.Overall, ev.Verdict, wantDesc)
			}
		})
	}
}

// TestP802BandBoundaryVerdicts is the per-signal table for the five signals
// the boundary collisions disabled, plus the two positive controls that
// already rode the band-2 critical escalation correctly. The controls are
// here so a regression that breaks the escalation path shows up as a
// control failure rather than as a mysterious change in the five.
func TestP802BandBoundaryVerdicts(t *testing.T) {
	fixtures := loneFireFixtures()

	cases := []struct {
		signal      string
		wantVerdict Verdict
		note        string
	}{
		// --- band 1 (=30) ---------------------------------------------------
		{
			signal:      SignalSCTyposquatHigh,
			wantVerdict: VerdictQuarantine,
			note: "was SevHigh, so the ceiling pinned overall to exactly 30, `30 < 30` is false, " +
				"and the band-2 critical escalation did not apply — a high-confidence typosquat " +
				"could only ever WARN. Now SevCritical, riding the escalation the design already built.",
		},
		{
			signal:      SignalVulnCVSSCritical,
			wantVerdict: VerdictQuarantine,
			note:        "POSITIVE CONTROL: already SevCritical, already escalated. Must not change.",
		},
		{
			signal:      SignalSCTransitiveCriticalVuln,
			wantVerdict: VerdictQuarantine,
			note:        "POSITIVE CONTROL: already SevCritical, already escalated. Must not change.",
		},
		// --- band 2 (=60) ---------------------------------------------------
		{
			signal:      SignalQualVersionAnomaly,
			wantVerdict: VerdictWarn,
			note:        "ceiling moved 60 → 59: exactly-60 skipped band 2 entirely and returned ALLOW.",
		},
		{
			signal:      SignalSCHiddenUnicode,
			wantVerdict: VerdictWarn,
			note:        "Trojan Source detection. The offline guard hard-blocks on it; the server could not warn.",
		},
		{
			signal:      SignalSCRepoArchived,
			wantVerdict: VerdictWarn,
			note:        "ceiling moved 60 → 59.",
		},
		{
			signal:      SignalSCRepoMissing,
			wantVerdict: VerdictWarn,
			note:        "ceiling moved 60 → 59.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.signal, func(t *testing.T) {
			in, ok := fixtures[tc.signal]
			if !ok {
				t.Fatalf("no lone-fire fixture for %s", tc.signal)
			}
			ev := EvaluatePackage(in, Options{})
			if ev.Verdict != tc.wantVerdict {
				t.Errorf("%s fired alone: verdict=%q overall=%d, want %q — %s",
					tc.signal, ev.Verdict, ev.RolledUp.Overall, tc.wantVerdict, tc.note)
			}
		})
	}
}

// TestBand2CeilingsSitBelowTheWarnThreshold is the declarative half of the
// band-2 fix: it pins the VALUES so a later edit cannot quietly put a
// medium-tier ceiling back onto the threshold. 59 is the top of the warn
// band — the tightest claim these signals were ever making — and it has no
// interaction with UpgradePromotionEligible, whose only score gate is
// ThresholdQuarantine (see TestBand2CeilingChangeCannotDeleteAnUpgrade).
func TestBand2CeilingsSitBelowTheWarnThreshold(t *testing.T) {
	for _, id := range []string{
		SignalQualVersionAnomaly,
		SignalSCHiddenUnicode,
		SignalSCRepoArchived,
		SignalSCRepoMissing,
	} {
		sig := Registry[id]
		if sig.MaxImpact != ThresholdWarn-1 {
			t.Errorf("%s: MaxImpact = %d, want %d (ThresholdWarn-1). A medium-tier ceiling AT %d "+
				"lands on the band-2 boundary and resolves to ALLOW — the signal can never warn.",
				id, sig.MaxImpact, ThresholdWarn-1, ThresholdWarn)
		}
	}
}

// TestBand2CeilingChangeCannotDeleteAnUpgrade is the counterpart to the
// reasoning that rejected 30 → 29 for band 1. Lowering a ceiling below
// ThresholdQuarantine trips UpgradePromotionEligible's gate (c) and silently
// deletes the "upgrade to X" advice. 59 is nowhere near that gate — and in
// any case all four band-2 signals live in a vetoed category (supply_chain
// or quality), so a package on which one of them fired was never promotable
// to begin with. Both halves are asserted so neither can drift.
func TestBand2CeilingChangeCannotDeleteAnUpgrade(t *testing.T) {
	fixtures := loneFireFixtures()
	for _, id := range []string{
		SignalQualVersionAnomaly,
		SignalSCHiddenUnicode,
		SignalSCRepoArchived,
		SignalSCRepoMissing,
	} {
		sig := Registry[id]
		if sig.MaxImpact < ThresholdQuarantine {
			t.Errorf("%s: MaxImpact %d is below ThresholdQuarantine %d — this trips "+
				"UpgradePromotionEligible gate (c) and deletes the upgrade recommendation",
				id, sig.MaxImpact, ThresholdQuarantine)
		}
		if _, vetoed := upgradeVetoCategories[sig.Category]; !vetoed {
			t.Errorf("%s: category %q is not in upgradeVetoCategories — the ceiling change is only "+
				"promotion-neutral because these signals veto promotion outright", id, sig.Category)
		}
		// Behavioural half: with a safe upgrade on offer, the verdict is
		// still not laundered into upgrade_available by the promotion gate.
		ev := EvaluatePackage(fixtures[id], Options{})
		if UpgradePromotionEligible(ev) {
			t.Errorf("%s fired alone is UpgradePromotionEligible — a vetoed-category signal must never promote", id)
		}
	}
}

// TestTyposquatHighCannotPromoteToUpgradeAvailable is the band-1 counterpart:
// the severity change is safe precisely because a lone typosquat can never
// reach the promotion gate. supply_chain is vetoed outright at
// upgradeVetoCategories, and UpgradePromotionEligible additionally requires a
// vulnerability-category deficit, which a lone typosquat never produces. So
// the fix introduces exactly one new behaviour (warn → quarantine) and not a
// third one.
func TestTyposquatHighCannotPromoteToUpgradeAvailable(t *testing.T) {
	sig := Registry[SignalSCTyposquatHigh]
	if _, vetoed := upgradeVetoCategories[sig.Category]; !vetoed {
		t.Fatalf("sc.typosquat_high category %q is not vetoed — the SevCritical change would then be able "+
			"to interact with the upgrade-promotion gate", sig.Category)
	}
	ev := EvaluatePackage(loneFireFixtures()[SignalSCTyposquatHigh], Options{})
	if UpgradePromotionEligible(ev) {
		t.Error("a lone high-confidence typosquat must never be promoted to upgrade_available — " +
			"a newer release of a typosquatted package is still typosquatted")
	}
}
