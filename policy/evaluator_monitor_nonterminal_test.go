package policy

import (
	"testing"
	"time"
)

// F1 of docs/attack-coverage-2026: a monitor match ended evaluation, so the
// seeded "Block brand-new versions" monitor rule (precedence 140, every
// version under 10 days old) returned before the hidden-unicode block (150)
// and the demo typosquat block. In prod it shadowed those blocks in 41 of 46
// orgs, for exactly the young versions an attack ships as. Monitor observes;
// it must never switch off an enforcing rule ranked after it.

func TestMonitorMatchDoesNotShadowLaterBlock(t *testing.T) {
	pols := atkBSeedPolicies(t)

	// GlassWorm shape: a 2-day-old version of an established package
	// carrying a variation-selector run. Matches the cooldown monitor (140)
	// first, then the hidden-unicode block (150).
	glass := atkBCtx("react-native-country-select", "0.3.91", 2*atkBYear, 2*atkBDay)
	glass.HasHiddenUnicode = true
	glass.HiddenUnicodeKinds = []string{"variation_selector"}
	atkBWantBlock(t, atkBEval(t, pols, glass), "Block bidi-override hidden Unicode payloads")

	// Typosquat shape: a 3-day-old version flagged as a squat.
	squat := atkBCtx("proc-macro1", "1.0.107", 2*atkBYear, 3*atkBDay)
	squat.IsSuspectedTyposquat = true
	atkBWantBlock(t, atkBEval(t, pols, squat), demoPolicyPrefix+"Block suspected typosquats")

	// The monitor rule still records a young version nothing else matches.
	plain := atkBCtx("left-pad", "1.3.1", 2*atkBYear, 2*atkBDay)
	res := atkBEval(t, pols, plain)
	if res.Action != ModeMonitor || res.MatchedPolicy == nil || res.MatchedPolicy.Precedence != 140 {
		t.Fatalf("young clean version: want the precedence-140 monitor, got %s by %+v", res.Action, res.MatchedPolicy)
	}

	// The same payload on an old version is blocked as before.
	old := glass
	vr := time.Now().Add(-200 * atkBDay)
	old.VersionReleaseDate = &vr
	atkBWantBlock(t, atkBEval(t, pols, old), "Block bidi-override hidden Unicode payloads")
}

func TestMonitorMatchOrdering(t *testing.T) {
	yes := true
	mon := Policy{ID: "mon", Name: "mon", Mode: ModeMonitor, Status: StatusEnabled, Precedence: 10,
		Conditions: Conditions{HasInstallScript: &yes}}
	blk := Policy{ID: "blk", Name: "blk", Mode: ModeBlock, Status: StatusEnabled, Precedence: 20,
		Conditions: Conditions{HasInstallScript: &yes}}
	qua := Policy{ID: "qua", Name: "qua", Mode: ModeQuarantine, Status: StatusEnabled, Precedence: 20,
		Conditions: Conditions{HasInstallScript: &yes}}
	alw := Policy{ID: "alw", Name: "alw", Mode: ModeAllow, Status: StatusEnabled, Precedence: 20,
		Conditions: Conditions{HasInstallScript: &yes}}
	ctx := atkBCtx("pkg", "1.0.0", 2*atkBYear, 200*atkBDay)
	ctx.HasInstallScript = true

	for _, tc := range []struct {
		name string
		pols []Policy
		want Mode
		by   string
	}{
		{"later block wins over monitor", []Policy{mon, blk}, ModeBlock, "blk"},
		{"later quarantine wins over monitor", []Policy{mon, qua}, ModeQuarantine, "qua"},
		// An allow ranked after a monitor does not erase the observation:
		// both serve the package, and the monitor is the higher-ranked match.
		{"later allow keeps the monitor", []Policy{mon, alw}, ModeMonitor, "mon"},
		// An allow ranked first (an exception) is still terminal.
		{"earlier allow is terminal", []Policy{{ID: "exc", Name: "exc", Mode: ModeAllow, Status: StatusEnabled,
			Precedence: 1, Conditions: Conditions{HasInstallScript: &yes}}, mon, blk}, ModeAllow, "exc"},
		{"earlier block is terminal", []Policy{blk, mon}, ModeBlock, "blk"},
		{"first of two monitors is recorded", []Policy{mon, {ID: "mon2", Name: "mon2", Mode: ModeMonitor,
			Status: StatusEnabled, Precedence: 15, Conditions: Conditions{HasInstallScript: &yes}}}, ModeMonitor, "mon"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := atkBEval(t, tc.pols, ctx)
			if res.Action != tc.want || res.MatchedPolicy == nil || res.MatchedPolicy.Name != tc.by {
				name := "<nil>"
				if res.MatchedPolicy != nil {
					name = res.MatchedPolicy.Name
				}
				t.Fatalf("got %s by %s, want %s by %s", res.Action, name, tc.want, tc.by)
			}
		})
	}
}
