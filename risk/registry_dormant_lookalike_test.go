package risk

import (
	"strings"
	"testing"
	"time"
)

// dormantLookalikeInput is an established, otherwise clean package whose
// typosquat hit the server cleared, carrying the dormant-release fact.
func dormantLookalikeInput() Input {
	in := Input{
		Ecosystem:       "npm",
		Package:         "popular-lib",
		Version:         "3.0.0",
		WeeklyDownloads: intp(2_000_000),
		MaintainerCount: 3,
	}
	in.DormantLookalikeSimilarTo = "popular-1ib"
	in.DormantLookalikeConfidence = "high"
	in.DormantLookalikePriorVersion = "2.0.0"
	in.DormantLookalikeGapDays = 1100
	return in
}

// TestDormantLookalikeReleaseSignal pins the shape the owner chose
// (2026-10-22): a warn-level signal, never softened by the damper (the
// packages it fires on are established by construction), and never a block.
func TestDormantLookalikeReleaseSignal(t *testing.T) {
	sig, ok := Registry[SignalSCDormantLookalikeRelease]
	if !ok {
		t.Fatal("sc.dormant_lookalike_release not registered")
	}
	if sig.Category != CategorySupplyChain || sig.Weight != -20 || sig.MaxImpact != maxImpactWarnTop {
		t.Fatalf("want supply_chain, weight -20, MaxImpact %d; got %+v", maxImpactWarnTop, sig)
	}
	if sig.DampEstablished || sig.TakeoverIndicator {
		t.Fatal("must not be dampable (it only fires on established packages) or suspend the damper")
	}
	if fired, _, _ := sig.Fires(Input{}); fired {
		t.Fatal("fired with no dormant-release fact")
	}
	fired, detail, ev := sig.Fires(dormantLookalikeInput())
	if !fired || !strings.Contains(detail, `"popular-1ib"`) || !strings.Contains(detail, "1100 days") || !strings.Contains(detail, "2.0.0") {
		t.Fatalf("fired=%v detail=%q", fired, detail)
	}
	if ev["similarTo"] != "popular-1ib" || ev["gapDays"] != 1100 || ev["priorVersion"] != "2.0.0" || ev["confidence"] != "high" {
		t.Fatalf("evidence %v", ev)
	}
}

// TestDormantLookalikeReleaseWarnsNotBlocks: the same established package is
// allow without the fact and warn with it — not quarantine.
func TestDormantLookalikeReleaseWarnsNotBlocks(t *testing.T) {
	opts := Options{Now: func() time.Time { return dampNow }}
	base := dormantLookalikeInput()
	base.DormantLookalikeSimilarTo = ""
	if ev := EvaluatePackage(base, opts); ev.Verdict != VerdictAllow {
		t.Fatalf("baseline verdict %q (overall %d), want allow", ev.Verdict, ev.DirectScore.Overall)
	}
	ev := EvaluatePackage(dormantLookalikeInput(), opts)
	if ev.Verdict != VerdictWarn {
		t.Fatalf("verdict %q (overall %d), want warn", ev.Verdict, ev.DirectScore.Overall)
	}
	if f, ok := findFired(ev, SignalSCDormantLookalikeRelease); !ok || f.Evidence["damped"] == true {
		t.Fatalf("finding missing or damped: %+v", f)
	}
}

// TestEstablishedReasonIgnoresNuGetSentinel: NuGet dates unlisted versions
// 1900-01-01. A first-published date that old is not survival evidence, so it
// must not satisfy the release-history line's age half.
func TestEstablishedReasonIgnoresNuGetSentinel(t *testing.T) {
	sentinel := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	if why := EstablishedReason(nil, "", nil, 110, &sentinel, dampNow); why != "" {
		t.Fatalf("1900 sentinel established the package: %q", why)
	}
	real := time.Date(2014, 4, 1, 0, 0, 0, 0, time.UTC)
	if why := EstablishedReason(nil, "", nil, 110, &real, dampNow); why == "" {
		t.Fatal("a real 2014 first release with 110 versions must still clear")
	}
}
