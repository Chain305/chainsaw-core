package intelligence

import (
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
)

// TestAttack2026_46_SleeperGemDormancy: SleeperGem (RubyGems, 2026-07-18)
// used two long-idle maintainer accounts. Dendreo's last good release was
// 1.1.2 on 2020-10-24; the backdoored 1.1.3 was its first release in almost
// six years. sc.release_after_dormancy flags exactly that from the dated
// version timeline — at weight 0 (recall unmeasured), so it is a report
// finding, not a verdict mover and not a policy condition.
//
// Drives the report projection (versionPublishedAt / priorReleaseOf via
// ProjectToRiskInput) and the risk engine. Control: a release one month
// after its predecessor does not fire.
func TestAttack2026_46_SleeperGemDormancy(t *testing.T) {
	ts := func(s string) time.Time { v, _ := time.Parse(time.RFC3339, s); return v }
	eval := func(prior time.Time) (*risk.Evaluation, risk.FiredSignal, bool) {
		r := &Report{Identity: IdentitySection{Ecosystem: "rubygems", Package: "Dendreo", Version: "1.1.3"}}
		r.SupplyChain.MalwareStatus = "clean"
		r.Maintenance.VersionTimeline = []VersionRelease{
			{Version: "1.1.1", PublishedAt: prior.AddDate(0, -3, 0)},
			{Version: "1.1.2", PublishedAt: prior},
			{Version: "1.1.3", PublishedAt: ts("2026-07-18T14:00:00Z")},
		}
		ev := risk.EvaluatePackage(ProjectToRiskInput(r), risk.Options{Now: func() time.Time { return ts("2026-07-18T16:00:00Z") }})
		for _, cs := range ev.DirectScore.Categories {
			for _, f := range cs.FiredSignals {
				if f.ID == risk.SignalSCReleaseAfterDormancy {
					return ev, f, true
				}
			}
		}
		return ev, risk.FiredSignal{}, false
	}

	ev, f, ok := eval(ts("2020-10-24T12:00:00Z"))
	if !ok {
		t.Fatalf("Dendreo 1.1.3 after 1.1.2 (2020-10-24): sc.release_after_dormancy did not fire (verdict %q)", ev.Verdict)
	}
	if f.Weight != 0 {
		t.Fatalf("sc.release_after_dormancy weight %v; the classification assumes weight 0 (detection only)", f.Weight)
	}
	if f.Evidence["priorVersion"] != "1.1.2" {
		t.Fatalf("evidence %v, want priorVersion 1.1.2", f.Evidence)
	}
	if _, _, ok := eval(ts("2026-06-18T12:00:00Z")); ok {
		t.Fatal("a release one month after its predecessor flagged as dormant")
	}
}
