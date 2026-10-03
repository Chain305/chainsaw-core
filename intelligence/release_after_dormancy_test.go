package intelligence

import (
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
)

// TestReleaseAfterDormancy: the ctx shape (years silent, then a release)
// fires the weight-0 fact from the timeline the report already carries; a
// normal cadence and an undatable release do not.
func TestReleaseAfterDormancy(t *testing.T) {
	d := func(y int) time.Time { return time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC) }
	fired := func(r *Report) bool {
		ev := risk.EvaluatePackage(ProjectToRiskInput(r), risk.Options{})
		for _, c := range ev.DirectScore.Categories {
			for _, f := range c.FiredSignals {
				if f.ID == risk.SignalSCReleaseAfterDormancy {
					return true
				}
			}
		}
		return false
	}
	report := func(ver string, at *time.Time, tl ...VersionRelease) *Report {
		r := &Report{}
		r.Identity.Ecosystem, r.Identity.Package, r.Identity.Version = "pypi", "ctx", ver
		r.Release.PublishedAt = at
		r.Maintenance.VersionTimeline = tl
		return r
	}
	at := d(2022)
	if !fired(report("0.2.2", &at, VersionRelease{Version: "0.1.2", PublishedAt: d(2014)}, VersionRelease{Version: "0.2.2", PublishedAt: d(2022)})) {
		t.Fatal("8 years silent then a release must fire")
	}
	at = d(2021)
	if fired(report("1.1.0", &at, VersionRelease{Version: "1.0.0", PublishedAt: d(2020)}, VersionRelease{Version: "1.1.0", PublishedAt: d(2021)})) {
		t.Fatal("a one-year gap must not fire")
	}
	if fired(report("1.1.0", nil, VersionRelease{Version: "1.0.0"}, VersionRelease{Version: "1.1.0"})) {
		t.Fatal("an undated timeline cannot place the release and must not fire")
	}
}
