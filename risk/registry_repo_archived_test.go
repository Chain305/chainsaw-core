package risk

import (
	"testing"
	"time"
)

// Shapes from corpus-v1 rev5 with repo liveness wired. bundler/bundler is
// archived because bundler moved into rubygems/rubygems, and the gem still
// releases; kubefed's and paperclip's repos are archived because the
// projects are retired.
func TestRepoArchivedNeedsNoRecentRelease(t *testing.T) {
	daysAgo := func(d int) *time.Time { v := time.Now().Add(-time.Duration(d) * 24 * time.Hour); return &v }
	fires := func(eco, pkg string, latest *time.Time) bool {
		in := Input{Ecosystem: eco, Package: pkg, Version: "1.0.0", RepoLinkStatus: "archived", LatestReleaseAt: latest}
		for _, cs := range EvaluatePackage(in, Options{}).DirectScore.Categories {
			for _, fs := range cs.FiredSignals {
				if fs.ID == SignalSCRepoArchived {
					return true
				}
			}
		}
		return false
	}
	if fires("rubygems", "bundler", daysAgo(3)) {
		t.Error("bundler: archived repo with a release 3 days ago is a moved project, not a retired one")
	}
	if fires("nuget", "NexusMods.MnemonicDB.Abstractions", daysAgo(340)) {
		t.Error("NexusMods.MnemonicDB.Abstractions: release inside a year, must not fire")
	}
	if !fires("go", "sigs.k8s.io/kubefed", daysAgo(1515)) {
		t.Error("kubefed: retired, last release four years ago, must fire")
	}
	if !fires("rubygems", "paperclip", daysAgo(2990)) {
		t.Error("paperclip: retired, must fire")
	}
	if !fires("go", "github.com/bitnami/kubecfg", nil) {
		t.Error("unknown release date is not evidence of life; must fire")
	}
}
