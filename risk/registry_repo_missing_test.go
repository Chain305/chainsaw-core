package risk

import (
	"testing"
	"time"
)

// A missing repo keeps its warn ceiling on a young package and on one whose
// age is unknown, and is priced without the ceiling on an established one.
// Shapes: npm atomic-lockfile@1.4.2 (Datadog malware; published 2026-06-10,
// taken down two days later, repo never existed) against rubygems
// omniauth-urbit@0.1.0 (benign; repo deleted years after release).
func TestRepoMissingCeilingNeedsYoungOrUnknownAge(t *testing.T) {
	daysAgo := func(d int) *time.Time { v := time.Now().Add(-time.Duration(d) * 24 * time.Hour); return &v }
	evalIn := func(in Input) (map[string]bool, Verdict) {
		in.Ecosystem, in.Package, in.Version, in.RepoLinkStatus = "npm", "x", "1.0.0", "missing"
		ev := EvaluatePackage(in, Options{})
		out := map[string]bool{}
		for _, cs := range ev.DirectScore.Categories {
			for _, fs := range cs.FiredSignals {
				out[fs.ID] = true
			}
		}
		return out, ev.Verdict
	}
	eval := func(pub, first *time.Time) (map[string]bool, Verdict) {
		return evalIn(Input{PublishedAt: pub, FirstPublishedAt: first})
	}
	if got, v := eval(daysAgo(1), daysAgo(1)); !got[SignalSCRepoMissing] || got[SignalSCRepoMissingEstablished] || v != VerdictWarn {
		t.Errorf("atomic-lockfile (1 day old): want sc.repo_missing and warn, got %v %s", got, v)
	}
	if got, v := eval(nil, nil); !got[SignalSCRepoMissing] || v != VerdictWarn {
		t.Errorf("unknown age must keep the ceiling, got %v %s", got, v)
	}
	if got, _ := eval(daysAgo(30), daysAgo(3000)); !got[SignalSCRepoMissing] {
		t.Errorf("a new version of an old package keeps the ceiling, got %v", got)
	}
	// rubygems iprocess@2.0.2: version from 2012, first-release date unknown.
	if got, _ := eval(daysAgo(5000), nil); got[SignalSCRepoMissing] || !got[SignalSCRepoMissingEstablished] {
		t.Errorf("an old version with no first-release date is established, got %v", got)
	}
	got, v := eval(daysAgo(3000), daysAgo(3100))
	if got[SignalSCRepoMissing] || !got[SignalSCRepoMissingEstablished] || v != VerdictAllow {
		t.Errorf("omniauth-urbit (8 years old): want sc.repo_missing_established and allow, got %v %s", got, v)
	}
	// A new version on an old name whose own publish date was not captured
	// (no publishedAt on the version document, or a failed timeline fetch
	// with FirstPublishedAt carried from the prior row) is unknown age, not
	// established: that is what a takeover release looks like.
	if got, v := eval(nil, daysAgo(3000)); !got[SignalSCRepoMissing] || got[SignalSCRepoMissingEstablished] || v != VerdictWarn {
		t.Errorf("old first release, undated version: want sc.repo_missing and warn, got %v %s", got, v)
	}
	// nuget Qute.Shared@1.0.3: no publishedAt on the registration document;
	// the version is dated by its own timeline entry / registration leaf.
	got, v = evalIn(Input{VersionPublishedAt: daysAgo(900), FirstPublishedAt: daysAgo(1000)})
	if got[SignalSCRepoMissing] || !got[SignalSCRepoMissingEstablished] || v != VerdictAllow {
		t.Errorf("version dated only by VersionPublishedAt: want established and allow, got %v %s", got, v)
	}
}
