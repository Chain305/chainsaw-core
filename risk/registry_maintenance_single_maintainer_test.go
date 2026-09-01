package risk

import (
	"testing"
	"time"
)

// P8-11. `maint.single_maintainer` reads MaintainerCount, which on
// Maven/Gradle is derived from the POM `<developers>` block — hand-written
// prose whose entry count is not a headcount. spring-core-6.1.0.pom lists
// exactly one `<developer>`, so the signal fired on Spring Framework and
// called it a bus-factor risk. (Whether that block is a publisher IDENTITY
// is a separate and still-open question, filed as P8-70; this signal needs
// only the weaker claim that the COUNT is meaningless.)
//
// These tests drive the real EvaluatePackage rather than calling Fires
// directly, so they break if the guard is bypassed by a later refactor of
// the evaluation path and not only if the predicate itself changes.

func singleMaintainerFired(eval *Evaluation) bool {
	if eval == nil {
		return false
	}
	for _, cat := range eval.DirectScore.Categories {
		for _, fs := range cat.FiredSignals {
			if fs.ID == SignalMaintSingleMaintainer {
				return true
			}
		}
	}
	return false
}

// A single POM `<developer>` must not be read as a single maintainer.
//
// The case variants are not padding. `risk.Input.Ecosystem` is the RAW
// caller-supplied string — `risk_projection.go:153` copies
// `r.Identity.Ecosystem` through untouched and the intel HTTP handlers build
// the key without folding case — while the provider side normalises via
// `normalizeEcosystemKey` before dispatching to `runMaven`. So a request for
// "Maven" fills Maintainers from the POM and would slip a case-sensitive
// guard. The first version of this fix compared the raw string and every
// capitalised spelling below fired; they are the regression test for that.
func TestSingleMaintainer_POMEcosystems_Quiet(t *testing.T) {
	for _, eco := range []string{
		"maven", "gradle", // canonical tokens
		"Maven", "MAVEN", "Gradle", "GRADLE", // case variants — the P8-11 near-miss
		" maven", "maven ", // stray whitespace from a hand-built key
		"maven-central", // defensive: a proxy REPO name, not an ecosystem token
	} {
		in := Input{Ecosystem: eco, MaintainerCount: 1}
		if singleMaintainerFired(EvaluatePackage(in, Options{})) {
			t.Errorf("%q: %q fired on a POM <developers> count of 1; that field is "+
				"self-declared and carries no bus-factor information", eco, SignalMaintSingleMaintainer)
		}
	}
}

// The guard must not change the VERDICT silently for anyone else. This pins
// the flip that justified the epoch-10 bump: with the signal firing the
// package is WARN at overall=59, with it guarded it is ALLOW at 60. If a
// later refactor makes this stop flipping, the epoch-history entry for 10 is
// wrong and should be corrected rather than left as folklore.
func TestSingleMaintainer_GuardIsVerdictAffecting(t *testing.T) {
	stale := time.Now().AddDate(-4, 0, 0)
	mk := func(eco string) *Evaluation {
		return EvaluatePackage(Input{
			Ecosystem:            eco,
			MaintainerCount:      1,
			VersionDataAvailable: true,
			VersionCount:         12,
			IsSuspectedTyposquat: true,
			TyposquatConfidence:  "medium",
			LastRepoCommitAt:     &stale,
			ManifestConfusion:    true,
		}, Options{})
	}
	npm, maven := mk("npm"), mk("maven")
	if npm.Verdict == maven.Verdict {
		t.Fatalf("expected a verdict flip and got none (npm=%v/%d maven=%v/%d). "+
			"Either the band arithmetic changed or the epoch-10 history note in "+
			"core/intelligence/report.go is now wrong — fix the note, do not delete this test",
			npm.Verdict, npm.DirectScore.Overall, maven.Verdict, maven.DirectScore.Overall)
	}
	if maven.DirectScore.Overall <= npm.DirectScore.Overall {
		t.Errorf("guard should RAISE the maven score: npm=%d maven=%d",
			npm.DirectScore.Overall, maven.DirectScore.Overall)
	}
}

// Negative control. The guard must be scoped to the POM ecosystems and must
// not quietly disable the signal everywhere — if this passes while the test
// above also passes, the guard is doing exactly one thing.
func TestSingleMaintainer_NonPOMEcosystems_StillFire(t *testing.T) {
	for _, eco := range []string{"npm", "pypi", "pip", "cargo", "rubygems", "nuget", "go"} {
		in := Input{Ecosystem: eco, MaintainerCount: 1}
		if !singleMaintainerFired(EvaluatePackage(in, Options{})) {
			t.Errorf("%s: expected %q to fire on a real maintainer count of 1",
				eco, SignalMaintSingleMaintainer)
		}
	}
}

// The guard keys on the ecosystem, not on the count, so a POM listing several
// developers stays quiet for the ordinary reason too.
func TestSingleMaintainer_CountUnaffectedOutsidePOM(t *testing.T) {
	for _, n := range []int{0, 2, 5} {
		in := Input{Ecosystem: "npm", MaintainerCount: n}
		if singleMaintainerFired(EvaluatePackage(in, Options{})) {
			t.Errorf("npm MaintainerCount=%d: signal fired but only 1 should", n)
		}
	}
}
