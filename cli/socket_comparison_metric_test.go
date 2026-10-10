package cli

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/risk"
)

// The three metric artifacts fixed for rev 5 (docs/REPORTS.md
// #socket-comparison-2026-10-03-rev5). Each test fails on the old behaviour.

// Our side of a report-only concept is the report field, never Socket's alert.
// Before the fix, an alert alone wrote both sides, so a row whose report had
// no URL strings still scored urlStrings as agreement.
func TestReportOnlyConceptNeedsOurField(t *testing.T) {
	alerts := []string{"urlStrings", "highEntropyStrings", "networkAccess"}

	ours, theirs := reportOnlyConcepts(&intelligence.ArtifactScanSection{}, alerts)
	if len(ours) != 0 {
		t.Fatalf("report has none of the four fields, but ours = %v: Socket's alert is being counted as our finding", ours)
	}
	if want := []string{"highEntropyStrings", "urlStrings"}; !reflect.DeepEqual(theirs, want) {
		t.Fatalf("theirs = %v, want %v", theirs, want)
	}

	ours, _ = reportOnlyConcepts(&intelligence.ArtifactScanSection{URLStrings: true, TooManyFiles: true}, alerts)
	if want := []string{"tooManyFiles", "urlStrings"}; !reflect.DeepEqual(ours, want) {
		t.Fatalf("ours = %v, want %v (our side must follow the report field, alert or not)", ours, want)
	}
}

// The unknown arm of maint.unpopular_package ("Download count unavailable")
// measured nothing; before the fix it scored as unpopularPackage agreement on
// every row whose download fetch failed. Driven through the real engine so a
// change to how the arm is expressed breaks this test, not the metric.
func TestUnknownArmIsNotConceptAgreement(t *testing.T) {
	fired := func(n int) (risk.FiredSignal, bool) {
		ev := risk.EvaluatePackage(risk.Input{Ecosystem: "npm", Downloads: &n, DownloadsWindow: "week"}, risk.Options{})
		for _, c := range ev.DirectScore.Categories {
			for _, f := range c.FiredSignals {
				if f.ID == risk.SignalMaintUnpopularPackage {
					return f, true
				}
			}
		}
		return risk.FiredSignal{}, false
	}

	unknown, ok := fired(-1)
	if !ok {
		t.Fatal("maint.unpopular_package did not fire on the -1 sentinel; this test no longer exercises the unknown arm")
	}
	if countsTowardConcept(unknown) {
		t.Fatalf("unknown arm (severity %q) counts toward unpopularPackage agreement", unknown.Severity)
	}
	measured, ok := fired(3)
	if !ok || !countsTowardConcept(measured) {
		t.Fatalf("3 downloads/week must fire and count (fired=%v, severity %q)", ok, measured.Severity)
	}
}

// Feed-known malicious rows emit only sc.known_malicious, so the behavioural
// view must leave them out while the full view keeps them.
func TestBehaviouralViewExcludesFeedKnownMalicious(t *testing.T) {
	ledger := []cmpRow{
		{CSSignals: []string{"sc.known_malicious"}, ConceptSK: []string{"networkAccess", "shellAccess"}},
		{CSSignals: []string{"cap.network"}, ConceptBoth: []string{"networkAccess"}, ConceptSK: []string{"envVars"}},
	}
	all := func(*cmpRow) bool { return true }
	_, _, sk, _ := conceptTotals(ledger, all)
	if sk != 3 {
		t.Fatalf("full view socket-only = %d, want 3", sk)
	}
	both, _, sk, by := conceptTotals(ledger, func(l *cmpRow) bool { return !feedKnownMalicious(l) })
	if both != 1 || sk != 1 || !reflect.DeepEqual(by, map[string]int{"envVars": 1}) {
		t.Fatalf("behavioural view: both=%d socket-only=%d by=%v; want 1, 1, {envVars:1}", both, sk, by)
	}
}

// One sc.known_malicious is one finding. Mapped to both `malware` and
// `gptMalware`, it scored agreement on one and Chainsaw-only on the other
// whenever Socket raised just one of them. gptMalware is a declined LLM
// verdict since 2026-10-09, so alone it meets nothing on Socket's side.
func TestKnownMaliciousIsOneConcept(t *testing.T) {
	cs, sk, _, _ := rowConcepts([]string{"sc.known_malicious"}, nil, &intelligence.ArtifactScanSection{}, []string{"gptMalware"})
	if len(cs) != 1 || len(sk) != 0 {
		t.Fatalf("gptMalware alone: ours=%v theirs=%v; want our malware concept and nothing of theirs", cs, sk)
	}
	for _, alerts := range [][]string{{"malware"}, {"malware", "gptMalware"}} {
		cs, sk, _, _ := rowConcepts([]string{"sc.known_malicious"}, nil, &intelligence.ArtifactScanSection{}, alerts)
		if len(cs) != 1 || len(sk) != 1 {
			t.Fatalf("alerts %v: ours=%v theirs=%v; want exactly one malware concept on each side", alerts, cs, sk)
		}
		for c := range cs {
			if _, ok := sk[c]; !ok {
				t.Fatalf("alerts %v: our malware concept %q does not meet theirs %v", alerts, c, sk)
			}
		}
	}
}

// The report-only fix, end to end through rowConcepts: an alert with our field
// absent is Socket-only.
func TestRowConceptsReportOnlyNeedsField(t *testing.T) {
	cs, sk, _, _ := rowConcepts(nil, nil, &intelligence.ArtifactScanSection{}, []string{"trivialPackage"})
	if _, ok := cs["trivialPackage"]; ok {
		t.Fatalf("trivialPackage counted on our side with TrivialPackage=false: ours=%v", cs)
	}
	if _, ok := sk["trivialPackage"]; !ok {
		t.Fatalf("Socket's trivialPackage alert lost: theirs=%v", sk)
	}
}

// A report whose registry metadata failed is Unknown at the verdict level, but
// what its artifact scan observed must still reach the concept metric.
// Before the fix the row's concepts came only from the (empty) verdict signal
// set, so Socket's networkAccess there scored Socket-only.
func TestUnknownVerdictKeepsArtifactConcepts(t *testing.T) {
	rep := intelligence.Report{}
	rep.Identity = intelligence.IdentitySection{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"}
	rep.Scan = intelligence.ArtifactScanSection{Performed: true, NetworkAccess: true}
	rep.Observation.Warnings = []intelligence.Warning{{Provider: "registrymetadata", Code: intelligence.WarnRegistryCancelled}}

	if !intelligence.ProjectToRiskInput(&rep).SignalsUnavailable {
		t.Fatal("fixture no longer projects as unavailable; the test exercises nothing")
	}
	if ev := risk.EvaluatePackage(intelligence.ProjectToRiskInput(&rep), risk.Options{}); ev.Verdict != risk.VerdictUnknown {
		t.Fatalf("verdict = %s, want unknown: the verdict metric must keep Unknown", ev.Verdict)
	}
	ids, _ := recoveredConceptSignals(&rep)
	cs, _, _, _ := rowConcepts(ids, nil, &rep.Scan, []string{"networkAccess"})
	if _, ok := cs["networkAccess"]; !ok {
		t.Fatalf("recovered signals %v: the artifact scan's network access is lost from the concept metric", ids)
	}
	for _, id := range ids {
		if m := socketConceptMap[id]; m.Bucket == bucketMetadata {
			t.Fatalf("metadata-bucket signal %s recovered from a report with no registry document", id)
		}
	}
}

// The repo-liveness counterfactual clears every input RepoLiveness writes, so
// a flag it alone decides comes back allow, archived and missing alike.
func TestWithoutRepoLivenessClearsEveryRepoInput(t *testing.T) {
	old := time.Now().AddDate(-5, 0, 0)
	archived := true
	for _, in := range []risk.Input{
		{RepoLinkStatus: "archived", RepoArchived: &archived, LastRepoCommitAt: &old},
		{RepoLinkStatus: "missing"},
	} {
		if v := risk.EvaluatePackage(in, risk.Options{}).Verdict; v != risk.VerdictWarn {
			t.Fatalf("%s: verdict %s, want warn: the fixture no longer exercises the ceiling", in.RepoLinkStatus, v)
		}
		got := withoutRepoLiveness(in)
		if got.RepoLinkStatus != "" || got.RepoArchived != nil || got.LastRepoCommitAt != nil {
			t.Errorf("%s: repo inputs survived: %q %v %v", in.RepoLinkStatus, got.RepoLinkStatus, got.RepoArchived, got.LastRepoCommitAt)
		}
		if v := risk.EvaluatePackage(got, risk.Options{}).Verdict; v != risk.VerdictAllow {
			t.Errorf("%s: counterfactual verdict %s, want allow", in.RepoLinkStatus, v)
		}
	}
}

// B1 (judge round 2): a Go row's headline is graded without sc.transitive_*,
// and the verdict as scored survives beside it; other ecosystems keep theirs.
func TestHeadlineEvalDropsTransitiveOnGoOnly(t *testing.T) {
	in := risk.Input{TransitiveCriticalCount: 1}
	fired := func(ev *risk.Evaluation) bool {
		for _, c := range ev.DirectScore.Categories {
			for _, fs := range c.FiredSignals {
				if strings.HasPrefix(fs.ID, "sc.transitive_") {
					return true
				}
			}
		}
		return false
	}
	npm, npmWith, _ := headlineEval("npm", in)
	if !fired(npm) || string(npm.Verdict) != npmWith {
		t.Fatalf("npm: transitive fired=%v verdict %s vs as-scored %s; the fixture no longer exercises sc.transitive_*", fired(npm), npm.Verdict, npmWith)
	}
	goEv, goWith, goNoRepo := headlineEval("go", in)
	if fired(goEv) {
		t.Errorf("go: headline carries sc.transitive_*")
	}
	if goWith != npmWith || string(goEv.Verdict) == goWith {
		t.Errorf("go: headline %s, as scored %s; want the as-scored verdict kept (%s) and the headline to differ", goEv.Verdict, goWith, npmWith)
	}
	if goNoRepo != string(goEv.Verdict) {
		t.Errorf("go: no-repo verdict %s is not built on the headline input (%s)", goNoRepo, goEv.Verdict)
	}
}
