package risk

import (
	"sort"
	"testing"
	"time"
)

var dampNow = time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)

func intp(n int) *int { return &n }

func TestEstablishedReason(t *testing.T) {
	old := time.Date(2023, 8, 23, 0, 0, 0, 0, time.UTC)
	young := time.Date(2026, 1, 9, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		downloads *int
		window    string
		weekly    *int
		versions  int
		first     *time.Time
		want      bool
	}{
		{"npm weekly at line", nil, "", intp(EstablishedWeeklyDownloads), 0, nil, true},
		{"npm weekly below (expres)", nil, "", intp(8_167), 0, nil, false},
		{"week window only", intp(2_000_000), "week", nil, 0, nil, true},
		{"crates.io 90d (typedmap)", intp(204_545), "90d", nil, 0, nil, true},
		{"crates.io 90d below (s2-common)", intp(42_887), "90d", nil, 60, &young, false},
		{"history (dbsp)", intp(24_227), "90d", nil, 299, &old, true},
		{"packagist month has no line", intp(5_000_000), "month", nil, 0, nil, false},
		{"rubygems total has no line", intp(500_000_000), "total", nil, 0, nil, false},
		{"failed fetch", nil, "", intp(-1), 0, nil, false},
		{"no data", nil, "", nil, 0, nil, false},
		{"many versions, no first publish", nil, "", nil, 300, nil, false},
	} {
		got := EstablishedReason(tc.downloads, tc.window, tc.weekly, tc.versions, tc.first, dampNow) != ""
		if got != tc.want {
			t.Errorf("%s: established=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestDampEstablishedSet pins the dampable set. Adding a signal here is a
// scoring decision: it must be hygiene evidence that popularity or release
// history refutes, never malware, compromise, vulnerability or licence.
func TestDampEstablishedSet(t *testing.T) {
	want := []string{
		SignalMaintAbandonedRepo, SignalMaintSingleMaintainer, SignalQualVersionAnomaly,
		SignalSCRepoArchived, SignalSCRepoMissing, SignalSCRepoMissingEstablished,
		SignalSCTyposquatHigh, SignalSCTyposquatLow, SignalSCTyposquatMedium,
	}
	assertFlagSet(t, "DampEstablished", func(s Signal) bool { return s.DampEstablished }, want)
	for id, s := range Registry {
		if !s.DampEstablished {
			continue
		}
		if s.TakeoverIndicator || s.NotTunable || s.Weight <= -999 {
			t.Errorf("%s: dampable but also a takeover indicator, untunable or a sentinel", id)
		}
		if s.Category == CategoryVulnerability || s.Category == CategoryLicense {
			t.Errorf("%s: %s signals must never be damped", id, s.Category)
		}
	}
}

// TestTakeoverIndicatorSet pins the signals that suspend the damper.
func TestTakeoverIndicatorSet(t *testing.T) {
	want := []string{
		SignalSCAppCredentialExfil, SignalSCDependencyCredential, SignalSCEnvVarAppeared,
		SignalSCExfilSinkUsed, SignalSCFilesystemAppeared, SignalSCImportTimeShell,
		SignalSCInstallScriptEvalEnc, SignalSCInstallScriptNetwork, SignalSCKnownMalicious,
		SignalSCMaintainerAccountVeryYoung, SignalSCMaintainerAccountYoung, SignalSCManifestConfusion,
		SignalSCNonExistentAuthor, SignalSCPublisherChanged, SignalSCRepoOwnershipMismatch,
		SignalSCShellAppeared, SignalSCTransitiveMalware,
		SignalSCProvenanceDowngrade,
	}
	assertFlagSet(t, "TakeoverIndicator", func(s Signal) bool { return s.TakeoverIndicator }, want)
}

func assertFlagSet(t *testing.T, flag string, has func(Signal) bool, want []string) {
	t.Helper()
	var got []string
	for id, s := range Registry {
		if has(s) {
			got = append(got, id)
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("%s set changed:\n got  %v\n want %v", flag, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s set changed:\n got  %v\n want %v", flag, got, want)
		}
	}
}

// archivedInput fires sc.repo_archived (ceiling 59: alone it holds a package
// at the top of the warn band) and nothing else negative.
func archivedInput(weekly int) Input {
	return Input{
		Ecosystem:       "npm",
		Package:         "popular-lib",
		Version:         "1.0.0",
		RepoLinkStatus:  "archived",
		WeeklyDownloads: intp(weekly),
		MaintainerCount: 3,
	}
}

// TestDamperLiftsHygieneCeilingOnEstablished: the same archived-repo finding
// warns on an obscure package and stays allow on an established one, with the
// finding kept and marked damped.
func TestDamperLiftsHygieneCeilingOnEstablished(t *testing.T) {
	opts := Options{Now: func() time.Time { return dampNow }}

	obscure := EvaluatePackage(archivedInput(500), opts)
	if obscure.Verdict != VerdictWarn {
		t.Fatalf("obscure archived package: verdict %q (overall %d), want warn", obscure.Verdict, obscure.DirectScore.Overall)
	}

	est := EvaluatePackage(archivedInput(2_000_000), opts)
	if est.Verdict != VerdictAllow {
		t.Fatalf("established archived package: verdict %q (overall %d, ceiling %q), want allow",
			est.Verdict, est.DirectScore.Overall, est.DirectScore.CeilingSignal)
	}
	f, ok := findFired(est, SignalSCRepoArchived)
	if !ok {
		t.Fatal("damped finding was dropped; it must stay visible")
	}
	if f.Evidence["damped"] != true || f.Evidence["damped_reason"] == nil {
		t.Errorf("damped finding lacks its evidence: %+v", f.Evidence)
	}
	if want := Registry[SignalSCRepoArchived].Weight / 2; f.Weight != want {
		t.Errorf("damped weight %v, want %v", f.Weight, want)
	}
}

// TestDamperSuspendedByTakeoverIndicator: an established package that also
// shows a publisher change is the takeover scenario; nothing is softened.
func TestDamperSuspendedByTakeoverIndicator(t *testing.T) {
	opts := Options{Now: func() time.Time { return dampNow }}
	in := archivedInput(2_000_000)
	in.PublisherChanged = true
	in.Ecosystem = "npm"
	ev := EvaluatePackage(in, opts)
	f, ok := findFired(ev, SignalSCRepoArchived)
	if !ok {
		t.Fatal("sc.repo_archived did not fire")
	}
	if f.Evidence["damped"] == true || f.Weight != Registry[SignalSCRepoArchived].Weight {
		t.Errorf("hygiene signal damped despite a takeover indicator: %+v", f)
	}
	if ev.Verdict == VerdictAllow {
		t.Errorf("established package with a publisher change resolved to allow (overall %d)", ev.DirectScore.Overall)
	}
}

func findFired(ev *Evaluation, id string) (FiredSignal, bool) {
	for _, cs := range ev.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			if f.ID == id {
				return f, true
			}
		}
	}
	return FiredSignal{}, false
}
