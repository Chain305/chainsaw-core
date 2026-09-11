package intelligence

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/metadata"
	"github.com/chain305/chainsaw-core/risk"
)

func recallRow() metadata.PackageMetadataRow {
	return metadata.PackageMetadataRow{
		OrgID: "org1",
		PackageMetadata: metadata.PackageMetadata{
			Repository: "npmjs",
			Package:    "left-pad",
			Version:    "1.3.0",
		},
	}
}

func triggers(evs []SupplyChainAlertEvent) []SupplyChainAlertTrigger {
	out := make([]SupplyChainAlertTrigger, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Trigger)
	}
	return out
}

func ptr(b bool) *bool { return &b }

// --- Requirement 3: the Performed guard. Written first because it is the
// one that turns every artifact the scanner skipped (>256 MiB, fetch
// failure, artifact scanning disabled) into a phantom alert if it is
// missing. A true → false flip means NOBODY LOOKED, not "it got better";
// a false → true flip means "we finally looked", not "a new risk".

func TestDiffSupplyChain_ScanPerformedGuard(t *testing.T) {
	// The artifact fields are at their WORST in next and their BEST in
	// prior in every row below, so any row that fires is firing purely
	// because the Performed guard let it through.
	worst := ArtifactScanSection{
		HasInstallScript:     true,
		InstallScriptFetches: true,
		InstallScriptKind:    "fetches_remote",
	}
	cases := []struct {
		name                  string
		priorDone, nextDone   bool
		wantInstallScriptFire bool
	}{
		{"neither side scanned", false, false, false},
		{"we finally looked (false -> true)", false, true, false},
		{"nobody looked this time (true -> false)", true, false, false},
		{"both sides scanned", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prior := &Report{Scan: ArtifactScanSection{Performed: tc.priorDone}}
			nextScan := worst
			nextScan.Performed = tc.nextDone
			next := &Report{Scan: nextScan}

			got := DiffSupplyChain(recallRow(), "npm", prior, next)
			fired := len(got) > 0
			if fired != tc.wantInstallScriptFire {
				t.Fatalf("fired = %v (%v), want %v", fired, triggers(got), tc.wantInstallScriptFire)
			}
			if fired && got[0].Trigger != AlertInstallScriptAppeared {
				t.Fatalf("trigger = %q, want %q", got[0].Trigger, AlertInstallScriptAppeared)
			}
		})
	}
}

// A scan that ran on both sides and LOST its install script must stay
// silent — weakening is not a recall.
func TestDiffSupplyChain_InstallScriptRemovedIsSilent(t *testing.T) {
	prior := &Report{Scan: ArtifactScanSection{
		Performed: true, HasInstallScript: true, InstallScriptFetches: true, InstallScriptKind: "fetches_remote",
	}}
	next := &Report{Scan: ArtifactScanSection{Performed: true, InstallScriptKind: "none"}}
	if got := DiffSupplyChain(recallRow(), "npm", prior, next); len(got) != 0 {
		t.Fatalf("want no events, got %v", triggers(got))
	}
}

func TestDiffSupplyChain_NilPriorIsNotARecall(t *testing.T) {
	next := &Report{
		SupplyChain: SupplyChainSection{MalwareStatus: "malicious", MalwareID: "MAL-1"},
		Risk:        &risk.Evaluation{Verdict: risk.VerdictQuarantine},
		Scan:        ArtifactScanSection{Performed: true, HasInstallScript: true},
	}
	if got := DiffSupplyChain(recallRow(), "npm", nil, next); got != nil {
		t.Fatalf("nil prior must produce nil, got %v", triggers(got))
	}
	if got := DiffSupplyChain(recallRow(), "npm", &Report{}, nil); got != nil {
		t.Fatalf("nil next must produce nil, got %v", triggers(got))
	}
}

// --- Strengthening vs weakening, one table for every signal. Each row is
// run in both directions: forward must fire exactly the named trigger,
// reversed must fire nothing.

func TestDiffSupplyChain_StrengthenFiresWeakenDoesNot(t *testing.T) {
	cases := []struct {
		name       string
		clean      *Report
		bad        *Report
		want       SupplyChainAlertTrigger
		wantDetail string
		wantPrior  string
		wantNext   string
	}{
		{
			name:  "malware appeared",
			clean: &Report{SupplyChain: SupplyChainSection{MalwareStatus: "clean"}},
			bad: &Report{SupplyChain: SupplyChainSection{
				MalwareStatus: "malicious", MalwareID: "MAL-2026-1", MalwareSummary: "credential stealer",
			}},
			want:       AlertMalwareAppeared,
			wantDetail: "MAL-2026-1 credential stealer",
			wantPrior:  "clean",
			wantNext:   "malicious",
		},
		{
			name:  "malware appeared from unset",
			clean: &Report{},
			bad: &Report{SupplyChain: SupplyChainSection{
				MalwareStatus: "malicious", MalwareID: "MAL-9",
			}},
			want:       AlertMalwareAppeared,
			wantDetail: "MAL-9",
			wantPrior:  "unset",
			wantNext:   "malicious",
		},
		{
			name:  "typosquat suspected",
			clean: &Report{SupplyChain: SupplyChainSection{TyposquatStatus: "clean"}},
			bad: &Report{SupplyChain: SupplyChainSection{
				TyposquatStatus: "suspected", TyposquatSimilarTo: "lodash", TyposquatConfidence: "high",
			}},
			want:       AlertTyposquatAppeared,
			wantDetail: "similar to lodash (confidence high)",
			wantPrior:  "clean",
			wantNext:   "suspected",
		},
		{
			// confirmed_safe is a CLEAN state despite sharing a prefix
			// with "confirmed". Moving off it into "suspected" fires.
			name:  "confirmed_safe to suspected",
			clean: &Report{SupplyChain: SupplyChainSection{TyposquatStatus: "confirmed_safe"}},
			bad: &Report{SupplyChain: SupplyChainSection{
				TyposquatStatus: "suspected", TyposquatSimilarTo: "requests",
			}},
			want:       AlertTyposquatAppeared,
			wantDetail: "similar to requests",
			wantPrior:  "confirmed_safe",
			wantNext:   "suspected",
		},
		{
			name:  "publisher changed from false",
			clean: &Report{SupplyChain: SupplyChainSection{PublisherChanged: ptr(false)}},
			bad: &Report{SupplyChain: SupplyChainSection{
				PublisherChanged: ptr(true), PublisherAdded: []string{"eve"}, PublisherRemoved: []string{"alice"},
			}},
			want:       AlertPublisherChanged,
			wantDetail: "added eve; removed alice",
			wantPrior:  "false",
			wantNext:   "true",
		},
		{
			name:       "publisher changed from unevaluated",
			clean:      &Report{},
			bad:        &Report{SupplyChain: SupplyChainSection{PublisherChanged: ptr(true)}},
			want:       AlertPublisherChanged,
			wantDetail: "publisher set changed",
			wantPrior:  "unset",
			wantNext:   "true",
		},
		{
			name:  "install script appeared",
			clean: &Report{Scan: ArtifactScanSection{Performed: true, InstallScriptKind: "none"}},
			bad: &Report{Scan: ArtifactScanSection{
				Performed: true, HasInstallScript: true, InstallScriptKind: "present",
			}},
			want:       AlertInstallScriptAppeared,
			wantDetail: "install script added",
			wantPrior:  "none",
			wantNext:   "present",
		},
		{
			// A script that already existed but now fetches remote code
			// is reported as the stronger of the two, once.
			name: "install script starts fetching remote",
			clean: &Report{Scan: ArtifactScanSection{
				Performed: true, HasInstallScript: true, InstallScriptKind: "present",
			}},
			bad: &Report{Scan: ArtifactScanSection{
				Performed: true, HasInstallScript: true, InstallScriptFetches: true, InstallScriptKind: "fetches_remote",
			}},
			want:       AlertInstallScriptAppeared,
			wantDetail: "install script fetches remote code",
			wantPrior:  "present",
			wantNext:   "fetches_remote",
		},
		{
			name:       "verdict allow to quarantine",
			clean:      &Report{Risk: &risk.Evaluation{Verdict: risk.VerdictAllow}},
			bad:        &Report{Risk: &risk.Evaluation{Verdict: risk.VerdictQuarantine}},
			want:       AlertVerdictDegraded,
			wantDetail: "risk verdict allow → quarantine",
			wantPrior:  "allow",
			wantNext:   "quarantine",
		},
		{
			name:       "verdict warn to replace",
			clean:      &Report{Risk: &risk.Evaluation{Verdict: risk.VerdictWarn}},
			bad:        &Report{Risk: &risk.Evaluation{Verdict: risk.VerdictReplace}},
			want:       AlertVerdictDegraded,
			wantDetail: "risk verdict warn → replace",
			wantPrior:  "warn",
			wantNext:   "replace",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"/strengthening fires", func(t *testing.T) {
			got := DiffSupplyChain(recallRow(), "npm", tc.clean, tc.bad)
			if len(got) != 1 {
				t.Fatalf("want exactly 1 event, got %d (%v)", len(got), triggers(got))
			}
			ev := got[0]
			if ev.Trigger != tc.want {
				t.Errorf("trigger = %q, want %q", ev.Trigger, tc.want)
			}
			if ev.Detail != tc.wantDetail {
				t.Errorf("detail = %q, want %q", ev.Detail, tc.wantDetail)
			}
			if ev.PriorValue != tc.wantPrior || ev.NextValue != tc.wantNext {
				t.Errorf("transition = %q → %q, want %q → %q",
					ev.PriorValue, ev.NextValue, tc.wantPrior, tc.wantNext)
			}
			if ev.OrgID != "org1" || ev.RepoName != "npmjs" || ev.Ecosystem != "npm" ||
				ev.Package != "left-pad" || ev.Version != "1.3.0" {
				t.Errorf("coordinate not stamped: %+v", ev)
			}
		})
		t.Run(tc.name+"/weakening is silent", func(t *testing.T) {
			if got := DiffSupplyChain(recallRow(), "npm", tc.bad, tc.clean); len(got) != 0 {
				t.Fatalf("reversed transition must be silent, got %v", triggers(got))
			}
		})
		t.Run(tc.name+"/no change is silent", func(t *testing.T) {
			if got := DiffSupplyChain(recallRow(), "npm", tc.bad, tc.bad); len(got) != 0 {
				t.Fatalf("identical reports must be silent, got %v", triggers(got))
			}
		})
	}
}

// --- Requirement 6: VerdictUnknown is not a risk judgement and must
// never be folded into allow, in either direction.

func TestDiffSupplyChain_VerdictUnknownNeverAlerts(t *testing.T) {
	eval := func(v risk.Verdict) *Report { return &Report{Risk: &risk.Evaluation{Verdict: v}} }
	cases := []struct {
		name         string
		prior, next  *Report
		wantNoEvents bool
	}{
		{"allow -> unknown is a loss of evaluation", eval(risk.VerdictAllow), eval(risk.VerdictUnknown), true},
		{"unknown -> quarantine has no known prior", eval(risk.VerdictUnknown), eval(risk.VerdictQuarantine), true},
		{"unknown -> allow", eval(risk.VerdictUnknown), eval(risk.VerdictAllow), true},
		{"unknown -> unknown", eval(risk.VerdictUnknown), eval(risk.VerdictUnknown), true},
		{"empty verdict -> quarantine", eval(""), eval(risk.VerdictQuarantine), true},
		{"prior Risk nil", &Report{}, eval(risk.VerdictQuarantine), true},
		{"next Risk nil", eval(risk.VerdictAllow), &Report{}, true},
		{"both Risk nil", &Report{}, &Report{}, true},
		// The control: two KNOWN verdicts still alert, so the rows above
		// are proving the Unknown guard and not an accidental no-op.
		{"allow -> quarantine still alerts", eval(risk.VerdictAllow), eval(risk.VerdictQuarantine), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DiffSupplyChain(recallRow(), "npm", tc.prior, tc.next)
			if tc.wantNoEvents && len(got) != 0 {
				t.Fatalf("want no events, got %v", triggers(got))
			}
			if !tc.wantNoEvents && len(got) != 1 {
				t.Fatalf("want 1 event, got %d (%v)", len(got), triggers(got))
			}
		})
	}
}

// --- Requirements 4 and 5: fields deliberately not diffed.

func TestDiffSupplyChain_UndiffedFieldsStaySilent(t *testing.T) {
	commit := mustTime(t, time.RFC3339, "2026-09-01T00:00:00Z")
	prior := &Report{}
	next := &Report{SupplyChain: SupplyChainSection{
		// No provider writes ReservedNamespaceViolation (report.go).
		ReservedNamespaceViolation: ptr(true),
		ReservedNamespaceReason:    "reserved",
		// In-memory mirrors the persistence layer never stores, so a
		// loaded prior never has them and every refresh would look like
		// a flip.
		RepoArchived:     ptr(true),
		RepoLastCommitAt: &commit,
	}}
	if got := DiffSupplyChain(recallRow(), "npm", prior, next); len(got) != 0 {
		t.Fatalf("undiffed fields must stay silent, got %v", triggers(got))
	}
}

// --- Multiple simultaneous flips, and determinism.

func TestDiffSupplyChain_MultipleFlipsAreDeterministic(t *testing.T) {
	prior := &Report{
		SupplyChain: SupplyChainSection{MalwareStatus: "clean", TyposquatStatus: "clean", PublisherChanged: ptr(false)},
		Scan:        ArtifactScanSection{Performed: true},
		Risk:        &risk.Evaluation{Verdict: risk.VerdictAllow},
	}
	next := &Report{
		SupplyChain: SupplyChainSection{
			MalwareStatus:      "malicious",
			MalwareID:          "MAL-7",
			TyposquatStatus:    "suspected",
			TyposquatSimilarTo: "lodash",
			PublisherChanged:   ptr(true),
		},
		Scan: ArtifactScanSection{Performed: true, HasInstallScript: true, InstallScriptKind: "present"},
		Risk: &risk.Evaluation{Verdict: risk.VerdictQuarantine},
	}

	first := DiffSupplyChain(recallRow(), "npm", prior, next)
	if len(first) != 5 {
		t.Fatalf("want 5 events, got %d (%v)", len(first), triggers(first))
	}
	want := []SupplyChainAlertTrigger{
		AlertInstallScriptAppeared,
		AlertMalwareAppeared,
		AlertPublisherChanged,
		AlertTyposquatAppeared,
		AlertVerdictDegraded,
	}
	if got := triggers(first); !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v (sorted by trigger)", got, want)
	}
	for i := 0; i < 5; i++ {
		again := DiffSupplyChain(recallRow(), "npm", prior, next)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differs:\n first: %+v\n again: %+v", i, first, again)
		}
	}
}

// TestDiffSupplyChain_VerdictOutageDoesNotAlert pins the guard against
// the highest-value false positive this feature can produce.
//
// A stored verdict is computed from whatever facts that cycle had. When
// the advisory lane times out, the report carries no CVEs, the verdict
// resolves to `allow`, and that is persisted. When the lane answers on
// the next cycle the verdict resolves to `quarantine` — and a naive
// diff pages CRITICAL, telling everyone who pulled the package that it
// just went bad, for a CVE that was never absent from the package, only
// from our view of it.
//
// A matcher or feed outage affects whole cohorts at once, so this is not
// a single spurious page; it is the shape that burns the channel.
func TestDiffSupplyChain_VerdictOutageDoesNotAlert(t *testing.T) {
	withCats := func(v risk.Verdict, available map[risk.Category]bool) *Report {
		cats := map[risk.Category]risk.CategoryScore{}
		for cat, ok := range available {
			cats[cat] = risk.CategoryScore{DataAvailable: ok}
		}
		return &Report{Risk: &risk.Evaluation{
			Verdict:     v,
			DirectScore: risk.Score{Categories: cats},
		}}
	}

	all := map[risk.Category]bool{risk.CategorySupplyChain: true, risk.CategoryVulnerability: true}
	noVulnFeed := map[risk.Category]bool{risk.CategorySupplyChain: true, risk.CategoryVulnerability: false}

	t.Run("vuln feed came back: silent", func(t *testing.T) {
		got := DiffSupplyChain(recallRow(), "npm",
			withCats(risk.VerdictAllow, noVulnFeed),
			withCats(risk.VerdictQuarantine, all))
		if len(got) != 0 {
			t.Errorf("alerted on a feed recovering: %+v", got)
		}
	})

	t.Run("same coverage both sides: alerts", func(t *testing.T) {
		got := DiffSupplyChain(recallRow(), "npm",
			withCats(risk.VerdictAllow, all),
			withCats(risk.VerdictQuarantine, all))
		if len(got) != 1 {
			t.Fatalf("a genuine degradation under equal coverage must alert, got %d events", len(got))
		}
	})

	t.Run("coverage lost: silent", func(t *testing.T) {
		got := DiffSupplyChain(recallRow(), "npm",
			withCats(risk.VerdictAllow, all),
			withCats(risk.VerdictQuarantine, noVulnFeed))
		if len(got) != 1 {
			t.Errorf("losing a feed while worsening on the remaining evidence should still alert, got %d", len(got))
		}
	})

	t.Run("one side has coverage data, the other does not: silent", func(t *testing.T) {
		got := DiffSupplyChain(recallRow(), "npm",
			&Report{Risk: &risk.Evaluation{Verdict: risk.VerdictAllow}},
			withCats(risk.VerdictQuarantine, all))
		if len(got) != 0 {
			t.Errorf("alerted across an asymmetric coverage record: %+v", got)
		}
	})

	t.Run("neither side has coverage data: alerts", func(t *testing.T) {
		// Symmetric ignorance. We know nothing about either evaluation's
		// coverage, which is no reason to believe coverage is what moved.
		got := DiffSupplyChain(recallRow(), "npm",
			&Report{Risk: &risk.Evaluation{Verdict: risk.VerdictAllow}},
			&Report{Risk: &risk.Evaluation{Verdict: risk.VerdictQuarantine}})
		if len(got) != 1 {
			t.Errorf("suppressed a degradation with no coverage evidence either way, got %d", len(got))
		}
	})
}

// TestDiffSupplyChain_TyposquatAgreesWithActionable pins that the recall
// trigger and the rest of the product mean the same thing by "typosquat".
//
// TyposquatIsActionable — what the is_typosquat column and the inventory
// facet use — excludes low confidence. The trigger used to fire on
// `suspected` at any confidence, so a low-confidence hit minted a finding
// whose own detail read "(confidence low)" while the product called it
// not actionable. A matcher update that reclassifies a cohort to
// low-confidence suspected is exactly the event this feature exists to
// notice, so the disagreement would have surfaced at its worst moment.
func TestDiffSupplyChain_TyposquatAgreesWithActionable(t *testing.T) {
	report := func(status, confidence string) *Report {
		return &Report{SupplyChain: SupplyChainSection{
			TyposquatStatus:     status,
			TyposquatConfidence: confidence,
			TyposquatSimilarTo:  "lodash",
		}}
	}
	cases := []struct {
		name        string
		prior, next *Report
		wantEvents  int
	}{
		{"clean -> low confidence is not actionable", report("clean", ""), report("suspected", "low"), 0},
		{"clean -> medium confidence alerts", report("clean", ""), report("suspected", "medium"), 1},
		{"clean -> high confidence alerts", report("clean", ""), report("suspected", "high"), 1},
		{"clean -> ungraded still alerts", report("clean", ""), report("suspected", ""), 1},
		{"low -> high is a real escalation", report("suspected", "low"), report("suspected", "high"), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DiffSupplyChain(recallRow(), "npm", tc.prior, tc.next)
			if len(got) != tc.wantEvents {
				t.Errorf("events = %d, want %d (%v)", len(got), tc.wantEvents, triggers(got))
			}
			for _, ev := range got {
				if strings.Contains(ev.Detail, "similar to  ") || strings.HasSuffix(ev.Detail, "similar to ") {
					t.Errorf("detail has an empty target: %q", ev.Detail)
				}
			}
		})
	}

	t.Run("whitespace-only target says so", func(t *testing.T) {
		next := report("suspected", "high")
		next.SupplyChain.TyposquatSimilarTo = "   "
		got := DiffSupplyChain(recallRow(), "npm", report("clean", ""), next)
		if len(got) != 1 {
			t.Fatalf("want 1 event, got %d", len(got))
		}
		if !strings.Contains(got[0].Detail, "no target recorded") {
			t.Errorf("detail = %q, want the no-target phrasing", got[0].Detail)
		}
	})
}
