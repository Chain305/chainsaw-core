package risk

import (
	"reflect"
	"testing"
)

// TestNoFixSummaries_KeysMatchEvaluatorStrings pins the display table in
// evaluation.go to the strings resolveVerdict actually emits. The table is
// keyed on exact summary text; if a future edit to evaluator.go rewords one
// of the "no known safe version" sentences, the rewrite would silently stop
// firing and the page would go back to asserting a falsehood. This test is
// the tripwire for that.
func TestNoFixSummaries_KeysMatchEvaluatorStrings(t *testing.T) {
	crit := map[string]FiredSignal{
		"vuln.kev": {ID: "vuln.kev", Severity: SevCritical, Weight: -40},
	}
	cases := []struct {
		name      string
		overall   int
		primitive map[string]FiredSignal
		opts      Options
	}{
		{
			name:    "band1 quarantine, no fix, no alternative",
			overall: 5,
		},
		{
			name:      "critical signal, no fix, no alternative",
			overall:   95,
			primitive: crit,
		},
		{
			name:    "band1 with alternative but no safe version",
			overall: 5,
			opts:    Options{Alternative: "some-other-pkg"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, res := resolveVerdict(c.overall, c.primitive, nil, c.opts)
			if _, ok := noFixSummaries[res.Summary]; !ok {
				t.Fatalf("summary %q is not a key in noFixSummaries — the "+
					"display rewrite in evaluation.go has drifted from "+
					"evaluator.go and the page will keep claiming no fix exists",
					res.Summary)
			}
		})
	}
}

// TestApplyKnownFix_LeavesVerdictAlone is the invariant that matters: the
// display annotation must not be able to move an enforcement answer.
func TestApplyKnownFix_LeavesVerdictAlone(t *testing.T) {
	before, res := resolveVerdict(5, nil, nil, Options{})
	if before != VerdictQuarantine {
		t.Fatalf("precondition: want quarantine, got %q", before)
	}
	ev := &Evaluation{
		Verdict:    before,
		Resolution: res,
		DirectScore: Score{
			Overall:          5,
			MinCategoryScore: 5,
			WorstCategory:    CategoryVulnerability,
		},
	}
	ev.RolledUp = ev.DirectScore

	ev.ApplyKnownFix("4.18.1")

	if ev.Verdict != VerdictQuarantine {
		t.Fatalf("Evaluation.Verdict moved to %q — enforcement must not change", ev.Verdict)
	}
	if ev.Resolution.Verdict != VerdictQuarantine {
		t.Fatalf("Resolution.Verdict moved to %q", ev.Resolution.Verdict)
	}
	if ev.DirectScore.Overall != 5 || ev.RolledUp.Overall != 5 {
		t.Fatalf("scores moved: direct=%d rolled=%d", ev.DirectScore.Overall, ev.RolledUp.Overall)
	}
	if ev.Resolution.SafeVersion != "4.18.1" {
		t.Fatalf("SafeVersion = %q, want 4.18.1", ev.Resolution.SafeVersion)
	}
	if ev.Resolution.PatchAdvisory != "Patched in 4.18.1 — upgrade and re-scan." {
		t.Fatalf("PatchAdvisory = %q", ev.Resolution.PatchAdvisory)
	}
	want := "High-risk package. Patched in 4.18.1 — upgrade and re-scan. Manual review required until then."
	if ev.Resolution.Summary != want {
		t.Fatalf("Summary = %q, want %q", ev.Resolution.Summary, want)
	}
}

// TestApplyKnownFix_EmptyIsNoOp — "we could not establish a version that
// clears every CVE" must render exactly as it does today, not as a blank
// advisory row.
func TestApplyKnownFix_EmptyIsNoOp(t *testing.T) {
	_, res := resolveVerdict(5, nil, nil, Options{})
	original := res
	res.ApplyKnownFix("")
	if !reflect.DeepEqual(res, original) {
		t.Fatalf("empty safeVersion mutated the resolution: %+v", res)
	}
}

// TestApplyKnownFix_LeavesUnrelatedSummaryAlone — a summary that never
// claimed a fix was missing keeps its wording; only the display fields are
// added.
func TestApplyKnownFix_LeavesUnrelatedSummaryAlone(t *testing.T) {
	res := Resolution{Verdict: VerdictWarn, Summary: "Package has notable risk signals. Review before use."}
	res.ApplyKnownFix("2.0.0")
	if res.Summary != "Package has notable risk signals. Review before use." {
		t.Fatalf("Summary rewritten unexpectedly: %q", res.Summary)
	}
	if res.SafeVersion != "2.0.0" || res.PatchAdvisory == "" {
		t.Fatalf("display fields not populated: %+v", res)
	}
	if res.Verdict != VerdictWarn {
		t.Fatalf("Verdict moved to %q", res.Verdict)
	}
}

// TestApplyKnownFix_UnknownVerdictGetsNoAdvice — a NOT-EVALUATED result must
// never sprout an upgrade line. For a coordinate the registry never
// published, the CVE rows describe a different version entirely.
func TestApplyKnownFix_UnknownVerdictGetsNoAdvice(t *testing.T) {
	res := Resolution{
		Verdict: VerdictUnknown,
		Summary: "Risk signals could not be evaluated for this package — this is NOT a clean result.",
	}
	original := res
	res.ApplyKnownFix("4.19.2")
	if !reflect.DeepEqual(res, original) {
		t.Fatalf("unknown verdict was annotated: %+v", res)
	}
}

// TestApplyKnownFix_NilReceivers guards the convenience wrapper.
func TestApplyKnownFix_NilReceivers(t *testing.T) {
	var ev *Evaluation
	ev.ApplyKnownFix("1.0.0") // must not panic
	var res *Resolution
	res.ApplyKnownFix("1.0.0") // must not panic
}
