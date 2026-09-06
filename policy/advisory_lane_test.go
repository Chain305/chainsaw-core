package policy

import (
	"context"
	"sort"
	"sync"
	"testing"
)

// advisory_lane_test.go carries two things:
//
//  1. THE DOCTRINE PROOFS. Mechanical evidence for why the dark advisory
//     lane ships as a record-only marker and NOT as a matrix edit or an
//     evaluator semantics change. These are the tests a future reader
//     should run before "just lowering the cell".
//  2. THE BEHAVIOUR TESTS for the marker itself, including the
//     verdict-neutrality assertion.

// aptRequest is a plain apt repository pull. apt is one of the six
// ecosystems with no vulnerability advisory source.
func aptRequest() EvaluationContext {
	return EvaluationContext{
		OrgID: "org-1", Repository: "apt-hosted", RepositoryFormat: "apt",
		PackageName: "openssl", PackageVersion: "3.0.2",
	}
}

func verdict(t *testing.T, policies []Policy, ctx EvaluationContext) Mode {
	t.Helper()
	e := &Evaluator{}
	return e.EvaluateWithPolicies(ctx, policies, 0).Action
}

// withVulnCellsLowered flips ConditionCVE / ConditionCVSS / ConditionEPSS
// for apt to SupportNone — "the obvious fix" — runs fn, and restores.
// Not parallel-safe by construction; these tests must not call t.Parallel.
func withVulnCellsLowered(fn func()) {
	saved := map[ConditionType]SupportLevel{}
	for _, c := range vulnerabilityLaneConditions {
		saved[c] = SupportMatrix[EcoAPT][c]
		SupportMatrix[EcoAPT][c] = SupportNone
	}
	defer func() {
		for c, l := range saved {
			SupportMatrix[EcoAPT][c] = l
		}
	}()
	fn()
}

// TestLoweringVulnerabilityCellsIsAFailOpen is the P8-17 refutation,
// executed rather than argued.
//
// The dark signal reads as ABSENT (CVSSScore 0.0, EPSSScore 0.0,
// IsVulnerable false), so every NEGATIVE-POLARITY block rule keyed on
// these columns MATCHES today and BLOCKS. Marking the cells SupportNone
// makes detectUnsupported fire, the evaluator `continue`s past the whole
// policy, and all of those blocks silently stop.
//
// That is the direction docs/plan_qa_phase8_remediation.md:1284-1285
// forbids ("RECONCILE UPWARD ONLY... That is a proxy fail-open. The
// direction is not optional"), and it is why the fix in advisory_lane.go
// is a marker rather than a cell move.
func TestLoweringVulnerabilityCellsIsAFailOpen(t *testing.T) {
	cases := []struct {
		name          string
		cond          Conditions
		blocksToday   bool
		wantFailOpen  bool
		polarityNotes string
	}{
		{"isVulnerable:false", Conditions{IsVulnerable: boolPtr(false)}, true, true,
			"the 'block anything not confirmed clean' shape"},
		{"cvssMax:5.0", Conditions{CVSSMax: floatPtr(5.0)}, true, true,
			"0.0 <= 5.0 matches the dark score"},
		{"epssMax:0.5", Conditions{EPSSMax: floatPtr(0.5)}, true, true,
			"0.0 <= 0.5 matches the dark score"},
		{"cvssMin:7.0", Conditions{CVSSMin: floatPtr(7.0)}, false, false,
			"positive polarity: never matched a dark score, so nothing is lost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{ID: "p", Status: StatusEnabled, Mode: ModeBlock, Conditions: tc.cond}

			before := verdict(t, []Policy{p}, aptRequest())
			if got := before == ModeBlock; got != tc.blocksToday {
				t.Fatalf("premise broken: blocks today = %v, want %v (%s)", got, tc.blocksToday, tc.polarityNotes)
			}

			var after Mode
			withVulnCellsLowered(func() { after = verdict(t, []Policy{p}, aptRequest()) })

			lostABlock := before == ModeBlock && after != ModeBlock
			if lostABlock != tc.wantFailOpen {
				t.Fatalf("lowering the cell: before=%s after=%s, lost-a-block=%v want %v",
					before, after, lostABlock, tc.wantFailOpen)
			}
			if lostABlock {
				t.Logf("CONFIRMED FAIL-OPEN: %s blocked before, %s after. %s", before, after, tc.polarityNotes)
			}
		})
	}
}

// TestUnsupportedNonMatchIsVerdictIdenticalToSkip is the second half of
// the step-1 refutation: there is no PROPORTIONATE consequence to swap in
// for the whole-policy `continue`, because Conditions is a pure
// conjunction.
//
// matchesConditions returns false on the FIRST mismatched condition, so
// "this one condition does not match" and "this policy does not match"
// are the same statement. Whatever mix of supported and unsupported
// conditions a rule carries, the two semantics produce the same verdict —
// which is why the reviewer's first option is a no-op, and the second
// (`continue` only when EVERY used column is unsupported) reduces to it.
func TestUnsupportedNonMatchIsVerdictIdenticalToSkip(t *testing.T) {
	mixes := []struct {
		name string
		cond Conditions
	}{
		{"dark cvssMin + supported malicious", Conditions{CVSSMin: floatPtr(7.0), IsKnownMalicious: boolPtr(true)}},
		{"dark cvssMax + supported malicious", Conditions{CVSSMax: floatPtr(5.0), IsKnownMalicious: boolPtr(true)}},
		{"dark isVulnerable + supported typosquat", Conditions{IsVulnerable: boolPtr(false), IsSuspectedTyposquat: boolPtr(true)}},
		{"dark epssMin only", Conditions{EPSSMin: floatPtr(0.5)}},
	}
	for _, mode := range []Mode{ModeBlock, ModeAllow, ModeMonitor, ModeQuarantine} {
		for _, m := range mixes {
			for _, malicious := range []bool{false, true} {
				ctx := aptRequest()
				ctx.IsKnownMalicious = malicious
				ctx.IsSuspectedTyposquat = malicious
				p := Policy{ID: "p", Status: StatusEnabled, Mode: mode, Conditions: m.cond}

				// SKIP semantics: the whole policy is discarded.
				var skipVerdict Mode
				withVulnCellsLowered(func() { skipVerdict = verdict(t, []Policy{p}, ctx) })

				// NON-MATCH semantics: force the dark condition to fail
				// while every other condition still evaluates. For a
				// pure conjunction this is what "that condition does not
				// match" MEANS, and it is expressible today by making
				// the dark condition unsatisfiable.
				nonMatch := p
				nonMatch.Conditions = m.cond
				nonMatch.Conditions.CVSSMin = floatPtr(1e9) // unsatisfiable
				nonMatch.Conditions.CVSSMax = nil
				nonMatch.Conditions.EPSSMax = nil
				nonMatch.Conditions.IsVulnerable = nil
				nonMatchVerdict := verdict(t, []Policy{nonMatch}, ctx)

				if skipVerdict != nonMatchVerdict {
					t.Errorf("%s/%s/malicious=%v: skip=%s non-match=%s — if these ever differ, "+
						"the condition set stopped being a pure conjunction and the step-1 "+
						"analysis in advisory_lane.go must be redone",
						mode, m.name, malicious, skipVerdict, nonMatchVerdict)
				}
			}
		}
	}
}

// TestIgnoringADarkConditionIsAFailOpen covers the ONE semantics that
// does differ from the status quo — drop the dark column and evaluate the
// rest — and shows why it is forbidden.
//
// For a BLOCK rule it over-blocks (the operator's constraint is deleted).
// For an ALLOW rule it is a straight fail-open: the allow rule matches
// MORE coordinates, so it shadows the block rule behind it and a refused
// package is admitted.
func TestIgnoringADarkConditionIsAFailOpen(t *testing.T) {
	ctx := aptRequest()
	ctx.IsKnownMalicious = true

	blockMalware := Policy{ID: "z-block", Status: StatusEnabled, Mode: ModeBlock,
		Conditions: Conditions{IsKnownMalicious: boolPtr(true)}}

	// An allow rule narrowed by a dark condition, ordered ahead of the
	// malware block.
	allowNarrowed := Policy{ID: "a-allow", Status: StatusEnabled, Mode: ModeAllow,
		Conditions: Conditions{CVSSMin: floatPtr(9.0)}}
	// The same rule as the "ignore the dark column" semantics would
	// evaluate it: nothing left to narrow on, so it matches everything.
	allowIgnoringDark := Policy{ID: "a-allow", Status: StatusEnabled, Mode: ModeAllow,
		Conditions: Conditions{}}

	today := verdict(t, []Policy{allowNarrowed, blockMalware}, ctx)
	if today != ModeBlock {
		t.Fatalf("premise broken: a known-malicious apt pull should block today, got %s", today)
	}
	ignoring := verdict(t, []Policy{allowIgnoringDark, blockMalware}, ctx)
	if ignoring != ModeAllow {
		t.Fatalf("premise broken: ignoring the dark column should widen the allow rule, got %s", ignoring)
	}
	t.Logf("CONFIRMED FAIL-OPEN: ignoring the dark condition turns %s into %s on a known-malicious package", today, ignoring)

	// And the same semantics on a block rule deletes the operator's
	// constraint instead of preserving it.
	blockNarrowed := Policy{ID: "b", Status: StatusEnabled, Mode: ModeBlock,
		Conditions: Conditions{CVSSMin: floatPtr(7.0), IsKnownMalicious: boolPtr(true)}}
	blockIgnoringDark := Policy{ID: "b", Status: StatusEnabled, Mode: ModeBlock,
		Conditions: Conditions{IsKnownMalicious: boolPtr(true)}}
	if a, b := verdict(t, []Policy{blockNarrowed}, ctx), verdict(t, []Policy{blockIgnoringDark}, ctx); a == b {
		t.Errorf("premise broken: ignoring the dark column should have changed the block rule's verdict (%s == %s)", a, b)
	}
}

// --- the marker itself -------------------------------------------------

type recordingAuditor struct {
	mu     sync.Mutex
	events []SkipAuditEvent
}

func (r *recordingAuditor) RecordPolicyRuleSkipped(_ context.Context, ev SkipAuditEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingAuditor) byReason(reason string) []SkipAuditEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []SkipAuditEvent
	for _, e := range r.events {
		if e.Reason == reason {
			out = append(out, e)
		}
	}
	return out
}

func evalWithAuditor(policies []Policy, ctx EvaluationContext) (*recordingAuditor, EvaluationResult) {
	a := &recordingAuditor{}
	e := (&Evaluator{}).WithSkipAuditor(a)
	return a, e.EvaluateWithPolicies(ctx, policies, 0)
}

// TestDarkAdvisoryLaneIsRecordOnly is the verdict-neutrality assertion:
// wiring the auditor must change no verdict anywhere, and the event must
// be emitted with RuleEvaluated=true so no sink can mistake it for a
// skip.
func TestDarkAdvisoryLaneIsRecordOnly(t *testing.T) {
	conds := []Conditions{
		{CVSSMin: floatPtr(7.0)},
		{CVSSMax: floatPtr(5.0)},
		{EPSSMin: floatPtr(0.5)},
		{EPSSMax: floatPtr(0.5)},
		{IsVulnerable: boolPtr(true)},
		{IsVulnerable: boolPtr(false)},
		{CVSSMin: floatPtr(7.0), IsKnownMalicious: boolPtr(true)},
	}
	for _, mode := range []Mode{ModeBlock, ModeAllow, ModeMonitor, ModeQuarantine} {
		for i, c := range conds {
			for _, malicious := range []bool{false, true} {
				ctx := aptRequest()
				ctx.IsKnownMalicious = malicious
				p := Policy{ID: "p", Status: StatusEnabled, Mode: mode, Conditions: c}

				bare := verdict(t, []Policy{p}, ctx)
				_, withAudit := evalWithAuditor([]Policy{p}, ctx)
				if bare != withAudit.Action {
					t.Fatalf("VERDICT MOVED (%s cond#%d malicious=%v): %s without auditor, %s with. "+
						"The dark-lane marker must be record-only.", mode, i, malicious, bare, withAudit.Action)
				}
			}
		}
	}

	// And the event carries the honest shape.
	a, _ := evalWithAuditor([]Policy{{
		ID: "pol-1", Status: StatusEnabled, Mode: ModeBlock,
		Conditions: Conditions{CVSSMin: floatPtr(7.0)},
	}}, aptRequest())

	got := a.byReason(SkipReasonNoAdvisorySource)
	if len(got) == 0 {
		t.Fatal("no no_advisory_source event emitted for cvssMin on apt")
	}
	var conditions []string
	for _, ev := range got {
		if !ev.RuleEvaluated {
			t.Errorf("condition %s: RuleEvaluated=false — the rule DID run; a sink will report it as skipped", ev.Condition)
		}
		if ev.Ecosystem != "apt" || ev.PolicyID != "pol-1" || ev.OrgID != "org-1" {
			t.Errorf("event mis-attributed: %+v", ev)
		}
		conditions = append(conditions, ev.Condition)
	}
	sort.Strings(conditions)
	// ConditionsUsedBy maps cvssMin to BOTH CVE and CVSS.
	if want := "[CVE CVSS]"; sprint(conditions) != want {
		t.Errorf("conditions reported = %v, want %s", conditions, want)
	}
	if n := len(a.byReason(SkipReasonUnsupportedEcosystem)); n != 0 {
		t.Errorf("emitted %d unsupported_ecosystem events — the two reasons must not be conflated", n)
	}
}

func sprint(s []string) string {
	out := "["
	for i, v := range s {
		if i > 0 {
			out += " "
		}
		out += v
	}
	return out + "]"
}

// TestDarkAdvisoryLaneIsSilentOnCoveredEcosystems — no noise where the
// lane genuinely runs. npm has an OSV bucket; docker is scanner-advised.
func TestDarkAdvisoryLaneIsSilentOnCoveredEcosystems(t *testing.T) {
	for _, format := range []string{"npm", "pip", "maven", "go", "cargo", "rubygems", "nuget", "composer", "pub", "docker"} {
		ctx := aptRequest()
		ctx.RepositoryFormat = format
		ctx.Repository = format + "-hosted"
		a, _ := evalWithAuditor([]Policy{{
			ID: "p", Status: StatusEnabled, Mode: ModeBlock,
			Conditions: Conditions{CVSSMin: floatPtr(7.0)},
		}}, ctx)
		if n := len(a.byReason(SkipReasonNoAdvisorySource)); n != 0 {
			t.Errorf("%s: %d dark-lane events on an ecosystem with an advisory source", format, n)
		}
	}
}

// TestDarkAdvisoryLaneOnlyFiresForTargetedPolicies — a rule scoped to
// another coordinate says nothing about this request, and one row per
// policy per request would bury the rows that mean something.
func TestDarkAdvisoryLaneOnlyFiresForTargetedPolicies(t *testing.T) {
	other := Policy{
		ID: "p-other", Status: StatusEnabled, Mode: ModeBlock,
		Identifier: Identifier{TargetPackageName: "some-other-package"},
		Conditions: Conditions{CVSSMin: floatPtr(7.0)},
	}
	a, _ := evalWithAuditor([]Policy{other}, aptRequest())
	if n := len(a.byReason(SkipReasonNoAdvisorySource)); n != 0 {
		t.Errorf("emitted %d dark-lane events for a policy that does not target this coordinate", n)
	}

	mine := other
	mine.ID = "p-mine"
	mine.Identifier = Identifier{TargetPackageName: "openssl"}
	a2, _ := evalWithAuditor([]Policy{mine}, aptRequest())
	if n := len(a2.byReason(SkipReasonNoAdvisorySource)); n == 0 {
		t.Error("no dark-lane event for a policy that DOES target this coordinate")
	}
}

// TestDarkAdvisoryLaneDoesNotDoubleReportUnsupportedCells — a column that
// is ALSO SupportNone is already reported as a real skip, with the whole
// policy discarded. Reporting it a second time under no_advisory_source
// would tell the operator the rule both did and did not run.
func TestDarkAdvisoryLaneDoesNotDoubleReportUnsupportedCells(t *testing.T) {
	p := Policy{ID: "p", Status: StatusEnabled, Mode: ModeBlock,
		Conditions: Conditions{CVSSMin: floatPtr(7.0)}}
	var a *recordingAuditor
	withVulnCellsLowered(func() { a, _ = evalWithAuditor([]Policy{p}, aptRequest()) })

	if n := len(a.byReason(SkipReasonNoAdvisorySource)); n != 0 {
		t.Errorf("emitted %d no_advisory_source events for a cell that is already SupportNone", n)
	}
	if n := len(a.byReason(SkipReasonUnsupportedEcosystem)); n == 0 {
		t.Error("expected the unsupported_ecosystem skip to still fire")
	}
	for _, ev := range a.byReason(SkipReasonUnsupportedEcosystem) {
		if ev.RuleEvaluated {
			t.Errorf("condition %s: a genuine skip must carry RuleEvaluated=false", ev.Condition)
		}
	}
}

// TestDarkAdvisoryLaneSetIsDerivedFromTheMatrix guards the mirrored table
// against an ecosystem being added to SupportMatrix and forgotten here.
// An unknown key answers "has a source" on purpose — see the doc comment
// on EcosystemHasAdvisorySource — so this asserts the two stay joined.
func TestDarkAdvisoryLaneSetIsDerivedFromTheMatrix(t *testing.T) {
	for eco := range ecosystemsWithAdvisorySource {
		if _, ok := SupportMatrix[eco]; !ok {
			t.Errorf("%s is in ecosystemsWithAdvisorySource but has no SupportMatrix row", eco)
		}
	}
	if got, want := len(EcosystemsWithoutAdvisorySource())+len(ecosystemsWithAdvisorySource), len(AllEcosystems()); got != want {
		t.Errorf("dark set + covered set = %d, want %d matrix rows", got, want)
	}
	if EcosystemHasAdvisorySource("not-an-ecosystem") != true {
		t.Error("an unknown ecosystem must answer 'has a source' — claiming a coverage gap from ignorance is the maven-hosted bug")
	}
}
