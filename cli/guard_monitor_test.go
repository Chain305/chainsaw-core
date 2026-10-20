package cli

// guard_monitor_test.go — monitor mode's boundary: demote ONLY what the
// allowlist could clear (guardAllowlistableVerdict), nothing harder. The
// adversarial finding this guards against: matching on the severity STRING
// would have demoted the homoglyph block, whose severity IS "typosquat-high".

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

// monitorVerdictFixture builds one verdict per severity family, with the
// flags the real lanes set. These are run through guardMonitorDemote directly
// so the boundary is pinned at the predicate level, independent of which lane
// happened to produce each severity today.
func monitorVerdictFixture() []guardVerdict {
	spec := packageSpec{Ecosystem: "npm", Name: "x"}
	return []guardVerdict{
		{Spec: spec, Block: true, Severity: "malicious", Reason: "known-malicious"},
		{Spec: spec, Block: true, Severity: "known-vulnerable", Reason: "advisory"},
		{Spec: spec, Block: true, Severity: guardSeverityTyposquatHigh, Unwaivable: true, Reason: "homoglyph"},
		{Spec: spec, Block: true, Severity: guardSeverityBehavioralHigh, Reason: "bytes"},
		{Spec: spec, Block: true, Severity: guardSeverityPolicy, Reason: "policy"},
		{Spec: spec, Block: true, Severity: "coverage", Reason: "coverage gate"},
		{Spec: spec, Block: true, Severity: guardSeverityArtifactSwap, Unwaivable: true, Reason: "artifact-swap"},
		{Spec: spec, Block: true, Severity: guardSeverityTyposquatHigh, Reason: "d=1 edit-distance"}, // the ONE demotable shape
	}
}

// TestGuardMonitorDemoteBoundaryIsTheAllowlistBoundary: in monitor mode,
// exactly the plain (waivable) typosquat block demotes; every harder
// severity — including the homoglyph block that CARRIES "typosquat-high" —
// still blocks.
func TestGuardMonitorDemoteBoundaryIsTheAllowlistBoundary(t *testing.T) {
	t.Setenv(guardModeEnv, guardModeMonitor)
	vs := monitorVerdictFixture()
	demoted := guardMonitorDemote(vs)
	if demoted != 1 {
		t.Fatalf("demoted %d verdicts, want exactly 1 (the plain typosquat block): %+v", demoted, vs)
	}
	for i, v := range vs {
		if v.Severity == guardSeverityTyposquatHigh && !v.Unwaivable {
			if v.Block || !v.MonitorDemoted {
				t.Errorf("the allowlistable typosquat block must demote, got %+v", v)
			}
			continue
		}
		if !v.Block || v.MonitorDemoted {
			t.Errorf("verdict %d (%s) must keep blocking untouched, got %+v", i, v.Severity, v)
		}
	}
}

// TestGuardMonitorOffByDefaultAndFailsSafe: unset, "enforce", and a TYPO all
// leave every block standing. A misspelled loosening knob must fail back to
// enforcement, not forward to silence.
func TestGuardMonitorOffByDefaultAndFailsSafe(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
	}{
		{"unset", ""}, {"enforce", "enforce"}, {"typo", "moniter"}, {"empty", " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(guardModeEnv, tc.env)
			if guardMonitorActive() {
				t.Fatalf("%q must not enable monitor mode", tc.env)
			}
			if got := guardModeLabel(); got != guardModeEnforce {
				t.Fatalf("guardModeLabel() = %q, want enforce", got)
			}
			vs := monitorVerdictFixture()
			if n := guardMonitorDemote(vs); n != 0 {
				t.Fatalf("demoted %d verdicts with the knob %q — enforcement is not the default", n, tc.env)
			}
		})
	}
}

// TestGuardMonitorDemotesTyposquatBlockEndToEnd: through the REAL ladder
// (evaluateAll) on the embedded corpus. `lodahs` is a d=1 transposition of
// lodash (#101) that blocks in enforce mode; in monitor mode the run must
// return blocked=false with the verdict demoted — and the demotion must be
// visible (the printer renders it, asserted below).
func TestGuardMonitorDemotesTyposquatBlockEndToEnd(t *testing.T) {
	ctx := context.Background()
	spec := packageSpec{Ecosystem: "npm", Name: "lodahs"}

	vs, blocked := newSeedOnlyGuard(t).evaluateAll(ctx, []packageSpec{spec})
	if !blocked || !vs[0].Block || vs[0].MonitorDemoted {
		t.Fatalf("fixture no longer blocks in enforce mode: blocked=%v %+v — re-pick it", blocked, vs[0])
	}

	t.Setenv(guardModeEnv, guardModeMonitor)
	vs, blocked = newSeedOnlyGuard(t).evaluateAll(ctx, []packageSpec{spec})
	if blocked {
		t.Fatalf("monitor mode must not refuse the install: %+v", vs)
	}
	if vs[0].Block || !vs[0].MonitorDemoted {
		t.Fatalf("the typosquat block must demote to a marked warn, got %+v", vs[0])
	}
	if vs[0].Severity != guardSeverityTyposquatHigh {
		t.Errorf("the demoted verdict keeps its severity as the record of what the lane found, got %q", vs[0].Severity)
	}
}

// TestGuardMonitorKeepsHomoglyphAndMalwareBlocking: the two hard-evidence
// lanes, end to end.
func TestGuardMonitorKeepsHomoglyphAndMalwareBlocking(t *testing.T) {
	t.Setenv(guardModeEnv, guardModeMonitor)
	ctx := context.Background()

	// Homoglyph: Cyrillic U+0430 in `nаn` against corpus `nan` — the same
	// fixture TestGuardHomoglyphBlocksIgnoreTheD1Gate proves fails the d=1
	// gate, so only the arm separation can be what blocks it.
	g := newSeedOnlyGuard(t)
	d := typosquat.NewDetectorWithConfig(guardLogger, typosquat.ThresholdConfig{
		MaxRelativeDistance: guardMaxRelativeDistance,
	})
	d.LoadEcosystem("npm", []typosquat.PopularPackage{{Name: "nan", Rank: 1476}})
	g.detectors["npm"] = d
	vs, blocked := g.evaluateAll(ctx, []packageSpec{{Ecosystem: "npm", Name: "nаn"}})
	if !blocked || !vs[0].Block || vs[0].MonitorDemoted || !vs[0].Unwaivable {
		t.Fatalf("homoglyph must block in monitor mode too (severity IS typosquat-high — the predicate, not the string, must decide): %+v", vs[0])
	}

	// Known-malicious: a synthetic coordinate the index refuses.
	idx := malware.NewIndex(guardLogger)
	idx.Load([]*malware.OSVEntry{{
		ID: "MAL-TEST-MONITOR",
		Affected: []malware.OSVAffected{{
			Package:  malware.OSVPackage{Ecosystem: "npm", Name: "event-stream"},
			Versions: []string{"3.3.6"},
		}},
	}})
	g2 := newSeedOnlyGuard(t)
	g2.malware = idx
	vs, blocked = g2.evaluateAll(ctx, []packageSpec{{Ecosystem: "npm", Name: "event-stream", Version: "3.3.6"}})
	if !blocked || !vs[0].Block || vs[0].MonitorDemoted || vs[0].Severity != "malicious" {
		t.Fatalf("known-malicious must block in monitor mode too: %+v", vs[0])
	}
}

// TestGuardMonitorPrintsDemotion: the printer renders a demoted verdict as
// exactly ONE "! monitor" line, never silenced by --quiet, and never doubled
// by the catch-all severity arm.
func TestGuardMonitorPrintsDemotion(t *testing.T) {
	spec := packageSpec{Ecosystem: "npm", Name: "lodahs"}
	v := guardVerdict{
		Spec: spec, Block: false, MonitorDemoted: true,
		Severity: guardSeverityTyposquatHigh, Reason: "looks like a typosquat of \"lodash\"",
	}
	for _, quiet := range []bool{false, true} {
		out := printedLines(t, quiet, v)
		if !strings.Contains(out, "! monitor") || !strings.Contains(out, "monitor mode") {
			t.Errorf("quiet=%v: the demotion must be visible, got:\n%s", quiet, out)
		}
		if n := strings.Count(out, "lodahs"); n != 1 {
			t.Errorf("quiet=%v: the demoted verdict must render exactly one line for the package, got %d:\n%s", quiet, n, out)
		}
	}
}

// TestGuardMonitorNoticesAndState: the run-level notice says the machine is
// in monitor, and the posture is recorded in guard_state.json where
// `guard status` reads it.
func TestGuardMonitorNoticesAndState(t *testing.T) {
	// The notice (suppressible — it is context, the per-verdict lines carry
	// the substance).
	t.Setenv(guardModeEnv, guardModeMonitor)
	if got := guardModeLabel(); got != guardModeMonitor {
		t.Fatalf("guardModeLabel() = %q, want monitor", got)
	}
	g := newLocalGuard()
	found := false
	for _, n := range g.notices {
		if strings.Contains(n, "monitor mode") && strings.Contains(n, guardModeEnv) {
			found = true
		}
	}
	if !found {
		t.Errorf("monitor mode must add a run-level notice, got %v", g.notices)
	}

	// The persisted record and its `guard status` rendering.
	writeGuardStateForTest(t, &guardState{})
	processGuardOutcome("npm", nil, false)
	st := loadGuardState()
	if st.Mode != guardModeMonitor {
		t.Fatalf("guard_state.json mode = %q, want monitor", st.Mode)
	}
	out := runGuardStatusText(t)
	if got := guardStatusRow(out, "Mode"); !strings.Contains(got, "monitor") {
		t.Fatalf("guard status Mode row = %q, want it to name monitor\n--- output ---\n%s", got, out)
	}

	// A legacy state file (no Mode) reads as enforce; the env var wins when set.
	writeGuardStateForTest(t, &guardState{})
	t.Setenv(guardModeEnv, "")
	if got := guardStatusModeLabel(loadGuardState()); got != guardModeEnforce {
		t.Fatalf("empty persisted mode must read as enforce, got %q", got)
	}
	t.Setenv(guardModeEnv, guardModeMonitor)
	if got := guardStatusModeLabel(&guardState{}); !strings.Contains(got, guardModeMonitor) {
		t.Fatalf("env monitor must win over an empty persisted mode, got %q", got)
	}
}

// TestGuardEstablishedClearsPersistToGuardState: the counter the clear
// increments is visible in `guard status` through guard_state.json — the
// existing stats mechanism, not a new command.
func TestGuardEstablishedClearsPersistToGuardState(t *testing.T) {
	writeGuardStateForTest(t, &guardState{})
	processGuardOutcome("npm", []guardVerdict{
		{Spec: packageSpec{Ecosystem: "npm", Name: "pug"}, ClearedReason: "cleared: established"},
	}, false)
	st := loadGuardState()
	if st.EstablishedClears != 1 {
		t.Fatalf("EstablishedClears = %d, want 1", st.EstablishedClears)
	}
	out := runGuardStatusText(t)
	if got := guardStatusRow(out, "Established clears"); got != "1" {
		t.Fatalf("guard status Established clears row = %q, want 1\n--- output ---\n%s", got, out)
	}
}

// TestGuardMonitorDoesNotDemoteCoverageRefusal: a coverage-gate refusal (or
// an invalid coverage configuration) is a promise this machine made, not name
// inference — monitor mode must not touch it.
func TestGuardMonitorDoesNotDemoteCoverageRefusal(t *testing.T) {
	t.Setenv(guardModeEnv, guardModeMonitor)
	t.Setenv("CHAINSAW_COVERAGE_MODE", "closed")
	t.Setenv("CHAINSAW_COVERAGE_REQUIRED", "malware")
	t.Setenv(guardDBEnv, filepath.Join(t.TempDir(), "absent.json"))

	g := newLocalGuard()
	vs, blocked := g.evaluateAll(context.Background(), []packageSpec{{Ecosystem: "npm", Name: "lodash"}})
	if !blocked {
		t.Fatalf("coverage refusal must stand in monitor mode: %+v", vs)
	}
	for _, v := range vs {
		if v.Severity == "coverage" && (!v.Block || v.MonitorDemoted) {
			t.Fatalf("coverage refusal was demoted by monitor mode: %+v", v)
		}
	}
}
