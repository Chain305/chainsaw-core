package githubactions

import (
	"testing"

	"github.com/chain305/chainsaw-core/intelligence"
)

func TestBuildReport(t *testing.T) {
	t.Run("empty findings produces empty Actions section", func(t *testing.T) {
		got := BuildReport(nil)
		if got == nil {
			t.Fatal("BuildReport(nil) returned nil; expected non-nil Report")
		}
		if got.Actions == nil {
			t.Fatal("Actions section is nil; expected non-nil with empty Findings slice")
		}
		if len(got.Actions.Findings) != 0 {
			t.Errorf("Findings len = %d, want 0", len(got.Actions.Findings))
		}
		if got.Identity.Ecosystem != reportEcosystem {
			t.Errorf("Identity.Ecosystem = %q, want %q", got.Identity.Ecosystem, reportEcosystem)
		}
		if got.Identity.Package != reportPackage {
			t.Errorf("Identity.Package = %q, want %q", got.Identity.Package, reportPackage)
		}
	})

	t.Run("mixed findings all map across", func(t *testing.T) {
		findings := []Finding{
			{
				Ref:      ActionRef{Raw: "actions/checkout@v4", Owner: "actions", Name: "checkout", Version: "v4"},
				Signal:   SignalActionUnpinnedRef,
				Severity: "medium",
				Message:  "unpinned",
			},
			{
				Ref:      ActionRef{Raw: "actoins/checkout@v4", Owner: "actoins", Name: "checkout", Version: "v4"},
				Signal:   SignalActionTyposquat,
				Severity: "high",
				Message:  "typosquat",
				Detail:   "actions/checkout",
			},
			{
				Ref:      ActionRef{Raw: "tj-actions/changed-files@v1", Owner: "tj-actions", Name: "changed-files", Version: "v1"},
				Signal:   SignalActionMalicious,
				Severity: "high",
				Message:  "malicious",
				Detail:   "GHSA-mrrh-fwg8-r2c3",
			},
		}
		got := BuildReport(findings)
		if got.Actions == nil || len(got.Actions.Findings) != 3 {
			t.Fatalf("got %d findings, want 3", len(got.Actions.Findings))
		}
		// Order must match the input order — BuildReport is a pure mapping,
		// not a re-sort. Assert each slot by index.
		want := []intelligence.ActionFinding{
			{Signal: SignalActionUnpinnedRef, Severity: "medium", Ref: "actions/checkout@v4"},
			{Signal: SignalActionTyposquat, Severity: "high", Ref: "actoins/checkout@v4", Detail: "actions/checkout"},
			{Signal: SignalActionMalicious, Severity: "high", Ref: "tj-actions/changed-files@v1", Detail: "GHSA-mrrh-fwg8-r2c3"},
		}
		for i, w := range want {
			g := got.Actions.Findings[i]
			if g != w {
				t.Errorf("Findings[%d] = %+v, want %+v", i, g, w)
			}
		}
	})

	t.Run("Ref string falls back to owner/name@version when Raw empty", func(t *testing.T) {
		findings := []Finding{
			{
				Ref:      ActionRef{Owner: "actions", Name: "checkout", Version: "v4"}, // no Raw
				Signal:   SignalActionUnpinnedRef,
				Severity: "medium",
			},
			{
				Ref:      ActionRef{Owner: "actions", Name: "checkout"}, // no Version, no Raw
				Signal:   SignalActionUnpinnedRef,
				Severity: "medium",
			},
		}
		got := BuildReport(findings)
		if len(got.Actions.Findings) != 2 {
			t.Fatalf("got %d findings, want 2", len(got.Actions.Findings))
		}
		if got.Actions.Findings[0].Ref != "actions/checkout@v4" {
			t.Errorf("Findings[0].Ref = %q, want %q", got.Actions.Findings[0].Ref, "actions/checkout@v4")
		}
		if got.Actions.Findings[1].Ref != "actions/checkout" {
			t.Errorf("Findings[1].Ref = %q, want %q", got.Actions.Findings[1].Ref, "actions/checkout")
		}
	})

	t.Run("BuildReport output round-trips through ProjectToRiskInput", func(t *testing.T) {
		// End-to-end sanity: the projector's ActionRef* fields should
		// flip on when BuildReport produces a typosquat/unpinned finding.
		// This is the whole point of this bridge.
		findings := []Finding{
			{Ref: ActionRef{Raw: "actions/checkout@v4"}, Signal: SignalActionUnpinnedRef, Severity: "medium"},
			{Ref: ActionRef{Raw: "actoins/checkout@v4"}, Signal: SignalActionTyposquat, Severity: "high"},
			{Ref: ActionRef{Raw: "rando/thing@v1"}, Signal: SignalActionUnknownPublisher, Severity: "low"},
		}
		report := BuildReport(findings)
		in := intelligence.ProjectToRiskInput(report)
		if !in.ActionRefUnpinned {
			t.Errorf("ActionRefUnpinned = false, want true")
		}
		if !in.ActionRefTyposquat {
			t.Errorf("ActionRefTyposquat = false, want true")
		}
		if !in.ActionRefUnknownPublisher {
			t.Errorf("ActionRefUnknownPublisher = false, want true")
		}
		if len(in.ActionRefUnpinnedRefs) != 1 || in.ActionRefUnpinnedRefs[0] != "actions/checkout@v4" {
			t.Errorf("ActionRefUnpinnedRefs = %v, want [actions/checkout@v4]", in.ActionRefUnpinnedRefs)
		}
	})
}
