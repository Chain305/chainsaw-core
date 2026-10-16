package cli

import (
	"strings"
	"testing"
)

const prWorkflowSHA = "11bd71901bbe5b1630ceea73d27597364c9af683"

func prWorkflow(uses ...string) string {
	var b strings.Builder
	b.WriteString("name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n")
	for _, u := range uses {
		b.WriteString("      - uses: " + u + "\n")
	}
	return b.String()
}

func TestIsWorkflowFile(t *testing.T) {
	for rel, want := range map[string]bool{
		".github/workflows/ci.yml":       true,
		".github/workflows/release.yaml": true,
		"sub/.github/workflows/ci.yml":   true,
		"action.yml":                     true,
		"actions/deploy/action.yaml":     true,
		".github/workflows/README.md":    false,
		"config/ci.yml":                  false,
		".github/dependabot.yml":         false,
		"package.json":                   false,
	} {
		if got := isWorkflowFile(rel); got != want {
			t.Errorf("isWorkflowFile(%q) = %v, want %v", rel, got, want)
		}
	}
}

// TestDiffWorkflowRowsCarryActionSignals: only refs the PR added or changed
// become rows; a SHA pin moved to a tag is an upgrade flagged unpinned, and a
// known-compromised action blocks.
func TestDiffWorkflowRowsCarryActionSignals(t *testing.T) {
	base := prWorkflow("actions/checkout@"+prWorkflowSHA, "actions/setup-node@"+prWorkflowSHA)
	head := prWorkflow("actions/checkout@v5", "actions/setup-node@"+prWorkflowSHA, "tj-actions/changed-files@v35", "tj-actions/changed-files@v35")
	added, upgraded, err := diffWorkflow(".github/workflows/ci.yml", []byte(base), []byte(head))
	if err != nil {
		t.Fatal(err)
	}
	if len(upgraded) != 1 || upgraded[0].Name != "actions/checkout" || upgraded[0].Version != "v5" ||
		upgraded[0].PreviousVersion == nil || *upgraded[0].PreviousVersion != prWorkflowSHA {
		t.Fatalf("want one upgrade actions/checkout %s -> v5, got %+v", prWorkflowSHA, upgraded)
	}
	if !hasPRSignal(upgraded[0].Signals, "action.unpinned_ref") || upgraded[0].Verdict != "warn" {
		t.Errorf("SHA -> tag must warn action.unpinned_ref, got %+v", upgraded[0])
	}
	if len(added) != 1 || added[0].Name != "tj-actions/changed-files" {
		t.Fatalf("want one added row (a ref used twice is one row; setup-node is unchanged), got %+v", added)
	}
	if !hasPRSignal(added[0].Signals, "action.malicious") || added[0].Verdict != "block" || added[0].Ecosystem != "github_actions" {
		t.Errorf("a known-compromised action must block, got %+v", added[0])
	}

	if a, u, err := diffWorkflow("ci.yml", []byte(base), []byte(base)); err != nil || len(a)+len(u) != 0 {
		t.Errorf("an unchanged workflow must produce no rows, got %+v %+v %v", a, u, err)
	}
	if _, _, err := diffWorkflow("ci.yml", nil, []byte("jobs: [unclosed")); err == nil {
		t.Error("an unparseable head workflow must be an error (counted as a parse failure), not silence")
	}
}

// TestBuildPRScanReportInspectsWorkflows: a workflow change used to be
// skipped outright (classifyManifest does not know it), so a PR adding a
// compromised action exited 0.
func TestBuildPRScanReportInspectsWorkflows(t *testing.T) {
	prScanPolicyTestEnv(t, "")
	dir, base, head := initPRScanRepo(t, ".github/workflows/ci.yml",
		prWorkflow("actions/checkout@"+prWorkflowSHA),
		prWorkflow("actions/checkout@"+prWorkflowSHA, "tj-actions/changed-files@v35"))
	report, code, err := buildPRScanReport(base, head, dir)
	if err != nil {
		t.Fatal(err)
	}
	if code != prScanExitBlocking || report.Summary.Blocking != 1 || len(report.Added) != 1 {
		t.Fatalf("want exit %d with one blocking row, got exit %d %+v", prScanExitBlocking, code, report)
	}
	sarif := prScanToSARIF(report)
	if len(sarif.Runs) == 0 || len(sarif.Runs[0].Results) == 0 {
		t.Fatalf("the action finding must reach SARIF, got %+v", sarif)
	}
}
