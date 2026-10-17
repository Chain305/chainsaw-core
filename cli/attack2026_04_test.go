package cli

// Attack 2026-04: aquasecurity/trivy repo takeover (hackerbot-claw,
// 2026-02-28). A pull_request_target workflow (apidiff.yaml) checked out the
// fork's head and ran it with the base repository's secrets and write token;
// the stolen credentials set up the 2026-03-19 compromise (attack 13).
//
// What Chainsaw does: `chainsaw scan-actions` lints the workflow structure
// (githubactions.LintWorkflow) and reports action.pwn_request at severity
// high, so the default --fail-on high exits 1. It is a repo-hygiene gate on
// the victim's own workflows: it refuses the vulnerable workflow in CI, it
// cannot stop a fork PR against a workflow already merged and not scanned.
//
// pr-scan: since v0.22.106 (F12) diffWorkflow also runs the lint, so a PR
// that adds this workflow gets a block row (a warn row before v0.22.110) carrying action.pwn_request; the
// pull_request twin gets none.

import (
	"os"
	"path/filepath"
	"testing"
)

// atk26PinnedCheckout / atk26PinnedSetupGo are real-shaped 40-hex pins so the
// fixtures carry no unpinned-ref noise.
const (
	atk26PinnedCheckout = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
	atk26PinnedSetupGo  = "actions/setup-go@0aaccfd150d50ccaeb58ebd88d36e91967a5f35b"
)

// atk26WriteWF writes one workflow file into a fresh .github/workflows dir
// and returns the file path.
func atk26WriteWF(t *testing.T, name, body string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// atk26Sigs maps every reported signal to its severity.
func atk26Sigs(r scanActionsReport) map[string]string {
	out := map[string]string{}
	for _, f := range r.Findings {
		out[f.Signal] = f.Severity
	}
	return out
}

// atk26TrivyAPIDiff is the apidiff.yaml shape: pull_request_target, checkout
// of the PR head SHA, then the fork's Go code runs.
func atk26TrivyAPIDiff(trigger string) string {
	return `name: API Diff Check
on:
  ` + trigger + `:
    types: [opened, synchronize]
permissions:
  contents: read
  pull-requests: write
jobs:
  apidiff:
    runs-on: ubuntu-latest
    steps:
      - uses: ` + atk26PinnedCheckout + `
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          fetch-depth: 0
      - uses: ` + atk26PinnedSetupGo + `
        with:
          go-version-file: go.mod
      - name: Run apidiff
        run: go run ./magefiles apidiff
        env:
          GITHUB_TOKEN: ${{ secrets.ORG_REPO_TOKEN }}
`
}

func TestAttack2026_04_TrivyPwnRequest(t *testing.T) {
	bad := atk26WriteWF(t, "apidiff.yaml", atk26TrivyAPIDiff("pull_request_target"))
	code, r, err := runScanActionsJSON(t, bad, "")
	if err != nil {
		t.Fatal(err)
	}
	if atk26Sigs(r)["action.pwn_request"] != "high" || code != 1 {
		t.Fatalf("pull_request_target + head checkout + run: want high action.pwn_request and exit 1 at default --fail-on, got exit %d %+v", code, r.Findings)
	}

	// Negative twin: the same job on pull_request runs the fork's code with
	// a read-only token and no secrets — not a pwn request.
	good := atk26WriteWF(t, "apidiff.yaml", atk26TrivyAPIDiff("pull_request"))
	code, r, err = runScanActionsJSON(t, good, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := atk26Sigs(r)["action.pwn_request"]; ok || code != 0 {
		t.Fatalf("pull_request twin: want no pwn_request and exit 0, got exit %d %+v", code, r.Findings)
	}

	// pr-scan, since v0.22.106 (F12): the PR that introduces this workflow
	// gets a block row for the workflow file carrying action.pwn_request.
	if !atk26PRScanLints(t, "apidiff.yaml", atk26TrivyAPIDiff("pull_request_target"), "action.pwn_request") {
		t.Fatal("pr-scan: want a block row with action.pwn_request for the pull_request_target workflow")
	}
	if atk26PRScanLints(t, "apidiff.yaml", atk26TrivyAPIDiff("pull_request"), "action.pwn_request") {
		t.Fatal("pr-scan: the pull_request twin must not carry action.pwn_request")
	}
}

// atk26PRScanLints reports whether pr-scan's diffWorkflow, for a PR adding
// the workflow, returns a block row for the file carrying signal.
func atk26PRScanLints(t *testing.T, name, body, signal string) bool {
	t.Helper()
	rel := ".github/workflows/" + name
	added, upgraded, err := diffWorkflow(rel, nil, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	// Since v0.22.110 every introduced workflow-lint finding blocks.
	want := "block"
	for _, e := range append(added, upgraded...) {
		if hasPRSignal(e.Signals, signal) {
			if e.Name != rel || e.Verdict != want {
				t.Fatalf("pr-scan lint row: want %s row named %s, got %+v", want, rel, e)
			}
			return true
		}
	}
	return false
}
