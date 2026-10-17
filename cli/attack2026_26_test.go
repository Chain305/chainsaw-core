package cli

// Attack 2026-26: elementary-data forged release (2026-04-24). The
// update_pylon_issue.yml workflow interpolated ${{ github.event.comment.body }}
// into a shell run: step; a PR comment carrying a curl|bash stager ran with
// the repo GITHUB_TOKEN, tagged an orphan commit v0.23.3 and dispatched the
// real release pipeline (PyPI elementary-data 0.23.3, GHCR
// ghcr.io/elementary-data/elementary:0.23.3, payload in elementary.pth).
//
// Workflow half (this file): scan-actions reports action.script_injection
// (high), default exit 1. Negative twin: the comment passed through env: and
// read as "$COMMENT_BODY", which bash never parses as code.
// Package half: core/malware (feed) and core/pysource (.pth gap).

import "testing"

func TestAttack2026_26_ElementaryScriptInjection(t *testing.T) {
	wf := func(step string) string {
		return `name: Update Pylon issue
on:
  issue_comment:
    types: [created]
jobs:
  handle_comment:
    runs-on: ubuntu-latest
    steps:
      - name: Extract Issue or Pull Request Details
` + step
	}
	const injected = `        run: |
          COMMENT="${{ github.event.comment.body }}"
          echo "comment=$COMMENT" >> "$GITHUB_OUTPUT"
`
	const viaEnv = `        env:
          COMMENT_BODY: ${{ github.event.comment.body }}
        run: |
          echo "comment=$COMMENT_BODY" >> "$GITHUB_OUTPUT"
`
	code, r, err := runScanActionsJSON(t, atk26WriteWF(t, "update_pylon_issue.yml", wf(injected)), "")
	if err != nil {
		t.Fatal(err)
	}
	if atk26Sigs(r)["action.script_injection"] != "high" || code != 1 {
		t.Fatalf("comment.body in run: want high script_injection, exit 1; got exit %d %+v", code, r.Findings)
	}
	code, r, err = runScanActionsJSON(t, atk26WriteWF(t, "update_pylon_issue.yml", wf(viaEnv)), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := atk26Sigs(r)["action.script_injection"]; ok || code != 0 {
		t.Fatalf("env-passed twin: want no script_injection, exit 0; got exit %d %+v", code, r.Findings)
	}
}
