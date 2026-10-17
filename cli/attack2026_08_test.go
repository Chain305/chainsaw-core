package cli

// Attack 2026-08: kubernetes-el Pwn Request (2026-03-05). A
// pull_request_target workflow checked out the fork's branch and ran it; the
// token it got was used to replace kubernetes.el with a destructive command.
//
// Same mechanism as attack 04, different shape: the checkout names the fork
// repository and head ref instead of the head SHA. scan-actions reports
// action.pwn_request (high, default exit 1), and since v0.22.106 (F12)
// pr-scan reports it on the PR that adds the workflow. Negative twin: a
// workflow_run job that checks out the default branch only.

import "testing"

func TestAttack2026_08_KubernetesElPwnRequest(t *testing.T) {
	const pwn = `name: CI
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ` + atk26PinnedCheckout + `
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
          ref: ${{ github.event.pull_request.head.ref }}
      - run: make test
`
	code, r, err := runScanActionsJSON(t, atk26WriteWF(t, "ci.yml", pwn), "")
	if err != nil {
		t.Fatal(err)
	}
	if atk26Sigs(r)["action.pwn_request"] != "high" || code != 1 {
		t.Fatalf("fork repository+head ref checkout under pull_request_target: want high pwn_request, exit 1; got exit %d %+v", code, r.Findings)
	}
	if !atk26PRScanLints(t, "ci.yml", pwn, "action.pwn_request") {
		t.Fatal("pr-scan: want a warn row with action.pwn_request")
	}

	const safe = `name: CI
on:
  workflow_run:
    workflows: [build]
    types: [completed]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: ` + atk26PinnedCheckout + `
      - run: make test
`
	code, r, err = runScanActionsJSON(t, atk26WriteWF(t, "ci.yml", safe), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := atk26Sigs(r)["action.pwn_request"]; ok || code != 0 {
		t.Fatalf("workflow_run job on the base checkout: want no pwn_request, exit 0; got exit %d %+v", code, r.Findings)
	}
	if atk26PRScanLints(t, "ci.yml", safe, "action.pwn_request") {
		t.Fatal("pr-scan: the base-checkout workflow_run twin must not carry action.pwn_request")
	}
}
