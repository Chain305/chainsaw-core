package cli

// Attack 2026-05: xygeni/xygeni-action v5 tag repointed (2026-03-03). Stolen
// maintainer credentials moved the mutable v5 tag to commit
// 4bf1d4e19ad81a3e8d4063755ae0f482dd3baf12, whose action.yml carried a C2
// reverse shell. Workflows pinned to a commit SHA were unaffected.
//
// What Chainsaw does: scan-actions reports action.unpinned_ref (medium) on
// `@v5`. The default gate is --fail-on high, so this exits 0 by default;
// `--fail-on medium` exits 1 and so enforces SHA pinning, which removes the
// tag-repoint class entirely. Since v0.22.111 pr-scan blocks a PR that adds a
// third-party action by tag, so the repoint never reaches a workflow merged
// through a gated PR. Nothing knows the commit is malicious: the
// static Actions feed has no xygeni entry and no GHSA was published.

import (
	"fmt"
	"testing"
)

func TestAttack2026_05_XygeniTagRepoint(t *testing.T) {
	const wf = `name: security
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: xygeni/xygeni-action@%s
        with:
          token: ${{ secrets.XYGENI_TOKEN }}
`
	tag := atk26WriteWF(t, "xygeni.yml", fmt.Sprintf(wf, "v5"))

	code, r, err := runScanActionsJSON(t, tag, "")
	if err != nil {
		t.Fatal(err)
	}
	sigs := atk26Sigs(r)
	if sigs["action.unpinned_ref"] != "medium" {
		t.Fatalf("@v5 must be reported unpinned (medium), got %+v", r.Findings)
	}
	if _, ok := sigs["action.malicious"]; ok {
		t.Fatalf("no feed lists xygeni-action; a malicious hit means the seed changed: %+v", r.Findings)
	}
	if code != 0 {
		t.Fatalf("default --fail-on high: unpinned is medium, want exit 0, got %d", code)
	}
	if code, _, _ = runScanActionsJSON(t, tag, "medium"); code != 1 {
		t.Fatalf("--fail-on medium must refuse the mutable tag, exit %d", code)
	}

	// Negative twin: the same action pinned to the clean commit SHA passes
	// the same gate (unknown_publisher is low and does not trip medium).
	pinned := atk26WriteWF(t, "xygeni.yml", fmt.Sprintf(wf, "c7e4d1c3cbbf3f22e0b3b8a2a37b4c1a6f3d9e01"))
	code, r, err = runScanActionsJSON(t, pinned, "medium")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := atk26Sigs(r)["action.unpinned_ref"]; ok || code != 0 {
		t.Fatalf("SHA-pinned twin: want no unpinned_ref and exit 0 at --fail-on medium, got exit %d %+v", code, r.Findings)
	}

	// pr-scan: a PR adding the third-party @v5 ref gets a block row with
	// unpinned_ref (a warn row before v0.22.111): the tag is what attack 5
	// re-pointed.
	added, _, err := diffWorkflow(".github/workflows/xygeni.yml", nil, []byte(fmt.Sprintf(wf, "v5")))
	if err != nil || len(added) != 1 || !hasPRSignal(added[0].Signals, "action.unpinned_ref") || added[0].Verdict != "block" {
		t.Fatalf("pr-scan row for @v5: want block with action.unpinned_ref, got %+v %v", added, err)
	}
	// Since v0.22.116 the Chainsaw Guard Action's own tag blocks too...
	guard := "name: guard\non: pull_request\njobs:\n  g:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: Chain305/chainsaw-core/enforcement/github-actions@action-v1\n"
	gAdded, _, gErr := diffWorkflow(".github/workflows/guard.yml", nil, []byte(guard))
	if gErr != nil || len(gAdded) != 1 || gAdded[0].Verdict != "block" || !hasPRSignal(gAdded[0].Signals, "action.unpinned_ref") {
		t.Fatalf("pr-scan row for the Chainsaw Guard Action @action-v1: want block on unpinned_ref, got %+v %v", gAdded, gErr)
	}
	// ...and the SHA-pinned form the docs publish does not.
	guardPinned := "name: guard\non: pull_request\njobs:\n  g:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: Chain305/chainsaw-core/enforcement/github-actions@0b078db7fb65ee61dc79852e0d7bd6774e83390e # v0.22.119\n"
	if gp, _, err := diffWorkflow(".github/workflows/guard.yml", nil, []byte(guardPinned)); err != nil || len(gp) != 1 || gp[0].Verdict == "block" {
		t.Fatalf("pr-scan row for the SHA-pinned Guard Action: want not blocked, got %+v %v", gp, err)
	}
	// Since v0.22.112 chain305 is a known publisher: no unknown_publisher row.
	if hasPRSignal(gAdded[0].Signals, "action.unknown_publisher") {
		t.Fatalf("pr-scan flags the Chainsaw Guard Action as an unknown publisher: %+v", gAdded[0])
	}
	first := "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
	added, _, err = diffWorkflow(".github/workflows/ci.yml", nil, []byte(first))
	// Since v0.22.114 GitHub's own actions block too when tag-pinned...
	if err != nil || len(added) != 1 || !hasPRSignal(added[0].Signals, "action.unpinned_ref") || added[0].Verdict != "block" {
		t.Fatalf("pr-scan row for actions/checkout@v4: want block with action.unpinned_ref, got %+v %v", added, err)
	}
	// ...and not when pinned by commit SHA.
	pinnedCO := "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4\n"
	added, _, err = diffWorkflow(".github/workflows/ci.yml", nil, []byte(pinnedCO))
	if err != nil || len(added) != 1 || added[0].Verdict == "block" {
		t.Fatalf("pr-scan row for SHA-pinned actions/checkout: want not blocked, got %+v %v", added, err)
	}
	// Since v0.22.115 a SHA-pinned action from a publisher outside the
	// known-publisher list blocks on action.unknown_publisher alone.
	unk := "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: codecov/codecov-action@0123456789abcdef0123456789abcdef01234567\n"
	added, _, err = diffWorkflow(".github/workflows/cov.yml", nil, []byte(unk))
	if err != nil || len(added) != 1 || added[0].Verdict != "block" || !hasPRSignal(added[0].Signals, "action.unknown_publisher") ||
		hasPRSignal(added[0].Signals, "action.unpinned_ref") {
		t.Fatalf("pr-scan row for SHA-pinned codecov: want block on unknown_publisher only, got %+v %v", added, err)
	}
}
