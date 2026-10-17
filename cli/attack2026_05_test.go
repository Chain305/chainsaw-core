package cli

// Attack 2026-05: xygeni/xygeni-action v5 tag repointed (2026-03-03). Stolen
// maintainer credentials moved the mutable v5 tag to commit
// 4bf1d4e19ad81a3e8d4063755ae0f482dd3baf12, whose action.yml carried a C2
// reverse shell. Workflows pinned to a commit SHA were unaffected.
//
// What Chainsaw does: scan-actions reports action.unpinned_ref (medium) on
// `@v5`. The default gate is --fail-on high, so this exits 0 by default;
// `--fail-on medium` exits 1 and so enforces SHA pinning, which removes the
// tag-repoint class entirely. Nothing knows the commit is malicious: the
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

	// pr-scan: a PR adding the @v5 ref gets a warn row with unpinned_ref.
	added, _, err := diffWorkflow(".github/workflows/xygeni.yml", nil, []byte(fmt.Sprintf(wf, "v5")))
	if err != nil || len(added) != 1 || !hasPRSignal(added[0].Signals, "action.unpinned_ref") || added[0].Verdict != "warn" {
		t.Fatalf("pr-scan row for @v5: want warn with action.unpinned_ref, got %+v %v", added, err)
	}
}
