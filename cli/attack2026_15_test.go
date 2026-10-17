package cli

// Attack 2026-15: Checkmarx developer tooling (TeamPCP, 2026-03-23 to
// 2026-05-09). The CI half: checkmarx/kics-github-action had all 35 release
// tags repointed to attacker commits, and checkmarx/ast-github-action 2.3.32
// and 2.3.35 were malicious. The Docker half (checkmarx/kics v2.1.20-debian,
// v2.1.21-debian, v2.1.21) is in core/malware; OpenVSX / VS Code extensions
// and the Jenkins checkmarx-ast-scanner plugin are outside every surface.
//
// No feed Chainsaw ships lists these actions (static seed: tj-actions,
// reviewdog, rtCamp). What fires is feed-blind: action.unpinned_ref (medium)
// on every tag ref, and action.unknown_publisher (low) because checkmarx is
// not on the known-publisher list. --fail-on medium refuses the tag refs;
// the default high gate does not.

import "testing"

func TestAttack2026_15_CheckmarxActions(t *testing.T) {
	wf := func(kics, ast string) string {
		return `name: sast
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: ` + atk26PinnedCheckout + `
      - uses: checkmarx/kics-github-action@` + kics + `
        with:
          path: .
      - uses: checkmarx/ast-github-action@` + ast + `
        with:
          cx_tenant: ${{ secrets.CX_TENANT }}
`
	}
	bad := atk26WriteWF(t, "sast.yml", wf("v2.1.11", "2.3.32"))
	code, r, err := runScanActionsJSON(t, bad, "")
	if err != nil {
		t.Fatal(err)
	}
	unpinned, unknown := 0, 0
	for _, f := range r.Findings {
		switch f.Signal {
		case "action.malicious":
			t.Fatalf("a feed now lists %s/%s; update the attack-15 classification", f.Owner, f.Name)
		case "action.unpinned_ref":
			unpinned++
		case "action.unknown_publisher":
			unknown++
		}
	}
	if unpinned != 2 || unknown != 2 || code != 0 {
		t.Fatalf("want 2 unpinned + 2 unknown_publisher and exit 0 at default, got exit %d %+v", code, r.Findings)
	}
	if code, _, _ = runScanActionsJSON(t, bad, "medium"); code != 1 {
		t.Fatalf("--fail-on medium must refuse the Checkmarx tag refs, exit %d", code)
	}

	// Negative twin: both pinned to full commit SHAs pass --fail-on medium
	// (unknown_publisher stays, at low).
	good := atk26WriteWF(t, "sast.yml", wf("cfb6d7d0e8d22e9d43c1e5f1d3a4e7b6c9a0b1c2", "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"))
	code, r, err = runScanActionsJSON(t, good, "medium")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := atk26Sigs(r)["action.unpinned_ref"]; ok || code != 0 {
		t.Fatalf("SHA-pinned twin: want exit 0 at --fail-on medium, got exit %d %+v", code, r.Findings)
	}
}
