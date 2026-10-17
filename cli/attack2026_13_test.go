package cli

// Attack 2026-13: Trivy v0.69.4 + trivy-action / setup-trivy tag hijack
// (TeamPCP, 2026-03-19). GHSA-69fq-xp46-6x23 lists GitHub Actions
// aquasecurity/trivy-action < 0.35.0 and aquasecurity/setup-trivy < 0.2.6
// (tags force-pushed to credential-stealing commits; SHA pins unaffected),
// plus github.com/aquasecurity/trivy 0.69.4 and Docker Hub aquasec/trivy
// 0.69.4-0.69.6 (the Docker half is tested in core/malware and
// internal/server).
//
// What this file proves on the Actions half:
//   - Feed-blind: scan-actions reports action.unpinned_ref (medium) on the
//     tag refs, so --fail-on medium refuses them before any advisory exists.
//   - Feed-timed: with the GHSA in the local GitHub Actions OSV snapshot
//     (github-actions-osv/ beside the guard cache) scan-actions reports
//     action.malicious (high) and exits 1 at the default gate; the clean
//     0.35.0 / 0.2.6 releases do not match.
//   - Gap: without a snapshot the CLI has only the three-entry static seed,
//     which has no Trivy entry; pr-scan always uses only the static seed.

import (
	"os"
	"path/filepath"
	"testing"
)

const atk13GHSA = `{"id":"GHSA-69fq-xp46-6x23","summary":"Trivy ecosystem supply chain compromise",
"affected":[
 {"package":{"ecosystem":"GitHub Actions","name":"aquasecurity/trivy-action"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0.35.0"}]}]},
 {"package":{"ecosystem":"GitHub Actions","name":"aquasecurity/setup-trivy"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0.2.6"}]}]}
]}`

func atk13WF(trivyAction, setupTrivy string) string {
	return `name: scan
on: [push]
jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: aquasecurity/setup-trivy@` + setupTrivy + `
      - uses: aquasecurity/trivy-action@` + trivyAction + `
        with:
          scan-type: fs
`
}

func TestAttack2026_13_TrivyActionTagHijack(t *testing.T) {
	cache := t.TempDir()
	t.Setenv(guardDBEnv, filepath.Join(cache, "known_malicious.json"))
	bad := atk26WriteWF(t, "scan.yml", atk13WF("0.34.2", "v0.2.5"))

	// No snapshot: static seed only.
	code, r, err := runScanActionsJSON(t, bad, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := atk26Sigs(r)["action.malicious"]; ok {
		t.Fatalf("static seed now lists Trivy actions; update the attack-13 classification: %+v", r.Findings)
	}
	if atk26Sigs(r)["action.unpinned_ref"] != "medium" || code != 0 {
		t.Fatalf("no snapshot: want medium unpinned_ref only, exit 0; got exit %d %+v", code, r.Findings)
	}
	if code, _, _ = runScanActionsJSON(t, bad, "medium"); code != 1 {
		t.Fatalf("--fail-on medium must refuse the tag refs before any advisory, exit %d", code)
	}

	// pr-scan: static seed only, so the tag gets warn (unpinned), never block.
	added, _, err := diffWorkflow(".github/workflows/scan.yml", nil, []byte(atk13WF("0.34.2", "v0.2.5")))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range added {
		if hasPRSignal(e.Signals, "action.malicious") || e.Verdict == "block" {
			t.Fatalf("pr-scan blocked %s without a feed entry: update attack-13 gap note: %+v", e.Name, e)
		}
	}

	// With the GHSA in the local snapshot: malicious, high, default exit 1.
	dir := filepath.Join(cache, scanActionsOSVDirName)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "GHSA-69fq-xp46-6x23.json"), []byte(atk13GHSA), 0o644); err != nil {
		t.Fatal(err)
	}
	code, r, err = runScanActionsJSON(t, bad, "")
	if err != nil {
		t.Fatal(err)
	}
	malicious := map[string]bool{}
	for _, f := range r.Findings {
		if f.Signal == "action.malicious" && f.Severity == "high" {
			malicious[f.Owner+"/"+f.Name] = true
		}
	}
	if !malicious["aquasecurity/trivy-action"] || !malicious["aquasecurity/setup-trivy"] || code != 1 {
		t.Fatalf("with GHSA snapshot: want both actions malicious and exit 1, got exit %d %+v", code, r.Findings)
	}

	// Negative twin: the clean releases cut after the incident.
	code, r, err = runScanActionsJSON(t, atk26WriteWF(t, "scan.yml", atk13WF("0.35.0", "v0.2.6")), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := atk26Sigs(r)["action.malicious"]; ok || code != 0 {
		t.Fatalf("clean 0.35.0 / v0.2.6 must not match the GHSA, got exit %d %+v", code, r.Findings)
	}
}
