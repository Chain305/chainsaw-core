package cli

// Attack 2026-54: BindsNET forged merge commit (2026-08-29). A collaborator's
// credentials force-pushed a forged copy of merge bbafb9ae over 20 branches;
// its tree added .vscode/tasks.json (runOn: folderOpen, hidden) running
// `node ./public/fonts/fa-solid-400.woff2` (32 KB obfuscated JS) and a
// .vscode/settings.json enabling task.allowAutomaticTasks. A Dependabot merge
// carried it into master. No package release was affected (GHSA-6f2q-w3r8-xxhj).
//
// Covered since v0.22.106 (F16): scan-repo flags a .vscode/tasks.json task
// with runOn: folderOpen (vscode-folder-open-task) and a .vscode/settings.json
// turning on task.allowAutomaticTasks (vscode-automatic-tasks-on), and pr-scan
// gives a PR that introduces either a warn row (a block row since v0.22.109). A force-push is not a PR, so
// scan-repo as a required check is the gate that sees the forged commit.
// Negative twin: an ordinary build task with no runOn.

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
	for rel, rule := range map[string]string{".vscode/tasks.json": "vscode-folder-open-task", ".vscode/settings.json": "vscode-automatic-tasks-on"} {
		body := map[string]string{".vscode/tasks.json": tasks, ".vscode/settings.json": settings}[rel]
		base := rel[len(".vscode/"):]
		got := inspectFile(rel, base, body)
		if !isScanRepoCandidate(base) || len(got) != 1 || got[0].Rule != rule {
			t.Fatalf("scan-repo %s: want one %s finding, got %+v", rel, rule, got)
		}
		e, ok := diffVSCodeConfig(rel, nil, []byte(body))
		if !ok || e.Verdict != "block" || !hasPRSignal(e.Signals, rule) {
			t.Fatalf("pr-scan %s: want a block row with %s, got %+v", rel, rule, e)
		}
		// Already in base: not this PR's change, no row.
		if _, ok := diffVSCodeConfig(rel, []byte(body), []byte(body)); ok {
			t.Fatalf("pr-scan %s: a finding already in base must not be re-reported", rel)
		}
	}

	// An escaped key is the same key to VS Code's JSONC reader.
	if got := inspectFile(".vscode/tasks.json", "tasks.json", `{"tasks":[{"command":"x","runOptions":{"run\u004fn":"folder\u004Fpen"}}]}`); len(got) != 1 {
		t.Fatalf("escaped runOn/folderOpen not flagged: %+v", got)
	}

	// Negative twin: a build task that runs only when asked.
	const build = `{"version":"2.0.0","tasks":[{"label":"build","type":"shell","command":"make","group":"build"}]}`
	if got := inspectFile(".vscode/tasks.json", "tasks.json", build); len(got) != 0 {
		t.Fatalf("ordinary build task flagged: %+v", got)
	}
	// And a tasks.json outside .vscode/ is not editor config.
	if got := inspectFile("ci/tasks.json", "tasks.json", tasks); len(got) != 0 {
		t.Fatalf("ci/tasks.json flagged: %+v", got)
	}

	// Control: the inspector is live — a git requirement is a proxy bypass.
	if got := inspectFile("requirements.txt", "requirements.txt", "bindsnet @ git+https://github.com/BindsNET/bindsnet\n"); len(got) == 0 {
		t.Fatal("control: scan-repo must flag a git requirement")
	}
}
