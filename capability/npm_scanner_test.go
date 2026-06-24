package capability_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/chain305/chainsaw-core/capability"
)

// writeTestFile writes content to name inside dir, creating parent dirs.
func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestScanNPM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		files      map[string]string
		wantCaps   []capability.Capability
		wantAbsent []capability.Capability
	}{
		{
			name: "clean package — no capabilities",
			files: map[string]string{
				"index.js": "const x = 1 + 1;\nconsole.log(x);\n",
			},
			wantAbsent: []capability.Capability{
				capability.CapNetwork, capability.CapShell,
				capability.CapFilesystemWrite, capability.CapFilesystemRead,
				capability.CapEnvAccess, capability.CapNativeCode,
				capability.CapDynamicEval,
			},
		},
		{
			name: "cap.network — require net",
			files: map[string]string{
				"index.js": "const net = require('net');\nnet.connect(80, 'example.com');\n",
			},
			wantCaps:   []capability.Capability{capability.CapNetwork},
			wantAbsent: []capability.Capability{capability.CapShell},
		},
		{
			name: "cap.network — require http",
			files: map[string]string{
				"lib/http.js": "const http = require('http');\n",
			},
			wantCaps: []capability.Capability{capability.CapNetwork},
		},
		{
			name: "cap.network — fetch()",
			files: map[string]string{
				"lib/fetch.js": "async function go() { return fetch('https://example.com'); }\n",
			},
			wantCaps: []capability.Capability{capability.CapNetwork},
		},
		{
			name: "cap.shell — require child_process",
			files: map[string]string{
				"index.js": "const {execSync} = require('child_process');\nexecSync('ls');\n",
			},
			wantCaps: []capability.Capability{capability.CapShell},
		},
		{
			name: "cap.shell — spawn",
			files: map[string]string{
				"run.js": "const {spawn} = require('child_process');\nspawn('sh', ['-c', cmd]);\n",
			},
			wantCaps: []capability.Capability{capability.CapShell},
		},
		{
			name: "cap.filesystem_write",
			files: map[string]string{
				"writer.js": "const fs = require('fs');\nfs.writeFileSync('/tmp/out', data);\n",
			},
			wantCaps: []capability.Capability{capability.CapFilesystemWrite},
		},
		{
			name: "cap.filesystem_read",
			files: map[string]string{
				"reader.js": "const fs = require('fs');\nconst data = fs.readFileSync('./config');\n",
			},
			wantCaps: []capability.Capability{capability.CapFilesystemRead},
		},
		{
			name: "cap.env_access",
			files: map[string]string{
				"config.js": "const token = process.env.API_TOKEN;\n",
			},
			wantCaps: []capability.Capability{capability.CapEnvAccess},
		},
		{
			name: "cap.dynamic_eval — eval()",
			files: map[string]string{
				"evil.js": "eval(atob(payload));\n",
			},
			wantCaps: []capability.Capability{capability.CapDynamicEval},
		},
		{
			name: "cap.dynamic_eval — Function()",
			files: map[string]string{
				"dyn.js": "const fn = new Function('return 1');\n",
			},
			wantCaps: []capability.Capability{capability.CapDynamicEval},
		},
		{
			name: "cap.dynamic_eval — vm.runInThisContext",
			files: map[string]string{
				"vm.js": "const vm = require('vm');\nvm.runInThisContext(code);\n",
			},
			wantCaps: []capability.Capability{capability.CapDynamicEval},
		},
		{
			name: "multiple caps in one file",
			files: map[string]string{
				"multi.js": "\nconst http = require('http');\nconst {execSync} = require('child_process');\nconst token = process.env.SECRET;\nfs.writeFileSync('out.txt', result);\n",
			},
			wantCaps: []capability.Capability{
				capability.CapNetwork, capability.CapShell,
				capability.CapEnvAccess, capability.CapFilesystemWrite,
			},
		},
		{
			name: "test files are ignored by suffix",
			files: map[string]string{
				// These should be ignored
				"src/foo.test.js":  "const {execSync} = require('child_process');\n",
				"src/bar.spec.js":  "const net = require('net');\n",
				"src/baz.test.mjs": "eval('bad');\n",
				// This should be scanned
				"lib/index.js": "const x = 1;\n",
			},
			wantAbsent: []capability.Capability{
				capability.CapShell, capability.CapDynamicEval, capability.CapNetwork,
			},
		},
		{
			name: "test directory is skipped entirely",
			files: map[string]string{
				"test/helpers.js": "const cp = require('child_process');\n",
				"tests/utils.js":  "process.env.SECRET;\n",
				"index.js":        "module.exports = {};\n",
			},
			wantAbsent: []capability.Capability{
				capability.CapShell, capability.CapEnvAccess,
			},
		},
		{
			name: "node_modules skipped",
			files: map[string]string{
				"node_modules/evil/index.js": "require('child_process');\n",
				"index.js":                   "module.exports = {};\n",
			},
			wantAbsent: []capability.Capability{capability.CapShell},
		},
		{
			name: "cap.native_code — binding.gyp present",
			files: map[string]string{
				"binding.gyp": `{"targets": [{"target_name": "addon", "sources": ["addon.cc"]}]}`,
				"index.js":    "module.exports = require('./build/Release/addon.node');\n",
			},
			wantCaps: []capability.Capability{capability.CapNativeCode},
		},
		{
			name: "cap.native_code — .node file",
			files: map[string]string{
				"build/Release/addon.node": "\x7fELF",
				"index.js":                 "module.exports = {};\n",
			},
			wantCaps: []capability.Capability{capability.CapNativeCode},
		},
		{
			name: "non-JS files not scanned",
			files: map[string]string{
				"README.md":    "require('child_process') — example in docs",
				"package.json": `{"name": "test", "version": "1.0.0"}`,
				"index.js":     "module.exports = {};\n",
			},
			wantAbsent: []capability.Capability{capability.CapShell},
		},
		{
			name: "typescript file scanned",
			files: map[string]string{
				"src/client.ts": "const token = process.env.TOKEN;\n",
			},
			wantCaps: []capability.Capability{capability.CapEnvAccess},
		},
		{
			name: "cap.minified_or_bundled absent for small file",
			files: map[string]string{
				"dist/bundle.js": "const x = 1;\n",
			},
			wantAbsent: []capability.Capability{capability.CapMinifiedOrBundled},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for name, content := range tc.files {
				writeTestFile(t, dir, name, content)
			}
			caps, err := capability.ScanNPM(dir)
			if err != nil {
				t.Fatalf("ScanNPM error: %v", err)
			}
			for _, want := range tc.wantCaps {
				if _, ok := caps[want]; !ok {
					t.Errorf("expected capability %q to be present; got %v", want, caps)
				}
			}
			for _, absent := range tc.wantAbsent {
				if _, ok := caps[absent]; ok {
					t.Errorf("capability %q should be absent; got evidence: %v", absent, caps[absent])
				}
			}
		})
	}
}

// TestScanNPMLargeFileSkipped verifies that files > MaxFileScanBytes get
// the cap.minified_or_bundled marker instead of being scanned for patterns.
func TestScanNPMLargeFileSkipped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	large := make([]byte, capability.MaxFileScanBytes+1)
	for i := range large {
		large[i] = 'a'
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.js"), large, 0o644); err != nil {
		t.Fatal(err)
	}

	caps, err := capability.ScanNPM(dir)
	if err != nil {
		t.Fatalf("ScanNPM error: %v", err)
	}
	if _, ok := caps[capability.CapMinifiedOrBundled]; !ok {
		t.Errorf("expected cap.minified_or_bundled for oversized file; caps=%v", caps)
	}
}

// TestScanNPMEvidenceCapped verifies evidence is capped at MaxEvidencePerCap.
func TestScanNPMEvidenceCapped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	var content string
	for i := 0; i < 10; i++ {
		content += "const _ = process.env.VAR;\n"
	}
	writeTestFile(t, dir, "index.js", content)

	caps, err := capability.ScanNPM(dir)
	if err != nil {
		t.Fatalf("ScanNPM error: %v", err)
	}
	ev := caps[capability.CapEnvAccess]
	if len(ev) == 0 {
		t.Fatal("expected cap.env_access evidence")
	}
	if len(ev) > capability.MaxEvidencePerCap {
		t.Errorf("evidence count %d exceeds MaxEvidencePerCap %d", len(ev), capability.MaxEvidencePerCap)
	}
}

// TestScanNPMNonExistentDir verifies Scan returns an error for a missing dir.
func TestScanNPMNonExistentDir(t *testing.T) {
	t.Parallel()
	_, err := capability.ScanNPM("/this/path/does/not/exist/12345abc")
	if err == nil {
		t.Error("expected error for non-existent directory, got nil")
	}
}

// TestScanNPMEmptyDir verifies Scan returns nil capabilities for an empty dir.
func TestScanNPMEmptyDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	caps, err := capability.ScanNPM(dir)
	if err != nil {
		t.Fatalf("ScanNPM error: %v", err)
	}
	if len(caps) != 0 {
		t.Errorf("expected no caps for empty dir, got %v", caps)
	}
}

// TestAnalyzeNPMEndToEnd verifies the top-level Analyze dispatcher for npm.
func TestAnalyzeNPMEndToEnd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTestFile(t, dir, "index.js", "const {exec} = require('child_process');\nexec('ls');\n")

	report, err := capability.Analyze(dir, "npm")
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	if report == nil {
		t.Fatal("Analyze returned nil report")
	}
	if report.Unsupported {
		t.Error("npm should not be unsupported")
	}
	if !report.Has(capability.CapShell) {
		t.Errorf("expected cap.shell in report; got %v", report.Capabilities)
	}
}

// TestAnalyzeUnsupportedEcosystem verifies that unknown ecosystems return
// an Unsupported report without error.
func TestAnalyzeUnsupportedEcosystem(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	report, err := capability.Analyze(dir, "pip")
	if err != nil {
		t.Fatalf("Analyze returned unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("Analyze returned nil report")
	}
	if !report.Unsupported {
		t.Error("pip should be Unsupported in v1")
	}
}
