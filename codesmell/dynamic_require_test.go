package codesmell

import "testing"

// Positives are verbatim from rev5 npm rows (socket-comparison-2026-10-03),
// through ScanDynamicRequire so the whole runRules path runs.
func TestScanDynamicRequire(t *testing.T) {
	for _, tc := range []struct {
		name, file, body string
		want             bool
	}{
		{"b2.mpm 0.1.2 (socket fires)", "mpm.js", `let getConfig = require(path.join(process.cwd(),"mpm.config.js"));` + "\n", true},
		{"xg-csshint 0.2.0 (socket fires)", "src/parse.js", "var pluginFn=require(pluginPath);\n", true},
		{"tf-checkout-react template", "src/utils/getImage.ts", "image = require(`./images/${name}`)\n", true},
		{"esbuild dynamic __require", "dist/index.mjs", "var plugin = __require(pluginName);\n", true},
		{"literal + expression", "lib/locale.js", "module.exports = require('./locale/' + lang);\n", true},

		{"string literal", "index.js", "const fs = require('fs');\n", false},
		{"template with no substitution", "index.js", "const x = require(`./x`);\n", false},
		{"webpack runtime", "dist/main.js", "var m = __webpack_require__(42);\n", false},
		{"a helper named _require", "lib/loader.js", "var m = _require(id);\n", false},
		{"createRequire", "index.mjs", "const require2 = createRequire(import.meta.url);\n", false},
		{"require.resolve", "index.js", "const p = require.resolve('pkg');\n", false},
		{"not JavaScript", "setup.py", "require(name)\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScanDynamicRequire(map[string][]byte{tc.file: []byte(tc.body)}); got.Fired != tc.want {
				t.Errorf("fired=%v, want %v (%+v)", got.Fired, tc.want, got.Matches)
			}
		})
	}
}
