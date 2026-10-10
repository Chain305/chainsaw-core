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

		// Python. Positives: bentoml 1.4.34 (verbatim) and the other shapes.
		{"bentoml model.py:592", "src/bentoml/_internal/models/model.py", "        module = importlib.import_module(self.module)\n", true},
		{"__import__ with fromlist", "pkg/utils.py", "module = __import__(module_name, fromlist=[class_name])\n", true},
		{"bare import_module", "pkg/plugins.py", "mod = import_module(name)\n", true},
		{"literal + expr", "pkg/loader.py", "m = importlib.import_module('pkg.backends.' + name)\n", true},
		{"literal % expr", "pkg/loader.py", "m = __import__('pkg.%s' % name)\n", true},
		{"literal .format", "pkg/loader.py", "m = import_module('pkg.{}'.format(name))\n", true},
		{"f-string", "pkg/loader.py", "m = importlib.import_module(f\"pkg.{name}\")\n", true},
		{"indexed name", "pkg/loader.py", "m = __import__(names[0])\n", true},

		{"literal import_module", "pkg/x.py", "m = importlib.import_module('json')\n", false},
		{"literal __import__", "setup.py", "VERSION = __import__('pkg').__version__\n", false},
		{"literal with fromlist", "pkg/x.py", "m = __import__('os.path', fromlist=['join'])\n", false},
		{"f-string with no substitution", "pkg/x.py", "m = import_module(f'pkg.backends')\n", false},
		{"plain import", "pkg/x.py", "import importlib\nfrom importlib import import_module\n", false},
		{"not Python", "index.js", "const m = importlib.import_module(name)\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScanDynamicRequire(map[string][]byte{tc.file: []byte(tc.body)}); got.Fired != tc.want {
				t.Errorf("fired=%v, want %v (%+v)", got.Fired, tc.want, got.Matches)
			}
		})
	}
}
