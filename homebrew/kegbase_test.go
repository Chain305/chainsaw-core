package homebrew

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func kegPrefix(t *testing.T) (string, string) {
	t.Helper()
	p := t.TempDir()
	keg := filepath.Join(p, "Cellar", "pyenv", "2.5.4")
	for rel, body := range map[string]string{
		"INSTALL_RECEIPT.json":    `{"time":1}`,
		"libexec/pyenv":           "#!/bin/bash\necho real\n",
		"share/doc/README":        "docs",
		"lib/x/__pycache__/a.pyc": "bytecode",
	} {
		os.MkdirAll(filepath.Dir(filepath.Join(keg, rel)), 0o755)
		os.WriteFile(filepath.Join(keg, rel), []byte(body), 0o755)
	}
	os.Symlink("../libexec/pyenv", filepath.Join(keg, "libexec", "link"))
	return p, keg
}

func paths(fs []Finding) string {
	var s []string
	for _, f := range fs {
		s = append(s, f.Path+": "+f.Reason)
	}
	return strings.Join(s, "\n")
}

func TestCheckKegs(t *testing.T) {
	p, keg := kegPrefix(t)
	first, err := CheckKegs(p, nil)
	if err != nil || len(first.Findings) != 0 || len(first.Fresh) != 1 || first.Kegs != 1 {
		t.Fatalf("first: %+v %v", first, err)
	}
	if len(first.Baseline) != 0 {
		t.Fatalf("a fresh keg was absorbed before the caller accepted it: %v", first.Baseline)
	}
	first.Accept("pyenv/2.5.4", true)
	if _, ok := first.Baseline["pyenv/2.5.4"].Files["lib/x/__pycache__/a.pyc"]; !ok {
		t.Error("bytecode not recorded")
	}
	again, _ := CheckKegs(p, first.Baseline)
	if len(again.Findings) != 0 || len(again.Fresh) != 0 || again.Hashed != 0 {
		t.Fatalf("unchanged: %+v", again)
	}

	// Touched, or bytecode appearing: not findings. Bytecode changed: is.
	now := time.Now().Add(time.Hour)
	os.Chtimes(filepath.Join(keg, "share/doc/README"), now, now)
	os.WriteFile(filepath.Join(keg, "lib/x/__pycache__/b.pyc"), []byte("new"), 0o644)
	if r, _ := CheckKegs(p, first.Baseline); len(r.Findings) != 0 {
		t.Fatalf("touch: %s", paths(r.Findings))
	}
	os.WriteFile(filepath.Join(keg, "lib/x/__pycache__/a.pyc"), []byte("forged"), 0o644)
	if r, _ := CheckKegs(p, first.Baseline); !strings.Contains(paths(r.Findings), "a.pyc: changed") {
		t.Fatalf("pyc: %s", paths(r.Findings))
	}
	os.WriteFile(filepath.Join(keg, "lib/x/__pycache__/a.pyc"), []byte("bytecode"), 0o755)

	// The Binance step: the formula's script replaced in place, same size.
	os.WriteFile(filepath.Join(keg, "libexec/pyenv"), []byte("#!/bin/bash\necho evil\n"), 0o755)
	os.WriteFile(filepath.Join(keg, "libexec/dropper"), []byte("x"), 0o755)
	os.Remove(filepath.Join(keg, "libexec/link"))
	os.Symlink("/tmp/evil", filepath.Join(keg, "libexec/link"))
	r, _ := CheckKegs(p, first.Baseline)
	got := paths(r.Findings)
	for _, want := range []string{
		"Cellar/pyenv/2.5.4/libexec/pyenv: changed since it was poured",
		"Cellar/pyenv/2.5.4/libexec/dropper: added since it was poured",
		"Cellar/pyenv/2.5.4/libexec/link: changed since it was poured",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	// Sticky: the stored record is the poured one, so the next run repeats it.
	if r2, _ := CheckKegs(p, r.Baseline); len(r2.Findings) != 3 {
		t.Errorf("not sticky: %s", paths(r2.Findings))
	}

	// A new receipt: re-poured, the changes listed for the caller, the old
	// record kept until the caller accepts.
	os.WriteFile(filepath.Join(keg, "INSTALL_RECEIPT.json"), []byte(`{"time":2}`), 0o644)
	r3, _ := CheckKegs(p, r.Baseline)
	if len(r3.Findings) != 0 || len(r3.Repoured) != 1 || len(r3.Changed["pyenv/2.5.4"]) != 3 || r3.Baseline["pyenv/2.5.4"].Receipt != r.Baseline["pyenv/2.5.4"].Receipt {
		t.Errorf("re-pour: %+v", r3)
	}

	// Being uninstalled (receipt already gone, files going): re-poured,
	// never a finding by itself.
	os.Remove(filepath.Join(keg, "INSTALL_RECEIPT.json"))
	os.Remove(filepath.Join(keg, "share/doc/README"))
	if r4, _ := CheckKegs(p, first.Baseline); len(r4.Findings) != 0 {
		t.Errorf("uninstall: %s", paths(r4.Findings))
	}
}

func TestHashRegularRefusesSymlink(t *testing.T) {
	d := t.TempDir()
	os.Symlink("/etc/hosts", filepath.Join(d, "l"))
	if _, _, err := HashRegular(filepath.Join(d, "l")); err == nil {
		t.Error("followed a symlink")
	}
}

// Code brew installs outside a keg: npm's own tree and Python's startup
// hooks in the prefix site-packages.
func TestCheckKegsOutOfKegTrees(t *testing.T) {
	p := t.TempDir()
	npm := filepath.Join(p, "lib/node_modules/npm")
	site := filepath.Join(p, "lib/python3.13/site-packages")
	for rel, body := range map[string]string{
		"lib/node_modules/npm/package.json":       `{"version":"11.0.0"}`,
		"lib/node_modules/npm/lib/cli.js":         "real",
		"lib/python3.13/site-packages/a.pth":      "import os",
		"lib/python3.13/site-packages/pkg/mod.py": "pip's",
	} {
		os.MkdirAll(filepath.Dir(filepath.Join(p, rel)), 0o755)
		os.WriteFile(filepath.Join(p, rel), []byte(body), 0o644)
	}
	os.MkdirAll(filepath.Join(p, "Cellar"), 0o755)
	first, _ := CheckKegs(p, nil)
	for _, k := range first.Fresh {
		first.Accept(k, true)
	}
	if _, ok := first.Baseline[":lib/python3.13/site-packages"].Files["pkg/mod.py"]; ok {
		t.Fatal("pip-installed package recorded")
	}
	os.WriteFile(filepath.Join(npm, "lib/cli.js"), []byte("evil"), 0o644)
	os.WriteFile(filepath.Join(site, "zz-evil.pth"), []byte("import evil"), 0o644)
	os.WriteFile(filepath.Join(site, "pkg/mod.py"), []byte("pip upgraded"), 0o644)
	r, _ := CheckKegs(p, first.Baseline)
	got := paths(r.Findings)
	if !strings.Contains(got, "lib/node_modules/npm/lib/cli.js: changed since root recorded it") ||
		!strings.Contains(got, "lib/python3.13/site-packages/zz-evil.pth: added since root recorded it") || len(r.Findings) != 2 {
		t.Fatalf("got\n%s", got)
	}
	// npm updating itself rewrites package.json: re-poured, not tamper.
	os.WriteFile(filepath.Join(npm, "package.json"), []byte(`{"version":"11.1.0"}`), 0o644)
	os.Remove(filepath.Join(site, "zz-evil.pth"))
	if r, _ := CheckKegs(p, first.Baseline); len(r.Findings) != 0 || len(r.Repoured) != 1 || r.Repoured[0] != ":lib/node_modules/npm" {
		t.Fatalf("npm self-update: %+v", r)
	}
}

// The comparison that vouches for a unit re-reads the disk after network
// calls: StillMatches is false when anything moved since CheckKegs hashed it.
func TestKegCheckStillMatches(t *testing.T) {
	p, keg := kegPrefix(t)
	r, _ := CheckKegs(p, nil)
	if !r.StillMatches(p, "pyenv/2.5.4") {
		t.Fatal("unchanged keg does not match")
	}
	os.WriteFile(filepath.Join(keg, "libexec/pyenv"), []byte("#!/bin/bash\necho swapped\n"), 0o755)
	if r.StillMatches(p, "pyenv/2.5.4") {
		t.Fatal("swapped file still matches")
	}
	if r.StillMatches(p, "nope/1.0") {
		t.Fatal("unknown key matches")
	}
}

// One stuffed keg cannot hold the root run: too many entries, or a budget
// that runs out inside the walk, is an error (escalated by the caller).
func TestRecordKegBounds(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 1200; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%04d", i)), nil, 0o644)
	}
	old := KegMaxFiles
	t.Cleanup(func() { KegMaxFiles = old })
	KegMaxFiles = 1100
	if _, _, err := recordKeg(dir, nil, nil, time.Now().Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "more than 1100 entries") {
		t.Fatalf("cap: %v", err)
	}
	KegMaxFiles = old
	if _, _, err := recordKeg(dir, nil, nil, time.Now().Add(-time.Second)); err == nil || !strings.Contains(err.Error(), "did not finish") {
		t.Fatalf("deadline: %v", err)
	}
}
