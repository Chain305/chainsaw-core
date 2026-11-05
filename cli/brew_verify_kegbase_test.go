package cli

import (
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/homebrew"
)

// kegBaseFixture: a root-run setup over a temp prefix treated as the
// Apple-silicon one, with a stub bottle server whose rebuild-0 bottle of
// each name/version is bottles[name/version] (path -> content).
func kegBaseFixture(t *testing.T) (prefix string, bottles map[string]map[string]string, run func() brewVerifyResult) {
	t.Helper()
	prefix = t.TempDir()
	bottles = map[string]map[string]string{}
	saved := []func(){}
	save := func(restore func()) { saved = append(saved, restore) }
	oldPrefix, oldSup, oldMajor, oldFetch := brewKegComparePrefix, brewKegsSupported, brewMacOSMajor, brewVerifyFetchVendor
	oldEuid, oldDir, oldSecure := brewVerifyGeteuid, brewLinksBaselineDir, brewVerifyFileSecure
	save(func() {
		brewKegComparePrefix, brewKegsSupported, brewMacOSMajor, brewVerifyFetchVendor = oldPrefix, oldSup, oldMajor, oldFetch
		brewVerifyGeteuid, brewLinksBaselineDir, brewVerifyFileSecure = oldEuid, oldDir, oldSecure
	})
	t.Cleanup(func() {
		for _, f := range saved {
			f()
		}
	})
	brewKegComparePrefix, brewKegsSupported = prefix, true
	brewMacOSMajor = func() (int, error) { return 15, nil }
	brewVerifyGeteuid = func() int { return 0 }
	brewLinksBaselineDir = filepath.Join(t.TempDir(), "db")
	brewVerifyFileSecure = func(string) error { return nil }
	brewVerifyFetchVendor = func(query string, out any) error {
		if kegFetchFails {
			return errors.New("server unreachable")
		}
		q, _ := url.ParseQuery(query)
		name := q.Get("name")
		if q.Get("kind") == "npm-self" {
			name = "npm-self"
		}
		files, ok := bottles[name+"/"+q.Get("version")]
		m := map[string]any{"missing": "index", "unavailable": "no index", "core_formula": !strings.HasPrefix(name, "tapped")}
		if ok && (q.Get("rebuild") == "0" || name == "npm-self") {
			var fs []map[string]any
			for p, c := range files {
				if t, isLink := strings.CutPrefix(c, "->"); isLink {
					fs = append(fs, map[string]any{"path": p, "link": t})
				} else {
					// writeKeg writes every file 0755, as the bottle would ship them.
					fs = append(fs, map[string]any{"path": p, "sha256": shaOf(c), "exec": true})
				}
			}
			m = map[string]any{"tag": q.Get("tag"), "rebuild": "0", "files": fs, "post_install_defined": strings.HasPrefix(name, "post"),
				"current": !strings.HasPrefix(q.Get("version"), "0.")}
		}
		b, _ := json.Marshal(m)
		return json.Unmarshal(b, out)
	}
	run = func() brewVerifyResult {
		res := brewVerifyResult{Tamper: []string{}, NotAssessed: []string{}, Errors: []string{}, Drift: []string{}, linkPrior: kegLinkPrior}
		verifyKegBaseline(&res, prefix, "", false)
		res.Verdict = brewVerdictOf(res)
		return res
	}
	return prefix, bottles, run
}

// kegLinkPrior stands in for the link baseline verifyLinks would read;
// kegFetchFails makes every server call fail.
var (
	kegLinkPrior  map[string]string
	kegFetchFails bool
)

func writeKeg(t *testing.T, prefix, key string, files map[string]string) string {
	t.Helper()
	dir := filepath.Join(prefix, "Cellar", filepath.FromSlash(key))
	if strings.HasPrefix(key, "../") {
		dir = filepath.Join(prefix, filepath.FromSlash(strings.TrimPrefix(key, "../")))
	}
	for p, c := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		os.Remove(filepath.Join(dir, p))
		var err error
		if t2, isLink := strings.CutPrefix(c, "->"); isLink {
			err = os.Symlink(t2, filepath.Join(dir, p))
		} else {
			err = os.WriteFile(filepath.Join(dir, p), []byte(c), 0o755)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const repoured = `{"poured_from_bottle":true,"source":{"tap":"homebrew/core"},"time":2}`

func TestKegBaselineReceiptRewriteDoesNotLaunder(t *testing.T) {
	prefix, bottles, run := kegBaseFixture(t)
	poured := map[string]string{"libexec/pyenv": "real\n", "lib/x/__pycache__/m.pyc": "bytecode"}
	bottles["pyenv/2.5.4"] = map[string]string{"libexec/pyenv": "real\n"}
	dir := writeKeg(t, prefix, "pyenv/2.5.4", poured)
	writeKeg(t, prefix, "pyenv/2.5.4", map[string]string{"INSTALL_RECEIPT.json": pouredCore})
	if res := run(); res.Verdict != brewVerdictClean {
		t.Fatalf("first run: %s %v %v", res.Verdict, res.Tamper, res.NotAssessed)
	}

	// Edit, then rewrite the receipt so the keg reads as re-poured.
	os.WriteFile(filepath.Join(dir, "libexec/pyenv"), []byte("evil\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "INSTALL_RECEIPT.json"), []byte(repoured), 0o644)
	for i := 0; i < 2; i++ { // sticky: the second run repeats it
		res := run()
		if res.Verdict != brewVerdictTamper || !strings.Contains(strings.Join(res.Tamper, "\n"), "Cellar/pyenv/2.5.4/libexec/pyenv: changed when the keg was re-poured") {
			t.Fatalf("run %d: %s %v", i, res.Verdict, res.Tamper)
		}
	}

	// A planted .pyc with the receipt untouched is caught too.
	os.WriteFile(filepath.Join(dir, "libexec/pyenv"), []byte("real\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "INSTALL_RECEIPT.json"), []byte(pouredCore), 0o644)
	if res := run(); res.Verdict != brewVerdictClean {
		t.Fatalf("restored: %s %v", res.Verdict, res.Tamper)
	}
	os.WriteFile(filepath.Join(dir, "lib/x/__pycache__/m.pyc"), []byte("forged"), 0o644)
	os.WriteFile(filepath.Join(dir, "lib/x/__pycache__/new.pyc"), []byte("fresh"), 0o644)
	res := run()
	if got := strings.Join(res.Tamper, "\n"); !strings.Contains(got, "m.pyc: changed since it was poured") || strings.Contains(got, "new.pyc") {
		t.Fatalf("pyc: %v", res.Tamper)
	}
}

func TestKegBaselineLegitRepour(t *testing.T) {
	prefix, bottles, run := kegBaseFixture(t)
	bottles["jq/1.8.2"] = map[string]string{"bin/jq": "v1"}
	dir := writeKeg(t, prefix, "jq/1.8.2", map[string]string{"bin/jq": "v1", "INSTALL_RECEIPT.json": pouredCore})
	run()
	// `brew reinstall jq` of the same bottle, then of a rebuilt one.
	os.WriteFile(filepath.Join(dir, "INSTALL_RECEIPT.json"), []byte(repoured), 0o644)
	if res := run(); res.Verdict != brewVerdictClean {
		t.Fatalf("same bottle: %s %v", res.Verdict, res.Tamper)
	}
	bottles["jq/1.8.2"] = map[string]string{"bin/jq": "v2"}
	os.WriteFile(filepath.Join(dir, "bin/jq"), []byte("v2"), 0o755)
	os.WriteFile(filepath.Join(dir, "INSTALL_RECEIPT.json"), []byte(`{"poured_from_bottle":true,"source":{"tap":"homebrew/core"},"time":3}`), 0o644)
	if res := run(); res.Verdict != brewVerdictClean {
		t.Fatalf("rebuilt bottle: %s %v %v", res.Verdict, res.Tamper, res.NotAssessed)
	}
	if res := run(); res.Verdict != brewVerdictClean {
		t.Fatalf("after: %s", res.Verdict)
	}
}

func TestKegBaselineNewKegs(t *testing.T) {
	prefix, bottles, run := kegBaseFixture(t)
	writeKeg(t, prefix, "jq/1.8.2", map[string]string{"bin/jq": "x", "INSTALL_RECEIPT.json": pouredCore})
	bottles["jq/1.8.2"] = map[string]string{"bin/jq": "x"}
	run()

	// A version core never bottled, forged next to the real one (and
	// claiming a tap): not assessed on every run, never absorbed.
	writeKeg(t, prefix, "jq/9.9", map[string]string{"bin/jq": "evil", "INSTALL_RECEIPT.json": `{"source":{"tap":"evil/tap"}}`})
	for i := 0; i < 2; i++ {
		res := run()
		if res.Verdict != brewVerdictIncomplete || !strings.Contains(strings.Join(res.NotAssessed, "\n"), "keg jq/9.9: new since the last root run and does not match") {
			t.Fatalf("run %d: %s %v", i, res.Verdict, res.NotAssessed)
		}
	}
	os.RemoveAll(filepath.Join(prefix, "Cellar/jq/9.9"))

	// A new keg matching its bottle is absorbed silently.
	bottles["gh/2.0"] = map[string]string{"bin/gh": "gh"}
	writeKeg(t, prefix, "gh/2.0", map[string]string{"bin/gh": "gh", "INSTALL_RECEIPT.json": pouredCore})
	if res := run(); res.Verdict != brewVerdictClean {
		t.Fatalf("matching new keg: %s %v", res.Verdict, res.NotAssessed)
	}

	// A keg directory swapped for a link to an edited copy.
	copyDir := t.TempDir()
	os.Rename(filepath.Join(prefix, "Cellar/gh/2.0"), filepath.Join(copyDir, "2.0"))
	os.Symlink(filepath.Join(copyDir, "2.0"), filepath.Join(prefix, "Cellar/gh/2.0"))
	if res := run(); res.Verdict != brewVerdictTamper || !strings.Contains(strings.Join(res.Tamper, "\n"), "Cellar/gh/2.0: is a symlink") {
		t.Fatalf("symlinked keg: %s %v", res.Verdict, res.Tamper)
	}
}

func TestKegBaselineOversizeFile(t *testing.T) {
	prefix, bottles, run := kegBaseFixture(t)
	old := homebrew.KegMaxFileBytes
	t.Cleanup(func() { homebrew.KegMaxFileBytes = old })
	homebrew.KegMaxFileBytes = 4
	bottles["jq/1.8.2"] = map[string]string{"bin/jq": "x"}
	writeKeg(t, prefix, "jq/1.8.2", map[string]string{"bin/jq": "x", "share/big": "123456789", "INSTALL_RECEIPT.json": pouredCore})
	if res := run(); !strings.Contains(strings.Join(res.Tamper, "\n"), "share/big: larger than") {
		t.Fatalf("oversize: %v", res.Tamper)
	}
}

// Second red-team round: a touched receipt must not launder a retargeted
// link (N1), an added file (N2) or a forged .pyc (N3) even when the rest of
// the keg matches its bottle; a .pyc removed and re-planted is caught (N4).
func TestKegBaselineRepourIsWholeKeg(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(dir string)
		want string
	}{
		{"retargeted link", func(dir string) {
			os.Remove(filepath.Join(dir, "bin/pyenv"))
			os.Symlink("/tmp/evil", filepath.Join(dir, "bin/pyenv"))
		}, "bin/pyenv: changed when the keg was re-poured"},
		{"added file", func(dir string) {
			os.MkdirAll(filepath.Join(dir, "pyenv.d/exec"), 0o755)
			os.WriteFile(filepath.Join(dir, "pyenv.d/exec/x.bash"), []byte("evil"), 0o644)
		}, "pyenv.d/exec/x.bash: changed when the keg was re-poured"},
		{"forged pyc", func(dir string) {
			os.WriteFile(filepath.Join(dir, "lib/__pycache__/m.pyc"), []byte("forged"), 0o644)
		}, "lib/__pycache__/m.pyc: changed when the keg was re-poured; a bottle cannot vouch"},
	} {
		t.Run(c.name, func(t *testing.T) {
			prefix, bottles, run := kegBaseFixture(t)
			bottles["pyenv/2.5.4"] = map[string]string{"libexec/pyenv": "real", "bin/pyenv": "->../libexec/pyenv"}
			dir := writeKeg(t, prefix, "pyenv/2.5.4", map[string]string{"libexec/pyenv": "real", "bin/pyenv": "->../libexec/pyenv",
				"lib/__pycache__/m.pyc": "bytecode", "INSTALL_RECEIPT.json": pouredCore})
			if res := run(); res.Verdict != brewVerdictClean {
				t.Fatalf("first: %s %v %v", res.Verdict, res.Tamper, res.NotAssessed)
			}
			c.edit(dir)
			os.WriteFile(filepath.Join(dir, "INSTALL_RECEIPT.json"), []byte(repoured), 0o644)
			res := run()
			if res.Verdict != brewVerdictTamper || !strings.Contains(strings.Join(res.Tamper, "\n"), c.want) {
				t.Fatalf("%s %v %v", res.Verdict, res.Tamper, res.NotAssessed)
			}
		})
	}
	t.Run("pyc removed then re-planted", func(t *testing.T) {
		prefix, bottles, run := kegBaseFixture(t)
		bottles["pyenv/2.5.4"] = map[string]string{"libexec/pyenv": "real"}
		dir := writeKeg(t, prefix, "pyenv/2.5.4", map[string]string{"libexec/pyenv": "real", "lib/__pycache__/m.pyc": "bytecode", "INSTALL_RECEIPT.json": pouredCore})
		run()
		os.Remove(filepath.Join(dir, "lib/__pycache__/m.pyc"))
		if res := run(); res.Verdict != brewVerdictClean {
			t.Fatalf("removal: %s %v", res.Verdict, res.Tamper)
		}
		os.WriteFile(filepath.Join(dir, "lib/__pycache__/m.pyc"), []byte("forged"), 0o644)
		if res := run(); !strings.Contains(strings.Join(res.Tamper, "\n"), "m.pyc: changed since it was poured") {
			t.Fatalf("re-planted: %s %v", res.Verdict, res.Tamper)
		}
	})
}

// N6: a fake keg under a name core does not have is accepted with a note,
// but a name root recorded as pyenv's moving onto it is reported every run.
func TestKegBaselineLinkTakeover(t *testing.T) {
	prefix, bottles, run := kegBaseFixture(t)
	bottles["pyenv/2.5.4"] = map[string]string{"bin/pyenv": "real"}
	writeKeg(t, prefix, "pyenv/2.5.4", map[string]string{"bin/pyenv": "real", "INSTALL_RECEIPT.json": pouredCore})
	os.MkdirAll(filepath.Join(prefix, "bin"), 0o755)
	os.Symlink("../Cellar/pyenv/2.5.4/bin/pyenv", filepath.Join(prefix, "bin/pyenv"))
	kegLinkPrior = map[string]string{"bin/pyenv": "pyenv"}
	t.Cleanup(func() { kegLinkPrior = nil })
	run()
	writeKeg(t, prefix, "tapped-evil/1.0", map[string]string{"bin/pyenv": "evil", "INSTALL_RECEIPT.json": `{"source":{"tap":"me/tap"}}`})
	if res := run(); res.Verdict != brewVerdictIncomplete || !strings.Contains(strings.Join(res.NotAssessed, "\n"), "with no bottle to compare") {
		t.Fatalf("fake tap keg: %s %v", res.Verdict, res.NotAssessed)
	}
	os.Remove(filepath.Join(prefix, "bin/pyenv"))
	os.Symlink("../Cellar/tapped-evil/1.0/bin/pyenv", filepath.Join(prefix, "bin/pyenv"))
	for i := 0; i < 2; i++ {
		res := run()
		if !strings.Contains(strings.Join(res.NotAssessed, "\n"), "bin/pyenv: recorded as pyenv's, now links into tapped-evil/1.0") {
			t.Fatalf("run %d: %s %v", i, res.Verdict, res.NotAssessed)
		}
	}
}

// N5: npm replacing itself is accepted only when it matches the registry.
func TestKegBaselineNpmTree(t *testing.T) {
	prefix, bottles, run := kegBaseFixture(t)
	os.MkdirAll(filepath.Join(prefix, "Cellar"), 0o755)
	npm := writeKeg(t, prefix, "../lib/node_modules/npm", map[string]string{"package.json": `{"version":"11.0.0"}`, "lib/cli.js": "v11.0", "npmrc": "prefix = " + prefix + "\n"})
	run()
	bottles["npm-self/11.1.0"] = map[string]string{"package.json": `{"version":"11.1.0"}`, "lib/cli.js": "v11.1"}
	writeKeg(t, prefix, "../lib/node_modules/npm", map[string]string{"package.json": `{"version":"11.1.0"}`, "lib/cli.js": "v11.1"})
	if res := run(); res.Verdict != brewVerdictClean {
		t.Fatalf("npm self-update: %s %v %v", res.Verdict, res.Tamper, res.NotAssessed)
	}
	os.WriteFile(filepath.Join(npm, "lib/cli.js"), []byte("evil"), 0o644)
	os.WriteFile(filepath.Join(npm, "package.json"), []byte(`{"version":"11.1.0" }`), 0o644)
	if res := run(); res.Verdict != brewVerdictTamper || !strings.Contains(strings.Join(res.Tamper, "\n"), "lib/node_modules/npm/lib/cli.js: differs from npm 11.1.0") {
		t.Fatalf("laundered npm: %s %v %v", res.Verdict, res.Tamper, res.NotAssessed)
	}
}

// N7: a sparse file is tamper without being read.
func TestKegBaselineSparseFile(t *testing.T) {
	prefix, bottles, run := kegBaseFixture(t)
	bottles["jq/1.8.2"] = map[string]string{"bin/jq": "x"}
	dir := writeKeg(t, prefix, "jq/1.8.2", map[string]string{"bin/jq": "x", "INSTALL_RECEIPT.json": pouredCore})
	f, _ := os.Create(filepath.Join(dir, "share/hole"))
	if f == nil {
		os.MkdirAll(filepath.Join(dir, "share"), 0o755)
		f, _ = os.Create(filepath.Join(dir, "share/hole"))
	}
	f.Truncate(1 << 30)
	f.Close()
	if res := run(); !strings.Contains(strings.Join(res.Tamper, "\n"), "share/hole: a sparse file") {
		t.Fatalf("sparse: %v", res.Tamper)
	}
}

// Round 3, M1: a new keg is vouched only when every difference from its
// bottle is explained: added files by a formula that defines post_install,
// retargeted links by landing in brew's own trees.
func TestKegBaselineFreshKegExplained(t *testing.T) {
	for _, c := range []struct {
		name, key string
		files     map[string]string
		accepted  bool
	}{
		{"link out of the prefix", "pyenv/2.4.0", map[string]string{"bin/pyenv": "->/tmp/evil"}, false},
		{"added hook, no post_install", "pyenv/2.4.0", map[string]string{"pyenv.d/exec/x.bash": "evil"}, false},
		{"added file, post_install", "postpy/3.13", map[string]string{"bin/pip3": "shim"}, true},
		{"link into the Cellar", "pyenv/2.4.0", map[string]string{"bin/pyenv": "->../../../pyenv/2.4.0/libexec/pyenv"}, true},
		// Round 4: user-writable global packages, another formula's keg,
		// and an older genuine bottle extracted by hand get no benefit of
		// the doubt.
		{"link into another global package", "pyenv/2.4.0", map[string]string{"bin/pyenv": "->../../../../lib/node_modules/x/pyenv"}, false},
		{"link into another formula's keg", "pyenv/2.4.0", map[string]string{"bin/pyenv": "->../../../evil/1.0/pyenv"}, false},
		{"link to a dot-file beside the kegs", "pyenv/2.4.0", map[string]string{"bin/pyenv": "->../../.x"}, false},
		{"post_install additions at an old version", "postpy/0.9", map[string]string{"lib/sitecustomize.py": "evil"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			prefix, bottles, run := kegBaseFixture(t)
			name := strings.Split(c.key, "/")[0]
			bottles["jq/1.8.2"] = map[string]string{"bin/jq": "x"}
			writeKeg(t, prefix, "jq/1.8.2", map[string]string{"bin/jq": "x", "INSTALL_RECEIPT.json": pouredCore})
			run()
			bottles[c.key] = map[string]string{"libexec/" + name: "real", "bin/" + name: "->../libexec/" + name}
			files := map[string]string{"libexec/" + name: "real", "bin/" + name: "->../libexec/" + name, "INSTALL_RECEIPT.json": pouredCore}
			for k, v := range c.files {
				files[k] = v
			}
			writeKeg(t, prefix, c.key, files)
			for i := 0; i < 2; i++ {
				res := run()
				notes := strings.Join(res.NotAssessed, "\n")
				sticky := strings.Contains(notes, "does not match a published bottle")
				if c.accepted == sticky || (i == 1 && c.accepted && res.Verdict != brewVerdictClean) {
					t.Fatalf("run %d: accepted=%v want %v: %s %v", i, !sticky, c.accepted, res.Verdict, res.NotAssessed)
				}
			}
		})
	}
}

// Round 3, M2: npm's builtin npmrc and its .bin links are not free passes.
func TestKegBaselineNpmrcAndBinLinks(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"script-shell in npmrc", map[string]string{"npmrc": "prefix = PREFIX\nscript-shell=/tmp/sh\n"}, "npm/npmrc: differs"},
		{".bin link out of the tree", map[string]string{"node_modules/.bin/semver": "->/tmp/evil"}, "npm/node_modules/.bin/semver: differs"},
		{"clean", nil, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			prefix, bottles, run := kegBaseFixture(t)
			os.MkdirAll(filepath.Join(prefix, "Cellar"), 0o755)
			tree := map[string]string{"package.json": `{"version":"11.1.0"}`, "lib/cli.js": "v11.1",
				"node_modules/semver/bin/semver.js": "semver", "node_modules/.bin/semver": "->../semver/bin/semver.js",
				"npmrc": "prefix = " + prefix + "\n"}
			writeKeg(t, prefix, "../lib/node_modules/npm", map[string]string{"package.json": `{"version":"11.0.0"}`})
			run()
			bottles["npm-self/11.1.0"] = map[string]string{"package.json": `{"version":"11.1.0"}`, "lib/cli.js": "v11.1", "node_modules/semver/bin/semver.js": "semver"}
			for k, v := range c.files {
				tree[k] = strings.ReplaceAll(v, "PREFIX", prefix)
			}
			writeKeg(t, prefix, "../lib/node_modules/npm", tree)
			res := run()
			got := strings.Join(res.Tamper, "\n")
			if c.want == "" && res.Verdict != brewVerdictClean || c.want != "" && !strings.Contains(got, c.want) {
				t.Fatalf("%s %v %v", res.Verdict, res.Tamper, res.NotAssessed)
			}
		})
	}
}

// opt/ links: how kegs load each other. One root recorded as openssl@3's
// moved onto a keg no bottle vouches for is reported every run; brew's own
// alias links recorded on the first run are not.
func TestKegBaselineOptTakeover(t *testing.T) {
	prefix, bottles, run := kegBaseFixture(t)
	bottles["openssl@3/3.4.1"] = map[string]string{"lib/libssl.dylib": "real"}
	writeKeg(t, prefix, "openssl@3/3.4.1", map[string]string{"lib/libssl.dylib": "real", "INSTALL_RECEIPT.json": pouredCore})
	os.MkdirAll(filepath.Join(prefix, "opt"), 0o755)
	os.Symlink("../Cellar/openssl@3/3.4.1", filepath.Join(prefix, "opt/openssl@3"))
	os.Symlink("../Cellar/openssl@3/3.4.1", filepath.Join(prefix, "opt/openssl")) // brew alias
	links, _ := homebrew.CheckLinks(prefix, nil)
	kegLinkPrior = links.Baseline
	t.Cleanup(func() { kegLinkPrior = nil })
	if kegLinkPrior["opt/openssl"] != "openssl@3" {
		t.Fatalf("alias not recorded: %v", kegLinkPrior)
	}
	if res := run(); res.Verdict != brewVerdictClean {
		t.Fatalf("first: %s %v", res.Verdict, res.NotAssessed)
	}
	writeKeg(t, prefix, "tapped-ssl/1.0", map[string]string{"lib/libssl.dylib": "evil", "INSTALL_RECEIPT.json": `{"source":{"tap":"me/tap"}}`})
	run()
	os.Remove(filepath.Join(prefix, "opt/openssl@3"))
	os.Symlink("../Cellar/tapped-ssl/1.0", filepath.Join(prefix, "opt/openssl@3"))
	for i := 0; i < 2; i++ {
		if res := run(); !strings.Contains(strings.Join(res.NotAssessed, "\n"), "opt/openssl@3: recorded as openssl@3's, now links into tapped-ssl/1.0") {
			t.Fatalf("run %d: %s %v", i, res.Verdict, res.NotAssessed)
		}
	}
}

// A comparison that could not run never records anything: a new keg, a
// re-poured keg with changed files and a replaced npm tree all stay pending.
func TestKegBaselineFetchFailureNotAccepted(t *testing.T) {
	prefix, bottles, run := kegBaseFixture(t)
	t.Cleanup(func() { kegFetchFails = false })
	bottles["jq/1.8.2"] = map[string]string{"bin/jq": "x"}
	dir := writeKeg(t, prefix, "jq/1.8.2", map[string]string{"bin/jq": "x", "INSTALL_RECEIPT.json": pouredCore})
	writeKeg(t, prefix, "../lib/node_modules/npm", map[string]string{"package.json": `{"version":"11.0.0"}`, "npmrc": "prefix = " + prefix + "\n"})
	bottles["npm-self/11.0.0"] = map[string]string{"package.json": `{"version":"11.0.0"}`}
	if res := run(); res.Verdict != brewVerdictClean {
		t.Fatalf("first: %s %v %v", res.Verdict, res.Tamper, res.NotAssessed)
	}
	kegFetchFails = true
	writeKeg(t, prefix, "gh/2.0", map[string]string{"bin/gh": "gh", "INSTALL_RECEIPT.json": pouredCore})
	os.WriteFile(filepath.Join(dir, "bin/jq"), []byte("y"), 0o755)
	os.WriteFile(filepath.Join(dir, "INSTALL_RECEIPT.json"), []byte(repoured), 0o644)
	writeKeg(t, prefix, "../lib/node_modules/npm", map[string]string{"package.json": `{"version":"11.1.0"}`})
	for i := 0; i < 2; i++ {
		res := run()
		notes := strings.Join(res.NotAssessed, "\n")
		for _, want := range []string{"keg gh/2.0: new since the last root run; bottle not fetched", "keg jq/1.8.2: re-poured with changed files; bottle not fetched", "lib/node_modules/npm: replaced, not yet compared"} {
			if !strings.Contains(notes, want) {
				t.Fatalf("run %d: missing %q in %v", i, want, res.NotAssessed)
			}
		}
	}
}

// Where no bottle comparison exists (Intel, Linux, the Rosetta prefix), a
// re-pour that changed files is tamper, never absorbed; a macOS version
// that cannot be read is an error, not "unsupported".
func TestKegBaselineNoComparisonRepour(t *testing.T) {
	prefix, _, run := kegBaseFixture(t)
	brewKegComparePrefix = "/opt/homebrew" // this fixture prefix is now "elsewhere"
	dir := writeKeg(t, prefix, "jq/1.8.2", map[string]string{"bin/jq": "x", "INSTALL_RECEIPT.json": pouredCore})
	run()
	os.WriteFile(filepath.Join(dir, "bin/jq"), []byte("evil"), 0o755)
	os.WriteFile(filepath.Join(dir, "INSTALL_RECEIPT.json"), []byte(repoured), 0o644)
	for i := 0; i < 2; i++ {
		if res := run(); res.Verdict != brewVerdictTamper || !strings.Contains(strings.Join(res.Tamper, "\n"), "Cellar/jq/1.8.2/bin/jq: changed when the keg was re-poured; no bottle comparison") {
			t.Fatalf("run %d: %s %v", i, res.Verdict, res.Tamper)
		}
	}

	brewKegComparePrefix = prefix
	brewMacOSMajor = func() (int, error) { return 0, errors.New("sysctl failed") }
	writeKeg(t, prefix, "gh/2.0", map[string]string{"bin/gh": "gh", "INSTALL_RECEIPT.json": pouredCore})
	os.WriteFile(filepath.Join(dir, "INSTALL_RECEIPT.json"), []byte(pouredCore), 0o644) // undo the earlier re-pour
	os.WriteFile(filepath.Join(dir, "bin/jq"), []byte("x"), 0o755)
	if res := run(); res.Verdict != brewVerdictError || !strings.Contains(strings.Join(res.Errors, "\n"), "macOS version unknown") {
		t.Fatalf("macOS error: %s %v %v", res.Verdict, res.Errors, res.NotAssessed)
	}
}

// An out-of-keg tree moved away for one root run and brought back edited is
// compared with its old record, not recorded as new; a new site-packages
// holding a startup hook is not recorded.
func TestKegBaselineOutOfKegReappears(t *testing.T) {
	prefix, _, run := kegBaseFixture(t)
	os.MkdirAll(filepath.Join(prefix, "Cellar"), 0o755)
	site := writeKeg(t, prefix, "../lib/python3.13/site-packages", map[string]string{"a.pth": "import os"})
	run()
	away := t.TempDir() + "/sp"
	os.Rename(site, away)
	if res := run(); res.Verdict != brewVerdictClean {
		t.Fatalf("moved away: %s %v %v", res.Verdict, res.Tamper, res.NotAssessed)
	}
	os.Rename(away, site)
	os.WriteFile(filepath.Join(site, "a.pth"), []byte("import evil"), 0o644)
	if res := run(); !strings.Contains(strings.Join(res.Tamper, "\n"), "site-packages/a.pth: changed since root recorded it") {
		t.Fatalf("back edited: %s %v %v", res.Verdict, res.Tamper, res.NotAssessed)
	}

	writeKeg(t, prefix, "../lib/python3.14/site-packages", map[string]string{"zz.pth": "import evil"})
	for i := 0; i < 2; i++ {
		if res := run(); !strings.Contains(strings.Join(res.NotAssessed, "\n"), "lib/python3.14/site-packages: new since the last root run with Python startup hooks (zz.pth)") {
			t.Fatalf("run %d: %v", i, res.NotAssessed)
		}
	}
}

// --kegs: a keg that could not be compared leaves the verdict incomplete.
func TestVerifyKegsNotComparedIsIncomplete(t *testing.T) {
	prefix, _, _ := kegBaseFixture(t)
	writeKeg(t, prefix, "jq/1.8.2", map[string]string{"bin/jq": "x", "INSTALL_RECEIPT.json": pouredCore})
	kegFetchFails = true
	t.Cleanup(func() { kegFetchFails = false })
	res := brewVerifyResult{Tamper: []string{}, NotAssessed: []string{}, Errors: []string{}, Drift: []string{}}
	verifyKegs(&res, []string{prefix})
	if brewVerdictOf(res) != brewVerdictIncomplete || !strings.Contains(strings.Join(res.NotAssessed, "\n"), "keg jq/1.8.2: not compared, bottle not fetched") {
		t.Fatalf("%s %v", brewVerdictOf(res), res.NotAssessed)
	}
}

// A new npm tree naming a version the registry does not have is never
// recorded and never reads clean, first run or later.
func TestKegBaselineFreshNpmUnpublished(t *testing.T) {
	for _, first := range []bool{true, false} {
		prefix, bottles, run := kegBaseFixture(t)
		os.MkdirAll(filepath.Join(prefix, "Cellar"), 0o755)
		if !first {
			bottles["jq/1.8.2"] = map[string]string{"bin/jq": "x"}
			writeKeg(t, prefix, "jq/1.8.2", map[string]string{"bin/jq": "x", "INSTALL_RECEIPT.json": pouredCore})
			run()
		}
		writeKeg(t, prefix, "../lib/node_modules/npm", map[string]string{"package.json": `{"version":"11.99.0"}`, "lib/cli.js": "evil"})
		for i := 0; i < 2; i++ {
			res := run()
			if res.Verdict == brewVerdictClean || !strings.Contains(strings.Join(res.NotAssessed, "\n"), "lib/node_modules/npm: names npm 11.99.0") {
				t.Fatalf("first=%v run %d: %s %v", first, i, res.Verdict, res.NotAssessed)
			}
		}
	}
}

// Codex P1s, through the whole links + keg path (verifyBrew): a name
// root recorded as pyenv's moved onto a fake tap keg stays reported on
// every run, because the stored link baseline keeps pyenv; and a new
// bin/sudo linked into a fake keg is tamper on every run, never adopted.
func TestLinkTakeoverAndShadowPersist(t *testing.T) {
	prefix, bottles, _ := kegBaseFixture(t)
	sys := t.TempDir()
	os.WriteFile(filepath.Join(sys, "sudo"), []byte("x"), 0o755)
	oldSys, oldPH := homebrew.SystemCommandDirs, homebrew.PathHelperDirs
	t.Cleanup(func() { homebrew.SystemCommandDirs, homebrew.PathHelperDirs = oldSys, oldPH })
	homebrew.SystemCommandDirs, homebrew.PathHelperDirs = []string{sys}, nil
	oldTree := brewVerifyFetchTree
	t.Cleanup(func() { brewVerifyFetchTree = oldTree })

	bottles["pyenv/2.5.4"] = map[string]string{"bin/pyenv": "real"}
	writeKeg(t, prefix, "pyenv/2.5.4", map[string]string{"bin/pyenv": "real", "INSTALL_RECEIPT.json": pouredCore})
	os.MkdirAll(filepath.Join(prefix, "bin"), 0o755)
	os.MkdirAll(filepath.Join(prefix, "var/homebrew/linked"), 0o755)
	os.Symlink("../../../Cellar/pyenv/2.5.4", filepath.Join(prefix, "var/homebrew/linked/pyenv"))
	os.Symlink("../Cellar/pyenv/2.5.4/bin/pyenv", filepath.Join(prefix, "bin/pyenv"))
	run := func() brewVerifyResult { return verifyBrew(prefix, "", true, false, false) }
	if res := run(); res.Verdict != brewVerdictClean {
		t.Fatalf("baseline: %s %v %v %v", res.Verdict, res.Tamper, res.NotAssessed, res.Errors)
	}

	writeKeg(t, prefix, "tapped-evil/1.0", map[string]string{"bin/pyenv": "evil", "bin/sudo": "evil", "INSTALL_RECEIPT.json": `{"source":{"tap":"me/tap"}}`})
	run()
	// The real takeover also drops brew's linked record, so only the root
	// link baseline still says the name was pyenv's.
	os.Remove(filepath.Join(prefix, "var/homebrew/linked/pyenv"))
	os.Remove(filepath.Join(prefix, "bin/pyenv"))
	os.Symlink("../Cellar/tapped-evil/1.0/bin/pyenv", filepath.Join(prefix, "bin/pyenv"))
	os.Symlink("../Cellar/tapped-evil/1.0/bin/sudo", filepath.Join(prefix, "bin/sudo"))
	for i := 0; i < 3; i++ {
		res := run()
		notes, tamper := strings.Join(res.NotAssessed, "\n"), strings.Join(res.Tamper, "\n")
		if !strings.Contains(notes, "bin/pyenv: recorded as pyenv's, now links into tapped-evil/1.0") ||
			!strings.Contains(tamper, "bin/sudo: newly linked into tapped-evil/1.0, which no bottle vouches for, and shadows") {
			t.Fatalf("run %d: %s tamper=%v notes=%v", i, res.Verdict, res.Tamper, res.NotAssessed)
		}
	}
}

// Fix-check findings: a forced keg-check error never adopts a new shadowing
// link (C1); where no bottle comparison exists a routine install of a
// command named like a system one is not tamper (C2), and a failed fetch
// gives "not assessed", never tamper.
func TestShadowRuleEdges(t *testing.T) {
	setup := func(t *testing.T) (string, map[string]map[string]string, func() brewVerifyResult) {
		prefix, bottles, _ := kegBaseFixture(t)
		sys := t.TempDir()
		for _, n := range []string{"sudo", "git"} {
			os.WriteFile(filepath.Join(sys, n), []byte("x"), 0o755)
		}
		oldSys, oldPH := homebrew.SystemCommandDirs, homebrew.PathHelperDirs
		t.Cleanup(func() { homebrew.SystemCommandDirs, homebrew.PathHelperDirs = oldSys, oldPH })
		homebrew.SystemCommandDirs, homebrew.PathHelperDirs = []string{sys}, nil
		bottles["jq/1.8.2"] = map[string]string{"bin/jq": "x"}
		writeKeg(t, prefix, "jq/1.8.2", map[string]string{"bin/jq": "x", "INSTALL_RECEIPT.json": pouredCore})
		os.MkdirAll(filepath.Join(prefix, "bin"), 0o755)
		os.Symlink("../Cellar/jq/1.8.2/bin/jq", filepath.Join(prefix, "bin/jq"))
		run := func() brewVerifyResult { return verifyBrew(prefix, "", true, false, false) }
		if res := run(); res.Verdict != brewVerdictClean {
			t.Fatalf("baseline: %s %v %v %v", res.Verdict, res.Tamper, res.NotAssessed, res.Errors)
		}
		return prefix, bottles, run
	}

	t.Run("forced keg error adopts nothing", func(t *testing.T) {
		prefix, _, run := setup(t)
		writeKeg(t, prefix, "tapped-evil/1.0", map[string]string{"bin/sudo": "evil", "INSTALL_RECEIPT.json": `{"source":{"tap":"me/tap"}}`})
		os.Symlink("../Cellar/tapped-evil/1.0/bin/sudo", filepath.Join(prefix, "bin/sudo"))
		old := homebrew.KegMaxFiles
		homebrew.KegMaxFiles = 1
		if res := run(); res.Verdict == brewVerdictClean {
			t.Fatalf("forced error read clean")
		}
		homebrew.KegMaxFiles = old
		for i := 0; i < 2; i++ {
			if res := run(); !strings.Contains(strings.Join(res.Tamper, "\n"), "bin/sudo: newly linked into tapped-evil/1.0") {
				t.Fatalf("run %d after the forced error: %s %v %v", i, res.Verdict, res.Tamper, res.NotAssessed)
			}
		}
	})

	t.Run("no bottle comparison: routine install is not tamper", func(t *testing.T) {
		prefix, _, run := setup(t)
		brewKegComparePrefix = "/opt/homebrew" // this prefix is now one without bottle comparison
		writeKeg(t, prefix, "git/2.50", map[string]string{"bin/git": "git", "INSTALL_RECEIPT.json": pouredCore})
		os.Symlink("../Cellar/git/2.50/bin/git", filepath.Join(prefix, "bin/git"))
		run()
		if res := run(); res.Verdict != brewVerdictClean {
			t.Fatalf("second run after install: %s %v %v", res.Verdict, res.Tamper, res.NotAssessed)
		}
	})

	t.Run("failed fetch: not assessed, not tamper", func(t *testing.T) {
		prefix, _, run := setup(t)
		kegFetchFails = true
		t.Cleanup(func() { kegFetchFails = false })
		writeKeg(t, prefix, "git/2.50", map[string]string{"bin/git": "git", "INSTALL_RECEIPT.json": pouredCore})
		os.Symlink("../Cellar/git/2.50/bin/git", filepath.Join(prefix, "bin/git"))
		res := run()
		if len(res.Tamper) != 0 || !strings.Contains(strings.Join(res.NotAssessed, "\n"), "bin/git: newly linked into git/2.50, not yet compared") {
			t.Fatalf("%s tamper=%v notes=%v", res.Verdict, res.Tamper, res.NotAssessed)
		}
	})
}
