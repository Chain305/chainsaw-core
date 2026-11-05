package homebrew

import (
	"os"
	"path/filepath"
	"testing"
)

// healthyPrefix builds a prefix shaped like a real one: linked kegs with bin
// links, a keg-only formula reachable only through opt/, two kegs exporting
// the same name, and the unmanaged clutter a healthy Mac carries.
func healthyPrefix(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	mk := func(rel string) {
		if err := os.MkdirAll(filepath.Join(p, rel), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	file := func(rel string) {
		mk(filepath.Dir(rel))
		if err := os.WriteFile(filepath.Join(p, rel), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, rel string) {
		mk(filepath.Dir(rel))
		if err := os.Symlink(target, filepath.Join(p, rel)); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []struct{ f, v string }{{"pyenv", "2.5.4"}, {"jq", "1.8.2"}, {"python@3.12", "3.12.9"}, {"dupa", "1"}, {"dupb", "2"}} {
		link("../../../Cellar/"+k.f+"/"+k.v, "var/homebrew/linked/"+k.f)
		link("../Cellar/"+k.f+"/"+k.v, "opt/"+k.f)
	}
	file("Cellar/pyenv/2.5.4/libexec/pyenv")
	link("../libexec/pyenv", "Cellar/pyenv/2.5.4/bin/pyenv")
	link("../Cellar/pyenv/2.5.4/bin/pyenv", "bin/pyenv")
	file("Cellar/jq/1.8.2/bin/jq")
	link("../Cellar/jq/1.8.2/bin/jq", "bin/jq")
	file("Cellar/python@3.12/3.12.9/bin/2to3-3.12")
	link("../Cellar/python@3.12/3.12.9/bin/2to3-3.12", "bin/2to3-3.12")
	file("Cellar/dupa/1/bin/shared")
	file("Cellar/dupb/2/bin/shared")
	link("../Cellar/dupb/2/bin/shared", "bin/shared")
	file("Cellar/dupa/1/sbin/daemon")
	link("../Cellar/dupa/1/sbin/daemon", "sbin/daemon")
	// keg-only: installed, reachable through opt/, never linked into bin/.
	file("Cellar/openssl@3/3.5.0/bin/openssl")
	link("../Cellar/openssl@3/3.5.0", "opt/openssl@3")
	link("../Cellar/python@3.12/3.12.9", "opt/python3") // alias
	// unmanaged clutter: pip scripts, a cask link, a link to another tree.
	file("bin/inv")
	file("bin/brew")
	link("../Caskroom/ngrok/3.12.0/ngrok", "bin/ngrok")
	link("/opt/metasploit-framework/bin/msfrop", "bin/msfrop")
	file("bin/.keepme")
	return p
}

func TestCheckLinksHealthy(t *testing.T) {
	r, err := CheckLinks(healthyPrefix(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("healthy prefix has findings: %+v", r.Findings)
	}
	if r.LinkedKegs != 5 {
		t.Errorf("LinkedKegs = %d, want 5", r.LinkedKegs)
	}
	want := []string{"bin/inv", "bin/msfrop", "bin/ngrok"}
	if len(r.Unmanaged) != len(want) {
		t.Fatalf("Unmanaged = %v, want %v", r.Unmanaged, want)
	}
	for i := range want {
		if r.Unmanaged[i] != want[i] {
			t.Fatalf("Unmanaged = %v, want %v", r.Unmanaged, want)
		}
	}
}

func TestCheckLinksTamper(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(p string) error
		path   string
	}{
		{"regular file replaces link", func(p string) error {
			os.Remove(filepath.Join(p, "bin/pyenv"))
			return os.WriteFile(filepath.Join(p, "bin/pyenv"), []byte("#!/bin/sh\nevil\n"), 0o755)
		}, "bin/pyenv"},
		{"link to /tmp", func(p string) error {
			os.Remove(filepath.Join(p, "bin/pyenv"))
			return os.Symlink("/tmp/x", filepath.Join(p, "bin/pyenv"))
		}, "bin/pyenv"},
		{"link into another keg", func(p string) error {
			os.Remove(filepath.Join(p, "bin/pyenv"))
			return os.Symlink("../Cellar/jq/1.8.2/bin/jq", filepath.Join(p, "bin/pyenv"))
		}, "bin/pyenv"},
		{"dot-dot escape", func(p string) error {
			os.Remove(filepath.Join(p, "bin/jq"))
			return os.Symlink("../Cellar/jq/../../evil/jq", filepath.Join(p, "bin/jq"))
		}, "bin/jq"},
		{"sbin file", func(p string) error {
			os.Remove(filepath.Join(p, "sbin/daemon"))
			return os.WriteFile(filepath.Join(p, "sbin/daemon"), []byte("x"), 0o755)
		}, "sbin/daemon"},
		{"opt re-pointed", func(p string) error {
			os.Remove(filepath.Join(p, "opt/pyenv"))
			return os.Symlink("/tmp/d", filepath.Join(p, "opt/pyenv"))
		}, "opt/pyenv"},
		{"linked registry re-pointed", func(p string) error {
			os.Remove(filepath.Join(p, "var/homebrew/linked/jq"))
			return os.Symlink("/tmp/jq", filepath.Join(p, "var/homebrew/linked/jq"))
		}, "var/homebrew/linked/jq"},
		// linked/ is user-writable: deleting the record must not hide the swap.
		{"swap plus deleted linked record", func(p string) error {
			os.Remove(filepath.Join(p, "bin/pyenv"))
			os.Remove(filepath.Join(p, "var/homebrew/linked/pyenv"))
			return os.WriteFile(filepath.Join(p, "bin/pyenv"), []byte("evil"), 0o755)
		}, "bin/pyenv"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := healthyPrefix(t)
			base := baselineOf(t, p)
			if err := c.mutate(p); err != nil {
				t.Fatal(err)
			}
			r, err := CheckLinks(p, base)
			if err != nil {
				t.Fatal(err)
			}
			if !r.Tampered() {
				t.Fatalf("not tampered: %+v", r.Findings)
			}
			found := false
			for _, f := range r.Findings {
				if f.Path == c.path && f.Severity == SeverityTamper {
					found = true
				}
			}
			if !found {
				t.Fatalf("no TAMPER on %s: %+v", c.path, r.Findings)
			}
		})
	}
}

func TestCheckLinksWarnNotTamper(t *testing.T) {
	p := healthyPrefix(t)
	os.Remove(filepath.Join(p, "bin/jq"))
	r, err := CheckLinks(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Tampered() || len(r.Findings) != 1 || r.Findings[0].Severity != SeverityWarn || r.Findings[0].Path != "bin/jq" {
		t.Fatalf("want one WARN on bin/jq, got %+v", r.Findings)
	}
}

func TestCheckLinksNotAPrefix(t *testing.T) {
	if _, err := CheckLinks(t.TempDir(), nil); err == nil {
		t.Fatal("a directory without Cellar must be an error, never a clean report")
	}
}

// baselineOf is what a root run of the healthy prefix stores.
func baselineOf(t *testing.T, p string) map[string]string {
	t.Helper()
	r, err := CheckLinks(p, nil)
	if err != nil || len(r.Findings) != 0 {
		t.Fatalf("baseline run: %v %+v", err, r.Findings)
	}
	return r.Baseline
}

func TestCheckLinksBaseline(t *testing.T) {
	p := healthyPrefix(t)
	base := baselineOf(t, p)
	want := map[string]string{"bin/pyenv": "pyenv", "bin/jq": "jq", "bin/2to3-3.12": "python@3.12", "bin/shared": "dupb", "sbin/daemon": "dupa",
		// opt/ links record the formula they point at; opt/python3 is an alias.
		"opt/dupa": "dupa", "opt/dupb": "dupb", "opt/jq": "jq", "opt/openssl@3": "openssl@3", "opt/pyenv": "pyenv",
		"opt/python3": "python@3.12", "opt/python@3.12": "python@3.12"}
	if len(base) != len(want) {
		t.Fatalf("baseline %v, want %v", base, want)
	}
	for k, v := range want {
		if base[k] != v {
			t.Fatalf("baseline %v, want %v", base, want)
		}
	}

	t.Run("linked registry gone is no longer an error", func(t *testing.T) {
		q := healthyPrefix(t)
		os.RemoveAll(filepath.Join(q, "var/homebrew/linked"))
		r, err := CheckLinks(q, nil)
		if err != nil || r.Tampered() {
			t.Fatalf("err %v findings %+v", err, r.Findings)
		}
		if r.Baseline["bin/jq"] != "jq" {
			t.Fatalf("a live keg link must be baselined without a record: %v", r.Baseline)
		}
	})
	t.Run("uninstalled name is dropped", func(t *testing.T) {
		q := healthyPrefix(t)
		os.Remove(filepath.Join(q, "var/homebrew/linked/jq"))
		os.Remove(filepath.Join(q, "bin/jq"))
		r, err := CheckLinks(q, base)
		if err != nil || len(r.Findings) != 0 {
			t.Fatalf("err %v findings %+v", err, r.Findings)
		}
		if _, ok := r.Baseline["bin/jq"]; ok {
			t.Fatalf("absent name kept: %v", r.Baseline)
		}
	})
	t.Run("name moves to another formula", func(t *testing.T) {
		q := healthyPrefix(t)
		os.Remove(filepath.Join(q, "var/homebrew/linked/jq"))
		os.MkdirAll(filepath.Join(q, "Cellar/gojq/0.12/bin"), 0o755)
		os.WriteFile(filepath.Join(q, "Cellar/gojq/0.12/bin/jq"), []byte("x"), 0o755)
		os.Remove(filepath.Join(q, "bin/jq"))
		os.Symlink("../Cellar/gojq/0.12/bin/jq", filepath.Join(q, "bin/jq"))
		r, err := CheckLinks(q, base)
		if err != nil || len(r.Findings) != 0 || r.Baseline["bin/jq"] != "gojq" {
			t.Fatalf("err %v findings %+v baseline %v", err, r.Findings, r.Baseline)
		}
	})
	t.Run("swap without a record stays tamper and stays baselined", func(t *testing.T) {
		q := healthyPrefix(t)
		os.Remove(filepath.Join(q, "var/homebrew/linked/jq"))
		os.Remove(filepath.Join(q, "bin/jq"))
		os.WriteFile(filepath.Join(q, "bin/jq"), []byte("evil"), 0o755)
		r, err := CheckLinks(q, base)
		if err != nil || !r.Tampered() || r.Baseline["bin/jq"] != "jq" {
			t.Fatalf("err %v findings %+v baseline %v", err, r.Findings, r.Baseline)
		}
	})
	t.Run("fake keg path outside bin is tamper", func(t *testing.T) {
		q := healthyPrefix(t)
		os.Remove(filepath.Join(q, "var/homebrew/linked/jq"))
		os.Remove(filepath.Join(q, "bin/jq"))
		os.Symlink("../Cellar/jq/1.8.2/libexec/jq", filepath.Join(q, "bin/jq"))
		os.MkdirAll(filepath.Join(q, "Cellar/jq/1.8.2/libexec"), 0o755)
		os.WriteFile(filepath.Join(q, "Cellar/jq/1.8.2/libexec/jq"), []byte("evil"), 0o755)
		r, err := CheckLinks(q, base)
		if err != nil || !r.Tampered() {
			t.Fatalf("err %v findings %+v", err, r.Findings)
		}
	})
	t.Run("root-owned entry is warn and dropped", func(t *testing.T) {
		old := entryRootOwned
		t.Cleanup(func() { entryRootOwned = old })
		q := healthyPrefix(t)
		os.Remove(filepath.Join(q, "var/homebrew/linked/pyenv"))
		os.Remove(filepath.Join(q, "bin/pyenv"))
		os.WriteFile(filepath.Join(q, "bin/pyenv"), []byte("pkg"), 0o755)
		entryRootOwned = func(path string) bool { return path == filepath.Join(q, "bin/pyenv") }
		r, err := CheckLinks(q, base)
		if err != nil || r.Tampered() || len(r.Findings) != 1 || r.Findings[0].Severity != SeverityWarn {
			t.Fatalf("err %v findings %+v", err, r.Findings)
		}
		if _, ok := r.Baseline["bin/pyenv"]; ok {
			t.Fatalf("root-owned name kept: %v", r.Baseline)
		}
	})
	t.Run("unlinked keg does not claim a user file", func(t *testing.T) {
		// python.org / Docker Desktop FP: an installed but unlinked keg
		// ships a name some other installer put in bin/.
		q := healthyPrefix(t)
		os.MkdirAll(filepath.Join(q, "Cellar/docker/27.0/bin"), 0o755)
		os.WriteFile(filepath.Join(q, "Cellar/docker/27.0/bin/docker"), []byte("x"), 0o755)
		os.Symlink("/Applications/Docker.app/Contents/Resources/bin/docker", filepath.Join(q, "bin/docker"))
		r, err := CheckLinks(q, nil)
		if err != nil || len(r.Findings) != 0 {
			t.Fatalf("err %v findings %+v", err, r.Findings)
		}
	})
}

func TestResolveLinkAbsolute(t *testing.T) {
	if got := ResolveLink("/usr/local/bin", "/usr/local/Homebrew/bin/brew"); got != "/usr/local/Homebrew/bin/brew" {
		t.Fatalf("absolute: %s", got)
	}
	if got := ResolveLink("/usr/local/bin", "../Homebrew/bin/brew"); got != "/usr/local/Homebrew/bin/brew" {
		t.Fatalf("relative: %s", got)
	}
}

// A user-owned `sudo` in the prefix runs instead of /usr/bin/sudo and reads
// the password typed into it. Not brew's, so it used to be listed as
// unmanaged clutter and never flagged.
func TestCheckLinksSystemShadow(t *testing.T) {
	sys := t.TempDir()
	for _, n := range []string{"sudo", "ssh"} {
		if err := os.WriteFile(filepath.Join(sys, n), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old, oldPH := SystemCommandDirs, PathHelperDirs
	SystemCommandDirs, PathHelperDirs = []string{sys}, nil
	t.Cleanup(func() { SystemCommandDirs, PathHelperDirs = old, oldPH })

	p := healthyPrefix(t)
	if r, err := CheckLinks(p, nil); err != nil || len(r.Findings) != 0 {
		t.Fatalf("healthy prefix: %+v %v", r.Findings, err)
	}
	os.WriteFile(filepath.Join(p, "bin/sudo"), []byte("#!/bin/sh\nevil\n"), 0o755)
	os.Symlink("/tmp/fake-ssh", filepath.Join(p, "bin/ssh"))
	r, err := CheckLinks(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range r.Findings {
		if f.Severity == SeverityTamper {
			got[f.Path] = true
		}
	}
	if !got["bin/sudo"] || !got["bin/ssh"] || len(r.Findings) != 2 {
		t.Fatalf("want TAMPER on bin/sudo and bin/ssh, got %+v", r.Findings)
	}
	for _, u := range r.Unmanaged {
		if u == "bin/sudo" || u == "bin/ssh" {
			t.Fatalf("%s still listed as unmanaged", u)
		}
	}
}

// /usr/local/bin and the rest of path_helper's list count too, and a link
// into the (user-writable) Caskroom is no exemption.
func TestCheckLinksPathHelperShadow(t *testing.T) {
	sysDir, local := t.TempDir(), t.TempDir()
	for _, n := range []string{"aws", "docker"} {
		os.WriteFile(filepath.Join(local, n), []byte("x"), 0o755)
	}
	old, oldPH := SystemCommandDirs, PathHelperDirs
	SystemCommandDirs, PathHelperDirs = []string{sysDir}, []string{local}
	t.Cleanup(func() { SystemCommandDirs, PathHelperDirs = old, oldPH })

	p := healthyPrefix(t)
	os.WriteFile(filepath.Join(p, "bin/aws"), []byte("#!/bin/sh\nsteal\n"), 0o755)
	os.MkdirAll(filepath.Join(p, "Caskroom/x/1/Docker.app/Contents"), 0o755)
	os.Symlink("../Caskroom/x/1/Docker.app/Contents/docker", filepath.Join(p, "bin/docker"))
	r, err := CheckLinks(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.Path] = f.Severity == SeverityTamper
	}
	if !got["bin/aws"] || !got["bin/docker"] || len(r.Findings) != 2 {
		t.Fatalf("want TAMPER on bin/aws and bin/docker, got %+v (unmanaged %v)", r.Findings, r.Unmanaged)
	}
}
