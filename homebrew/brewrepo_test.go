package homebrew

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Reference ids from `printf ... | git hash-object --stdin`.
const (
	blobHello   = "ce013625030ba8dba906f756967f9e9ca394464a" // "hello\n"
	blobTarget  = "1de565933b05f74c75ff9a6520af5f9f8a5a2f1d" // "target"
	blobShebang = "1a2485251c33a70432394c93fb89330ef214bfc9" // "#!/bin/sh\n"
)

func write(t *testing.T, root, rel, body string, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// fixtureRepo is a brew checkout whose upstream tree is known exactly.
func fixtureRepo(t *testing.T) (string, []TreeEntry) {
	t.Helper()
	r := t.TempDir()
	write(t, r, "bin/brew", "#!/bin/sh\n", 0o755)
	write(t, r, "Library/Homebrew/cmd/install.rb", "hello\n", 0o644)
	if err := os.Symlink("target", filepath.Join(r, "Library/Homebrew/link")); err != nil {
		t.Fatal(err)
	}
	write(t, r, "Library/Homebrew/vendor/bundle/ruby/4.0.0/gems/x/lib/x.rb", "installed gem", 0o644)
	write(t, r, "Library/Homebrew/vendor/bundle/bundler/setup.rb", "hello\n", 0o644)
	write(t, r, "Library/Homebrew/.DS_Store", "finder", 0o644)
	write(t, r, "Library/Homebrew/vendor/bundle/bundler/README.md", "untracked gem docs", 0o644)
	return r, []TreeEntry{
		{"bin/brew", "100755", blobShebang},
		{"Library/Homebrew/cmd/install.rb", "100644", blobHello},
		{"Library/Homebrew/vendor/bundle/bundler/setup.rb", "100644", blobHello},
		{"Library/Homebrew/link", "120000", blobTarget},
		{"Library/Homebrew/cmd", "040000", "ignored-tree-sha"},
		{"docs/README.md", "100644", "out-of-scope"},
	}
}

func TestCompareBrewTreeClean(t *testing.T) {
	r, tree := fixtureRepo(t)
	rep, err := CompareBrewTree(r, "c", tree)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Compared != 4 || len(rep.Findings) != 0 {
		t.Fatalf("compared=%d findings=%+v", rep.Compared, rep.Findings)
	}
}

func TestCompareBrewTreeTamper(t *testing.T) {
	cases := []struct {
		name, path string
		mutate     func(r string)
	}{
		{"edited ruby", "Library/Homebrew/cmd/install.rb", func(r string) {
			write(t, r, "Library/Homebrew/cmd/install.rb", "hello\n#\n", 0o644)
		}},
		{"dropped ruby", "Library/Homebrew/cmd/evil.rb", func(r string) {
			write(t, r, "Library/Homebrew/cmd/evil.rb", "puts 1", 0o644)
		}},
		{"dropped executable", "Library/Homebrew/hook", func(r string) {
			write(t, r, "Library/Homebrew/hook", "x", 0o755)
		}},
		{"exec bit removed", "bin/brew", func(r string) { os.Chmod(filepath.Join(r, "bin/brew"), 0o644) }},
		{"symlink re-pointed", "Library/Homebrew/link", func(r string) {
			os.Remove(filepath.Join(r, "Library/Homebrew/link"))
			os.Symlink("/tmp/evil", filepath.Join(r, "Library/Homebrew/link"))
		}},
		{"symlink replaced by file", "Library/Homebrew/link", func(r string) {
			os.Remove(filepath.Join(r, "Library/Homebrew/link"))
			write(t, r, "Library/Homebrew/link", "target", 0o644)
		}},
		{"bin/ swapped for a symlink to a copy", "bin", func(r string) {
			copyDir := t.TempDir()
			write(t, copyDir, "brew", "#!/bin/sh\n", 0o755)
			os.RemoveAll(filepath.Join(r, "bin"))
			os.Symlink(copyDir, filepath.Join(r, "bin"))
		}},
		{"tracked file deleted", "Library/Homebrew/cmd/install.rb", func(r string) {
			os.Remove(filepath.Join(r, "Library/Homebrew/cmd/install.rb"))
		}},
		{"non-executable native extension", "Library/Homebrew/json.bundle", func(r string) {
			write(t, r, "Library/Homebrew/json.bundle", "\xcf\xfa\xed\xfe", 0o644)
		}},
		{"file dropped in a tracked vendor dir", "Library/Homebrew/vendor/bundle/bundler/fileutils.rb", func(r string) {
			write(t, r, "Library/Homebrew/vendor/bundle/bundler/fileutils.rb", "puts 1", 0o644)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, tree := fixtureRepo(t)
			c.mutate(r)
			rep, err := CompareBrewTree(r, "c", tree)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range rep.Findings {
				if f.Path == c.path && f.Severity == SeverityTamper {
					return
				}
			}
			t.Fatalf("no TAMPER on %s: %+v", c.path, rep.Findings)
		})
	}
}

func TestCheckGitConfig(t *testing.T) {
	stock := "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = false\n[remote \"origin\"]\n\turl = https://github.com/Homebrew/brew\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n[fetch]\n\tprune = true\n[homebrew]\n\tlatesttag = 7.0.11\n"
	setup := func(cfg string, hooks ...string) string {
		r := t.TempDir()
		write(t, r, ".git/config", cfg, 0o644)
		write(t, r, ".git/hooks/pre-commit.sample", "#!/bin/sh\n", 0o755)
		for _, h := range hooks {
			write(t, r, ".git/hooks/"+h, "#!/bin/sh\n", 0o755)
		}
		return r
	}
	if f, err := CheckGitConfig(setup(stock)); err != nil || len(f) != 0 {
		t.Fatalf("stock config: %v %+v", err, f)
	}
	for name, cfg := range map[string]string{
		"fsmonitor":  stock + "[core]\n\tfsmonitor = /tmp/payload\n",
		"hooksPath":  "[core]\n\thooksPath = /tmp/h\n",
		"include":    "[include]\n\tpath = /tmp/x\n",
		"filter":     "[filter \"x\"]\n\tsmudge = /tmp/x\n",
		"textconv":   "[diff \"x\"]\n\ttextconv = /tmp/x\n",
		"alias":      "[alias]\n\tdescribe = !/tmp/x\n",
		"sshCommand": "[core]\n\tsshCommand = /tmp/x\n",
		"same line":  "[core] fsmonitor = /tmp/x\n",
		"continued":  "[core]\n\texcludesFile = x \\\n",
		"insteadOf":  "[url \"ext::sh -c x\"]\n\tinsteadOf = https://github.com/Homebrew/brew\n",
		"ext remote": "[remote \"origin\"]\n\turl = ext::sh -c x\n",
		"uploadpack": "[remote \"origin\"]\n\tuploadpack = /tmp/x\n",
		"protocol":   "[protocol \"ext\"]\n\tallow = always\n",
	} {
		if f, err := CheckGitConfig(setup(cfg)); err != nil || len(f) != 1 || f[0].Severity != SeverityTamper {
			t.Errorf("%s: %v %+v", name, err, f)
		}
	}
	if f, _ := CheckGitConfig(setup(stock, "post-merge")); len(f) != 1 || f[0].Path != ".git/hooks/post-merge" || f[0].Severity != SeverityTamper {
		t.Errorf("hook brew runs not flagged: %+v", f)
	}
	// An org git template's pre-commit never fires in brew: a warning only.
	if f, _ := CheckGitConfig(setup(stock, "pre-commit")); len(f) != 1 || f[0].Severity != SeverityWarn {
		t.Errorf("pre-commit: %+v", f)
	}
	r := setup(stock)
	write(t, r, ".git/commondir", "/tmp/other\n", 0o644)
	if f, _ := CheckGitConfig(r); len(f) != 1 || f[0].Path != ".git/commondir" {
		t.Errorf("commondir: %+v", f)
	}
}

func TestCompareBrewTreeEmptyUpstreamIsError(t *testing.T) {
	r, _ := fixtureRepo(t)
	if _, err := CompareBrewTree(r, "c", []TreeEntry{{"docs/x", "100644", "a"}}); err == nil {
		t.Fatal("an upstream tree with nothing in scope must be an error, never clean")
	}
}

func TestReadHead(t *testing.T) {
	sha := strings.Repeat("a", 40)
	other := strings.Repeat("b", 40)
	cases := map[string]func(g string){
		"detached": func(g string) { write(t, g, "HEAD", sha+"\n", 0o644) },
		"loose ref": func(g string) {
			write(t, g, "HEAD", "ref: refs/heads/main\n", 0o644)
			write(t, g, "refs/heads/main", sha+"\n", 0o644)
		},
		"packed ref": func(g string) {
			write(t, g, "HEAD", "ref: refs/heads/main\n", 0o644)
			write(t, g, "packed-refs", "# pack\n"+other+" refs/heads/x\n"+sha+" refs/heads/main\n", 0o644)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			r := t.TempDir()
			setup(filepath.Join(r, ".git"))
			got, err := ReadHead(r)
			if err != nil || got != sha {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
	for name, head := range map[string]string{"garbage": "nope\n", "escape": "ref: refs/../../x\n", "short": "abc\n"} {
		t.Run(name, func(t *testing.T) {
			r := t.TempDir()
			write(t, filepath.Join(r, ".git"), "HEAD", head, 0o644)
			if _, err := ReadHead(r); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

// A HEAD symlinked at a root-only file must not be read, or quoted.
func TestReadHeadRefusesSymlinkAndNeverQuotes(t *testing.T) {
	r := t.TempDir()
	dir := t.TempDir()
	write(t, dir, "secret", "export CHAINSAW_TOKEN=s3cr3t\n", 0o600)
	os.MkdirAll(filepath.Join(r, ".git"), 0o755)
	os.Symlink(filepath.Join(dir, "secret"), filepath.Join(r, ".git/HEAD"))
	if _, err := ReadHead(r); err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("symlinked HEAD: %v", err)
	}
	// Refused because it is a symlink, not because its content is garbage.
	os.Remove(filepath.Join(r, ".git/HEAD"))
	write(t, dir, "sha", strings.Repeat("a", 40)+"\n", 0o644)
	os.Symlink(filepath.Join(dir, "sha"), filepath.Join(r, ".git/HEAD"))
	if _, err := ReadHead(r); err == nil {
		t.Fatal("followed a symlinked HEAD")
	}
	os.Remove(filepath.Join(r, ".git/HEAD"))
	write(t, filepath.Join(r, ".git"), "HEAD", "export CHAINSAW_TOKEN=s3cr3t\n", 0o644)
	if _, err := ReadHead(r); err == nil || strings.Contains(err.Error(), "s3cr3t") {
		t.Fatalf("garbage HEAD quoted: %v", err)
	}
}

func TestUpdateInProgress(t *testing.T) {
	r := t.TempDir()
	now := time.Now()
	if UpdateInProgress(r, now) {
		t.Fatal("idle repo reported busy")
	}
	write(t, r, ".git/FETCH_HEAD", "x", 0o644)
	if UpdateInProgress(r, now) {
		t.Fatal("FETCH_HEAD alone must not mask the comparison")
	}
	write(t, r, ".git/index.lock", "", 0o644)
	if !UpdateInProgress(r, now.Add(3*time.Minute)) {
		t.Fatal("fresh index.lock not reported")
	}
	if UpdateInProgress(r, now.Add(11*time.Minute)) {
		t.Fatal("a stale index.lock must not mask the comparison forever")
	}
	future := now.Add(24 * time.Hour)
	os.Chtimes(filepath.Join(r, ".git/index.lock"), future, future)
	if UpdateInProgress(r, now) {
		t.Fatal("a lock dated in the future must not count as an update in progress")
	}
}

func TestEnvDrift(t *testing.T) {
	server := "# generated\nHOMEBREW_SYSTEM_ENV_TAKES_PRIORITY=1\nHOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1\nHOMEBREW_NO_REQUIRE_TAP_TRUST=\n"
	if d, x := EnvDrift("# other stamp\n  HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY=1  \nHOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1\nHOMEBREW_NO_REQUIRE_TAP_TRUST=\nHOMEBREW_NO_ANALYTICS=1\n", server); len(d) != 0 || len(x) != 1 {
		t.Fatalf("clean file: drift=%v extra=%v", d, x)
	}
	// A correct block undone by a later line is drift: brew's last export wins.
	if d, _ := EnvDrift(server+"HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=\n", server); len(d) != 1 || !strings.Contains(d[0], "NO_FALLBACK") {
		t.Fatalf("later override not caught: %v", d)
	}
	if d, _ := EnvDrift("HOMEBREW_SYSTEM_ENV_TAKES_PRIORITY=1\n", server); len(d) != 2 {
		t.Fatalf("missing keys not caught: %v", d)
	}
}
