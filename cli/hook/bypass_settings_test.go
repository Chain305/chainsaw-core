package hook

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Settings that make a package manager resolve somewhere other than the
// chainsaw entry it was wired with. Each was reproduced with the real tool
// (Bundler 1.17, uv 0.9, Composer 2.10) against local fake registries.

func TestBundlerRefusesAndUnwiresUnderMirrorBypass(t *testing.T) {
	const fallbackKey = "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/__FALLBACK_TIMEOUT"
	for name, tc := range map[string]struct {
		seed string
		env  [2]string
	}{
		"mirror.all in the config":        {seed: "---\nBUNDLE_MIRROR__ALL: \"https://evil.example/\"\n"},
		"fallback_timeout in the config":  {seed: "---\n" + fallbackKey + ": \"1\"\n"},
		"rewritten fallback_timeout key":  {seed: "---\n" + fallbackKey + "/: \"1\"\n"},
		"mirror.all fallback_timeout":     {seed: "---\nBUNDLE_MIRROR__ALL__FALLBACK_TIMEOUT: \"1\"\n"},
		"BUNDLE_MIRROR__ALL in the env":   {env: [2]string{"BUNDLE_MIRROR__ALL", "https://evil.example/"}},
		"fallback_timeout in the env":     {env: [2]string{fallbackKey, "1"}},
		"BUNDLE_IGNORE_CONFIG in the env": {env: [2]string{"BUNDLE_IGNORE_CONFIG", "1"}},
	} {
		t.Run(name, func(t *testing.T) {
			home := sandboxHome(t)
			m := bundlerManager{}
			path := filepath.Join(home, ".bundle", "config")
			if tc.seed != "" {
				writeSeed(t, path, tc.seed)
			}
			if tc.env[0] != "" {
				t.Setenv(tc.env[0], tc.env[1])
			}
			err := m.Wire(testWireOpts())
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("Wire = %v, want a refusal", err)
			}
			if got, _ := os.ReadFile(path); string(got) != tc.seed {
				t.Fatalf("refused but modified:\n%s", got)
			}
		})
	}

	// Wired first, bypass added afterwards: Status must stop saying wired.
	home := sandboxHome(t)
	m := bundlerManager{}
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.Status(); !st.Wired {
		t.Fatal("not wired after Wire")
	}
	path := filepath.Join(home, ".bundle", "config")
	data, _ := os.ReadFile(path)
	writeSeed(t, path, string(data)+"BUNDLE_MIRROR__ALL: \"https://evil.example/\"\n")
	if st, _ := m.Status(); st.Wired {
		t.Fatal("Status wired with mirror.all set beside chainsaw's mirror")
	}
	writeSeed(t, path, string(data))
	t.Setenv("BUNDLE_MIRROR__ALL", "https://evil.example/")
	if st, _ := m.Status(); st.Wired {
		t.Fatal("Status wired with BUNDLE_MIRROR__ALL in the environment")
	}
}

// Bundler honours BUNDLE_CONFIG ahead of BUNDLE_USER_CONFIG.
func TestBundlerConfigPathHonoursBUNDLE_CONFIG(t *testing.T) {
	home := sandboxHome(t)
	t.Setenv("BUNDLE_USER_CONFIG", filepath.Join(home, "user-config"))
	t.Setenv("BUNDLE_CONFIG", filepath.Join(home, "bundle-config"))
	if got, _ := (bundlerManager{}).ConfigPath(); got != filepath.Join(home, "bundle-config") {
		t.Fatalf("ConfigPath = %s, want $BUNDLE_CONFIG", got)
	}
}

// Bundler::Settings#[]: local app config, then ENV, then global. Every file's
// bypass keys count even when the mirror came from another.
func TestBundlerRubygemsRouteOrder(t *testing.T) {
	home := sandboxHome(t)
	dir := t.TempDir()
	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	_ = os.Chdir(dir)
	writeSeed(t, filepath.Join(home, ".bundle", "config"), "---\n"+bundlerMirrorKey+": \"https://global/\"\n")
	t.Setenv(bundlerMirrorKey, "https://env/")
	if r := BundlerRubygemsRoute(); r.Mirror != "https://env/" {
		t.Fatalf("env must win over global, got %q", r.Mirror)
	}
	writeSeed(t, filepath.Join(dir, ".bundle", "config"), "---\n"+bundlerMirrorKey+": \"https://local/\"\n")
	if r := BundlerRubygemsRoute(); r.Mirror != "https://local/" {
		t.Fatalf("local must win over env, got %q", r.Mirror)
	}
	writeSeed(t, filepath.Join(home, ".bundle", "config"), "---\n"+bundlerMirrorKey+": \"https://global/\"\nBUNDLE_MIRROR__ALL: \"https://evil/\"\n")
	if r := BundlerRubygemsRoute(); len(r.Bypass) == 0 {
		t.Fatal("mirror.all in the global config not reported while the mirror came from the local one")
	}
	t.Setenv("BUNDLE_IGNORE_CONFIG", "1")
	if r := BundlerRubygemsRoute(); r.Mirror != "https://env/" {
		t.Fatalf("BUNDLE_IGNORE_CONFIG must drop both files, got %q", r.Mirror)
	}
}

// Bundler's YAMLSerializer reads any line with ": " as a key, comment or not,
// and `bundle config` writes it back; those junk keys outlived unwire.
func TestBundlerBlockHasNoKeyShapedComments(t *testing.T) {
	home := sandboxHome(t)
	m := bundlerManager{}
	opts := testWireOpts()
	opts.Credentials = testCreds
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, ".bundle", "config")
	data, _ := os.ReadFile(path)
	lines, _ := splitLines(data)
	for _, ln := range lines {
		c := strings.TrimSpace(ln)
		if strings.HasPrefix(c, "#") && (strings.Contains(c, ": ") || strings.HasSuffix(c, ":")) {
			t.Fatalf("Bundler would read this comment as a key: %s", ln)
		}
	}

	// A file an older build wrote, after `bundle config set foo bar`: the
	// markers are gone and our comments came back as quoted keys (the exact
	// shape Bundler 1.17 produced). Unwire removes them.
	writeSeed(t, path, "---\n"+
		"# generated-at: \"2026-11-17T07:21:58Z\"\n"+
		"# chainsaw: \"this file contains a credential in cleartext (the X line below).\"\n"+
		"# chainsaw restricts it to your user account: \"owner-only permissions on\"\n"+
		"# my own note: keep this\n"+
		bundlerMirrorKey+": \""+wantRubygemsSource+"\"\n"+
		bundlerKeyFor("chain305.com")+": \""+testCreds+"\"\n"+
		"BUNDLE_FOO: \"bar\"\n")
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatal(err)
	}
	got := string(mustRead(t, path))
	if strings.Contains(got, "generated-at") || strings.Contains(got, "cleartext") || strings.Contains(got, "restricts it") {
		t.Fatalf("junk keys survived Unwire:\n%s", got)
	}
	if !strings.Contains(got, "BUNDLE_FOO") || !strings.Contains(got, "# my own note: keep this") {
		t.Fatalf("Unwire removed the user's lines:\n%s", got)
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Bundler 1.17's key_for leaves "-" alone; 2.x maps it to "___".
func TestBundlerDashedHostCredentialBothSpellings(t *testing.T) {
	home := sandboxHome(t)
	opts := testWireOpts()
	opts.ServerURL = "https://chain-saw.example.com"
	opts.Credentials = testCreds
	if err := (bundlerManager{}).Wire(opts); err != nil {
		t.Fatal(err)
	}
	vals := bundlerValues(mustRead(t, filepath.Join(home, ".bundle", "config")))
	for _, k := range []string{"BUNDLE_CHAIN___SAW__EXAMPLE__COM", "BUNDLE_CHAIN-SAW__EXAMPLE__COM"} {
		if vals[k] != testCreds {
			t.Errorf("%s = %q, want the credential", k, vals[k])
		}
	}
	if err := (bundlerManager{}).Unwire(ScopeUser); err != nil {
		t.Fatal(err)
	}
	if got := string(mustRead(t, filepath.Join(home, ".bundle", "config"))); strings.Contains(got, "SAW") {
		t.Fatalf("Unwire left a credential key:\n%s", got)
	}
}

func TestUVRefusesEverySettingQueriedBeforeTheDefault(t *testing.T) {
	for name, seed := range map[string]string{
		"no-index + find-links":     "no-index = true\nfind-links = [\"https://evil.example/links/\"]\n",
		"find-links":                "find-links = [\"https://evil.example/links/\"]\n",
		"top-level extra-index":     "extra-index-url = [\"https://evil.example/simple/\"]\n",
		"non-default index":         "[[index]]\nname = \"foo\"\nurl = \"https://evil.example/simple/\"\n",
		"[pip] extra-index-url":     "[pip]\nextra-index-url = [\"https://evil.example/simple/\"]\n",
		"[pip] index-url":           "[pip]\nindex-url = \"https://evil.example/simple/\"\n",
		"explicit but also default": "[[index]]\nname = \"foo\"\nurl = \"https://evil.example/simple/\"\nexplicit = true\ndefault = true\n",
	} {
		t.Run(name, func(t *testing.T) {
			sandboxHome(t)
			m := uvManager{}
			path, _ := m.ConfigPath()
			writeSeed(t, path, seed)
			if err := m.Wire(testWireOpts()); !errors.Is(err, ErrRefused) {
				t.Fatalf("Wire = %v, want a refusal", err)
			}
			if got := string(mustRead(t, path)); got != seed {
				t.Fatalf("refused but modified:\n%s", got)
			}
		})
	}
}

// Added after wiring, a setting uv queries first makes Status not wired.
func TestUVStatusSeesSettingsAddedAfterWiring(t *testing.T) {
	sandboxHome(t)
	m := uvManager{}
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	path, _ := m.ConfigPath()
	data := mustRead(t, path)
	writeSeed(t, path, "extra-index-url = [\"https://evil.example/simple/\"]\n"+string(data))
	if st, _ := m.Status(); st.Wired {
		t.Fatal("Status wired with an extra-index-url uv queries before chainsaw")
	}
	writeSeed(t, path, "[[index]]\nname = \"torch\"\nurl = \"https://download.pytorch.org/whl/cpu\"\nexplicit = true\n"+string(data))
	if st, _ := m.Status(); !st.Wired {
		t.Fatal("an explicit index is used only when pinned; Status must stay wired")
	}
}

func TestComposerRefusesPackagistMirrors(t *testing.T) {
	for name, u := range map[string]string{
		"repo.packagist.org":   "https://repo.packagist.org",
		"private packagist":    "https://repo.packagist.com/acme/",
		"regional mirror":      "https://packagist.jp",
		"aliyun mirror":        "https://mirrors.aliyun.com/composer/",
		"tencent cloud mirror": "https://mirrors.cloud.tencent.com/composer/",
	} {
		t.Run(name, func(t *testing.T) {
			composerSandbox(t)
			m := composerManager{}
			cfg, _ := m.ConfigPath()
			seed := `{"repositories": {"mirror": {"type": "composer", "url": "` + u + `"}}}`
			writeSeed(t, cfg, seed)
			if err := m.Wire(testWireOpts()); !errors.Is(err, ErrRefused) {
				t.Fatalf("Wire = %v, want a refusal", err)
			}
			if got := string(mustRead(t, cfg)); got != seed {
				t.Fatalf("refused but modified:\n%s", got)
			}
		})
	}
	if IsPackagistMirror("https://satis.corp.internal/") {
		t.Fatal("a private Satis repository is not a Packagist mirror")
	}
}

// Composer 2.10's `composer config -g repositories.x` rewrites the keyed
// object as a list and prepends x. Status reads that form too.
func TestComposerStatusReadsListForm(t *testing.T) {
	composerSandbox(t)
	m := composerManager{}
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	cfg, _ := m.ConfigPath()
	ours := `{"name": "chainsaw", "type": "composer", "url": "https://chain305.com/repository/@acme-corp/packagist/"}`
	writeSeed(t, cfg, `{"repositories": [{"name": "private", "type": "composer", "url": "https://satis.corp.internal"}, `+ours+`, {"packagist.org": false}]}`)
	// R2-S6: an unrestricted composer repository ahead of chainsaw answers
	// for every package it has; restricted with "only" it does not.
	if st, _ := m.Status(); st.Wired {
		t.Fatal("list form with an unrestricted composer repo ahead of chainsaw read as wired")
	}
	writeSeed(t, cfg, `{"repositories": [{"name": "private", "type": "composer", "url": "https://satis.corp.internal", "only": ["corp/*"]}, `+ours+`, {"packagist.org": false}]}`)
	if st, _ := m.Status(); !st.Wired {
		t.Fatal("list form with an only-restricted private repo, chainsaw and Packagist off is wired")
	}
	writeSeed(t, cfg, `{"repositories": [{"name": "mirror", "type": "composer", "url": "https://repo.packagist.org"}, `+ours+`, {"packagist.org": false}]}`)
	if st, _ := m.Status(); st.Wired {
		t.Fatal("Status wired with a Packagist mirror prepended ahead of chainsaw")
	}
}

// A config that is a symlink is written through, not replaced.
func TestWriteAtomicFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles", "gemrc")
	writeSeed(t, target, "---\n")
	link := filepath.Join(dir, ".gemrc")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := writeAtomic(link, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced with a regular file")
	}
	if got := string(mustRead(t, target)); got != "new\n" {
		t.Fatalf("target = %q", got)
	}
	dangling := filepath.Join(dir, "dangling")
	_ = os.Symlink(filepath.Join(dir, "nowhere"), dangling)
	if err := writeAtomic(dangling, []byte("x")); err == nil {
		t.Fatal("wrote through a dangling symlink")
	}
}
