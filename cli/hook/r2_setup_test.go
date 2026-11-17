package hook

// Round-2 adversarial review of the install-hook wirers (R2-S2 … R2-S13).
// Each case was a setting under which the tool resolved somewhere other than
// chainsaw while Status said wired, or a legitimate setup Wire refused with no
// way through.

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// uvSystemSandbox points uv's system config lookup at a temp dir.
func uvSystemSandbox(t *testing.T) (xdgDir string) {
	t.Helper()
	xdgDir = t.TempDir()
	t.Setenv("XDG_CONFIG_DIRS", xdgDir)
	old := uvEtcConfig
	uvEtcConfig = filepath.Join(xdgDir, "no-etc-uv", "uv.toml")
	t.Cleanup(func() { uvEtcConfig = old })
	return xdgDir
}

// R2-S2: uv merges the system uv.toml under the user one and concatenates
// index arrays, so a foreign extra-index-url there is asked first.
func TestUVStatusReadsSystemConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX layout")
	}
	sandboxHome(t)
	xdg := uvSystemSandbox(t)
	m := uvManager{}
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.Status(); !st.Wired {
		t.Fatalf("not wired with no system config: %+v", st)
	}
	sys := filepath.Join(xdg, "uv", "uv.toml")
	writeSeed(t, sys, "extra-index-url = [\"https://u:topsecret@pypi.evil.example/simple\"]\n")
	st, _ := m.Status()
	if st.Wired || !strings.Contains(st.Bypassed, sys) {
		t.Fatalf("a foreign system index must unwire uv: %+v", st)
	}
	if strings.Contains(st.Bypassed, "topsecret") {
		t.Fatalf("credential in the reason: %s", st.Bypassed)
	}
	// The system file pointing at this same chainsaw index is fine.
	writeSeed(t, sys, "index-url = \"https://chain305.com/repository/@acme-corp/pypi/simple/\"\n")
	if st, _ := m.Status(); !st.Wired {
		t.Fatalf("system config naming chainsaw's own index read as a bypass: %+v", st)
	}
	// /etc/uv/uv.toml is the fallback when no XDG dir has one.
	_ = os.Remove(sys)
	writeSeed(t, uvEtcConfig, "find-links = [\"https://wheels.evil.example/\"]\n")
	if st, _ := m.Status(); st.Wired {
		t.Fatal("/etc/uv/uv.toml fallback not read")
	}
	// UV_CONFIG_FILE makes uv read that one file only.
	path, _ := m.ConfigPath()
	t.Setenv("UV_CONFIG_FILE", path)
	if st, _ := m.Status(); !st.Wired {
		t.Fatalf("UV_CONFIG_FILE set: uv reads no system config: %+v", st)
	}
}

// R2-S10: a user uv.toml whose index-url already IS this chainsaw was refused.
func TestUVWireAcceptsOwnIndexURL(t *testing.T) {
	sandboxHome(t)
	uvSystemSandbox(t)
	m := uvManager{}
	path, _ := m.ConfigPath()
	writeSeed(t, path, "index-url = \"https://chain305.com/repository/@acme-corp/pypi/simple/\"\n")
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatalf("Wire refused chainsaw's own index: %v", err)
	}
	if st, _ := m.Status(); !st.Wired {
		t.Fatalf("not wired: %+v", st)
	}
	writeSeed(t, path, "index-url = \"https://chain305.com/repository/@other-org/pypi/simple/\"\n")
	if err := m.Wire(testWireOpts()); !errors.Is(err, ErrRefused) {
		t.Fatalf("another org's index must still be refused: %v", err)
	}
}

// R2-S8: an explicit index pinned through [tool.uv.sources] is reported.
func TestUVPinnedForeignIndexes(t *testing.T) {
	table := map[string]any{
		"index": []map[string]any{
			{"name": "evil", "url": "https://evil.example/simple", "explicit": true},
			{"name": "ours", "url": "https://chain305.com/repository/@acme-corp/pypi/simple/", "explicit": true},
		},
		"sources": map[string]any{
			"requests": map[string]any{"index": "evil"},
			"internal": map[string]any{"index": "ours"},
			"local":    map[string]any{"path": "./local"},
		},
	}
	got := UVPinnedForeignIndexes(table, registryMatcher("https://chain305.com/repository/@acme-corp/pypi/simple/"))
	if len(got) != 1 || !strings.Contains(got[0], `"requests"`) || !strings.Contains(got[0], "evil.example") {
		t.Fatalf("pinned foreign indexes = %v", got)
	}
}

// R2-S3: Status must judge the mirror Bundler actually uses. A project
// ./.bundle/config or the environment wins over the global file.
func TestBundlerStatusUsesEffectiveMirror(t *testing.T) {
	sandboxHome(t)
	dir := t.TempDir()
	t.Chdir(dir)
	m := bundlerManager{}
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.Status(); !st.Wired {
		t.Fatalf("not wired: %+v", st)
	}
	writeSeed(t, filepath.Join(dir, ".bundle", "config"), "---\n"+bundlerMirrorKey+": \"https://gems.evil.example/\"\n")
	if st, _ := m.Status(); st.Wired || !strings.Contains(st.Bypassed, "gems.evil.example") {
		t.Fatalf("a project mirror overriding chainsaw's read as wired: %+v", st)
	}
	_ = os.RemoveAll(filepath.Join(dir, ".bundle"))
	t.Setenv(bundlerMirrorKey, "https://gems.evil.example/")
	if st, _ := m.Status(); st.Wired {
		t.Fatal("an environment mirror overriding chainsaw's read as wired")
	}
}

// R2-S4: Bundler tests BUNDLE_IGNORE_CONFIG for presence; "" counts.
func TestBundlerEmptyIgnoreConfigIsABypass(t *testing.T) {
	sandboxHome(t)
	t.Chdir(t.TempDir())
	m := bundlerManager{}
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUNDLE_IGNORE_CONFIG", "")
	if st, _ := m.Status(); st.Wired {
		t.Fatal("BUNDLE_IGNORE_CONFIG= (empty) read as wired")
	}
	if err := m.Wire(testWireOpts()); !errors.Is(err, ErrRefused) {
		t.Fatalf("Wire = %v under an empty BUNDLE_IGNORE_CONFIG, want a refusal", err)
	}
}

// R2-S10: fallback_timeout 0 / false turns Bundler's probe off, so it never
// falls back; only a positive timeout (or "true") is a bypass.
func TestBundlerFallbackTimeoutZeroIsNotABypass(t *testing.T) {
	const key = "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/__FALLBACK_TIMEOUT"
	for v, bypass := range map[string]bool{"0": false, "false": false, "0.5": false, "true": true, "1": true, "30": true, "-1": true} {
		if got := bundlerBypassKey(key, v) != ""; got != bypass {
			t.Errorf("fallback_timeout %q: bypass=%v, want %v", v, got, bypass)
		}
	}
	sandboxHome(t)
	t.Chdir(t.TempDir())
	m := bundlerManager{}
	path, _ := m.ConfigPath()
	writeSeed(t, path, "---\n"+key+": \"0\"\n")
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatalf("fallback_timeout 0 refused: %v", err)
	}
	if st, _ := m.Status(); !st.Wired {
		t.Fatalf("not wired: %+v", st)
	}
}

// R2-S6: `composer config -g repositories.corp composer <url>` after wiring
// rewrites the keyed object as a list with corp first. Status must flag it,
// and a re-wire (credential rotation) must work on the list.
func TestComposerListFormAheadOfChainsaw(t *testing.T) {
	composerSandbox(t)
	m := composerManager{}
	opts := testWireOpts()
	opts.Credentials = testCreds
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	cfg, _ := m.ConfigPath()
	ours := `{"name": "chainsaw", "type": "composer", "url": "https://chain305.com/repository/@acme-corp/packagist/"}`
	corp := `{"name": "corp", "type": "composer", "url": "https://satis.corp.internal"}`
	writeSeed(t, cfg, `{"repositories": [`+corp+`, `+ours+`, {"packagist.org": false}]}`)
	if st, _ := m.Status(); st.Wired || !strings.Contains(st.Bypassed, "corp") {
		t.Fatalf("a composer repository ahead of chainsaw read as wired: %+v", st)
	}
	// An "only" list limits it to named packages: not a bypass.
	corpOnly := `{"name": "corp", "type": "composer", "url": "https://satis.corp.internal", "only": ["corp/*"]}`
	writeSeed(t, cfg, `{"repositories": [`+corpOnly+`, `+ours+`, {"packagist.org": false}]}`)
	if st, _ := m.Status(); !st.Wired {
		t.Fatalf("an only-restricted repository read as a bypass: %+v", st)
	}
	// Re-wire on the list form (credential rotation) keeps the form and order.
	opts.Credentials = "cli-abc:rotated-value"
	if err := m.Wire(opts); err != nil {
		t.Fatalf("re-wire on list form: %v", err)
	}
	obj, err := parseJSONObject(mustRead(t, cfg))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := obj.get("repositories")
	repos, isList, err := ComposerRepos(raw)
	if err != nil || !isList || len(repos) != 3 || repos[0].Name != "corp" || repos[1].Name != "chainsaw" {
		t.Fatalf("list form or order lost: %v %v %+v", err, isList, repos)
	}
	if st, _ := m.Status(); !st.Wired {
		t.Fatalf("not wired after re-wire: %+v", st)
	}
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatalf("Unwire on list form: %v", err)
	}
	if got := string(mustRead(t, cfg)); strings.Contains(got, "chainsaw") || !strings.Contains(got, "satis.corp.internal") {
		t.Fatalf("after Unwire:\n%s", got)
	}
	// First wire with an unrestricted composer repo: refused, unless trusted.
	writeSeed(t, cfg, `{"repositories": {"corp": {"type": "composer", "url": "https://satis.corp.internal"}}}`)
	if err := m.Wire(opts); !errors.Is(err, ErrRefused) {
		t.Fatalf("Wire = %v with an unrestricted composer repository ahead, want a refusal", err)
	}
	opts.TrustedSources = []string{"https://satis.corp.internal/"}
	if err := m.Wire(opts); err != nil {
		t.Fatalf("a trusted repository must be kept: %v", err)
	}
	if st, _ := m.Status(); st.Wired {
		t.Fatal("Status must still report a trusted repository ahead of chainsaw")
	}
}

// R2-S10: Private Packagist with an "only" list is not a Packagist mirror.
func TestComposerPrivatePackagistWithOnly(t *testing.T) {
	composerSandbox(t)
	m := composerManager{}
	cfg, _ := m.ConfigPath()
	writeSeed(t, cfg, `{"repositories": {"acme": {"type": "composer", "url": "https://repo.packagist.com/acme/", "only": ["acme/*"]}}}`)
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatalf("Private Packagist limited by only refused: %v", err)
	}
	if st, _ := m.Status(); !st.Wired {
		t.Fatalf("not wired: %+v", st)
	}
}

// R2-S10: a private gem source plus rubygems.org had no way through. A
// trusted source is kept beside chainsaw's; Status still reports it.
func TestGemTrustedSourceKept(t *testing.T) {
	sandboxHome(t)
	m := gemManager{}
	path, _ := m.ConfigPath()
	seed := "---\n:sources:\n- https://gems.corp.internal/\n- https://rubygems.org/\n"
	writeSeed(t, path, seed)
	if err := m.Wire(testWireOpts()); !errors.Is(err, ErrRefused) {
		t.Fatalf("untrusted private source: Wire = %v, want a refusal", err)
	}
	opts := testWireOpts()
	opts.TrustedSources = []string{"https://gems.corp.internal"}
	if err := m.Wire(opts); err != nil {
		t.Fatalf("trusted private source: %v", err)
	}
	got := string(mustRead(t, path))
	if !strings.Contains(got, "gems.corp.internal") || strings.Contains(got, "- https://rubygems.org/") || !strings.Contains(got, wantRubygemsSource) {
		t.Fatalf("want chainsaw + the trusted source, rubygems.org replaced:\n%s", got)
	}
	if err := m.Wire(opts); err != nil {
		t.Fatalf("re-wire: %v", err)
	}
	if st, _ := m.Status(); st.Wired || !strings.Contains(st.Bypassed, "gems.corp.internal") {
		t.Fatalf("Status must still report the extra source: %+v", st)
	}
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatal(err)
	}
	if got := string(mustRead(t, path)); got != seed {
		t.Fatalf("Unwire did not restore the original sources:\n%s", got)
	}
}

// R2-S13: a system-scope write never follows a link out of its directory.
func TestSystemScopeRefusesEscapingLink(t *testing.T) {
	dir := t.TempDir()
	elsewhere := filepath.Join(t.TempDir(), "victim")
	writeSeed(t, elsewhere, "original\n")
	link := filepath.Join(dir, "npmrc")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := writeConfigFile(link, []byte("x\n"), WireOpts{Scope: ScopeSystem}); err == nil {
		t.Fatal("system-scope write followed a link out of its directory")
	}
	if got := string(mustRead(t, elsewhere)); got != "original\n" {
		t.Fatalf("link target rewritten: %q", got)
	}
	// Within the same directory, and at user scope, links are still followed.
	inside := filepath.Join(dir, "npmrc.real")
	writeSeed(t, inside, "a\n")
	link2 := filepath.Join(dir, "npmrc2")
	_ = os.Symlink(inside, link2)
	if err := writeConfigFile(link2, []byte("b\n"), WireOpts{Scope: ScopeSystem}); err != nil {
		t.Fatalf("same-directory link refused: %v", err)
	}
	if err := writeConfigFile(link, []byte("y\n"), WireOpts{Scope: ScopeUser}); err != nil {
		t.Fatalf("user-scope dotfiles link refused: %v", err)
	}
}
