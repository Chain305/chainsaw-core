package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

const bundlerMirrorKeyT = "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/"

// doctorSandbox isolates HOME, the bundler/uv/gem env and the cwd, and sets
// the configured server and org.
func doctorSandbox(t *testing.T, org string) (home, dir string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	for _, k := range []string{"BUNDLE_CONFIG", "BUNDLE_USER_CONFIG", "BUNDLE_USER_HOME", "BUNDLE_APP_CONFIG",
		"BUNDLE_MIRROR__ALL", "BUNDLE_IGNORE_CONFIG", bundlerMirrorKeyT, "GEMRC", "XDG_CONFIG_HOME"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("CHAINSAW_SERVER", rewriteTestServer)
	viper.Set("server_url", "")
	viper.Set("org_slug", org)
	t.Cleanup(func() { viper.Set("org_slug", "") })
	dir = t.TempDir()
	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	return home, dir
}

func writeT(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func gemfileLockFlagged() bool {
	for _, h := range scanLockfilesForPublicSources() {
		if strings.HasPrefix(h, "Gemfile.lock") {
			return true
		}
	}
	return false
}

// H7: the Gemfile.lock relaxation holds only when Bundler, by its own rules,
// fetches from this server's repository for the configured org.
func TestGemfileLockRelaxationFailsClosed(t *testing.T) {
	ours := rewriteTestServer + "/repository/@acme/rubygems/"
	global := func(extra string) string { return "---\n" + bundlerMirrorKeyT + ": \"" + ours + "\"\n" + extra }
	cases := []struct {
		name    string
		org     string
		global  string
		local   string
		env     map[string]string
		lock    string
		wantHit bool
	}{
		{name: "routed", org: "acme", global: global(""), wantHit: false},
		{name: "mirror.all in global config", org: "acme", global: global("BUNDLE_MIRROR__ALL: \"https://evil.example/\"\n"), wantHit: true},
		{name: "BUNDLE_MIRROR__ALL in env", org: "acme", global: global(""), env: map[string]string{"BUNDLE_MIRROR__ALL": "https://evil.example/"}, wantHit: true},
		{name: "fallback_timeout", org: "acme", global: global(bundlerMirrorKeyT + "__FALLBACK_TIMEOUT/: \"1\"\n"), wantHit: true},
		{name: "BUNDLE_IGNORE_CONFIG", org: "acme", global: global(""), env: map[string]string{"BUNDLE_IGNORE_CONFIG": "1"}, wantHit: true},
		{name: "another org's repository", org: "other", global: global(""), wantHit: true},
		{name: "org unknown", org: "", global: global(""), wantHit: true},
		{name: "local config wins over global", org: "acme", global: global(""), local: "---\n" + bundlerMirrorKeyT + ": \"https://evil.example/\"\n", wantHit: true},
		{name: "env wins over global", org: "acme", global: global(""), env: map[string]string{bundlerMirrorKeyT: "https://evil.example/"}, wantHit: true},
		{name: "http rubygems remote is not mirrored", org: "acme", global: global(""), lock: "GEM\n  remote: http://rubygems.org/\n", wantHit: true},
		{name: "gem.coop remote is not mirrored", org: "acme", global: global(""), lock: "GEM\n  remote: https://gem.coop/\n", wantHit: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home, dir := doctorSandbox(t, c.org)
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			lock := c.lock
			if lock == "" {
				lock = "GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.2.1)\n"
			}
			writeT(t, filepath.Join(dir, "Gemfile.lock"), lock)
			writeT(t, filepath.Join(home, ".bundle", "config"), c.global)
			if c.local != "" {
				writeT(t, filepath.Join(dir, ".bundle", "config"), c.local)
			}
			if got := gemfileLockFlagged(); got != c.wantHit {
				t.Fatalf("Gemfile.lock flagged = %v, want %v", got, c.wantHit)
			}
		})
	}

	// BUNDLE_CONFIG is the global file Bundler reads, ahead of ~/.bundle/config.
	t.Run("BUNDLE_CONFIG", func(t *testing.T) {
		home, dir := doctorSandbox(t, "acme")
		writeT(t, filepath.Join(dir, "Gemfile.lock"), "GEM\n  remote: https://rubygems.org/\n")
		writeT(t, filepath.Join(home, ".bundle", "config"), "---\n"+bundlerMirrorKeyT+": \"https://evil.example/\"\n")
		writeT(t, filepath.Join(home, "bc"), global(""))
		t.Setenv("BUNDLE_CONFIG", filepath.Join(home, "bc"))
		if gemfileLockFlagged() {
			t.Fatal("the mirror in $BUNDLE_CONFIG routes through chainsaw")
		}
	})
}

// H10: a project's pyproject.toml [tool.uv] is queried before the user's
// uv.toml; doctor used to read only ./uv.toml.
func TestProjectIndexOverrideUV(t *testing.T) {
	chainsawIndex := rewriteTestServer + "/repository/@acme/pypi/simple/"
	py := func(tail string) string {
		return "[project]\nname = \"p\"\nversion = \"0\"\n\n" + tail
	}
	cases := []struct {
		name, uvToml, pyproject string
		want                    bool
	}{
		{name: "foreign project index", pyproject: py("[[tool.uv.index]]\nname = \"foo\"\nurl = \"https://evil.example/simple/\"\n"), want: true},
		{name: "explicit project index", pyproject: py("[[tool.uv.index]]\nname = \"torch\"\nurl = \"https://download.pytorch.org/whl/cpu\"\nexplicit = true\n"), want: false},
		{name: "chainsaw project index", pyproject: py("[[tool.uv.index]]\nname = \"c\"\nurl = \"" + chainsawIndex + "\"\ndefault = true\n"), want: false},
		{name: "find-links", pyproject: py("[tool.uv]\nfind-links = [\"https://evil.example/links/\"]\n"), want: true},
		{name: "no-index", pyproject: py("[tool.uv]\nno-index = true\n"), want: true},
		{name: "extra-index-url with credentials", pyproject: py("[tool.uv]\nextra-index-url = [\"https://u:topsecret@evil.example/simple/\"]\n"), want: true},
		{name: "no [tool.uv]", pyproject: py(""), want: false},
		{name: "uv.toml shadows pyproject", uvToml: "[[index]]\nname = \"foo\"\nurl = \"https://evil.example/simple/\"\n", pyproject: py(""), want: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, dir := doctorSandbox(t, "acme")
			if c.uvToml != "" {
				writeT(t, filepath.Join(dir, "uv.toml"), c.uvToml)
			}
			writeT(t, filepath.Join(dir, "pyproject.toml"), c.pyproject)
			got := projectIndexOverride("uv")
			if (got != "") != c.want {
				t.Fatalf("projectIndexOverride = %q, want finding=%v", got, c.want)
			}
			if strings.Contains(got, "topsecret") {
				t.Fatalf("reason leaks a credential: %s", got)
			}
		})
	}
}

// H8: project composer.json repositories are queried before global ones.
func TestProjectIndexOverrideComposer(t *testing.T) {
	ours := rewriteTestServer + "/repository/@acme/packagist/"
	cases := []struct {
		name, json string
		want       bool
	}{
		{name: "anonymous packagist in a list", json: `{"repositories":[{"type":"composer","url":"https://repo.packagist.org"}]}`, want: true},
		{name: "packagist.org re-declared in a map", json: `{"repositories":{"packagist.org":{"type":"composer","url":"https://repo.packagist.org"}}}`, want: true},
		{name: "foreign satis", json: `{"repositories":[{"type":"composer","url":"https://satis.corp.internal"}]}`, want: true},
		{name: "chainsaw only", json: `{"repositories":[{"type":"composer","url":"` + ours + `"}]}`, want: false},
		{name: "vcs and packagist off", json: `{"repositories":[{"type":"vcs","url":"https://github.com/acme/x"},{"packagist.org":false}]}`, want: false},
		{name: "no repositories", json: `{"require":{"psr/log":"*"}}`, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, dir := doctorSandbox(t, "acme")
			writeT(t, filepath.Join(dir, "composer.json"), c.json)
			if got := projectIndexOverride("composer"); (got != "") != c.want {
				t.Fatalf("projectIndexOverride = %q, want finding=%v", got, c.want)
			}
		})
	}
}

// M12: uv and RubyGems env vars that route around the wired config.
func TestEnvDriftReasonNewWatches(t *testing.T) {
	home, _ := doctorSandbox(t, "acme")
	watch := func(key string) envWatch {
		for _, ws := range envOverrides {
			for _, w := range ws {
				if w.Key == key {
					return w
				}
			}
		}
		t.Fatalf("%s is not watched", key)
		return envWatch{}
	}
	for _, c := range []struct {
		key, val string
		drift    bool
	}{
		{"UV_INDEX", "foo=https://evil.example/simple/", true},
		{"UV_INDEX", "https://chain305.example.com/chainproxy/repository/@acme/pypi/simple/ evil=https://evil.example/simple/", true},
		{"UV_INDEX", "c=https://chain305.example.com/chainproxy/repository/@acme/pypi/simple/", false},
		{"UV_FIND_LINKS", "https://evil.example/links/", true},
		{"UV_EXTRA_INDEX_URL", "https://evil.example/simple/", true},
		{"UV_NO_INDEX", "1", true},
		{"UV_NO_INDEX", "false", false},
		{"UV_NO_CONFIG", "1", true},
		{"BUNDLE_MIRROR__ALL", "https://evil.example/", true},
		{"BUNDLE_IGNORE_CONFIG", "1", true},
	} {
		if got := envDriftReason(watch(c.key), c.val); (got != "") != c.drift {
			t.Errorf("%s=%s: reason %q, want drift=%v", c.key, c.val, got, c.drift)
		}
	}

	gemrc := filepath.Join(home, "ci-gemrc")
	writeT(t, gemrc, "---\n:sources:\n- https://gems.corp.internal/\n")
	t.Setenv("GEMRC", gemrc)
	if got := envDriftReason(watch("GEMRC"), gemrc); got == "" {
		t.Error("GEMRC naming a file with a foreign :sources: is not drift")
	}
	writeT(t, gemrc, "---\n:verbose: true\n")
	if got := envDriftReason(watch("GEMRC"), gemrc); got != "" {
		t.Errorf("GEMRC without :sources: reported as drift: %s", got)
	}
}
