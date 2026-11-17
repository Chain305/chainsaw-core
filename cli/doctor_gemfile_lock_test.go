package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// Bundler's mirror leaves Gemfile.lock saying `remote: https://rubygems.org/`
// by design. doctor --strict must not call that a bypass when the mirror in
// effect is this Chainsaw server — and must keep calling it one otherwise.
func TestGemfileLockRemoteJudgedByBundlerMirror(t *testing.T) {
	const mirrorKey = "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/"
	cases := []struct {
		name    string
		mirror  string // "" = no ~/.bundle/config mirror
		server  string
		wantHit bool
	}{
		{"no mirror", "", rewriteTestServer, true},
		{"mirror at this chainsaw", rewriteTestServer + "/repository/@acme/rubygems/", rewriteTestServer, false},
		{"mirror elsewhere", "https://gems.corp.internal/", rewriteTestServer, true},
		{"mirror at chainsaw but wrong repo", rewriteTestServer + "/repository/@acme/npmjs/", rewriteTestServer, true},
		{"server unknown", rewriteTestServer + "/repository/@acme/rubygems/", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			for _, k := range []string{"BUNDLE_USER_CONFIG", "BUNDLE_USER_HOME", "BUNDLE_APP_CONFIG"} {
				t.Setenv(k, "")
			}
			t.Setenv("CHAINSAW_SERVER", c.server)
			viper.Set("server_url", "")
			viper.Set("org_slug", "acme")
			t.Cleanup(func() { viper.Set("org_slug", "") })
			dir := t.TempDir()
			wd, _ := os.Getwd()
			t.Cleanup(func() { _ = os.Chdir(wd) })
			if err := os.Chdir(dir); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile("Gemfile.lock", []byte("GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.2.1)\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if c.mirror != "" {
				cfg := filepath.Join(home, ".bundle", "config")
				_ = os.MkdirAll(filepath.Dir(cfg), 0o755)
				if err := os.WriteFile(cfg, []byte("---\n"+mirrorKey+": \""+c.mirror+"\"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			hit := false
			for _, h := range scanLockfilesForPublicSources() {
				if strings.HasPrefix(h, "Gemfile.lock") {
					hit = true
				}
			}
			if hit != c.wantHit {
				t.Fatalf("Gemfile.lock flagged = %v, want %v", hit, c.wantHit)
			}
		})
	}
}
