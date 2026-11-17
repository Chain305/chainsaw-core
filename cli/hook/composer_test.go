package hook

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func composerSandbox(t *testing.T) (home string) {
	t.Helper()
	home = sandboxHome(t)
	t.Setenv("COMPOSER_HOME", "")
	old := composerEtcXDG
	composerEtcXDG = filepath.Join(home, "no-etc-xdg")
	t.Cleanup(func() { composerEtcXDG = old })
	return home
}

// composerRepoOrderAndPackagist decodes config.json the way Composer reads
// its repositories: an ordered, keyed object.
func composerRepoOrderAndPackagist(t *testing.T, data []byte) {
	t.Helper()
	obj, err := parseJSONObject(data)
	if err != nil {
		t.Fatalf("config.json does not parse: %v\n%s", err, data)
	}
	raw, ok := obj.get("repositories")
	if !ok {
		t.Fatalf("no repositories:\n%s", data)
	}
	repos, err := parseJSONObject(raw)
	if err != nil {
		t.Fatalf("repositories is not an object: %v", err)
	}
	var keys []string
	for _, f := range repos {
		keys = append(keys, f.Key)
	}
	if got := strings.Join(keys, ","); got != "private,chainsaw,packagist.org" {
		t.Fatalf("repository order = %s, want the user's own first (Composer queries in order)\n%s", got, data)
	}
	if u := repoURLOf(mustGet(t, repos, "chainsaw")); u != "https://chain305.com/repository/@acme-corp/packagist/" {
		t.Fatalf("chainsaw url = %q", u)
	}
	if p := string(mustGet(t, repos, "packagist.org")); p != "false" {
		t.Fatalf("packagist.org = %s, want false", p)
	}
}

func mustGet(t *testing.T, o jsonObject, k string) json.RawMessage {
	t.Helper()
	v, ok := o.get(k)
	if !ok {
		t.Fatalf("missing %q", k)
	}
	return v
}

func TestComposerHomeResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX layout")
	}
	home := composerSandbox(t)
	// sandboxHome leaves XDG_CONFIG_HOME set (to ""): Composer counts ANY
	// XDG_* variable, so the XDG candidate comes first and, with neither
	// directory present, wins.
	if got, _ := composerHome(); got != filepath.Join(home, ".config", "composer") {
		t.Errorf("XDG host, nothing on disk: %s", got)
	}
	// ~/.composer existing beats an absent XDG dir.
	_ = os.MkdirAll(filepath.Join(home, ".composer"), 0o755)
	if got, _ := composerHome(); got != filepath.Join(home, ".composer") {
		t.Errorf("existing ~/.composer: %s", got)
	}
	// Both exist: XDG first.
	_ = os.MkdirAll(filepath.Join(home, ".config", "composer"), 0o755)
	if got, _ := composerHome(); got != filepath.Join(home, ".config", "composer") {
		t.Errorf("both exist: %s", got)
	}
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	if got, _ := composerHome(); got != filepath.Join(home, ".composer") {
		t.Errorf("XDG_CONFIG_HOME=/xdg (absent) with ~/.composer present: %s", got)
	}
	t.Setenv("COMPOSER_HOME", "/ch")
	if got, _ := composerHome(); got != "/ch" {
		t.Errorf("COMPOSER_HOME: %s", got)
	}
}

// A macOS-shaped host: no XDG_* variable at all and no /etc/xdg.
func TestComposerHomeWithoutXDG(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX layout")
	}
	home := composerSandbox(t)
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "XDG_") {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
	}
	if got, _ := composerHome(); got != filepath.Join(home, ".composer") {
		t.Errorf("no XDG signal: %s, want ~/.composer", got)
	}
	_ = os.MkdirAll(composerEtcXDG, 0o755)
	if got, _ := composerHome(); got != filepath.Join(home, ".config", "composer") {
		t.Errorf("/etc/xdg present: %s, want ~/.config/composer", got)
	}
}

func TestComposerRefusesProjectScope(t *testing.T) {
	composerSandbox(t)
	opts := testWireOpts()
	opts.Scope = ScopeProject
	if err := (composerManager{}).Wire(opts); err == nil {
		t.Fatal("project scope accepted; composer.json is committed")
	}
	if err := (composerManager{}).Unwire(ScopeProject); !errors.Is(err, ErrNotWired) {
		t.Fatalf("Unwire(project) = %v, want ErrNotWired", err)
	}
}

func TestComposerCredentialsLandInAuthJSONOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	composerSandbox(t)
	m := composerManager{}
	cfg, _ := m.ConfigPath()
	authPath := filepath.Join(filepath.Dir(cfg), "auth.json")
	writeSeed(t, authPath, `{"github-oauth": {"github.com": "ghp_x"}}`)
	opts := testWireOpts()
	opts.Credentials = testCreds
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	c, _ := os.ReadFile(cfg)
	if strings.Contains(string(c), "s3cr3t") {
		t.Fatalf("secret in config.json:\n%s", c)
	}
	a, _ := os.ReadFile(authPath)
	var doc map[string]map[string]any
	if err := json.Unmarshal(a, &doc); err != nil {
		t.Fatal(err)
	}
	entry, _ := doc["http-basic"]["chain305.com"].(map[string]any)
	if entry["username"] != "cli-abc" || entry["password"] != "s3cr3t-value" {
		t.Fatalf("http-basic entry = %v\n%s", entry, a)
	}
	if doc["github-oauth"]["github.com"] != "ghp_x" {
		t.Fatalf("user's github-oauth lost:\n%s", a)
	}
	if info, _ := os.Stat(authPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("auth.json mode %04o, want 0600", info.Mode().Perm())
	}
	if paths, _ := ConfigPathsForScope(m, ScopeUser); len(paths) != 2 || paths[1] != authPath {
		t.Fatalf("ConfigPathsForScope = %v; auth.json backups would go unreported", paths)
	}
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatal(err)
	}
	a, _ = os.ReadFile(authPath)
	if strings.Contains(string(a), "s3cr3t") || !strings.Contains(string(a), "ghp_x") {
		t.Fatalf("Unwire left auth.json as:\n%s", a)
	}
}

func TestComposerRefusals(t *testing.T) {
	for name, tc := range map[string]struct{ cfg, auth string }{
		"composer repo ahead":      {cfg: `{"repositories": [{"name": "corp", "type": "composer", "url": "https://satis.corp/"}]}`},
		"foreign chainsaw repo":    {cfg: `{"repositories": {"chainsaw": {"type": "composer", "url": "https://elsewhere/"}}}`},
		"packagist mirror":         {cfg: `{"repositories": {"packagist.org": {"type": "composer", "url": "https://mirror.corp/"}}}`},
		"invalid json":             {cfg: `{"repositories": `},
		"foreign http-basic entry": {cfg: `{}`, auth: `{"http-basic": {"chain305.com": {"username": "x", "password": "y"}}}`},
	} {
		t.Run(name, func(t *testing.T) {
			composerSandbox(t)
			m := composerManager{}
			cfg, _ := m.ConfigPath()
			authPath := filepath.Join(filepath.Dir(cfg), "auth.json")
			writeSeed(t, cfg, tc.cfg)
			if tc.auth != "" {
				writeSeed(t, authPath, tc.auth)
			}
			opts := testWireOpts()
			opts.Credentials = testCreds
			err := m.Wire(opts)
			if err == nil {
				t.Fatal("Wire accepted a config it cannot own safely")
			}
			if got, _ := os.ReadFile(cfg); string(got) != tc.cfg {
				t.Fatalf("refused but modified config.json:\n%s", got)
			}
			if tc.auth != "" {
				if got, _ := os.ReadFile(authPath); string(got) != tc.auth {
					t.Fatalf("refused but modified auth.json:\n%s", got)
				}
			}
		})
	}
}

// The user turned packagist off themselves: unwire must leave it off.
func TestComposerUnwireKeepsUserPackagistFalse(t *testing.T) {
	composerSandbox(t)
	m := composerManager{}
	cfg, _ := m.ConfigPath()
	writeSeed(t, cfg, `{"repositories": {"packagist.org": false}}`)
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(cfg)
	if !strings.Contains(string(got), `"packagist.org": false`) || strings.Contains(string(got), "chainsaw") {
		t.Fatalf("after Unwire:\n%s", got)
	}
}

// Re-enabling Packagist by hand is a bypass; Status must say so.
func TestComposerStatusNeedsPackagistOff(t *testing.T) {
	composerSandbox(t)
	m := composerManager{}
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	cfg, _ := m.ConfigPath()
	data, _ := os.ReadFile(cfg)
	writeSeed(t, cfg, strings.Replace(string(data), `"packagist.org": false`, `"packagist.org": true`, 1))
	if st, _ := m.Status(); st.Wired {
		t.Fatal("Status wired with Packagist re-enabled")
	}
}

// Rotating the credential replaces our entry; a value the user edited after
// we wrote it is theirs, and Unwire leaves it.
func TestComposerAuthOwnership(t *testing.T) {
	composerSandbox(t)
	m := composerManager{}
	cfg, _ := m.ConfigPath()
	authPath := filepath.Join(filepath.Dir(cfg), "auth.json")
	opts := testWireOpts()
	opts.Credentials = testCreds
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	opts.Credentials = "cli-abc:rotated-value"
	if err := m.Wire(opts); err != nil {
		t.Fatalf("re-Wire with a rotated secret: %v", err)
	}
	a, _ := os.ReadFile(authPath)
	if strings.Contains(string(a), "s3cr3t") || !strings.Contains(string(a), "rotated-value") {
		t.Fatalf("rotation did not replace our entry:\n%s", a)
	}
	writeSeed(t, authPath, strings.Replace(string(a), "rotated-value", "users-own", 1))
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatal(err)
	}
	if a, _ = os.ReadFile(authPath); !strings.Contains(string(a), "users-own") {
		t.Fatalf("Unwire deleted a credential the user changed:\n%s", a)
	}
}

func TestComposerStatusIgnoresOtherManagers(t *testing.T) {
	composerSandbox(t)
	if err := (npmManager{}).Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	if st, _ := (composerManager{}).Status(); st.Wired {
		t.Fatalf("composer reports wired; %s was never written", st.ConfigPath)
	}
}
