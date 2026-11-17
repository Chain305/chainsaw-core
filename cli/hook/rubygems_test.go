package hook

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const wantRubygemsSource = "https://chain305.com/repository/@acme-corp/rubygems/"

// bundlerValues reads the file the way Bundler's YAMLSerializer does.
func bundlerValues(data []byte) map[string]string {
	out := map[string]string{}
	lines, _ := splitLines(data)
	for _, ln := range lines {
		if k, v, ok := parseBundlerLine(ln); ok {
			out[k] = v
		}
	}
	return out
}

func bundlerMirrorIsChainsaw(t *testing.T, data []byte) {
	t.Helper()
	if got := bundlerValues(data)[bundlerMirrorKey]; got != wantRubygemsSource {
		t.Fatalf("%s = %q, want %q\n%s", bundlerMirrorKey, got, wantRubygemsSource, data)
	}
	if strings.Contains(string(data), "FALLBACK_TIMEOUT") {
		t.Fatalf("a mirror fallback_timeout lets Bundler fall back to rubygems.org:\n%s", data)
	}
}

func gemSourcesAreOnlyChainsaw(t *testing.T, data []byte) {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("gemrc does not parse: %v\n%s", err, data)
	}
	src, _ := doc[":sources"].([]any)
	if len(src) != 1 || !strings.HasSuffix(src[0].(string), "chain305.com/repository/@acme-corp/rubygems/") {
		t.Fatalf(":sources: = %v, want only the chainsaw source\n%s", src, data)
	}
}

func writeSeed(t *testing.T, path, seed string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBundlerKeyDerivation(t *testing.T) {
	if got := bundlerKeyFor("chain-305.example.com"); got != "BUNDLE_CHAIN___305__EXAMPLE__COM" {
		t.Fatalf("got %s", got)
	}
	if got := bundlerSettingName(bundlerMirrorKey); got != "mirror.https://rubygems.org" {
		t.Fatalf("got %s", got)
	}
}

func TestBundlerConfigPathResolution(t *testing.T) {
	home := sandboxHome(t)
	m := bundlerManager{}
	if got, _ := m.ConfigPath(); got != filepath.Join(home, ".bundle", "config") {
		t.Errorf("default = %s", got)
	}
	t.Setenv("BUNDLE_USER_HOME", "/bh")
	if got, _ := m.ConfigPath(); got != filepath.Join("/bh", "config") {
		t.Errorf("BUNDLE_USER_HOME = %s", got)
	}
	t.Setenv("BUNDLE_USER_CONFIG", "/bc/cfg")
	if got, _ := m.ConfigPath(); got != "/bc/cfg" {
		t.Errorf("BUNDLE_USER_CONFIG = %s", got)
	}
	if _, err := m.ConfigPathForScope(ScopeProject); err == nil {
		t.Error("project scope accepted; a project .bundle/config is often committed")
	}
}

// Bundler rewrites the whole file on `bundle config set`, dropping our
// markers. Ownership must survive that, and Unwire must remove ONLY ours.
func TestBundlerOwnershipSurvivesBundlerRewrite(t *testing.T) {
	sandboxHome(t)
	m := bundlerManager{}
	path, _ := m.ConfigPath()
	opts := testWireOpts()
	opts.Credentials = testCreds
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	// What `bundle config set --global jobs 8` leaves behind: same keys, no
	// comments, quoted with String#inspect.
	rewritten := "---\nBUNDLE_JOBS: \"8\"\n" + bundlerMirrorKey + ": \"" + wantRubygemsSource + "\"\nBUNDLE_CHAIN305__COM: \"" + testCreds + "\"\n"
	writeSeed(t, path, rewritten)
	if st, _ := m.Status(); !st.Wired {
		t.Fatal("Status lost the wire after a Bundler rewrite")
	}
	if err := m.Wire(opts); err != nil {
		t.Fatalf("re-Wire after a Bundler rewrite: %v", err)
	}
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	vals := bundlerValues(got)
	if vals["BUNDLE_JOBS"] != "8" || len(vals) != 1 {
		t.Fatalf("Unwire left %v, want only the user's BUNDLE_JOBS\n%s", vals, got)
	}
}

func TestBundlerRefusesForeignMirrorAndCredential(t *testing.T) {
	for name, seed := range map[string]string{
		"corporate mirror":        "---\n" + bundlerMirrorKey + ": \"https://gems.corp.internal/\"\n",
		"hand-pasted same mirror": "---\n" + bundlerMirrorKey + ": \"" + wantRubygemsSource + "\"\n",
		"hand-pasted credential":  "---\nBUNDLE_CHAIN305__COM: \"someone:else\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			sandboxHome(t)
			m := bundlerManager{}
			path, _ := m.ConfigPath()
			writeSeed(t, path, seed)
			opts := testWireOpts()
			opts.Credentials = testCreds
			if err := m.Wire(opts); err == nil {
				t.Fatal("Wire overwrote a mirror/credential chainsaw did not write")
			}
			if got, _ := os.ReadFile(path); string(got) != seed {
				t.Fatalf("refused but modified:\n%s", got)
			}
			// And Unwire must not delete what the user set.
			if err := m.Unwire(ScopeUser); !errors.Is(err, ErrNotWired) {
				t.Fatalf("Unwire = %v, want ErrNotWired", err)
			}
			if got, _ := os.ReadFile(path); string(got) != seed {
				t.Fatalf("Unwire removed a user-owned key:\n%s", got)
			}
		})
	}
}

// A user who edits OUR mirror value after wiring now owns it; Unwire leaves it.
func TestBundlerUnwireLeavesAValueTheUserChanged(t *testing.T) {
	sandboxHome(t)
	m := bundlerManager{}
	path, _ := m.ConfigPath()
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	writeSeed(t, path, "---\n"+bundlerMirrorKey+": \"https://gems.corp.internal/\"\n")
	if st, _ := m.Status(); st.Wired {
		t.Fatal("Status says wired although the mirror points elsewhere")
	}
	if err := m.Unwire(ScopeUser); !errors.Is(err, ErrNotWired) {
		t.Fatalf("Unwire = %v, want ErrNotWired", err)
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "gems.corp.internal") {
		t.Fatalf("user's mirror removed:\n%s", got)
	}
}

func TestBundlerStatusIgnoresGemrc(t *testing.T) {
	sandboxHome(t)
	if err := (gemManager{}).Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	if st, _ := (bundlerManager{}).Status(); st.Wired {
		t.Fatalf("bundler reports wired from ~/.gemrc; %s was never written", st.ConfigPath)
	}
	sandboxHome(t)
	if err := (bundlerManager{}).Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	if st, _ := (gemManager{}).Status(); st.Wired {
		t.Fatalf("gem reports wired from ~/.bundle/config; %s was never written", st.ConfigPath)
	}
}

func TestBundlerRubygemsMirrorPrecedence(t *testing.T) {
	home := sandboxHome(t)
	dir := t.TempDir()
	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	_ = os.Chdir(dir)
	if BundlerRubygemsRoute().Mirror != "" {
		t.Fatal("mirror reported with no config at all")
	}
	writeSeed(t, filepath.Join(home, ".bundle", "config"), "---\n"+bundlerMirrorKey+": \"https://global/\"\n")
	if v := BundlerRubygemsRoute().Mirror; v != "https://global/" {
		t.Fatalf("global mirror = %q", v)
	}
	writeSeed(t, filepath.Join(dir, ".bundle", "config"), "---\nBUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG: \"https://local/\"\n")
	if v := BundlerRubygemsRoute().Mirror; v != "https://local/" {
		t.Fatalf("local app config must win over global, got %q", v)
	}
}

func TestGemConfigPathResolution(t *testing.T) {
	home := sandboxHome(t)
	m := gemManager{}
	if got, _ := m.ConfigPath(); got != filepath.Join(home, ".gemrc") {
		t.Errorf("default = %s", got)
	}
	// RubyGems 3.0 (macOS system Ruby) reads only ~/.gemrc, so the XDG file
	// is never the target; with only that file present, Wire refuses.
	xdg := filepath.Join(home, ".config", "gem", "gemrc")
	writeSeed(t, xdg, "---\n:verbose: true\n")
	if got, _ := m.ConfigPath(); got != filepath.Join(home, ".gemrc") {
		t.Errorf("with only the XDG file present, got %s", got)
	}
	if err := m.Wire(testWireOpts()); !errors.Is(err, ErrRefused) {
		t.Fatalf("Wire with only the XDG gemrc = %v, want a refusal", err)
	}
	if fileExists(filepath.Join(home, ".gemrc")) {
		t.Fatal("refused but created ~/.gemrc")
	}
	writeSeed(t, filepath.Join(home, ".gemrc"), "---\n")
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatalf("Wire with ~/.gemrc present: %v", err)
	}
}

// Files in $GEMRC are merged over ~/.gemrc: one that sets :sources: wins.
func TestGemStatusHonoursGEMRC(t *testing.T) {
	home := sandboxHome(t)
	m := gemManager{}
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	if st, _ := m.Status(); !st.Wired {
		t.Fatal("not wired after Wire")
	}
	other := filepath.Join(home, "ci-gemrc")
	writeSeed(t, other, "---\n:sources:\n- https://gems.corp.internal/\n")
	t.Setenv("GEMRC", other)
	if st, _ := m.Status(); st.Wired {
		t.Fatal("Status says wired while $GEMRC overrides :sources:")
	}
	if p, srcs, ok := GemSources(); !ok || p != other || len(srcs) != 1 || srcs[0] != "https://gems.corp.internal/" {
		t.Fatalf("GemSources = %s %v %v", p, srcs, ok)
	}
	writeSeed(t, other, "---\n:verbose: true\n")
	if st, _ := m.Status(); !st.Wired {
		t.Fatal("a $GEMRC file without :sources: does not override ~/.gemrc")
	}
}

func TestGemRefusesNonDefaultSources(t *testing.T) {
	for name, seed := range map[string]string{
		"corporate mirror":   "---\n:sources:\n- https://gems.corp.internal/\n",
		"default plus extra": "---\n:sources:\n- https://rubygems.org/\n- https://gems.corp.internal/\n",
		"inline list":        "---\n:sources: [https://gems.corp.internal/]\n",
	} {
		t.Run(name, func(t *testing.T) {
			sandboxHome(t)
			m := gemManager{}
			path, _ := m.ConfigPath()
			writeSeed(t, path, seed)
			if err := m.Wire(testWireOpts()); err == nil {
				t.Fatal("Wire replaced a source list the user chose")
			}
			if got, _ := os.ReadFile(path); string(got) != seed {
				t.Fatalf("refused but modified:\n%s", got)
			}
		})
	}
}

// `gem sources --add X` rewrites ~/.gemrc: markers gone, our source still
// listed beside X. Unwire removes ours and keeps X.
func TestGemUnwireAfterGemRewrite(t *testing.T) {
	sandboxHome(t)
	m := gemManager{}
	path, _ := m.ConfigPath()
	opts := testWireOpts()
	opts.Credentials = testCreds
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	src, _, _ := rubygemsSourceURL(opts, true)
	writeSeed(t, path, "---\n:sources:\n- "+src+"\n")
	if st, _ := m.Status(); !st.Wired {
		t.Fatal("Status lost the wire after a gem rewrite")
	}
	writeSeed(t, path, "---\n:sources:\n- "+src+"\n- https://gems.corp.internal/\n:verbose: true\n")
	if st, _ := m.Status(); st.Wired {
		t.Fatal("Status says wired while gem also resolves from gems.corp.internal")
	}
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if strings.Contains(string(got), "chain305.com") || !strings.Contains(string(got), "gems.corp.internal") || !strings.Contains(string(got), ":verbose: true") {
		t.Fatalf("Unwire after rewrite:\n%s", got)
	}
}

func TestGemCredentialInSourceURL(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	sandboxHome(t)
	m := gemManager{}
	opts := testWireOpts()
	opts.Credentials = testCreds
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	path, _ := m.ConfigPath()
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"https://cli-abc:s3cr3t-value@chain305.com/repository/@acme-corp/rubygems/"`) {
		t.Fatalf("credentialed source missing:\n%s", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o", info.Mode().Perm())
	}
	side, err := os.ReadFile(ownedSidecarPath(path))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(side), "s3cr3t") {
		t.Fatalf("the ownership record copies the secret:\n%s", side)
	}
}
