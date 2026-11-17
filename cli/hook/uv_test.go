package hook

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// uvDefaultIndexIsChainsaw decodes the file the way uv would and requires the
// single default index to be chainsaw's — at the TOP level, not swallowed by
// the user's last table.
func uvDefaultIndexIsChainsaw(t *testing.T, data []byte) {
	t.Helper()
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		t.Fatalf("uv.toml does not parse: %v\n%s", err, data)
	}
	idx, ok := doc["index"].([]map[string]any)
	if !ok || len(idx) != 1 {
		t.Fatalf("want exactly one top-level [[index]], got %#v\n%s", doc["index"], data)
	}
	if idx[0]["default"] != true || !strings.Contains(idx[0]["url"].(string), "/repository/@acme-corp/pypi/simple/") {
		t.Fatalf("[[index]] is not chainsaw's default index: %#v", idx[0])
	}
	if pip, ok := doc["pip"].(map[string]any); ok {
		for _, k := range []string{"index", "url", "default", "index-url"} {
			if _, bad := pip[k]; bad {
				t.Fatalf("chainsaw's index landed inside the user's [pip] table (%q)\n%s", k, data)
			}
		}
	}
}

func TestUVConfigPathResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX layout")
	}
	home := sandboxHome(t)
	m := uvManager{}
	got, _ := m.ConfigPath()
	if want := filepath.Join(home, ".config", "uv", "uv.toml"); got != want {
		t.Errorf("default user path = %s, want %s (uv uses ~/.config on macOS too)", got, want)
	}
	t.Setenv("XDG_CONFIG_HOME", "/x")
	if got, _ := m.ConfigPath(); got != "/x/uv/uv.toml" {
		t.Errorf("XDG path = %s", got)
	}
	t.Setenv("UV_CONFIG_FILE", "/y/custom.toml")
	if got, _ := m.ConfigPath(); got != "/y/custom.toml" {
		t.Errorf("UV_CONFIG_FILE not honoured: %s", got)
	}
}

// A pip wire must never make `status` report uv as wired: uv does not read
// pip.conf, and that false "wired" is the bug this manager exists to close.
func TestUVStatusIgnoresPipConfig(t *testing.T) {
	sandboxHome(t)
	if err := (pipManager{}).Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	st, err := uvManager{}.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Wired {
		t.Fatalf("uv reports wired from pip's config; uv.toml at %s was never written", st.ConfigPath)
	}
}

func TestUVRefusesForeignDefaultIndex(t *testing.T) {
	for name, seed := range map[string]string{
		"legacy index-url":    "index-url = \"https://mirror.internal/simple\"\n",
		"other default index": "[[index]]\nname = \"corp\"\nurl = \"https://mirror.internal/simple\"\ndefault = true\n",
		"inline index array":  "index = [{ name = \"corp\", url = \"https://mirror.internal/simple\" }]\n",
	} {
		t.Run(name, func(t *testing.T) {
			sandboxHome(t)
			m := uvManager{}
			path, _ := m.ConfigPath()
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
				t.Fatal(err)
			}
			err := m.Wire(testWireOpts())
			if err == nil {
				t.Fatal("Wire accepted a file that already chooses a default index")
			}
			if after, _ := os.ReadFile(path); string(after) != seed {
				t.Fatalf("refused but modified the file:\n%s", after)
			}
		})
	}
}

// A non-default user index is fine: uv tries it, then falls back to ours.
func TestUVKeepsNonDefaultUserIndex(t *testing.T) {
	sandboxHome(t)
	m := uvManager{}
	path, _ := m.ConfigPath()
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	seed := "[[index]]\nname = \"torch\"\nurl = \"https://download.pytorch.org/whl/cpu\"\nexplicit = true\n"
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	data, _ := os.ReadFile(path)
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		t.Fatal(err)
	}
	if idx := doc["index"].([]map[string]any); len(idx) != 2 {
		t.Fatalf("want user's index + chainsaw's, got %v", idx)
	}
}

func TestUVCredentialsInURLAndFileRestricted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	sandboxHome(t)
	m := uvManager{}
	opts := testWireOpts()
	opts.Credentials = testCreds
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	path, _ := m.ConfigPath()
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `url = "https://cli-abc:s3cr3t-value@chain305.com/repository/@acme-corp/pypi/simple/"`) {
		t.Fatalf("credentialed index url missing:\n%s", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestUVProjectScopeRefusesToShadowToolUV(t *testing.T) {
	sandboxHome(t)
	dir := t.TempDir()
	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("pyproject.toml", []byte("[project]\nname = \"x\"\n\n[tool.uv]\ndev-dependencies = []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := testWireOpts()
	opts.Scope = ScopeProject
	err := uvManager{}.Wire(opts)
	if err == nil || !strings.Contains(err.Error(), "[tool.uv]") {
		t.Fatalf("Wire = %v, want a refusal naming [tool.uv]", err)
	}
	if _, serr := os.Stat("uv.toml"); !os.IsNotExist(serr) {
		t.Fatal("uv.toml was created next to a pyproject.toml with [tool.uv]")
	}
}
