package installscripts

import "testing"

// TestCargoFollowsCargosBuildScriptRule pins the published-manifest shapes.
// crates.io writes `build = false` into every crate without a build script,
// and the old "any line starting with build" test read that as one:
// cfg-if, pkg-config and wasm-bindgen-macro all raised
// install_script_appeared recalls in prod.
func TestCargoFollowsCargosBuildScriptRule(t *testing.T) {
	const fetch = "fn main() { std::process::Command::new(\"curl\").arg(\"http://x.invalid\").status().unwrap(); }"
	cases := []struct {
		name    string
		toml    string
		buildRs string
		want    bool
	}{
		{"build = false (cfg-if 1.0.4)", "[package]\nname = \"cfg-if\"\nbuild = false\n", "", false},
		{"build = false beats a build.rs on disk", "[package]\nbuild = false\n", fetch, false},
		{"build-dependencies alone run nothing", "[package]\nbuild = false\n\n[build-dependencies]\ncc = \"1\"\n", "", false},
		{"declared path", "[package]\nbuild = \"build.rs\"\n", "fn main() {}", true},
		{"declared path, script not supplied", "[package]\nbuild = \"src/build.rs\"\n", "", true},
		{"no key, root build.rs present", "[package]\nname = \"x\"\n", "fn main() {}", true},
		{"no key, no build.rs", "[package]\nname = \"x\"\n", "", false},
		{"build key outside [package] is not the build script", "[package]\nname = \"x\"\n[features]\nbuild = []\n", "", false},
		{"trailing comment", "[package]\nbuild = false # none\n", "", false},
	}
	for _, tc := range cases {
		var br []byte
		if tc.buildRs != "" {
			br = []byte(tc.buildRs)
		}
		if got := Cargo([]byte(tc.toml), br); got.HasInstallScript != tc.want {
			t.Errorf("%s: HasInstallScript = %v, want %v (%+v)", tc.name, got.HasInstallScript, tc.want, got)
		}
	}
	if got := Cargo([]byte("[package]\nbuild = false\n"), []byte(fetch)); got.InstallScriptFetchesRemote {
		t.Error("a disabled build.rs must not be scanned for remote fetches")
	}
}
