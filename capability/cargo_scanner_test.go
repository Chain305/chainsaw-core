package capability_test

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/capability"
)

func TestScanCargo(t *testing.T) {
	t.Parallel()
	rs := func(src string) map[string]string { return map[string]string{"src/lib.rs": src} }
	runNativeCases(t, "cargo", []nativeCase{
		// positives
		{name: "use std::process::Command", files: rs("use std::process::Command;\nfn f() { Command::new(\"sh\").status(); }\n"), want: []capability.Capability{capability.CapShell}},
		{name: "full path Command", files: rs("fn f() { std::process::Command::new(\"sh\"); }\n"), want: []capability.Capability{capability.CapShell}},
		{name: "grouped use", files: rs("use std::process::{Stdio, Command};\n"), want: []capability.Capability{capability.CapShell}},
		{name: "tokio process", files: rs("fn f() { tokio::process::Command::new(\"sh\"); }\n"), want: []capability.Capability{capability.CapShell}},
		{name: "env::var", files: rs("fn f() { let _ = std::env::var(\"HOME\"); }\n"), want: []capability.Capability{capability.CapEnvAccess}},
		{name: "env! of a non-cargo name", files: rs("const K: &str = env!(\"API_KEY\");\n"), want: []capability.Capability{capability.CapEnvAccess}},
		{name: "option_env!", files: rs("const K: Option<&str> = option_env!(\"TOKEN\");\n"), want: []capability.Capability{capability.CapEnvAccess}},
		{name: "fs::write", files: rs("fn f() { std::fs::write(\"x\", b\"y\").unwrap(); }\n"), want: []capability.Capability{capability.CapFilesystemWrite}},
		{name: "File::create", files: rs("fn f() { File::create(\"x\").unwrap(); }\n"), want: []capability.Capability{capability.CapFilesystemWrite}},
		{name: "fs::read_to_string", files: rs("fn f() { fs::read_to_string(\"x\").unwrap(); }\n"), want: []capability.Capability{capability.CapFilesystemRead}},
		{name: "TcpStream", files: rs("fn f() { TcpStream::connect(\"x:1\").unwrap(); }\n"), want: []capability.Capability{capability.CapNetwork}},
		{name: "reqwest", files: rs("async fn f() { reqwest::get(\"https://x\").await; }\n"), want: []capability.Capability{capability.CapNetwork}},
		{name: "FFI block", files: rs("extern \"C\" {\n    fn abs(x: i32) -> i32;\n}\n"), want: []capability.Capability{capability.CapNativeCode}},
		{name: "links key", files: map[string]string{"Cargo.toml": "[package]\nname = \"x-sys\"\nlinks = \"x\"\n", "src/lib.rs": "\n"}, want: []capability.Capability{capability.CapNativeCode}},
		{name: "prebuilt lib", files: map[string]string{"lib/x.lib": "\x00", "src/lib.rs": "\n"}, want: []capability.Capability{capability.CapNativeCode}},
		{name: "libloading", files: rs("fn f() { unsafe { libloading::Library::new(\"x.so\") }; }\n"), want: []capability.Capability{capability.CapDynamicEval}},
		{name: "code after a closed cfg(test) module", files: rs("#[cfg(test)]\nmod tests {\n    fn t() { let s = \"}\"; }\n}\nfn f() { std::fs::write(\"x\", \"y\").unwrap(); }\n"),
			want: []capability.Capability{capability.CapFilesystemWrite}},

		// false-positive traps
		{name: "clap Command", files: rs("use clap::Command;\nfn f() { Command::new(\"app\"); }\n"), absent: nativeAllCaps},
		{name: "CommandExt is not Command", files: rs("use std::os::unix::process::CommandExt;\n"), absent: nativeAllCaps},
		{name: "cargo-provided env", files: rs("const V: &str = env!(\"CARGO_PKG_VERSION\");\ninclude!(concat!(env!(\"OUT_DIR\"), \"/x.rs\"));\nfn f() { let _ = std::env::var(\"OUT_DIR\"); }\n"), absent: nativeAllCaps},
		{name: "comments and doc comments", files: rs("// std::process::Command::new(\"sh\")\n/// std::env::var(\"X\")\n//! fs::write(\"x\", \"y\")\n/*\n extern \"C\" {\n*/\nfn f() {}\n"), absent: nativeAllCaps},
		{name: "cfg(test) module", files: rs("fn f() {}\n\n#[cfg(test)]\n#[allow(unused)]\nmod tests {\n    use super::*;\n    #[test]\n    fn t() {\n        std::fs::write(\"x\", \"{\").unwrap();\n        let _ = std::env::var(\"HOME\");\n    }\n}\n"), absent: nativeAllCaps},
		{name: "cfg(all(test, ..)) item", files: rs("#[cfg(all(test, not(loom)))]\nuse std::process::{Command, Output};\n"), absent: nativeAllCaps},
		{name: "wasm_bindgen extern block", files: rs("use wasm_bindgen::prelude::*;\n#[wasm_bindgen]\nextern \"C\" {\n    fn alert(s: &str);\n}\n"), absent: nativeAllCaps},
		{name: "extern C fn definition", files: rs("#[no_mangle]\npub extern \"C\" fn callback(x: i32) -> i32 { x }\n"), absent: nativeAllCaps},
		{name: "skipped dirs", files: map[string]string{"tests/it.rs": "fn f() { std::process::Command::new(\"sh\"); }\n", "benches/b.rs": "fn f() { std::fs::write(\"x\", \"y\"); }\n", "examples/e.rs": "fn f() { std::env::var(\"X\"); }\n"}, absent: nativeAllCaps},
	})
}

// The build script runs on the machine that builds the crate; its evidence says so.
func TestScanCargo_BuildScriptLabelled(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, manifest, file string }{
		{"default build.rs", "[package]\nname = \"x\"\n", "build.rs"},
		{"custom build path", "[package]\nname = \"x\"\nbuild = \"build/main.rs\"\n", "build/find.rs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			writeTestFile(t, dir, "Cargo.toml", tc.manifest)
			writeTestFile(t, dir, "build/main.rs", "fn main() {}\n")
			writeTestFile(t, dir, tc.file, "fn main() { cc::Build::new().file(\"x.c\").compile(\"x\"); }\n")
			writeTestFile(t, dir, "src/lib.rs", "fn f() { std::process::Command::new(\"x\"); }\n")
			rep, err := capability.Analyze(dir, "crates")
			if err != nil {
				t.Fatal(err)
			}
			ev := rep.Capabilities[capability.CapNativeCode]
			if len(ev) != 1 || ev[0].File != tc.file || !strings.HasPrefix(ev[0].Snippet, "build script: ") {
				t.Fatalf("native evidence = %+v", ev)
			}
			if sh := rep.Capabilities[capability.CapShell]; len(sh) != 1 || strings.HasPrefix(sh[0].Snippet, "build script") {
				t.Fatalf("src/ evidence labelled as build script: %+v", sh)
			}
		})
	}
}
