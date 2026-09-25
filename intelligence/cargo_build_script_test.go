package intelligence

import "testing"

// TestCargoBuildScriptIsTheCratesOwn: only the build script cargo would run
// is scanned — never a nested build.rs, never one the manifest disables.
func TestCargoBuildScriptIsTheCratesOwn(t *testing.T) {
	nested := map[string][]byte{
		"x-1.0.0/Cargo.toml":             []byte("[package]\nname = \"x\"\n"),
		"x-1.0.0/vendor/y/build.rs":      []byte("nested"),
		"x-1.0.0/examples/demo/build.rs": []byte("example"),
	}
	if got := cargoBuildScript(nested, nested["x-1.0.0/Cargo.toml"]); got != nil {
		t.Errorf("nested build.rs was taken as the crate's own: %q", got)
	}
	root := map[string][]byte{
		"x-1.0.0/Cargo.toml":        []byte("[package]\nname = \"x\"\n"),
		"x-1.0.0/build.rs":          []byte("root"),
		"x-1.0.0/vendor/y/build.rs": []byte("nested"),
	}
	if got := string(cargoBuildScript(root, root["x-1.0.0/Cargo.toml"])); got != "root" {
		t.Errorf("root build.rs: got %q", got)
	}
	declared := map[string][]byte{
		"x-1.0.0/Cargo.toml":   []byte("[package]\nbuild = \"tools/gen.rs\"\n"),
		"x-1.0.0/tools/gen.rs": []byte("declared"),
		"x-1.0.0/build.rs":     []byte("not-used"),
	}
	if got := string(cargoBuildScript(declared, declared["x-1.0.0/Cargo.toml"])); got != "declared" {
		t.Errorf("declared build path: got %q", got)
	}
	disabled := map[string][]byte{
		"x-1.0.0/Cargo.toml": []byte("[package]\nbuild = false\n"),
		"x-1.0.0/build.rs":   []byte("root"),
	}
	if got := cargoBuildScript(disabled, disabled["x-1.0.0/Cargo.toml"]); got != nil {
		t.Errorf("build = false still returned a script: %q", got)
	}
}
