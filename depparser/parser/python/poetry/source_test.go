package poetry

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
	"unsafe"
)

type row struct{ Name, Version, Origin, Hash string }

func parseFixture(t *testing.T, path string) []row {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pkgs, _, err := NewParser().Parse(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	var out []row
	for _, p := range pkgs {
		out = append(out, row{p.Name, p.Version, p.Origin, p.Hash})
	}
	return out
}

// TestSourceOrigin: real poetry.lock packages (poketwo/poketwo git,
// hhru/frontik devpi mirror and private devpi index, OpenMined/PipelineDP a
// legacy source that is pypi.org) plus poetry's other source types. A git
// package used to be scored as its PyPI namesake; a legacy index is the
// registry protocol on another host ("registry+<url>", decided by hash);
// pypi.org under a legacy source is PyPI. Break it like this: return "" from
// sourceOrigin for type "git".
func TestSourceOrigin(t *testing.T) {
	want := []row{
		{"discord-ext-menus", "1.0.0a32+g8686b5d", "git+https://github.com/Rapptz/discord-ext-menus.git#8686b5d1bbc1d3c862292eb436ab630d6e9c9b53", ""},
		{"consul", "1.0.0", "registry+https://devpi.pyn.ru/hh/hhdev/+simple",
			"sha256:4a99483fc7f4dbfd400e6aec7dc02d98aced8d6dbadf98ca7a6c11ee2aef0078 sha256:c3bbc67dda94d9bd5b7e422f8acdd9d07faba618c14a3dc524b0cfcb65bf158e"},
		{"aiohappyeyeballs", "2.6.1", "registry+https://devpi.pyn.ru/root/pypi/+simple",
			"sha256:c3f9d0113123803ccadfdf3f0faa505bc78e6a72d1cc4806cbd719826e943558 sha256:f349ba8f4b75cb25c99c5c2d84e997e485204d2902a9597802b0371f09331fb8"},
		{"absl-py", "2.4.0", "",
			"sha256:88476fd881ca8aab94ffa78b7b6c632a782ab3ba1cd19c9bd423abc4fb4cd28d sha256:8c6af82722b35cf71e0f4d1d47dcaebfff286e27110a99fc359349b247dfb5d4"},
		{"localdir", "0.1.0", "file:../localdir", ""},
		{"localfile", "0.2.0", "file:dist/localfile-0.2.0.tar.gz", "sha256:2222222222222222222222222222222222222222222222222222222222222222"},
		{"fromurl", "0.3.0", "https://example.com/fromurl-0.3.0.tar.gz", "sha256:3333333333333333333333333333333333333333333333333333333333333333"},
	}
	if got := parseFixture(t, "testdata/poetry.lock"); !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%v\nwant\n%v", got, want)
	}
}

// TestSourceOriginOldFormat: poetry < 1.2 (NixOS/nixops-aws) keeps hashes in
// [metadata.files] and git sources with only `reference`.
func TestSourceOriginOldFormat(t *testing.T) {
	want := []row{
		{"appdirs", "1.4.4", "",
			"sha256:7d5d0167b2b1ba821647616af46a749d1c653740dd0d2415100fe26e27afdf41 sha256:a841dacd6b99318a741b166adb07e19ee71a274450e68237b4650ca1055ab128"},
		{"nixops", "2.0.0", "git+https://github.com/NixOS/nixops.git#0330ead36be75c0b0f80cf84c227f13380daf414", ""},
		{"nixos-modules-contrib", "0.1.0", "git+https://github.com/nix-community/nixos-modules-contrib.git#6e4d21f47f0c40023a56a9861886bde146476198", ""},
	}
	if got := parseFixture(t, "testdata/old-format.poetry.lock"); !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%v\nwant\n%v", got, want)
	}
}

// TestMetadataFilesNotAmplified: poetry < 1.5's [metadata.files] is keyed by
// name, so every [[package]] of that name gets its list. The joined Hash is
// computed once per name and shared, not retained once per package. Break
// it like this: join oldFiles[name] per package again.
func TestMetadataFilesNotAmplified(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, "[[package]]\nname = \"g\"\nversion = \"1.0.%d\"\n\n", i)
	}
	b.WriteString("[metadata.files]\ng = [\n")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&b, "  {file = \"g-%d.whl\", hash = \"sha256:%064x\"},\n", i, i)
	}
	b.WriteString("]\n")
	pkgs, _, err := NewParser().Parse(context.Background(), strings.NewReader(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	backing := map[*byte]bool{}
	for _, p := range pkgs {
		if len(strings.Fields(p.Hash)) != 200 {
			t.Fatalf("%s@%s: %d hashes, want 200", p.Name, p.Version, len(strings.Fields(p.Hash)))
		}
		backing[unsafe.StringData(p.Hash)] = true
	}
	if len(pkgs) != 300 || len(backing) != 1 {
		t.Fatalf("%d packages, %d distinct Hash strings; want 300 sharing 1", len(pkgs), len(backing))
	}
}

// TestRedTeam2: the dependency graph is not built (it was quadratic in the
// versions of one name — 4,000 entries took 1m41s — and panicked on
// `b = {version = 1}`); an md5-only file stays in Hash as an unreadable
// placeholder; a url source on PyPI's host of another project is not the
// named package. Break it: restore upstream's parseDependencies, drop
// FileHash's placeholder, or return true from python.ProjectFile.
func TestRedTeam2(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 4000; i++ {
		fmt.Fprintf(&b, "[[package]]\nname = \"a\"\nversion = \"1.0.%d\"\n[package.dependencies]\na = \"==9\"\n", i)
	}
	start := time.Now()
	pkgs, _, err := NewParser().Parse(context.Background(), strings.NewReader(b.String()))
	if err != nil || len(pkgs) != 4000 {
		t.Fatalf("%d packages, err %v", len(pkgs), err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("4,000 same-name entries took %v", d)
	}

	const pub = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	lock := `[[package]]
name = "a"
version = "1.0"
files = [{file = "a-1.0.tar.gz", hash = "` + pub + `"}, {file = "a-1.0-py3-none-any.whl", hash = "md5:0123456789abcdef0123456789abcdef"}]
[package.dependencies]
b = {version = 1}

[[package]]
name = "b"
version = "1.0"
[package.source]
type = "url"
url = "https://files.pythonhosted.org/packages/bb/evilpkg-6.6.6-py3-none-any.whl"
`
	pkgs, deps, err := NewParser().Parse(context.Background(), strings.NewReader(lock))
	if err != nil {
		t.Fatal(err)
	}
	var got []row
	for _, p := range pkgs {
		got = append(got, row{p.Name, p.Version, p.Origin, p.Hash})
	}
	want := []row{
		{"a", "1.0", "", pub + " unknown:md5"},
		{"b", "1.0", "url+https://files.pythonhosted.org/packages/bb/evilpkg-6.6.6-py3-none-any.whl", ""},
	}
	if !reflect.DeepEqual(got, want) || deps != nil {
		t.Errorf("got\n%v (deps %v)\nwant\n%v", got, deps, want)
	}
}
