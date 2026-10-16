package pylock

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestParseSources: PEP 751 pylock.toml. An index package's Origin comes
// from `index` (PyPI → none; another index → "registry+<url>", credentials
// stripped) or, with no index, from the host its files are served from; its
// Hash is every wheel's and the sdist's sha256. vcs / directory / archive
// packages — dropped before when they had no version — carry their Origin.
// Break it like this: ignore p.VCS.
func TestParseSources(t *testing.T) {
	f, err := os.Open("testdata/pylock.toml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pkgs, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	type row struct{ Name, Version, Origin, Hash string }
	var got []row
	for _, p := range pkgs {
		got = append(got, row{p.Name, p.Version, p.Origin, p.Hash})
	}
	want := []row{
		{"attrs", "25.1.0", "", "sha256:1c97078a80c814273a76b2a298a932eb681c87415c11dee0a6921de7f1b02c3e sha256:c75a69e28a550a7e93789579c22aa26b0f5b83b75dc4e08fe092980051e1090a"},
		{"corp-utils", "1.4.0", "registry+https://artifactory.example.com/artifactory/api/pypi/pypi-internal/simple", "sha256:5555555555555555555555555555555555555555555555555555555555555555"},
		{"noindex", "2.0", "registry+https://mirror.example.org/", "sha256:6666666666666666666666666666666666666666666666666666666666666666"},
		{"from-vcs", "", "git+https://github.com/example/from-vcs.git#0a1b2c3d4e5f60718293a4b5c6d7e8f901234567", ""},
		{"from-dir", "", "file:./libs/from-dir", ""},
		{"from-archive", "0.5", "https://downloads.example.com/from_archive-0.5.tar.gz", "sha256:7777777777777777777777777777777777777777777777777777777777777777"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%v\nwant\n%v", got, want)
	}
}

// TestParseEveryFileURL: the installer fetches the URL each file records, so
// every file is read. Red-team PoCs: `index = pypi` with an evil wheel URL,
// and a pythonhosted wheel followed by an evil one, both came back as PyPI
// (no Origin) and took the namesake's verdict.
func TestParseEveryFileURL(t *testing.T) {
	const lock = `lock-version = "1.0"
created-by = "test"

[[packages]]
name = "requests"
version = "2.32.3"
index = "https://pypi.org/simple"
wheels = [{ url = "https://evil.example/requests-2.32.3-py3-none-any.whl", hashes = { sha256 = "1111111111111111111111111111111111111111111111111111111111111111" } }]

[[packages]]
name = "numpy"
version = "2.1.0"
wheels = [
  { url = "https://files.pythonhosted.org/packages/aa/numpy-2.1.0-cp311-cp311-manylinux_2_17_x86_64.whl", hashes = { sha256 = "2222222222222222222222222222222222222222222222222222222222222222" } },
  { url = "https://evil.example/numpy-2.1.0-cp312-cp312-manylinux_2_17_x86_64.whl", hashes = { sha256 = "3333333333333333333333333333333333333333333333333333333333333333" } },
]

[[packages]]
name = "corp"
version = "1.0"
index = "https://mirror.example.org/simple"
wheels = [{ url = "https://mirror.example.org/packages/corp-1.0-py3-none-any.whl", hashes = { sha256 = "4444444444444444444444444444444444444444444444444444444444444444" } }]

[[packages]]
name = "vendored"
version = "1.0"
wheels = [{ path = "wheels/vendored-1.0-py3-none-any.whl", hashes = { sha256 = "5555555555555555555555555555555555555555555555555555555555555555" } }]

[[packages]]
name = "clean"
version = "1.0"
index = "https://pypi.org/simple"
wheels = [{ url = "https://files.pythonhosted.org/packages/bb/clean-1.0-py3-none-any.whl", hashes = { sha256 = "6666666666666666666666666666666666666666666666666666666666666666" } }]
`
	pkgs, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Origin
	}
	want := map[string]string{
		"requests": "registry+https://evil.example/",
		"numpy":    "registry+https://evil.example/",
		"corp":     "registry+https://mirror.example.org/simple", // files on the index's own host
		"vendored": "file:wheels/vendored-1.0-py3-none-any.whl",
		"clean":    "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}

// TestParseRedTeam2: a file whose hashes we cannot read (none, blake2b only)
// stays in Hash as an unreadable placeholder, never dropped beside a public
// one; a file on PyPI's hosts of another project is not this package (its
// Origin is that file, NonRegistry). Break it: drop fileHashes' placeholder,
// or return true from python.ProjectFile.
func TestParseRedTeam2(t *testing.T) {
	const pub = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	const lock = `lock-version = "1.0"
created-by = "test"

[[packages]]
name = "requests"
version = "2.31.0"
index = "https://mirror.example/simple"
sdist = { url = "https://mirror.example/requests-2.31.0.tar.gz", hashes = { sha256 = "4444444444444444444444444444444444444444444444444444444444444444" } }
wheels = [
  { url = "https://mirror.example/requests-2.31.0-py3-none-any.whl" },
  { url = "https://mirror.example/requests-2.31.0-py2-none-any.whl", hashes = { blake2b = "00ff" } },
  { url = "https://mirror.example/requests-2.31.0-cp3-none-any.whl", hashes = { sha256 = "4444444444444444444444444444444444444444444444444444444444444444", md5 = "0123456789abcdef0123456789abcdef" } },
]

[[packages]]
name = "swapped"
version = "1.0"
wheels = [{ url = "https://files.pythonhosted.org/packages/bb/evilpkg-6.6.6-py3-none-any.whl", hashes = { sha256 = "4444444444444444444444444444444444444444444444444444444444444444" } }]

[[packages]]
name = "archived"
version = "1.0"
archive = { url = "https://files.pythonhosted.org/packages/cc/evilpkg-6.6.6.tar.gz", hashes = { md5 = "0123456789abcdef0123456789abcdef" } }
`
	pkgs, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatal(err)
	}
	type row struct{ Origin, Hash string }
	got := map[string]row{}
	for _, p := range pkgs {
		got[p.Name] = row{p.Origin, p.Hash}
	}
	want := map[string]row{
		"requests": {"registry+https://mirror.example/simple", pub + " unknown:blake2b unknown:none"},
		"swapped":  {"url+https://files.pythonhosted.org/packages/bb/evilpkg-6.6.6-py3-none-any.whl", pub},
		"archived": {"url+https://files.pythonhosted.org/packages/cc/evilpkg-6.6.6.tar.gz", "unknown:md5"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}
