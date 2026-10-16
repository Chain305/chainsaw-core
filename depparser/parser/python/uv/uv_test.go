package uv

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// TestParseSources: testdata/uv.lock is real uv output (HathorNetwork/
// hathor-core: PyPI, the editable project and workspace members, a git
// dependency; OpenTrafficCam/OTVision: pypi.nvidia.com) plus uv's other
// source kinds. Every package keeps its own Origin; PyPI's have none; the
// editable project is local code, not its PyPI namesake (it used to be
// scored as one); hashes are the sdist's and every wheel's. Break it like
// this: return "" from sourceOrigin for editable sources.
func TestParseSources(t *testing.T) {
	f, err := os.Open("testdata/uv.lock")
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
		{"aiohappyeyeballs", "2.3.5", "", "sha256:4d6dea59215537dbc746e93e779caea8178c866856a721c9c660d7a5a7b8be03 sha256:6fa48b9f1317254f122a07a131a86b71ca6946ca989ce6326fff54a99a920105"},
		{"hathor", "0.72.0", "file:.", ""},
		{"hathor-ct-crypto", "", "file:htr-rs/crates/hathor-ct-crypto", ""},
		{"hathorlib", "0.15.0", "file:hathorlib", ""},
		{"rocksdb", "0.10.1", "git+https://github.com/hathornetwork/python-rocksdb.git#8c20974458995ab7a1a64e046a40311e58450ffd", ""},
		{"tensorrt-cu12-bindings", "10.12.0.36", "registry+https://pypi.nvidia.com/", "sha256:408af91113c22f58f2f08404bfc1548baa8d78ce6126bd543acdc9d5819662ff sha256:f5128b8b2a379e65c09745ba97df58abf3a418cbfd6508d37f76121d9bdd3bc8 sha256:fb3a2ce96c7472a46bbee2030ce6a54fd6a32deda401c1c67d9de057550e0171"},
		{"from-url", "1.0", "https://example.com/dist/from_url-1.0.tar.gz", "sha256:1111111111111111111111111111111111111111111111111111111111111111"},
		{"pypi-url", "2.0", "", ""},
		{"local-path", "0.1", "file:../wheels/local_path-0.1-py3-none-any.whl", ""},
		{"local-dir", "0.2", "file:libs/local-dir", ""},
		{"workspace-root", "", "file:.", ""},
		{"private-index", "3.0", "registry+https://nexus.example/repository/pypi/simple", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%v\nwant\n%v", got, want)
	}
}

// TestParseWheelURLs: uv installs each file from the URL it recorded, not
// from `source.registry`. Red-team PoC: registry PyPI with an evil wheel URL
// came back as PyPI (no Origin) and took the namesake's verdict.
func TestParseWheelURLs(t *testing.T) {
	const lock = `version = 1

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/aa/requests-2.32.3.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }
wheels = [{ url = "https://evil.example/requests-2.32.3-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222" }]

[[package]]
name = "tensorrt"
version = "10.0"
source = { registry = "https://pypi.nvidia.com/" }
wheels = [{ url = "https://pypi.nvidia.com/tensorrt/tensorrt-10.0-py3-none-any.whl", hash = "sha256:3333333333333333333333333333333333333333333333333333333333333333" }]

[[package]]
name = "clean"
version = "1.0"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://files.pythonhosted.org/packages/bb/clean-1.0-py3-none-any.whl", hash = "sha256:4444444444444444444444444444444444444444444444444444444444444444" }]
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
		"tensorrt": "registry+https://pypi.nvidia.com/",
		"clean":    "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}

// TestParseRedTeam2: red-team round 2 PoCs.
//   - A file listed with no hash we can read (none, md5) stays in Hash as an
//     unreadable placeholder: a mirror lock with a public sdist hash and an
//     unhashed wheel used to hash as the sdist alone and match the public
//     release, while uv installs the wheel. Break it: drop FileHash's
//     placeholder.
//   - A wheel on files.pythonhosted.org of ANOTHER project (or version) is not
//     PyPI's `requests`: its Origin is the file, NonRegistry. Break it: return
//     true from python.ProjectFile.
func TestParseRedTeam2(t *testing.T) {
	const pub = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	const lock = `version = 1
[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://mirror.example/simple" }
sdist = { url = "https://mirror.example/packages/requests-2.31.0.tar.gz", hash = "` + pub + `" }
wheels = [{ url = "https://mirror.example/packages/requests-2.31.0-py3-none-any.whl" }]

[[package]]
name = "flask"
version = "3.0.0"
source = { registry = "https://mirror.example/simple" }
sdist = { url = "https://mirror.example/packages/flask-3.0.0.tar.gz", hash = "` + pub + `" }
wheels = [{ url = "https://mirror.example/packages/flask-3.0.0-py3-none-any.whl", hash = "md5:0123456789abcdef0123456789abcdef" }]

[[package]]
name = "swapped"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/aa/swapped-2.31.0.tar.gz", hash = "` + pub + `" }
wheels = [{ url = "https://files.pythonhosted.org/packages/bb/evilpkg-6.6.6-py3-none-any.whl", hash = "` + pub + `" }]

[[package]]
name = "from-pypi-url"
version = "1.0"
source = { url = "https://files.pythonhosted.org/packages/cc/evilpkg-6.6.6-py3-none-any.whl" }
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
		"requests":      {"registry+https://mirror.example/simple", pub + " unknown:none"},
		"flask":         {"registry+https://mirror.example/simple", pub + " unknown:md5"},
		"swapped":       {"url+https://files.pythonhosted.org/packages/bb/evilpkg-6.6.6-py3-none-any.whl", pub},
		"from-pypi-url": {"url+https://files.pythonhosted.org/packages/cc/evilpkg-6.6.6-py3-none-any.whl", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}
