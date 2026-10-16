package requirements

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func parse(t *testing.T, text string) map[string]string {
	t.Helper()
	pkgs, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, p := range pkgs {
		if p.Origin == "" { // registry packages only; sources: TestParseSources
			out[p.Name] = p.Version
		}
	}
	return out
}

// pip-compile --generate-hashes output: `pkg==ver \` with the hashes on
// indented continuation lines and the `# via` lines after. Every hashed line
// used to come back as version "2024.2.2 \".
func TestParsePipCompileHashes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "pip-compile-hashes.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := parse(t, string(data))
	if len(got) != 27 {
		t.Errorf("got %d packages, want 27: %v", len(got), got)
	}
	for name, ver := range got {
		if strings.ContainsAny(ver, " \t#;\\") || strings.Contains(ver, "--") || ver == "" {
			t.Errorf("%s: garbage version %q", name, ver)
		}
	}
	for name, want := range map[string]string{
		"certifi":        "2024.2.2",
		"uvicorn":        "0.29.0", // extras dropped
		"exceptiongroup": "1.2.0",  // marker dropped, package kept
		"uvloop":         "0.19.0",
		"websockets":     "12.0",
	} {
		if got[name] != want {
			t.Errorf("%s = %q, want %q", name, got[name], want)
		}
	}
}

func TestParseRequirementLines(t *testing.T) {
	text := `# header
--index-url https://pypi.org/simple
-r other.txt
-e git+https://github.com/x/y.git#egg=y
idna==3.6  # via requests
single==1.0.0 --hash=sha256:aaaa
two==2.0 --hash=sha256:aaaa --hash=sha256:bbbb
cont==3.0 \
    --hash=sha256:aaaa \
    --hash=sha256:bbbb
tight==4.0\
 --hash=sha256:cccc
marker==5.0 ; python_version < "3.11"
Spaced == 6.0
extra[a,b]==7.0
arb===8.0.post1
url @ https://example.com/url-1.0.tar.gz
ranged>=1.0
wild==1.*
compound==1.0,!=1.0.1
bare
`
	want := map[string]string{
		"idna": "3.6", "single": "1.0.0", "two": "2.0", "cont": "3.0", "tight": "4.0",
		"marker": "5.0", "Spaced": "6.0", "extra": "7.0", "arb": "8.0.post1",
	}
	if got := parse(t, text); !reflect.DeepEqual(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}

// srcPkg is one parsed package, flattened for comparison.
type srcPkg struct{ Name, Version, Origin, Hash string }

func parseAll(t *testing.T, text string) []srcPkg {
	t.Helper()
	pkgs, err := Parse(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	var out []srcPkg
	for _, p := range pkgs {
		out = append(out, srcPkg{p.Name, p.Version, p.Origin, p.Hash})
	}
	return out
}

// TestParseSources: real lines from the corpus (prescient-design/lobster
// `uv export`, splunk/salo and mozilla/bedrock pip-compile, desophos/
// idleon-saver). A source requirement is never dropped and never the PyPI
// namesake: it carries its Origin; a version only from a wheel/sdist name of
// the same project. `-e .` (the project itself) names nothing and is skipped.
// Break it like this: return ok=false for direct references again, or drop
// the Origin in sourcePackage.
func TestParseSources(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "sources.txt"))
	if err != nil {
		t.Fatal(err)
	}
	h := func(hexes ...string) string {
		var hs []string
		for _, x := range hexes {
			hs = append(hs, "sha256:"+x)
		}
		return strings.Join(hs, " ")
	}
	want := []srcPkg{
		{"accelerate", "1.2.1", "", h("03e161fc69d495daf2b9b5c8d5b43d06e2145520c04727b5bda56d49f1a43ab5", "be1cbb958cf837e7cdfbde46b812964b1b8ae94c9c7d94d921540beafcee8ddf")},
		{"aiobotocore", "2.17.0", "", h("a3041333c565bff9d63b4468bee4944f2d81cff63a45b10e5cc652f3837f9cc2", "aedccd5368a64401233ef9f27983d3d3cb6a507a6ca981f5ec1df014c00e260e")},
		{"beignet", "", "git+https://github.com/Genentech/beignet@b21da6613275b58706f02e2152ae798a32800a89", ""},
		{"flash-attn", "2.7.3", "", h("9078cf92355c4e3f77f01626ece8c71aad26bdbfa827c2af8c6ac5632cc1cc58")},
		{"flash-attn", "2.7.3+cu12torch2.5cxx11abiFalse", "https://github.com/Dao-AILab/flash-attention/releases/download/v2.7.3/flash_attn-2.7.3+cu12torch2.5cxx11abiFalse-cp310-cp310-linux_x86_64.whl", h("cd0ead6ad92bff21f90cf0aecdf859bc7145bf4e7dc8ed1fdc3cc38299651ce4")},
		{"aiohec", "", "https://github.com/splunk/aiohec/archive/refs/tags/v0.3.0.zip", h("925245d0ffad18fc096fea64cd9ebfe262b0905c6b2f41bd611f4b842db3185c")},
		{"mdx-outline", "", "https://github.com/mozmeao/mdx_outline/archive/refs/tags/markdown-3.4-compatibility.tar.gz", h("a78e112f80628246dd45858fe18404aaa8efb8dc81949bb1fbb87e91f9654afa")},
		{"chromecontroller", "", "git+https://github.com/desophos/ChromeController.git@HEAD", ""},
	}
	if got := parseAll(t, string(data)); !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%v\nwant\n%v", got, want)
	}
}

// TestParseSourceForms: bare VCS/archive URLs (#egg=, file names), -e
// lines, local paths, and a wheel on PyPI's own host (the registry package).
func TestParseSourceForms(t *testing.T) {
	text := `-e git+https://user:tok@github.com/x/y.git@v1#egg=y
-e ./libs/z
git+https://gitlab.com/a/b.git@main#egg=b&subdirectory=pkg
https://example.com/dist/c-2.0-py3-none-any.whl
./vendor/d-3.1.tar.gz
e @ file:///opt/wheels/e-1.0-py3-none-any.whl
f @ https://files.pythonhosted.org/packages/aa/bb/f-4.0-py3-none-any.whl
g[extra] @ https://example.com/h-1.0.tar.gz
`
	want := []srcPkg{
		{"y", "", "git+https://github.com/x/y.git@v1", ""},
		{"b", "", "git+https://gitlab.com/a/b.git@main", ""},
		{"c", "2.0", "https://example.com/dist/c-2.0-py3-none-any.whl", ""},
		{"d", "3.1", "file:./vendor/d-3.1.tar.gz", ""},
		{"e", "1.0", "file:///opt/wheels/e-1.0-py3-none-any.whl", ""},
		{"f", "4.0", "", ""},                              // PyPI's own file: the registry package
		{"g", "", "https://example.com/h-1.0.tar.gz", ""}, // the file is another project's
	}
	if got := parseAll(t, text); !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%v\nwant\n%v", got, want)
	}
}

// TestParseIndexURL: the primary index (wherever it appears in the file, in
// any spelling pip accepts) is the Origin of every index requirement when it
// is not PyPI; --extra-index-url alone changes nothing; --no-index with
// --find-links makes the find-links location the source. Break it like this:
// ignore the "--index-url" case in Packages.
func TestParseIndexURL(t *testing.T) {
	const reqs = "a==1.0\nb==2.0 --hash=sha256:" + "1111111111111111111111111111111111111111111111111111111111111111" + "\nc @ git+https://github.com/x/c\n"
	for _, tc := range []struct{ head, want string }{
		{"--index-url https://artifactory.example/api/pypi/pypi-remote/simple", "registry+https://artifactory.example/api/pypi/pypi-remote/simple"},
		{"-i https://tok:secret@devpi.example/root/pypi/+simple/", "registry+https://devpi.example/root/pypi/+simple/"},
		{"-ihttps://nexus.example/repository/pypi/simple", "registry+https://nexus.example/repository/pypi/simple"},
		{"--index-url=https://nexus.example/simple", "registry+https://nexus.example/simple"},
		{"--ind https://nexus.example/simple", "registry+https://nexus.example/simple"},
		{"--pypi-url https://nexus.example/simple", "registry+https://nexus.example/simple"},
		{"--index-url https://pypi.org/simple", ""},
		{"--index-url https://pypi.python.org/simple/", ""},
		{"--extra-index-url https://private.example/simple", ""},
		{"--no-index\n--find-links ./wheels", "file:./wheels"},
		{"", ""},
	} {
		for _, at := range []string{"head", "tail"} {
			text := tc.head + "\n" + reqs
			if at == "tail" {
				text = reqs + tc.head + "\n"
			}
			got := parseAll(t, text)
			if len(got) != 3 {
				t.Fatalf("%q (%s): %d packages: %v", tc.head, at, len(got), got)
			}
			for _, p := range got[:2] {
				if p.Origin != tc.want {
					t.Errorf("%q (%s): %s origin %q, want %q", tc.head, at, p.Name, p.Origin, tc.want)
				}
			}
			if got[2].Origin != "git+https://github.com/x/c" {
				t.Errorf("%q (%s): the source keeps its own origin, got %q", tc.head, at, got[2].Origin)
			}
		}
	}
}

// TestParseRedTeam2: an md5 --hash pip accepts stays in Hash as an
// unreadable placeholder (it used to be dropped, so a public sha256 beside
// it matched); a vendored .tar archive is a file: Origin like .tar.gz; a
// file on PyPI's host of another project is not the named package. Break
// it: drop FileHash's placeholder, or return true from python.ProjectFile.
func TestParseRedTeam2(t *testing.T) {
	const pub = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	text := "a==1.0 --hash=" + pub + " --hash=md5:0123456789abcdef0123456789abcdef\n" +
		"./vendor/evilpkg-1.0.tar\n" +
		"requests @ https://files.pythonhosted.org/packages/bb/evilpkg-6.6.6-py3-none-any.whl\n"
	want := []srcPkg{
		{"a", "1.0", "", pub + " unknown:md5"},
		{"evilpkg", "1.0", "file:./vendor/evilpkg-1.0.tar", ""},
		{"requests", "", "url+https://files.pythonhosted.org/packages/bb/evilpkg-6.6.6-py3-none-any.whl", ""},
	}
	if got := parseAll(t, text); !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%v\nwant\n%v", got, want)
	}
}
