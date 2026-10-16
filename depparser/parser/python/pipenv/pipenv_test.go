package pipenv

import (
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestParseSources: Pipfile.lock in pipenv's own layout. Index entries take
// their source from _meta.sources (no "index" key = the first source); a
// non-PyPI source is "registry+<url>" with credentials stripped; VCS, path
// and file entries — dropped before, having no version — carry their Origin;
// a file on PyPI's own host is PyPI's; an entry naming a source _meta does
// not list is not called PyPI's. Break it like this: drop the e.Git case.
func TestParseSources(t *testing.T) {
	f, err := os.Open("testdata/Pipfile.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pkgs, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		Name, Version, Origin, Hash string
		Dev                         bool
	}
	var got []row
	for _, p := range pkgs {
		got = append(got, row{p.Name, p.Version, p.Origin, p.Hash, p.Dev})
	}
	sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	want := []row{
		{"certifi", "2024.2.2", "", "sha256:9b469f3a900bf28dc19b8cfbf8019bf47f7fdd1a65a1d4ffb98fc14166beb4d1 sha256:e036ab49d5b79556f99cfc2d9320b34cfbe5be05c5871b51de9329f0603b0474", false},
		{"corp-utils", "1.4.0", "registry+https://nexus.example.com/repository/pypi-internal/simple", "sha256:4444444444444444444444444444444444444444444444444444444444444444", false},
		{"hglib", "", "hg+https://hg.example.com/hglib#tip", "", false},
		{"localpkg", "", "file:./packages/localpkg", "", false},
		{"lost", "0.1", "registry+(Pipfile source removed-source)", "", false},
		{"mylib", "", "git+https://github.com/example/mylib.git#8f1c1b2e3d4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b", "", false},
		{"pypiwheel", "3.2.1", "", "", false},
		{"pytest", "8.0.0", "", "sha256:2a8386cfc11fa9d2c50ee7b2a57e7d898ef90470a7a34c4b949ff59662bb78b7", true},
		{"requests", "2.31.0", "", "sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1", false},
		{"wheelpkg", "0.9.1", "https://downloads.example.com/wheelpkg-0.9.1-py3-none-any.whl", "", false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%v\nwant\n%v", got, want)
	}
}

// TestParseRedTeam2: an md5 hash pipenv passes to pip stays in Hash as an
// unreadable placeholder; a `file` on PyPI's host of another project is not
// the named package. Break it: drop FileHash's placeholder, or return true
// from python.ProjectFile.
func TestParseRedTeam2(t *testing.T) {
	const pub = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	lock := `{"_meta": {"sources": [{"name": "pypi", "url": "https://pypi.org/simple"}]},
"default": {
 "a": {"version": "==1.0", "hashes": ["` + pub + `", "md5:0123456789abcdef0123456789abcdef"]},
 "requests": {"file": "https://files.pythonhosted.org/packages/bb/evilpkg-6.6.6-py3-none-any.whl"}
}}`
	pkgs, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatal(err)
	}
	type row struct{ Version, Origin, Hash string }
	got := map[string]row{}
	for _, p := range pkgs {
		got[p.Name] = row{p.Version, p.Origin, p.Hash}
	}
	want := map[string]row{
		"a":        {"1.0", "", pub + " unknown:md5"},
		"requests": {"", "url+https://files.pythonhosted.org/packages/bb/evilpkg-6.6.6-py3-none-any.whl", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
}
