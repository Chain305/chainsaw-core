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
		out[p.Name] = p.Version
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
