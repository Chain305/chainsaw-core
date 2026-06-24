package provenance

import (
	"strings"
	"testing"

	"golang.org/x/mod/module"
)

func TestEscapeModulePath(t *testing.T) {
	cases := map[string]string{
		"github.com/foo/bar":        "github.com/foo/bar",
		"github.com/Foo/Bar":        "github.com/!foo/!bar",
		"github.com/GoogleChrome/x": "github.com/!google!chrome/x",
	}
	for in, want := range cases {
		got, err := module.EscapePath(in)
		if err != nil {
			t.Errorf("module.EscapePath(%q) err: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("module.EscapePath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGomodHandlesIncompatibleVersion asserts that +incompatible versions
// escape with '+' preserved (not percent-encoded, which url.PathEscape would do).
func TestGomodHandlesIncompatibleVersion(t *testing.T) {
	escMod, err := module.EscapePath("github.com/foo/bar")
	if err != nil {
		t.Fatal(err)
	}
	escVer, err := module.EscapeVersion("v1.0.0+incompatible")
	if err != nil {
		t.Fatal(err)
	}
	got := "/lookup/" + escMod + "@" + escVer
	if !strings.Contains(got, "+incompatible") {
		t.Errorf("escape must preserve '+': got %q", got)
	}
	if strings.Contains(got, "%2B") {
		t.Errorf("escape must not percent-encode '+': got %q", got)
	}
}

func TestSplitSumdbLookup(t *testing.T) {
	body := []byte("github.com/foo/bar@v1.2.3 h1:abc\ngithub.com/foo/bar@v1.2.3/go.mod h1:def\n\n2\n12345\nhashhashhash\n\n— sum.golang.org Az3grw==\n")
	prefix, note, ok := splitSumdbLookup(body)
	if !ok {
		t.Fatal("split failed")
	}
	if len(prefix) == 0 || len(note) == 0 {
		t.Fatalf("empty split: prefix=%q note=%q", prefix, note)
	}
}

func TestInferGoSourceRepo(t *testing.T) {
	cases := map[string]string{
		"github.com/foo/bar":    "https://github.com/foo/bar",
		"github.com/foo/bar/v2": "https://github.com/foo/bar",
		"gitlab.com/foo/bar":    "https://gitlab.com/foo/bar",
		"bitbucket.org/foo/bar": "https://bitbucket.org/foo/bar",
		"golang.org/x/crypto":   "",
		"example.com/single":    "",
	}
	for in, want := range cases {
		if got := inferGoSourceRepo(in); got != want {
			t.Errorf("inferGoSourceRepo(%q) = %q, want %q", in, got, want)
		}
	}
}
