package bun

import (
	"sort"
	"strings"
	"testing"
)

// The integrity hash below contains "//", as 14 of feldera/feldera's do. The
// old line-based comment strip cut it in half and the whole lockfile failed
// with "invalid character '\n' in string literal" (2026-10-05).
const lockWithSlashesInStrings = `{
  "lockfileVersion": 1,
  // a real comment, with a trailing comma after it in the next line
  "workspaces": {
    "": { "name": "x", "dependencies": { "svelte": "5.55.7", }, },
  },
  "packages": {
    "svelte": ["svelte@5.55.7", "", {}, "sha512-0PEIZNeIjkHoDR4YjjJp34biM0mDvplBe//mB+IHCqHDGV7pxF+7MklTvighcCPPZC7ynWyjdTA=="],
    "@scope/odd": ["@scope/odd@1.0.0", "https://registry.example.com/@scope/odd", { "note": "keeps ,] and // inside" }, "sha512-a//b=="],
  },
}
`

func TestParseKeepsDoubleSlashInsideStrings(t *testing.T) {
	pkgs, err := Parse(strings.NewReader(lockWithSlashesInStrings))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var got []string
	for _, p := range pkgs {
		got = append(got, p.Name+"@"+p.Version)
	}
	sort.Strings(got)
	want := []string{"@scope/odd@1.0.0", "svelte@5.55.7"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestStripJSONCLeavesStringsAlone(t *testing.T) {
	in := `{"a": "x // y ,]", "b": [1, 2,], // gone
"c": "\"//\"",}`
	want := `{"a": "x // y ,]", "b": [1, 2]` + `, ` + "\n" + `"c": "\"//\""}`
	if got := string(stripJSONC([]byte(in))); got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}
