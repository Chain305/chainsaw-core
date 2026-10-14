package cargo

import (
	"sort"
	"strings"
	"testing"
)

// Shaped like a real public workspace Cargo.lock: a workspace member (no source),
// a registry crate and a git dependency.
const lock = `version = 4

[[package]]
name = "dbsp"
version = "0.363.0"
dependencies = ["serde"]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "etl-config"
version = "0.1.0"
source = "git+https://github.com/supabase/etl?rev=abc#abc"
`

func TestParseSkipsWorkspaceCrates(t *testing.T) {
	pkgs, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range pkgs {
		got = append(got, p.Name+"@"+p.Version)
	}
	sort.Strings(got)
	if want := "etl-config@0.1.0,serde@1.0.228"; strings.Join(got, ",") != want {
		t.Fatalf("got %v, want %s (workspace crate dropped, git dependency kept)", got, want)
	}
}

// TestParseMarksNonCratesIOOrigin: a git or alternate-registry crate carries
// its `source` as Origin so no consumer scores it as the crates.io crate of
// the same name; crates.io crates, in either index form, carry none.
func TestParseMarksNonCratesIOOrigin(t *testing.T) {
	const src = lock + `
[[package]]
name = "anyhow"
version = "1.0.100"
source = "sparse+https://index.crates.io/"

[[package]]
name = "internal"
version = "2.0.0"
source = "registry+https://my-registry.example/index"
`
	pkgs, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := map[string]string{
		"serde":      "",
		"anyhow":     "",
		"etl-config": "git+https://github.com/supabase/etl?rev=abc#abc",
		"internal":   "registry+https://my-registry.example/index",
	}
	if len(pkgs) != len(want) {
		t.Fatalf("got %d packages, want %d: %+v", len(pkgs), len(want), pkgs)
	}
	for _, p := range pkgs {
		if o, ok := want[p.Name]; !ok || p.Origin != o {
			t.Errorf("%s: Origin = %q, want %q", p.Name, p.Origin, o)
		}
	}
}
