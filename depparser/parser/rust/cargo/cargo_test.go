package cargo

import (
	"sort"
	"strings"
	"testing"
)

// Shaped like feldera/feldera's Cargo.lock: a workspace member (no source),
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
