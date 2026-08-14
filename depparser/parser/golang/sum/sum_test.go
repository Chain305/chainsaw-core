package sum

import (
	"strings"
	"testing"
)

// TestParseStripsPrefixAndDedupes pins the go.sum side of the Y2 contract:
// the leading "v" is stripped, the "/go.mod" hash stub collapses into the
// module row, and each (module, version) is emitted once.
func TestParseStripsPrefixAndDedupes(t *testing.T) {
	const in = `github.com/spf13/cobra v1.6.0 h1:AAAA=
github.com/spf13/cobra v1.6.0/go.mod h1:BBBB=
golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc h1:CCCC=
golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc/go.mod h1:DDDD=
github.com/foo/bar v2.0.0+incompatible h1:EEEE=
short line
`
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := map[string]string{
		"github.com/spf13/cobra": "1.6.0",
		"golang.org/x/exp":       "0.0.0-20240103183307-be819d1f06fc",
		"github.com/foo/bar":     "2.0.0+incompatible",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d packages, want %d: %+v", len(got), len(want), got)
	}
	for _, p := range got {
		w, ok := want[p.Name]
		if !ok {
			t.Errorf("unexpected package %s@%s", p.Name, p.Version)
			continue
		}
		if p.Version != w {
			t.Errorf("%s version = %q, want %q", p.Name, p.Version, w)
		}
		if strings.HasPrefix(p.Version, "v") {
			t.Errorf("%s version %q still carries the leading \"v\"", p.Name, p.Version)
		}
	}
}
