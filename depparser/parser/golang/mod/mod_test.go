package mod_test

// Regression guard for the go.mod/go.sum "v"-prefix split.
//
// sum.Parse has always stripped the leading "v" from module versions;
// mod.Parse used to emit them verbatim. A directory holding both files
// therefore produced every module twice — "1.6.0" from go.sum and "v1.6.0"
// from go.mod — and the scan dedup key compares raw version strings, so the
// pair never collapsed (650 rows for 419 distinct coordinates on this repo's
// own go.mod/go.sum). mod.Parse now strips too; these tests keep the two
// parsers byte-identical.

import (
	"sort"
	"strings"
	"testing"

	gomod "github.com/chain305/chainsaw-core/depparser/parser/golang/mod"
	gosum "github.com/chain305/chainsaw-core/depparser/parser/golang/sum"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func TestParseStripsVersionPrefix(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want map[string]string
	}{
		{
			name: "require block",
			in: `module example.com/app

go 1.25.4

require (
	github.com/spf13/cobra v1.6.0
	golang.org/x/sys v0.15.0 // indirect
)
`,
			want: map[string]string{
				"github.com/spf13/cobra": "1.6.0",
				"golang.org/x/sys":       "0.15.0",
			},
		},
		{
			name: "single-line require",
			in: `module example.com/app

go 1.25.4

require github.com/stretchr/testify v1.8.4
`,
			want: map[string]string{"github.com/stretchr/testify": "1.8.4"},
		},
		{
			name: "pseudo-version keeps everything after the v",
			in: `module example.com/app

require (
	golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc
)
`,
			want: map[string]string{"golang.org/x/exp": "0.0.0-20240103183307-be819d1f06fc"},
		},
		{
			name: "prerelease and +incompatible suffixes survive",
			in: `module example.com/app

require (
	github.com/foo/bar v2.0.0+incompatible
	github.com/baz/qux v1.2.3-rc.1
)
`,
			want: map[string]string{
				"github.com/foo/bar": "2.0.0+incompatible",
				"github.com/baz/qux": "1.2.3-rc.1",
			},
		},
		{
			// A module path whose own name starts with "v" must not lose a
			// character — only the version is touched.
			name: "module path starting with v is untouched",
			in: `module example.com/app

require (
	vendor.example.com/vtool v1.0.0
)
`,
			want: map[string]string{"vendor.example.com/vtool": "1.0.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := gomod.Parse(strings.NewReader(tt.in))
			if err != nil {
				t.Fatalf("mod.Parse: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d packages %v, want %d", len(got), fmtPkgs(got), len(tt.want))
			}
			for _, p := range got {
				want, ok := tt.want[p.Name]
				if !ok {
					t.Errorf("unexpected package %s@%s", p.Name, p.Version)
					continue
				}
				if p.Version != want {
					t.Errorf("%s version = %q, want %q", p.Name, p.Version, want)
				}
				if strings.HasPrefix(p.Version, "v") {
					t.Errorf("%s version %q still carries the leading \"v\"", p.Name, p.Version)
				}
			}
		})
	}
}

// TestModAndSumAgreeOnVersionSpelling is the core Y2 guard: for the same set
// of modules, the two parsers must return byte-identical version strings.
func TestModAndSumAgreeOnVersionSpelling(t *testing.T) {
	const goMod = `module example.com/app

go 1.25.4

require (
	github.com/spf13/cobra v1.6.0
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc
)
`
	const goSum = `github.com/spf13/cobra v1.6.0 h1:AAAA=
github.com/spf13/cobra v1.6.0/go.mod h1:BBBB=
golang.org/x/sys v0.15.0 h1:CCCC=
golang.org/x/sys v0.15.0/go.mod h1:DDDD=
golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc h1:EEEE=
golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc/go.mod h1:FFFF=
`

	modPkgs, err := gomod.Parse(strings.NewReader(goMod))
	if err != nil {
		t.Fatalf("mod.Parse: %v", err)
	}
	sumPkgs, err := gosum.Parse(strings.NewReader(goSum))
	if err != nil {
		t.Fatalf("sum.Parse: %v", err)
	}

	modVer := index(modPkgs)
	sumVer := index(sumPkgs)
	if len(modVer) == 0 {
		t.Fatal("mod.Parse returned nothing")
	}
	for name, mv := range modVer {
		sv, ok := sumVer[name]
		if !ok {
			t.Errorf("%s present in go.mod but not go.sum fixture", name)
			continue
		}
		if mv != sv {
			t.Errorf("%s: mod.Parse version %q != sum.Parse version %q — "+
				"divergent spellings do not dedup and emit the module twice", name, mv, sv)
		}
	}
}

// TestNoDuplicateCoordinatesAcrossModAndSum asserts the user-visible symptom
// is gone: the union of both parsers' output over the same project holds one
// row per (name, version), and one row per module name.
func TestNoDuplicateCoordinatesAcrossModAndSum(t *testing.T) {
	const goMod = `module example.com/app

require (
	github.com/spf13/cobra v1.6.0
	golang.org/x/sys v0.15.0
)
`
	const goSum = `github.com/spf13/cobra v1.6.0 h1:AAAA=
github.com/spf13/cobra v1.6.0/go.mod h1:BBBB=
golang.org/x/sys v0.15.0 h1:CCCC=
golang.org/x/sys v0.15.0/go.mod h1:DDDD=
`

	modPkgs, err := gomod.Parse(strings.NewReader(goMod))
	if err != nil {
		t.Fatalf("mod.Parse: %v", err)
	}
	sumPkgs, err := gosum.Parse(strings.NewReader(goSum))
	if err != nil {
		t.Fatalf("sum.Parse: %v", err)
	}

	// The same dedup key core/cli/scan.go uses: raw name + raw version.
	coords := map[string]bool{}
	versionsPerName := map[string]map[string]bool{}
	for _, p := range append(append([]ftypes.Package{}, modPkgs...), sumPkgs...) {
		coords[p.Name+"@"+p.Version] = true
		if versionsPerName[p.Name] == nil {
			versionsPerName[p.Name] = map[string]bool{}
		}
		versionsPerName[p.Name][p.Version] = true
	}

	if len(coords) != 2 {
		keys := make([]string, 0, len(coords))
		for k := range coords {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Fatalf("distinct coordinates = %d, want 2 (one per module): %v", len(coords), keys)
	}
	for _, want := range []string{"github.com/spf13/cobra@1.6.0", "golang.org/x/sys@0.15.0"} {
		if !coords[want] {
			t.Errorf("missing coordinate %s", want)
		}
	}
	// Belt and braces: no module may carry two spellings of one version.
	for name, versions := range versionsPerName {
		if len(versions) != 1 {
			t.Errorf("%s resolved to %d version spellings, want 1", name, len(versions))
		}
	}
}

// TestParseReplace: a module replace is scored as the replacement module (no
// Origin — Go has no non-registry module paths), a path replace keeps the
// required coordinate with the directory as Origin, and a version-specific
// replace applies only to that version and wins over a wildcard. Directives
// from hashicorp/vault and kubernetes/kubernetes go.mod.
func TestParseReplace(t *testing.T) {
	const in = `module github.com/hashicorp/vault

go 1.25.4

replace github.com/hashicorp/vault/api => ./api

replace github.com/99designs/keyring => github.com/Jeffail/keyring v1.2.3

replace google.golang.org/grpc v1.84.0 => google.golang.org/grpc v1.83.2

replace github.com/ma314smith/signedxml v1.1.1 => github.com/moov-io/signedxml v1.1.1

replace (
	k8s.io/api => ./staging/src/k8s.io/api
	example.com/both => example.com/wild v1.0.0
	example.com/both v1.2.0 => example.com/specific v1.2.1
)

require (
	github.com/hashicorp/vault/api v1.23.0
	github.com/99designs/keyring v1.2.2 // indirect
	google.golang.org/grpc v1.84.0
	github.com/ma314smith/signedxml v1.1.0
	k8s.io/api v0.0.0
	example.com/both v1.2.0
	github.com/spf13/cobra v1.6.0
)
`
	got, err := gomod.Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var rows []string
	for _, p := range got {
		rows = append(rows, p.Name+"@"+p.Version+" "+p.Origin)
	}
	want := []string{
		"github.com/hashicorp/vault/api@1.23.0 file:./api",
		"github.com/Jeffail/keyring@1.2.3 ",
		"google.golang.org/grpc@1.83.2 ",
		"github.com/ma314smith/signedxml@1.1.0 ", // replace is for v1.1.1 only
		"k8s.io/api@0.0.0 file:./staging/src/k8s.io/api",
		"example.com/specific@1.2.1 ",
		"github.com/spf13/cobra@1.6.0 ",
	}
	if strings.Join(rows, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(rows, "\n"), strings.Join(want, "\n"))
	}
}

func index(pkgs []ftypes.Package) map[string]string {
	out := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		out[p.Name] = p.Version
	}
	return out
}

func fmtPkgs(pkgs []ftypes.Package) string {
	parts := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		parts = append(parts, p.Name+"@"+p.Version)
	}
	sort.Strings(parts)
	return "[" + strings.Join(parts, " ") + "]"
}

// TestParseReplaceOnLaxFallback: a directive newer than x/mod fails the strict
// parse and the parser falls back to ParseLax, which drops replaces. Red-team
// finding: every fork and local directory was then scored as upstream. The
// replaces are re-read; a fallback file whose replaces do not parse is refused.
func TestParseReplaceOnLaxFallback(t *testing.T) {
	const in = `module example.com/app

go 1.30

frobnicate example.com/tool

replace example.com/fork => github.com/attacker/fork v1.0.1

replace (
	example.com/local => ../local
)

require (
	example.com/fork v1.0.0
	example.com/local v0.0.0
	example.com/plain v1.2.3
)
`
	got, err := gomod.Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var rows []string
	for _, p := range got {
		rows = append(rows, p.Name+"@"+p.Version+" "+p.Origin)
	}
	want := "github.com/attacker/fork@1.0.1 \nexample.com/local@0.0.0 file:../local\nexample.com/plain@1.2.3 "
	if strings.Join(rows, "\n") != want {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(rows, "\n"), want)
	}

	bad := strings.Replace(in, "replace example.com/fork => github.com/attacker/fork v1.0.1", "replace example.com/fork => github.com/attacker/fork v1.0.1 extra", 1)
	if _, err := gomod.Parse(strings.NewReader(bad)); err == nil {
		t.Fatal("a fallback go.mod with an unreadable replace parsed; want an error, not requires without replaces")
	}
}
