package analyzer_test

// End-to-end guard for the go.mod/go.sum "v"-prefix split (Y2).
//
// WalkDir dispatches BOTH the go.mod and the go.sum analyzer over the same
// directory. Before the fix, mod.Parse emitted "v1.6.0" while sum.Parse
// emitted "1.6.0", so every module produced two rows that the scan dedup key
// (raw name + raw version) could not collapse — 650 rows for 419 distinct
// coordinates on this repo's own files. The fixture below is deliberately
// tiny; the assertion that matters is one row per module, not the count.

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	depanalyzer "github.com/chain305/chainsaw-core/depparser/analyzer"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func TestWalkDirGoModAndGoSumProduceNoDuplicateCoordinates(t *testing.T) {
	dir := t.TempDir()

	const goMod = `module example.com/app

go 1.25.4

require (
	github.com/spf13/cobra v1.6.0
	golang.org/x/sys v0.15.0 // indirect
	golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc
)
`
	// Real go.sum shape: two lines per module (archive hash + go.mod hash).
	const goSum = `github.com/spf13/cobra v1.6.0 h1:AAAA=
github.com/spf13/cobra v1.6.0/go.mod h1:BBBB=
golang.org/x/sys v0.15.0 h1:CCCC=
golang.org/x/sys v0.15.0/go.mod h1:DDDD=
golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc h1:EEEE=
golang.org/x/exp v0.0.0-20240103183307-be819d1f06fc/go.mod h1:FFFF=
`

	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.sum"), []byte(goSum), 0o600); err != nil {
		t.Fatalf("write go.sum: %v", err)
	}

	pkgs, err := depanalyzer.WalkDir(context.Background(), dir)
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	coords := map[string]bool{}
	spellings := map[string]map[string]bool{}
	for _, p := range pkgs {
		if p.Lang != ftypes.GoModule {
			continue
		}
		coords[p.Name+"@"+p.Version] = true
		if spellings[p.Name] == nil {
			spellings[p.Name] = map[string]bool{}
		}
		spellings[p.Name][p.Version] = true
	}

	want := []string{
		"github.com/spf13/cobra@1.6.0",
		"golang.org/x/exp@0.0.0-20240103183307-be819d1f06fc",
		"golang.org/x/sys@0.15.0",
	}
	if len(coords) != len(want) {
		got := make([]string, 0, len(coords))
		for k := range coords {
			got = append(got, k)
		}
		sort.Strings(got)
		t.Fatalf("distinct Go coordinates = %d, want %d\ngot: %s",
			len(coords), len(want), strings.Join(got, " "))
	}
	for _, w := range want {
		if !coords[w] {
			t.Errorf("missing coordinate %s", w)
		}
	}
	for name, versions := range spellings {
		if len(versions) != 1 {
			list := make([]string, 0, len(versions))
			for v := range versions {
				list = append(list, v)
			}
			sort.Strings(list)
			t.Errorf("%s emitted %d version spellings %v — go.mod and go.sum have diverged again",
				name, len(versions), list)
		}
	}
}
