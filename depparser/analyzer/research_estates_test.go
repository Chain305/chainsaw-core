package analyzer

// Benchmark-v2 lane D: parse public open-source lockfile "estates" with the
// product's own parsers, so the dependency counts behind estate-level numbers
// come from the code a customer runs. One estate per directory under
// RESEARCH_ESTATES; output is a coordinate list the vulnerability-gate runner
// (core/intelligence TestResearchVulnGateOverCoords) reads.
//
//	RESEARCH_ESTATES=/path/estates RESEARCH_ESTATES_OUT=/path/coords.csv \
//	  go test ./depparser/analyzer/ -run TestResearchParseEstates -count=1 -v

import (
	"context"
	"encoding/csv"
	"os"
	"path/filepath"
	"sort"
	"testing"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

// lockfile language -> the ecosystem key the OSV provider is indexed by.
var researchLangEco = map[ftypes.LangType]string{
	ftypes.Npm: "npm", ftypes.Yarn: "npm", ftypes.Pnpm: "npm", ftypes.Bun: "npm",
	ftypes.Pip: "pypi", ftypes.Pipenv: "pypi", ftypes.Poetry: "pypi", ftypes.Uv: "pypi", ftypes.PyLock: "pypi",
	ftypes.GoModule: "go", ftypes.Bundler: "rubygems", ftypes.Composer: "composer", ftypes.Cargo: "cargo",
}

func TestResearchParseEstates(t *testing.T) {
	root, outPath := os.Getenv("RESEARCH_ESTATES"), os.Getenv("RESEARCH_ESTATES_OUT")
	if root == "" || outPath == "" {
		t.Skip("RESEARCH_ESTATES and RESEARCH_ESTATES_OUT must both be set")
	}
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	w := csv.NewWriter(out)
	defer w.Flush()
	_ = w.Write([]string{"estate", "eco", "package", "version", "lang", "origin", "source"})
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		pkgs, err := WalkDir(context.Background(), filepath.Join(root, d.Name()))
		if err != nil {
			t.Errorf("%s: %v", d.Name(), err)
			continue
		}
		seen, rows := map[string]bool{}, [][]string{}
		for _, p := range pkgs {
			eco, ok := researchLangEco[p.Lang]
			if !ok || p.Name == "" || p.Version == "" {
				continue
			}
			key := eco + "\x00" + p.Name + "\x00" + p.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			src, _ := filepath.Rel(root, p.Source)
			rows = append(rows, []string{d.Name(), eco, p.Name, p.Version, string(p.Lang), p.Origin, src})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i][1]+rows[i][2]+rows[i][3] < rows[j][1]+rows[j][2]+rows[j][3] })
		for _, r := range rows {
			_ = w.Write(r)
		}
		t.Logf("%s: %d distinct coordinates", d.Name(), len(rows))
	}
}
