// Poetry analyzer — exact-filename match on `poetry.lock`, delegates to the
// vendored Trivy parser and converts ftypes.Package → analyzer.Package.
//
// Why this file (and not a generic table) exists:
// Each analyzer has its own Required() shape (exact match, suffix, regex)
// and its own reader-typing dance — Poetry needs xio.ReadSeekerAt, Gemfile
// would want a bufio.Scanner, Gradle wants a line-by-line parser, PyLock
// needs a companion pyproject.toml. A per-language file keeps each
// dispatcher small and readable; the shared plumbing (registry, WalkDir)
// sits in analyzer.go.
package analyzer

import (
	"context"
	"fmt"
	"path/filepath"

	poetry "github.com/chain305/chainsaw-core/depparser/parser/python/poetry"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func init() { Register(&poetryAnalyzer{}) }

type poetryAnalyzer struct{}

func (poetryAnalyzer) Type() ftypes.LangType { return ftypes.Poetry }

// Required matches exactly the file basename `poetry.lock`. Poetry does
// not support alternate lockfile names — if users set `tool.poetry.lock`
// to a custom path, Trivy doesn't match those either.
func (poetryAnalyzer) Required(path string) bool {
	return filepath.Base(path) == "poetry.lock"
}

// Parse opens the lock file and feeds it to the vendored Trivy parser,
// then flattens ftypes.Package into the chainsaw-native analyzer.Package
// shape. Dependency edges (ftypes.Dependency) are intentionally dropped
// at this boundary — the current vuln-scan pipeline only needs
// name+version tuples. If graph-aware SBOM generation lands later, widen
// the analyzer.Package struct to carry the deps too.
func (poetryAnalyzer) Parse(ctx context.Context, path string) ([]Package, error) {
	f, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	p := poetry.NewParser()
	fpkgs, _, err := p.Parse(ctx, f)
	if err != nil {
		return nil, err
	}

	out := make([]Package, 0, len(fpkgs))
	for _, fp := range fpkgs {
		// Skip dev-only deps — they aren't installed in a production
		// image and the vuln scan historically ignored them. Toggle this
		// via an option once the full manifest-vs-lock split is wired in.
		if fp.Dev {
			continue
		}
		out = append(out, Package{
			Name:    fp.Name,
			Version: fp.Version,
			Lang:    ftypes.Poetry,
			Source:  path,
		})
	}
	return out, nil
}
