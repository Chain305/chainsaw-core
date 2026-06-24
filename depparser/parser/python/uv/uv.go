// Package uv parses uv.lock files produced by Astral's uv package manager.
//
// Format: TOML. Top-level is `version = N`, then an array-of-tables
// `[[package]]` with name/version/source/dependencies. uv also emits a
// `[[distribution]]` table for wheel info we ignore.
//
// Trivy reference: pkg/dependency/parser/python/uv/parse.go.
package uv

import (
	"io"

	"github.com/BurntSushi/toml"

	"github.com/chain305/chainsaw-core/depparser/parser/python"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type lockfile struct {
	Packages []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		// Source tells us whether a package is the root workspace
		// project (which we skip — it isn't a dep, it's the subject).
		Source map[string]any `toml:"source"`
	} `toml:"package"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	var lf lockfile
	if _, err := toml.NewDecoder(r).Decode(&lf); err != nil {
		return nil, err
	}
	var out []ftypes.Package
	for _, p := range lf.Packages {
		if p.Name == "" || p.Version == "" {
			continue
		}
		// uv uses source = { virtual = "." } for the workspace root.
		if _, virtual := p.Source["virtual"]; virtual {
			continue
		}
		out = append(out, ftypes.Package{
			Name:    python.NormalizePkgName(p.Name, true),
			Version: p.Version,
		})
	}
	return out, nil
}
