// Package pylock parses pylock.toml (PEP 751 — standardized Python lock
// file format). Matches default filename `pylock.toml` and the PEP 751
// variant `pylock.{identifier}.toml`.
//
// Format: TOML. Top-level `packages` is an array of tables with
// name+version (plus optional index, hashes, marker, etc.).
//
// Trivy reference: pkg/dependency/parser/python/pylock/parse.go. Trivy
// additionally merges `pyproject.toml` to mark direct deps; that companion
// lookup is out of scope for this minimal port — every package is
// returned without a direct/indirect split.
package pylock

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
	} `toml:"packages"`
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
		out = append(out, ftypes.Package{
			Name:    python.NormalizePkgName(p.Name, true),
			Version: p.Version,
		})
	}
	return out, nil
}
