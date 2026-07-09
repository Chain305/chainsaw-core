// Package pipenv parses Pipfile.lock (Pipenv).
//
// Format: JSON. Top-level keys are "default" (prod) and "develop" (dev),
// each a map of pkg-name → {version: "==1.2.3"}. Metadata lives under
// "_meta" which we ignore.
//
// Trivy reference: pkg/dependency/parser/python/pipenv/parse.go. This
// file is a format-faithful rewrite emitting only name+version tuples
// (chainsaw's scanner does not consume the extra dep-graph fields Trivy
// carries). Licenses and hashes are dropped.
package pipenv

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/parser/python"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type entry struct {
	Version string `json:"version"`
}

type lockfile struct {
	Default map[string]entry `json:"default"`
	Develop map[string]entry `json:"develop"`
}

// Parse reads a Pipfile.lock from r and returns ftypes.Package entries.
// Dev-only dependencies are marked Dev=true so the caller can filter.
func Parse(r io.Reader) ([]ftypes.Package, error) {
	var lf lockfile
	if err := json.NewDecoder(r).Decode(&lf); err != nil {
		return nil, err
	}
	var out []ftypes.Package
	collect := func(m map[string]entry, dev bool) {
		for name, e := range m {
			// Pipenv writes versions as "==1.2.3" — strip the operator.
			ver := strings.TrimPrefix(e.Version, "==")
			if ver == "" {
				continue
			}
			out = append(out, ftypes.Package{
				Name:    python.NormalizePkgName(name, true),
				Version: ver,
				Dev:     dev,
			})
		}
	}
	collect(lf.Default, false)
	collect(lf.Develop, true)
	return out, nil
}
