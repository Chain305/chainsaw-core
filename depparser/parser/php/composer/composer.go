// Package composer parses composer.lock (PHP).
//
// Format: JSON. Top-level keys "packages" (prod) and "packages-dev" each
// hold an array of {name, version, ...} entries. We emit both with
// dev-flag set appropriately.
//
// Trivy reference: pkg/dependency/parser/php/composer/parse.go.
package composer

import (
	"encoding/json"
	"io"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type entry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type lockfile struct {
	Packages    []entry `json:"packages"`
	PackagesDev []entry `json:"packages-dev"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	var lf lockfile
	if err := json.NewDecoder(r).Decode(&lf); err != nil {
		return nil, err
	}
	var out []ftypes.Package
	push := func(e entry, dev bool) {
		if e.Name == "" || e.Version == "" {
			return
		}
		// Composer sometimes prefixes "v" on version strings (e.g.
		// "v1.2.3"); strip it for matching against vuln-scan DBs that
		// index semver without the v.
		v := strings.TrimPrefix(e.Version, "v")
		out = append(out, ftypes.Package{Name: e.Name, Version: v, Dev: dev})
	}
	for _, e := range lf.Packages {
		push(e, false)
	}
	for _, e := range lf.PackagesDev {
		push(e, true)
	}
	return out, nil
}
