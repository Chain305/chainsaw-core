// Package npm parses package-lock.json (npm).
//
// Format: JSON. Three on-the-wire shapes exist:
//
//   - v1 (npm 5/6) — tree under "dependencies" keyed by pkg name, nested
//     recursively.
//   - v2 (npm 7+) — flat map under "packages" keyed by node_modules path.
//     Still carries "dependencies" for backward compat.
//   - v3 — same as v2 but drops the legacy "dependencies" tree.
//
// We read "packages" first; if empty we fall back to the v1 recursive
// walk. The root "" entry (workspace root) is skipped — it isn't a dep.
//
// Trivy reference: pkg/dependency/parser/nodejs/npm/parse.go (considerably
// richer — handles workspaces, linked packages, peer-meta, symlink
// resolution, bundled-deps marking). This port covers the common case.
package npm

import (
	"encoding/json"
	"io"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type lockPackage struct {
	Name         string           `json:"name"`
	Version      string           `json:"version"`
	Dev          bool             `json:"dev"`
	Peer         bool             `json:"peer"`
	Link         bool             `json:"link"`
	Dependencies map[string]v1Dep `json:"dependencies"` // v1 nested
}

type v1Dep struct {
	Version      string           `json:"version"`
	Dev          bool             `json:"dev"`
	Dependencies map[string]v1Dep `json:"dependencies"`
}

type lockfile struct {
	LockfileVersion int                    `json:"lockfileVersion"`
	Packages        map[string]lockPackage `json:"packages"`
	Dependencies    map[string]v1Dep       `json:"dependencies"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	var lf lockfile
	if err := json.NewDecoder(r).Decode(&lf); err != nil {
		return nil, err
	}

	var out []ftypes.Package
	seen := map[string]bool{}
	emit := func(name, version string, dev bool) {
		if name == "" || version == "" {
			return
		}
		key := name + "@" + version
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, ftypes.Package{Name: name, Version: version, Dev: dev})
	}

	// v2/v3 path — flat "packages" map.
	if len(lf.Packages) > 0 {
		for path, p := range lf.Packages {
			if path == "" {
				continue // workspace root
			}
			if p.Link {
				continue // workspace symlink, not a real install
			}
			// Derive the package name from the node_modules path if
			// the entry didn't include an explicit "name". Path shape:
			// node_modules/foo  OR  node_modules/@scope/foo  OR nested
			// node_modules/x/node_modules/@scope/foo.
			name := p.Name
			if name == "" {
				name = deriveNameFromPath(path)
			}
			emit(name, p.Version, p.Dev || p.Peer)
		}
		return out, nil
	}

	// v1 path — recursive tree.
	var walk func(map[string]v1Dep, bool)
	walk = func(deps map[string]v1Dep, parentDev bool) {
		for name, d := range deps {
			dev := parentDev || d.Dev
			emit(name, d.Version, dev)
			if len(d.Dependencies) > 0 {
				walk(d.Dependencies, dev)
			}
		}
	}
	walk(lf.Dependencies, false)
	return out, nil
}

// deriveNameFromPath takes a node_modules path like
// "node_modules/foo/node_modules/@scope/bar" and returns "@scope/bar".
func deriveNameFromPath(p string) string {
	// Last "node_modules/" is the trailing scope anchor.
	i := strings.LastIndex(p, "node_modules/")
	if i < 0 {
		return p
	}
	return p[i+len("node_modules/"):]
}
