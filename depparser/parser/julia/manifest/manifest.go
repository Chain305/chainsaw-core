// Package manifest parses Julia's Manifest.toml.
//
// Format: TOML, two schema variants:
//
//	manifest_format = "1.0"  — deps at top-level keyed by name.
//	manifest_format = "2.0"  — deps under [[deps]] array-of-tables keyed
//	                           by UUID subsection; we read the flat map
//	                           under [deps] or fall back to the old form.
//
// We parse generically: every top-level table whose value is a map-like
// with "version" becomes a package. Arrays-of-tables under the same
// name are all emitted (e.g. multiple versions of the same package).
//
// Trivy reference: pkg/dependency/parser/julia/manifest/parse.go.
package manifest

import (
	"io"

	"github.com/BurntSushi/toml"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

// Manifest.toml has top-level metadata plus a map of name→[entries…]
// where each entry is a table with uuid/version/deps. We decode into a
// permissive generic shape and walk the tree.
type manifestV2 struct {
	JuliaVersion   string             `toml:"julia_version"`
	ManifestFormat string             `toml:"manifest_format"`
	Deps           map[string][]entry `toml:"deps"`
}

type entry struct {
	UUID    string `toml:"uuid"`
	Version string `toml:"version"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Try v2 shape first.
	var v2 manifestV2
	if _, err := toml.Decode(string(buf), &v2); err == nil && len(v2.Deps) > 0 {
		return flatten(v2.Deps), nil
	}

	// Fall back to v1: top-level is the map directly.
	var v1 map[string][]entry
	if _, err := toml.Decode(string(buf), &v1); err != nil {
		return nil, err
	}
	// Skip known meta keys that don't describe deps.
	for _, k := range []string{"julia_version", "manifest_format", "project_hash", "deps"} {
		delete(v1, k)
	}
	return flatten(v1), nil
}

func flatten(deps map[string][]entry) []ftypes.Package {
	seen := map[string]bool{}
	var out []ftypes.Package
	for name, entries := range deps {
		for _, e := range entries {
			if e.Version == "" {
				continue
			}
			k := name + "@" + e.Version
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, ftypes.Package{Name: name, Version: e.Version})
		}
	}
	return out
}
