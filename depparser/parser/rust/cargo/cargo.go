// Package cargo parses Cargo.lock (Rust).
//
// Format: TOML. Top-level is an array-of-tables `[[package]]` with
// name/version/source/checksum/dependencies. Entries whose source is the
// local workspace (no `source` field) are the crate being built — we
// include them: tools like cargo-audit actually scan those too.
//
// Trivy reference: pkg/dependency/parser/rust/cargo/parse.go.
package cargo

import (
	"io"

	"github.com/BurntSushi/toml"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type lockfile struct {
	Packages []struct {
		Name         string   `toml:"name"`
		Version      string   `toml:"version"`
		Source       string   `toml:"source"`
		Dependencies []string `toml:"dependencies"`
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
		out = append(out, ftypes.Package{Name: p.Name, Version: p.Version})
	}
	return out, nil
}
