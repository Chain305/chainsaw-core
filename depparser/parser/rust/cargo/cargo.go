// Package cargo parses Cargo.lock (Rust).
//
// Format: TOML. Top-level is an array-of-tables `[[package]]` with
// name/version/source/checksum/dependencies. Entries with no `source` field
// are the workspace's own crates and path dependencies — first-party code
// with no registry coordinate — and are SKIPPED, as the npm parser skips
// `link: true` and the bun parser skips workspace:/file: entries. They used
// to be included ("cargo-audit scans those too"), but cargo-audit matches
// advisories by crate NAME, which for local code is a coincidence, and
// scoring them against registry intelligence only produced `unknown` rows:
// 22 of feldera/feldera's 1,247 on 2026-10-07. git sources carry a `source`
// and stay in.
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
		if p.Name == "" || p.Version == "" || p.Source == "" {
			continue
		}
		out = append(out, ftypes.Package{Name: p.Name, Version: p.Version})
	}
	return out, nil
}
