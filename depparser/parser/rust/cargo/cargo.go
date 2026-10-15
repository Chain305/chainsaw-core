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
// 22 of 1,247 in one public open-source Cargo.lock on 2026-10-07. git sources carry a `source`
// and stay in, with Origin set: any `source` that is not crates.io (a git
// repository, an alternate registry) is a different package from the
// crates.io crate of the same name and version, and consumers must not score
// it as that crate (2026-10-14, a public open-source Cargo.lock: 22 git
// dependencies, 19 reported clean off their crates.io namesakes).
//
// Trivy reference: pkg/dependency/parser/rust/cargo/parse.go.
package cargo

import (
	"io"

	"github.com/BurntSushi/toml"

	"github.com/chain305/chainsaw-core/depparser/origin"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type lockfile struct {
	Packages []struct {
		Name         string   `toml:"name"`
		Version      string   `toml:"version"`
		Source       string   `toml:"source"`
		Checksum     string   `toml:"checksum"`
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
		pkg := ftypes.Package{Name: p.Name, Version: p.Version}
		if origin.Classify("cargo", p.Source) != origin.Public {
			pkg.Origin = origin.Sanitize(p.Source)
		}
		// checksum is the sha256 of the .crate — the same value crates.io
		// serves as the version's checksum (and an alternate registry's
		// index as cksum). Cargo.lock v1 kept checksums in a [metadata]
		// table instead; those are not read.
		if p.Checksum != "" {
			pkg.Hash = origin.NormalizeHash("sha256:" + p.Checksum)
		}
		out = append(out, pkg)
	}
	return out, nil
}
