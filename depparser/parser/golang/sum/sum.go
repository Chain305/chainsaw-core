// Package sum parses go.sum.
//
// Format: line-oriented text. Each line is
//
//	<module-path> <version>[/go.mod] h1:<hash>
//
// Only "<module> <version> h1:…" lines are packages: they hash the module
// ZIP, which exists only for a module the build downloaded. A
// "<version>/go.mod" line hashes just that version's go.mod file, which the
// go command reads during module graph resolution (MVS) for every version it
// considers, including the many it never selects. Emitting those as packages
// keyed 815 never-built versions on three public go.sum files (the
// lockfile corpus, 2026-10-15) — kubernetes 103, prometheus 185, vault 527.
//
// The h1: value is a dirhash (a hash over the sorted file list of the
// extracted module), not a hash of a file a registry serves, so it is NOT
// carried as Package.Hash.
//
// Versions begin with "v" per Go convention; we strip the leading "v" to
// match how vuln-scan DBs typically index semver.
//
// Trivy reference: pkg/dependency/parser/golang/sum/parse.go.
package sum

import (
	"bufio"
	"io"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func Parse(r io.Reader) ([]ftypes.Package, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	seen := map[string]bool{}
	var out []ftypes.Package
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || strings.HasSuffix(fields[1], "/go.mod") {
			continue
		}
		mod, ver := fields[0], strings.TrimPrefix(fields[1], "v")
		if mod == "" || ver == "" {
			continue
		}
		key := mod + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ftypes.Package{Name: mod, Version: ver})
	}
	return out, sc.Err()
}
