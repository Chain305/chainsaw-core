// Package sum parses go.sum.
//
// Format: line-oriented text. Each line is
//
//	<module-path> <version>[/go.mod] h1:<hash>
//
// We emit one Package per <module-path, version> pair, deduped (the
// "module" and its "/go.mod" stub produce two lines). Versions begin
// with "v" per Go convention; we strip the leading "v" to match how
// vuln-scan DBs typically index semver.
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
		if len(fields) < 3 {
			continue
		}
		mod := fields[0]
		ver := fields[1]
		// Strip "/go.mod" suffix from the mod-hash variant and the
		// leading "v" from the version.
		ver = strings.TrimSuffix(ver, "/go.mod")
		ver = strings.TrimPrefix(ver, "v")
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
