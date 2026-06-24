// Package mod parses go.mod.
//
// Manifest, but Go's go.mod already carries fully-resolved module
// versions (no ranges), so treating it as a lock file is accurate. The
// companion go.sum (see ../sum) adds transitives + build-time deps
// pulled in by test-only packages; go.mod itself only names direct
// requires.
//
// Ported verbatim from internal/cli/scan.go:parseGoMod. For higher
// fidelity (replace/exclude directives, toolchain pin), future work can
// swap this for Trivy's pkg/dependency/parser/golang/mod, which uses
// golang.org/x/mod/modfile.
package mod

import (
	"bufio"
	"io"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func Parse(r io.Reader) ([]ftypes.Package, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var out []ftypes.Package
	inRequire := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" {
			inRequire = false
			continue
		}
		if strings.HasPrefix(line, "require ") {
			// Single-line require.
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				out = append(out, ftypes.Package{Name: parts[0], Version: parts[1]})
			}
			continue
		}
		if !inRequire {
			continue
		}
		// Strip inline comments.
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			out = append(out, ftypes.Package{Name: parts[0], Version: parts[1]})
		}
	}
	return out, sc.Err()
}
