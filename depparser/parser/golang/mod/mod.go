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
				out = append(out, ftypes.Package{Name: parts[0], Version: normaliseVersion(parts[1])})
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
			out = append(out, ftypes.Package{Name: parts[0], Version: normaliseVersion(parts[1])})
		}
	}
	return out, sc.Err()
}

// normaliseVersion strips the leading "v" from a Go module version so this
// parser agrees byte-for-byte with its go.sum sibling (../sum, which has
// always stripped it) and with Trivy.
//
// Why this matters: a directory holding BOTH go.mod and go.sum used to emit
// every module twice — once "1.6.0" from go.sum, once "v1.6.0" from go.mod —
// and the scan dedup key compares raw version strings, so the pair never
// collapsed (650 rows for 419 distinct coordinates on this repo's own files).
//
// The stripped spelling is NOT resolvable against the Go module proxy, whose
// protocol requires the "v". Consumers that build proxy URLs re-add it — see
// core/intelligence/provider_registrymetadata.go (goProxyVersion) and
// core/depparser/dependency/id.go (ID).
func normaliseVersion(v string) string {
	return strings.TrimPrefix(v, "v")
}
