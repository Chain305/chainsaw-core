// Package requirements parses pip's requirements.txt.
//
// Manifest, not a lock file. Only pinned entries (== operator) produce a
// Package — anything else (ranges, tildes, star specifiers) is skipped
// since the vuln-scan pipeline wants an exact version.
//
// Ported verbatim from internal/cli/scan.go:parseRequirementsTxt. The
// behaviour differences vs Trivy's pkg/dependency/parser/python/packaging
// are intentional and documented there — Trivy additionally parses
// `-r`/`-c` includes and PEP 440 pre-release versions; chainsaw keeps a
// strict "pinned == only" policy so a scan result is always a set of
// fully-resolved packages.
package requirements

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
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip extras like "requests[security]==2.28.0".
		name := line
		if i := strings.IndexByte(name, '['); i >= 0 {
			name = name[:i] + name[strings.IndexByte(name, ']')+1:]
		}
		// Only pinned (==) specifiers produce a Package.
		idx := strings.Index(name, "==")
		if idx <= 0 {
			continue
		}
		pkg := strings.TrimSpace(name[:idx])
		ver := strings.TrimSpace(name[idx+2:])
		// Drop environment markers ("; python_version < '3.10'").
		if i := strings.IndexByte(ver, ';'); i >= 0 {
			ver = strings.TrimSpace(ver[:i])
		}
		if pkg == "" || ver == "" {
			continue
		}
		out = append(out, ftypes.Package{Name: pkg, Version: ver})
	}
	return out, sc.Err()
}
