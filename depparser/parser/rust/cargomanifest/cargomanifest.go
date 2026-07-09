// Package cargomanifest parses Cargo.toml (Rust manifests — NOT the
// lock file; Cargo.lock is handled by ../cargo).
//
// Manifest carries semver requirements that normally pin to "X.Y.Z"; we
// strip any leading range operator to produce a pinnable version. Inline
// tables like `serde = { version = "1", features = [...] }` are handled.
//
// Ported verbatim from internal/cli/scan.go:parseCargoToml. The native
// TOML library isn't used here because Cargo.toml allows per-section
// comments we don't want the TOML decoder to normalize, and because the
// line-by-line scanner preserves the original parser's quirks (e.g.
// compound version ranges are rejected via ContainsAny(" ,") rather than
// being wrongly accepted as a pinned version).
package cargomanifest

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
	inDeps := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			lower := strings.ToLower(line)
			inDeps = lower == "[dependencies]" ||
				lower == "[dev-dependencies]" ||
				lower == "[build-dependencies]"
			continue
		}
		if !inDeps {
			continue
		}
		// name = "version"  OR  name = { version = "..." }
		eqIdx := strings.IndexByte(line, '=')
		if eqIdx <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:eqIdx])
		rest := strings.TrimSpace(line[eqIdx+1:])
		var ver string
		switch {
		case strings.HasPrefix(rest, "\""):
			ver = strings.Trim(rest, "\"")
		case strings.HasPrefix(rest, "{"):
			// Inline table: extract version = "..."
			if idx := strings.Index(rest, "version"); idx >= 0 {
				after := rest[idx+len("version"):]
				after = strings.TrimSpace(after)
				if strings.HasPrefix(after, "=") {
					after = strings.TrimSpace(after[1:])
					after = strings.TrimLeft(after, "\"")
					if end := strings.IndexByte(after, '"'); end >= 0 {
						ver = after[:end]
					}
				}
			}
		}
		ver = strings.TrimLeft(strings.TrimSpace(ver), "^~>=<")
		if name == "" || ver == "" || strings.ContainsAny(ver, " ,") {
			continue
		}
		out = append(out, ftypes.Package{Name: name, Version: ver})
	}
	return out, sc.Err()
}
