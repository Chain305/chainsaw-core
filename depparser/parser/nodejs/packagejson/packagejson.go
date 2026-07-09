// Package packagejson parses Node.js package.json manifests.
//
// A manifest (not a lock file): it carries semver RANGES ("^1.2.3") rather
// than resolved versions. We only emit entries whose range pins to a
// single version — ranges like ">=1,<2" or "*" produce no package since
// they can't be matched against a vuln-DB keyed on exact versions.
//
// Dev, peer, and optional dependency sections are all read and marked
// Dev=true when appropriate. Chainsaw's scan pipeline filters dev deps
// at the analyzer-shim boundary so behaviour remains identical to the
// old `parsePackageJSON` path in internal/cli/scan.go (which this file
// replaces verbatim).
package packagejson

import (
	"encoding/json"
	"io"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type manifest struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	var m manifest
	if err := json.NewDecoder(r).Decode(&m); err != nil {
		return nil, err
	}
	var out []ftypes.Package
	collect := func(deps map[string]string, dev bool) {
		for name, ver := range deps {
			if v := normNPMVersion(ver); v != "" {
				out = append(out, ftypes.Package{Name: name, Version: v, Dev: dev})
			}
		}
	}
	collect(m.Dependencies, false)
	collect(m.DevDependencies, true)
	collect(m.PeerDependencies, false)
	collect(m.OptionalDependencies, false)
	return out, nil
}

// normNPMVersion strips semver range operators and returns the base
// version, or "" if the spec cannot be pinned. Kept byte-identical to
// the original implementation in internal/cli/scan.go so the behaviour
// change from moving this into the registry is zero.
func normNPMVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "*" || v == "latest" || v == "next" || v == "x" {
		return ""
	}
	if strings.Contains(v, " - ") {
		return ""
	}
	v = strings.TrimLeft(v, "^~>=<")
	v = strings.TrimSpace(v)
	if strings.ContainsAny(v, " ,|") {
		return ""
	}
	if v == "" || v == "x" || v == "X" || v == "*" {
		return ""
	}
	return v
}
