// Package pnpm parses pnpm-lock.yaml.
//
// Format: YAML. pnpm has evolved the schema across versions 5/6/7/9:
//   - v5/6: package keys like "/foo/1.0.0" or "/foo@1.0.0"
//   - v9:   fully-qualified keys like "foo@1.0.0(peer@2.0.0)"
//
// We parse the generic `packages:` top-level map and extract (name, version)
// from each key. The value body carries dependencies/resolution we ignore.
//
// Trivy reference: pkg/dependency/parser/nodejs/pnpm/parse.go.
package pnpm

import (
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type lockfile struct {
	LockfileVersion any                       `yaml:"lockfileVersion"`
	Packages        map[string]map[string]any `yaml:"packages"`
	// v9 also exposes a `snapshots` map; packages still carries the
	// authoritative name+version. Snapshots duplicate that with peer
	// context which we don't need.
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var lf lockfile
	if err := yaml.Unmarshal(buf, &lf); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []ftypes.Package
	for key, body := range lf.Packages {
		name, ver := parseKey(key)
		// v9 sometimes carries a "version" field inside the body when
		// the key is just an identifier; prefer that if non-empty.
		if ver == "" {
			if v, ok := body["version"].(string); ok {
				ver = v
			}
		}
		if name == "" || ver == "" {
			continue
		}
		k := name + "@" + ver
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, ftypes.Package{Name: name, Version: ver})
	}
	return out, nil
}

// parseKey turns a pnpm packages-map key into (name, version). Handles:
//
//	/foo/1.0.0
//	/foo@1.0.0
//	/@scope/foo/1.0.0
//	foo@1.0.0
//	foo@1.0.0(peer@2.0.0)
func parseKey(k string) (name, version string) {
	k = strings.TrimPrefix(k, "/")
	// Strip any peer-qualifier suffix: foo@1.0.0(peer@x) → foo@1.0.0
	if i := strings.Index(k, "("); i >= 0 {
		k = k[:i]
	}

	// New-style separator is "@" (after scope if present).
	sep := "@"
	if !strings.Contains(k, "@") || (strings.HasPrefix(k, "@") && strings.Count(k, "@") == 1) {
		// Old-style separator is "/".
		sep = "/"
	}

	if sep == "@" {
		// Scoped: "@scope/foo@1.0.0" → split on last "@"
		if strings.HasPrefix(k, "@") {
			idx := strings.LastIndex(k, "@")
			return k[:idx], k[idx+1:]
		}
		idx := strings.Index(k, "@")
		return k[:idx], k[idx+1:]
	}
	// "/" form: scoped "@scope/foo/1.0.0" has three segments — name is
	// first two joined.
	parts := strings.Split(k, "/")
	switch {
	case len(parts) == 2:
		return parts[0], parts[1]
	case len(parts) >= 3 && strings.HasPrefix(parts[0], "@"):
		return parts[0] + "/" + parts[1], parts[2]
	}
	return "", ""
}
