package depgraph

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

// pnpmLockfile is the subset of pnpm-lock.yaml we parse. pnpm uses one
// of several top-level layouts across versions 5..9; we handle the
// common shape (v6+ with "importers" for workspaces, "packages" map
// keyed by "/name@version" or "/name/version"), the single-project
// fallback where the root's direct deps live at the top level, and v9,
// whose keys have no leading "/" and whose dependency edges moved from
// "packages" into "snapshots" (keyed "name@version(peer@x)").
type pnpmLockfile struct {
	LockfileVersion      interface{}             `yaml:"lockfileVersion"`
	Importers            map[string]pnpmImporter `yaml:"importers"`
	Dependencies         map[string]pnpmDepRef   `yaml:"dependencies"`
	DevDependencies      map[string]pnpmDepRef   `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmDepRef   `yaml:"optionalDependencies"`
	Packages             map[string]pnpmPackage  `yaml:"packages"`
	Snapshots            map[string]pnpmPackage  `yaml:"snapshots"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmDepRef `yaml:"dependencies"`
	DevDependencies      map[string]pnpmDepRef `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmDepRef `yaml:"optionalDependencies"`
}

// pnpmDepRef is the value in an importer's dependencies map. v6+
// serialises it as {specifier, version}; v5 uses a bare string. A
// custom unmarshaler handles both.
type pnpmDepRef struct {
	Version string
}

func (r *pnpmDepRef) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		r.Version = value.Value
		return nil
	}
	var raw struct {
		Version   string `yaml:"version"`
		Specifier string `yaml:"specifier"`
	}
	if err := value.Decode(&raw); err != nil {
		return err
	}
	r.Version = raw.Version
	return nil
}

// pnpmPackage is the "/name@version" entry in pnpm's flat packages map.
// Dependencies references are name→version-or-suffix, matching the
// same encoding pnpm uses in importer entries.
type pnpmPackage struct {
	Name                 string                `yaml:"name"`
	Version              string                `yaml:"version"`
	Dev                  bool                  `yaml:"dev"`
	Dependencies         map[string]pnpmDepRef `yaml:"dependencies"`
	OptionalDependencies map[string]pnpmDepRef `yaml:"optionalDependencies"`
	PeerDependencies     map[string]pnpmDepRef `yaml:"peerDependencies"`
}

// ParsePnpmLockfile turns a pnpm-lock.yaml blob into a Graph.
//
// Simplifying assumptions (documented):
//
//   - Workspaces: each importer contributes its direct deps as Roots.
//     We do NOT namespace by importer — a package used by two
//     workspaces appears as a single node with both importers' roots
//     parenting it through the natural shared-transitive mechanic.
//   - Package key format: pnpm uses "/name@version(peer-suffix)" in
//     v6+, and "/name/version" in v5. We strip peer-dep suffixes (the
//     "(x@y)" trailing parens) when keying — two installs with
//     different peer resolutions collapse into the same Node. This is
//     intentional: the risk engine cares about name@version, not peer
//     resolution.
//   - Child edges: each packages[key].dependencies becomes an outgoing
//     edge. Children are looked up by (name, child-version-spec);
//     unresolved children are skipped.
//   - Prod flag: honored from pnpm's own "dev" annotation on each
//     packages entry. v9 dropped it, so there a node is Prod when it is
//     reachable from a non-dev importer dependency.
//
// pnpm 10+ can write two YAML documents (the package manager's own lock,
// then the project's); every document is read into the one graph. Reading
// only the first marked no project dependency direct.
func ParsePnpmLockfile(data []byte) (*Graph, error) {
	g := NewGraph()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	found := false
	for {
		var lf pnpmLockfile
		if err := dec.Decode(&lf); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("depgraph/pnpm: yaml unmarshal: %w", err)
		}
		if len(lf.Packages) == 0 && len(lf.Dependencies) == 0 && len(lf.Importers) == 0 {
			continue
		}
		found = true
		addPnpmDocument(g, lf)
	}
	if !found {
		return nil, fmt.Errorf("depgraph/pnpm: empty lockfile — no packages or importers")
	}
	return g, nil
}

// addPnpmDocument adds one YAML document of a pnpm lockfile to g.
func addPnpmDocument(g *Graph, lf pnpmLockfile) {
	// v9 has no "dev" annotation, so Prod is derived from reachability
	// after the edges are wired; every v9 lockfile has a snapshots map
	// unless it has no packages at all.
	v9 := len(lf.Snapshots) > 0

	// First pass: one Node per packages (and v9 snapshots) entry.
	// packageKey→Key index is used in pass 2 to resolve dependency
	// references.
	pkgKeyToGraphKey := make(map[string]Key, len(lf.Packages)+len(lf.Snapshots))
	for _, entries := range []map[string]pnpmPackage{lf.Packages, lf.Snapshots} {
		for rawKey, pkg := range entries {
			name, version := splitPnpmPackageKey(rawKey)
			if pkg.Name != "" {
				name = pkg.Name
			}
			if pkg.Version != "" {
				version = pkg.Version
			}
			if name == "" || version == "" {
				continue
			}
			k := Key{Ecosystem: "npm", Name: name, Version: version}
			g.AddNode(k, false, !pkg.Dev && !v9)
			pkgKeyToGraphKey[rawKey] = k
		}
	}

	// resolveRef turns a (name, versionOrKey) tuple into a Key by
	// checking the packages map for matching entries. pnpm deps are
	// typically written as name: "1.2.3(peer@x)" — which is the VERSION
	// portion of the /name@version key.
	resolveRef := func(name, versionOrKey string) (Key, bool) {
		for _, key := range []string{
			"/" + name + "@" + versionOrKey, // v6
			name + "@" + versionOrKey,       // v9
			"/" + name + "/" + versionOrKey, // v5
			versionOrKey,                    // alias, v9: "string-width@4.2.3"; v6: "/string-width@4.2.3"
		} {
			if k, ok := pkgKeyToGraphKey[key]; ok {
				return k, true
			}
		}
		// Peer-suffix stripped match — pnpm may write "1.2.3" in the
		// importer but store "/name@1.2.3(peer@x)" in packages.
		cleanVersion := stripPeerSuffix(versionOrKey)
		k := Key{Ecosystem: "npm", Name: name, Version: cleanVersion}
		if _, ok := g.Nodes[k]; ok {
			return k, true
		}
		return Key{}, false
	}

	// Second pass: importer roots.
	// If there are no importers, fall back to top-level dependencies
	// (old single-project lockfiles).
	addRootsFrom := func(deps map[string]pnpmDepRef, prod bool) {
		for name, ref := range deps {
			if ref.Version == "" {
				continue
			}
			k, ok := resolveRef(name, ref.Version)
			if !ok {
				continue
			}
			g.AddNode(k, true, prod)
			g.AddRoot(k)
		}
	}
	if len(lf.Importers) > 0 {
		for _, imp := range lf.Importers {
			addRootsFrom(imp.Dependencies, true)
			addRootsFrom(imp.OptionalDependencies, true)
			addRootsFrom(imp.DevDependencies, false)
		}
	} else {
		addRootsFrom(lf.Dependencies, true)
		addRootsFrom(lf.OptionalDependencies, true)
		addRootsFrom(lf.DevDependencies, false)
	}

	// Third pass: wire transitive edges (v9: from snapshots).
	edgeSource := lf.Packages
	if v9 {
		edgeSource = lf.Snapshots
	}
	for rawKey, pkg := range edgeSource {
		parentKey, ok := pkgKeyToGraphKey[rawKey]
		if !ok {
			continue
		}
		parentNode := g.Nodes[parentKey]
		parentProd := parentNode != nil && parentNode.Prod
		addChildEdges := func(deps map[string]pnpmDepRef, prodEdge bool) {
			for name, ref := range deps {
				if ref.Version == "" {
					continue
				}
				childKey, ok := resolveRef(name, ref.Version)
				if !ok {
					continue
				}
				if prodEdge && parentProd {
					g.AddNode(childKey, false, true)
				}
				g.AddEdge(parentKey, childKey)
			}
		}
		addChildEdges(pkg.Dependencies, true)
		addChildEdges(pkg.OptionalDependencies, true)
		addChildEdges(pkg.PeerDependencies, true)
	}

	if v9 {
		for _, r := range g.Roots {
			if g.Nodes[r].Prod {
				for _, d := range g.Descendants(r) {
					g.AddNode(d, false, true)
				}
			}
		}
	}
}

// splitPnpmPackageKey parses a packages-map key into (name, version).
// Accepts both formats:
//
//	/lodash@4.17.21          → ("lodash", "4.17.21")
//	/@scope/pkg@1.0.0        → ("@scope/pkg", "1.0.0")
//	/lodash/4.17.21          → ("lodash", "4.17.21")         [v5]
//	/@scope/pkg/1.0.0        → ("@scope/pkg", "1.0.0")       [v5]
//	/pkg@1.0.0(peer@1.0.0)   → ("pkg", "1.0.0")              [strip peer]
//	lodash@4.17.21           → ("lodash", "4.17.21")         [v9]
//	@scope/pkg@1.0.0(p@2)    → ("@scope/pkg", "1.0.0")       [v9]
func splitPnpmPackageKey(k string) (string, string) {
	rest := strings.TrimPrefix(k, "/") // v9 keys have no leading "/"
	// Strip any peer-dep suffix before splitting — the peer suffix
	// contains its own "@" which would otherwise confuse the name/version
	// split.
	if paren := strings.Index(rest, "("); paren > 0 {
		rest = rest[:paren]
	}
	// Prefer the "@version" split but skip the leading "@" of scoped
	// packages: the name ends at the FIRST "@" after it. Not the last — a v9
	// git key ("solady@git+https://git@github.com:…") has one in the URL.
	at := -1
	if i := strings.Index(rest[min(1, len(rest)):], "@"); i >= 0 {
		at = i + min(1, len(rest))
	}
	// Detect scoped+@version case: if rest starts with "@" and there's
	// only one "@" (the leading one), fall through to slash split.
	if strings.HasPrefix(rest, "@") && strings.Count(rest, "@") == 1 {
		// v5 "/@scope/pkg/1.0.0" layout — slash-split the last segment.
		if idx := strings.LastIndex(rest, "/"); idx > 0 {
			name := rest[:idx]
			version := rest[idx+1:]
			return name, stripPeerSuffix(version)
		}
	}
	if at > 0 {
		name := rest[:at]
		version := rest[at+1:]
		return name, stripPeerSuffix(version)
	}
	// Last-resort slash split for "/name/version" layout.
	if idx := strings.LastIndex(rest, "/"); idx > 0 {
		return rest[:idx], stripPeerSuffix(rest[idx+1:])
	}
	return "", ""
}

// stripPeerSuffix removes pnpm's "(peer@x@y)" trailing annotation used
// to disambiguate peer-dep resolutions. Everything before the first
// "(" is the pure semver string.
func stripPeerSuffix(v string) string {
	if idx := strings.Index(v, "("); idx > 0 {
		return v[:idx]
	}
	return v
}
