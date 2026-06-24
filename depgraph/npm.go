package depgraph

import (
	"encoding/json"
	"fmt"
	"strings"
)

// npmLockfile is the subset of package-lock.json v2/v3 we rely on.
// v2 keeps both "packages" and "dependencies" trees; v3 drops the
// legacy "dependencies" field. Both put the root project under
// packages[""] with its direct deps in dependencies/devDependencies.
type npmLockfile struct {
	Name            string                     `json:"name"`
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]*npmPackageNode `json:"packages"`
}

type npmPackageNode struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	DevOptional          bool              `json:"devOptional"`
	Peer                 bool              `json:"peer"`
	Optional             bool              `json:"optional"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// ParseNPMLockfile parses a package-lock.json v2 or v3 blob into a Graph.
//
// Resolution strategy (documented simplification):
//
//   - Root discovery: the empty-string key in "packages" is the root
//     project. Its dependencies + devDependencies define Roots.
//   - Child version resolution: for each parent at path P, we look up
//     each child "dep" by walking node_modules resolution — first
//     P/node_modules/dep, then pop the parent path's trailing
//     "/node_modules/..." and retry, up to the lockfile root. This
//     matches how Node resolves modules at runtime.
//   - Prod flag: a node is Prod unless every path that reaches it goes
//     through a devDependency. We approximate this by honoring the
//     "dev" flag npm writes on each package entry; for the root, prod
//     roots come from "dependencies" and dev roots from
//     "devDependencies".
//
// The parser is tolerant — unknown fields are ignored and a child that
// does not resolve to any known package is silently skipped (rather
// than aborting the parse). Callers get a best-effort graph; Validate
// on the result is still guaranteed to succeed.
func ParseNPMLockfile(data []byte) (*Graph, error) {
	var lf npmLockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("depgraph/npm: json unmarshal: %w", err)
	}
	if len(lf.Packages) == 0 {
		return nil, fmt.Errorf("depgraph/npm: no \"packages\" map — is this lockfile v1?")
	}

	g := NewGraph()

	// First pass: create a Node for every non-root packages entry.
	// Path→Key mapping lets pass 2 walk parent paths to resolve deps.
	pathToKey := make(map[string]Key, len(lf.Packages))
	for path, p := range lf.Packages {
		if path == "" {
			continue
		}
		if p == nil || p.Version == "" {
			continue
		}
		name := p.Name
		if name == "" {
			name = nameFromNodeModulesPath(path)
		}
		if name == "" {
			continue
		}
		k := Key{Ecosystem: "npm", Name: name, Version: p.Version}
		// Prod = !dev-only. npm marks pure-dev transitives with "dev":
		// true; we treat that as Prod=false. A node can be reached by
		// both a dev and a prod parent — we'll promote Prod=true below
		// when we discover a prod parent for it.
		prod := !p.Dev && !p.DevOptional
		g.AddNode(k, false, prod)
		pathToKey[path] = k
	}

	// Second pass: wire edges. For each packages[path] entry (including
	// the root), look up each dependency name via node_modules
	// resolution from that path.
	root := lf.Packages[""]
	if root == nil {
		return nil, fmt.Errorf("depgraph/npm: missing root entry packages[\"\"]")
	}

	// Register root deps as Roots.
	registerDep := func(name, _ string, prod bool) {
		childKey, ok := resolveNodeModules("", name, pathToKey)
		if !ok {
			return
		}
		// Root deps become Roots directly; promote Prod when applicable.
		g.AddNode(childKey, true, prod)
		g.AddRoot(childKey)
	}
	for name, spec := range root.Dependencies {
		registerDep(name, spec, true)
	}
	for name, spec := range root.DevDependencies {
		registerDep(name, spec, false)
	}

	// Wire transitive edges. Every non-root packages entry contributes
	// its dependencies as outgoing edges; resolution uses the parent's
	// path.
	for path, p := range lf.Packages {
		if path == "" || p == nil {
			continue
		}
		parentKey, ok := pathToKey[path]
		if !ok {
			continue
		}
		parentNode := g.Nodes[parentKey]
		parentProd := parentNode != nil && parentNode.Prod

		addEdge := func(childName string, prodEdge bool) {
			childKey, ok := resolveNodeModules(path, childName, pathToKey)
			if !ok {
				return
			}
			// Propagate Prod — a child reached by a prod edge is prod.
			if prodEdge && parentProd {
				g.AddNode(childKey, false, true)
			}
			g.AddEdge(parentKey, childKey)
		}
		for name := range p.Dependencies {
			addEdge(name, true)
		}
		for name := range p.OptionalDependencies {
			addEdge(name, true)
		}
		for name := range p.PeerDependencies {
			addEdge(name, true)
		}
		// Transitive devDeps only appear on workspace roots in practice;
		// treat them as non-prod edges.
		for name := range p.DevDependencies {
			addEdge(name, false)
		}
	}

	return g, nil
}

// resolveNodeModules implements Node's module resolution against the
// "packages" map: starting from startPath, look for node_modules/<name>
// at that nesting level, then progressively walk up one
// "node_modules/<x>" segment at a time (the way require() does at
// runtime) until we reach the lockfile root. Returns the Key of the
// resolved entry, or false when no match is found.
func resolveNodeModules(startPath, name string, pathToKey map[string]Key) (Key, bool) {
	p := startPath
	for {
		candidate := "node_modules/" + name
		if p != "" {
			candidate = p + "/node_modules/" + name
		}
		if k, ok := pathToKey[candidate]; ok {
			return k, true
		}
		if p == "" {
			return Key{}, false
		}
		// Pop one "node_modules/<x>" segment. Two cases:
		//   "foo/node_modules/bar" → "foo"
		//   "node_modules/bar"     → ""      (top-level pkg; ascend to root)
		idx := strings.LastIndex(p, "/node_modules/")
		if idx >= 0 {
			p = p[:idx]
			continue
		}
		if strings.HasPrefix(p, "node_modules/") {
			p = ""
			continue
		}
		return Key{}, false
	}
}

// nameFromNodeModulesPath extracts the package name from a
// "node_modules/..." path. Handles scoped packages like
// "node_modules/@scope/pkg" and nested paths like
// "foo/node_modules/@scope/pkg".
func nameFromNodeModulesPath(path string) string {
	idx := strings.LastIndex(path, "node_modules/")
	if idx < 0 {
		return ""
	}
	tail := path[idx+len("node_modules/"):]
	if tail == "" {
		return ""
	}
	if strings.HasPrefix(tail, "@") {
		// scope/name — keep both segments.
		parts := strings.SplitN(tail, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return tail
	}
	parts := strings.SplitN(tail, "/", 2)
	return parts[0]
}
