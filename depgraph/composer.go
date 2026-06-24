package depgraph

// Composer: roots can now come from composer.json when supplied (Wave 7
// follow-up to the Wave 3 inferred-root limitation).
//
// Composer (PHP) ships a real lockfile — composer.lock — as JSON. Its
// `packages` array contains fully resolved package@version entries, and
// each entry's `require` map names direct dependencies whose resolved
// versions live as siblings in the same array. `packages-dev` is the
// dev-only mirror; `platform` / `platform-dev` and the synthetic
// `ext-*`, `lib-*`, and bare `php` / `php-*` requires are PHP runtime
// concerns, not packages, and are skipped entirely.
//
// composer.lock alone does not include the root project's metadata —
// that lives in composer.json. When a caller has access to both files
// they should use ParseComposerLockfileWithJSON, which uses the
// composer.json `require` (prod) and `require-dev` (dev) maps as the
// canonical root list. Otherwise, this parser falls back to a
// pragmatic simplification for ROOT discovery:
//
//	Roots = the set of packages NOT referenced as a `require` target by
//	any other package in `packages` (or `packages-dev` when included).
//
// In other words: the top-of-graph nodes. This is close to but not
// strictly the same as composer.json's root deps — a package that is
// both a direct dep AND a transitive dep of another direct dep would
// not surface as a root here. That's a flagged limitation; the
// transitive walk itself is correct.
//
// Dev-only packages from `packages-dev` are added with Prod=false; prod
// packages from `packages` get Prod=true. Promotion is monotonic via
// Graph.AddNode so a package that appears in both sections ends up
// Prod=true (matches the Maven/npm behavior).

import (
	"encoding/json"
	"fmt"
	"strings"
)

// composerLockfile mirrors the on-disk shape of composer.lock. We only
// decode the fields we use; encoding/json silently ignores everything
// else, which is what we want — composer.lock is a sprawling format
// (dist URLs, hashes, autoload config, etc.) and we don't need any of
// it for graph construction.
type composerLockfile struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
}

// ParseComposerLockfile parses a composer.lock JSON byte stream into a
// Graph. Each entry in `packages` and `packages-dev` becomes a Node;
// entries in `require` produce edges to other entries (looked up by
// `name`, since composer.lock fully resolves transitive versions
// inside the same array).
//
// Limitations:
//   - Root discovery is the "not required by anyone else" heuristic
//     (see file-level comment); composer.json is not consulted. Use
//     ParseComposerLockfileWithJSON when both files are available.
//   - PHP platform packages (`ext-*`, `lib-*`, `php`, `php-*`, plus
//     anything declared in composer.lock's `platform`/`platform-dev`
//     blocks) are skipped — they aren't real packages.
//   - Dev packages get Prod=false. Production-only graphs are produced
//     by callers filtering on Node.Prod.
func ParseComposerLockfile(data []byte) (*Graph, error) {
	return ParseComposerLockfileWithJSON(data, nil)
}

// composerJSON mirrors the small slice of composer.json we use:
// `require` (prod direct deps) and `require-dev` (dev direct deps).
// Both are name → version-constraint maps; the constraint string is
// ignored because composer.lock has already resolved each name.
type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// ParseComposerLockfileWithJSON consumes both composer.lock (resolved
// graph) and composer.json (root deps declaration). When composerJSON
// is non-nil and parses successfully, its `require` and `require-dev`
// maps form the canonical root set: `require` entries are roots with
// Prod=true, `require-dev` entries are roots with Prod=false.
// Falls back to the existing "not required by anyone" inference when
// composerJSON is nil. A composer.json that parses but contains no
// require entries also falls back to inference, so an empty manifest
// does not strand the graph.
func ParseComposerLockfileWithJSON(lockfile []byte, composerJSONData []byte) (*Graph, error) {
	if len(lockfile) == 0 {
		return nil, fmt.Errorf("depgraph/composer: empty input")
	}
	var lock composerLockfile
	if err := json.Unmarshal(lockfile, &lock); err != nil {
		return nil, fmt.Errorf("depgraph/composer: %w", err)
	}
	if len(lock.Packages) == 0 && len(lock.PackagesDev) == 0 {
		return nil, fmt.Errorf("depgraph/composer: no packages in lockfile")
	}

	var manifest *composerJSON
	if len(composerJSONData) > 0 {
		var m composerJSON
		if err := json.Unmarshal(composerJSONData, &m); err != nil {
			return nil, fmt.Errorf("depgraph/composer: composer.json: %w", err)
		}
		if len(m.Require) > 0 || len(m.RequireDev) > 0 {
			manifest = &m
		}
	}

	g := NewGraph()

	// First pass: insert every node. Build a name→Key index so the
	// edge pass can resolve `require` targets without iterating
	// packages each time. composer.lock guarantees `name` is unique
	// across the union of packages and packages-dev (you can't have
	// the same package as both prod and dev).
	nameToKey := make(map[string]Key, len(lock.Packages)+len(lock.PackagesDev))
	for _, p := range lock.Packages {
		k, ok := composerKey(p)
		if !ok {
			return nil, fmt.Errorf("depgraph/composer: invalid package entry: name=%q version=%q", p.Name, p.Version)
		}
		g.AddNode(k, false, true)
		nameToKey[p.Name] = k
	}
	for _, p := range lock.PackagesDev {
		k, ok := composerKey(p)
		if !ok {
			return nil, fmt.Errorf("depgraph/composer: invalid dev package entry: name=%q version=%q", p.Name, p.Version)
		}
		g.AddNode(k, false, false)
		nameToKey[p.Name] = k
	}

	// Track which keys are referenced as a `require` target by
	// another package — anything NOT in this set is a root.
	required := make(map[Key]struct{}, len(nameToKey))

	addEdges := func(p composerPackage) error {
		from, ok := nameToKey[p.Name]
		if !ok {
			return fmt.Errorf("depgraph/composer: missing self-key for %q", p.Name)
		}
		for depName := range p.Require {
			if isComposerPlatform(depName) {
				continue
			}
			to, ok := nameToKey[depName]
			if !ok {
				// Required package not present in the lockfile —
				// composer.lock should never produce this for a
				// valid resolve, but tolerate it rather than
				// failing the whole graph (callers fall back to
				// flat eval if the graph errors).
				continue
			}
			g.AddEdge(from, to)
			required[to] = struct{}{}
		}
		return nil
	}
	for _, p := range lock.Packages {
		if err := addEdges(p); err != nil {
			return nil, err
		}
	}
	for _, p := range lock.PackagesDev {
		if err := addEdges(p); err != nil {
			return nil, err
		}
	}

	if manifest != nil {
		// Manifest-driven roots: walk require (prod) then require-dev
		// (dev) in lockfile order so the resulting Roots slice is
		// deterministic. We walk the lockfile's packages list and
		// promote names that appear in the manifest's require map —
		// this preserves the stable ordering of the lockfile (the
		// composer.json `require` map is unordered in Go).
		for _, p := range lock.Packages {
			if _, want := manifest.Require[p.Name]; !want {
				continue
			}
			k, ok := nameToKey[p.Name]
			if !ok {
				continue
			}
			g.AddNode(k, true, true)
			g.AddRoot(k)
		}
		for _, p := range lock.PackagesDev {
			if _, want := manifest.RequireDev[p.Name]; !want {
				continue
			}
			k, ok := nameToKey[p.Name]
			if !ok {
				continue
			}
			g.AddNode(k, true, false)
			g.AddRoot(k)
		}
		// Some manifest entries may sit in `packages` (a require-dev
		// transitively pulls them prod, or vice versa) — handle the
		// other direction too so a require-dev root that lockfile
		// resolved to packages still surfaces.
		for _, p := range lock.PackagesDev {
			if _, want := manifest.Require[p.Name]; !want {
				continue
			}
			k, ok := nameToKey[p.Name]
			if !ok {
				continue
			}
			g.AddNode(k, true, true)
			g.AddRoot(k)
		}
		for _, p := range lock.Packages {
			if _, want := manifest.RequireDev[p.Name]; !want {
				continue
			}
			k, ok := nameToKey[p.Name]
			if !ok {
				continue
			}
			g.AddNode(k, true, false)
			g.AddRoot(k)
		}
		return g, nil
	}

	// Roots: any node not required by any other. Walk packages first
	// then packages-dev so root order is stable and prod-first.
	addRootIfTop := func(p composerPackage) {
		k, ok := nameToKey[p.Name]
		if !ok {
			return
		}
		if _, isReq := required[k]; isReq {
			return
		}
		g.AddNode(k, true, false) // promote Direct; Prod was set in pass 1
		g.AddRoot(k)
	}
	for _, p := range lock.Packages {
		addRootIfTop(p)
	}
	for _, p := range lock.PackagesDev {
		addRootIfTop(p)
	}

	return g, nil
}

// composerKey extracts the canonical Key from a composer package
// entry. Names are vendor/package; we keep them as-is. Versions in
// composer.lock are fully resolved (e.g. "1.2.3" or "v1.2.3" or
// "dev-main"); we trust the lockfile and don't normalize.
func composerKey(p composerPackage) (Key, bool) {
	name := strings.TrimSpace(p.Name)
	version := strings.TrimSpace(p.Version)
	if name == "" || version == "" {
		return Key{}, false
	}
	return Key{Ecosystem: "composer", Name: name, Version: version}, true
}

// isComposerPlatform reports whether a require key is a PHP platform
// pseudo-package rather than a real composer package. composer.lock's
// `require` maps mix real deps with platform constraints; the latter
// have no corresponding entry in `packages` and must be filtered out
// before edge resolution.
func isComposerPlatform(name string) bool {
	if name == "php" {
		return true
	}
	if strings.HasPrefix(name, "php-") {
		return true
	}
	if strings.HasPrefix(name, "ext-") {
		return true
	}
	if strings.HasPrefix(name, "lib-") {
		return true
	}
	return false
}
