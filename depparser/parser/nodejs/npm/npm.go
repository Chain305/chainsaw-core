// Package npm parses package-lock.json and npm-shrinkwrap.json (npm). The two
// files have the same format; shrinkwrap is the publishable copy.
//
// Format: JSON. Three on-the-wire shapes exist:
//
//   - v1 (npm 5/6) — tree under "dependencies" keyed by pkg name, nested
//     recursively.
//   - v2 (npm 7+) — flat map under "packages" keyed by node_modules path.
//     Still carries "dependencies" for backward compat.
//   - v3 — same as v2 but drops the legacy "dependencies" tree.
//
// We read "packages" first; if empty we fall back to the v1 recursive
// walk. The root "" entry (workspace root) is skipped — it isn't a dep.
//
// Where a package comes from (docs/PLANS_INTELLIGENCE.md
// #plan-non-registry-sources): `resolved` is the tarball URL npm fetched. Any
// value origin.Classify does not call the public registry sets Origin — a git
// repository, a tarball URL, a file: tarball, or a registry tarball on another
// host (a mirror or a private registry; the server decides which by Hash).
// Workspace members and file: directories (keys outside node_modules/) are
// local code: Origin "file:<path>". `integrity` becomes Hash.
//
// Trivy reference: pkg/dependency/parser/nodejs/npm/parse.go.
package npm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/origin"
	"github.com/chain305/chainsaw-core/depparser/parser/nodejs/nodesource"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

// lockPackage is one entry in the v2/v3 flat "packages" map.
//
// Deliberately does NOT carry a "dependencies" field. In v2/v3 an entry's
// "dependencies" is a map of name → semver RANGE STRING (npm mirrors
// package.json's runtime deps into the root packages[""] entry), so a
// map[string]v1Dep field made encoding/json fail the whole document with an
// UnmarshalTypeError and Parse threw away a fully decoded lockfile. Nothing
// below reads it, so it stays gone — add a map[string]string only if a caller
// genuinely needs the declared ranges.
//
// "peer" is not read: npm sets it on a package reached through a peer
// dependency, which is installed in production unless "dev" is also set
// (60 production packages in the corpus were dropped while it counted as dev).
//
// Every field takes any JSON type, as npm does: arborist tests "dev" and
// "link" for truthiness and reads a non-string version or integrity as
// absent, so `"dev": 1` is a lockfile npm installs. A strict decode failed
// the whole file on it, and the install guard then checked nothing in it.
type lockPackage struct {
	Name      text  `json:"name"`
	Version   text  `json:"version"`
	Resolved  text  `json:"resolved"`
	Integrity text  `json:"integrity"`
	Dev       truth `json:"dev"`
	Link      truth `json:"link"`
}

type v1Dep struct {
	Version      text   `json:"version"`
	Resolved     text   `json:"resolved"`
	Integrity    text   `json:"integrity"`
	Dev          truth  `json:"dev"`
	Dependencies v1Deps `json:"dependencies"`
}

// v1Deps is a v1 "dependencies" tree level. A level that is not an object
// has no dependencies (npm reads none there); an entry that is not an
// object fails the v1 tree.
type v1Deps map[string]v1Dep

func (d *v1Deps) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil {
		return nil // not an object: npm finds no dependencies here either
	}
	*d = v1Deps{}
	for k, v := range raw {
		var e v1Dep
		if err := json.Unmarshal(v, &e); err != nil {
			return err
		}
		(*d)[k] = e
	}
	return nil
}

// text is a JSON string ("" for null); any other JSON value is an error.
type text string

func (t *text) UnmarshalJSON(b []byte) error {
	// A string or null only. npm coerces anything else to a string —
	// ["https://evil/x.tgz"] is fetched as that URL, 1 is version "1" — so
	// reading it as "" would hide the real source or drop the package
	// (red-team round 3). An error here fails just this entry: the partial
	// decode keeps the rest and the guard reports the file as not fully read.
	if string(b) == "null" {
		*t = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("expected a string, got %s", truncateJSON(b))
	}
	*t = text(s)
	return nil
}

// truncateJSON cuts a raw JSON value for an error message.
func truncateJSON(b []byte) string {
	if len(b) > 40 {
		return string(b[:40]) + "…"
	}
	return string(b)
}

// truth is a JSON value's JavaScript truthiness.
type truth bool

func (t *truth) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case nil:
		*t = false
	case bool:
		*t = truth(x)
	case float64:
		*t = x != 0
	case string:
		*t = x != ""
	default:
		*t = true // an object or array
	}
	return nil
}

type lockfile struct {
	Packages     map[string]json.RawMessage `json:"packages"`
	Dependencies json.RawMessage            `json:"dependencies"`
}

// Parse reads the lockfile. An entry it cannot read (not an object) is an
// error, but every other entry is still returned with it: a caller that
// enforces (the install guard) checks what it can AND reports the file as
// not fully read, rather than collapsing the whole tree to one line.
func Parse(r io.Reader) ([]ftypes.Package, error) {
	var lf lockfile
	if err := json.NewDecoder(r).Decode(&lf); err != nil {
		return nil, err
	}
	var c collector
	var errs []error
	if len(lf.Packages) > 0 {
		entries := make(map[string]lockPackage, len(lf.Packages))
		for p, raw := range lf.Packages {
			var e lockPackage
			if err := json.Unmarshal(raw, &e); err != nil {
				errs = append(errs, fmt.Errorf("packages[%q]: %w", p, err))
				continue
			}
			entries[p] = e
		}
		// A link entry ("node_modules/x": {link, resolved: "packages/x"})
		// names the workspace member it points at, which npm omits from the
		// member's own entry when it equals the directory name.
		linkName := map[string]string{}
		for p, e := range entries {
			if e.Link && e.Resolved != "" {
				linkName[string(e.Resolved)] = deriveNameFromPath(p)
			}
		}
		for _, p := range sortedKeys(entries) {
			e := entries[p]
			if p == "" || e.Link {
				continue // root; a symlink (its target is its own entry)
			}
			name, version, resolved := string(e.Name), string(e.Version), string(e.Resolved)
			if !strings.Contains(p, "node_modules/") && !IsRemote(resolved) {
				// A workspace member or a file: directory: local code,
				// reported when it has a version (nothing to report without).
				// One whose `resolved` is a URL or a git spec is fetched from
				// there, not local, and falls through to the source rule.
				if version == "" {
					continue
				}
				if name == "" {
					name = linkName[p]
				}
				if name == "" {
					name = path.Base(p)
				}
				c.add(ftypes.Package{Name: name, Version: version, Dev: bool(e.Dev), Origin: "file:" + p})
				continue
			}
			// an alias ("foo": "npm:bar@1") records the real name in "name"
			if name == "" {
				name = deriveNameFromPath(p)
			}
			c.add(pkg(name, version, resolved, string(e.Integrity), bool(e.Dev)))
		}
		return c.out, errors.Join(errs...)
	}
	var deps v1Deps
	if len(lf.Dependencies) > 0 {
		if err := json.Unmarshal(lf.Dependencies, &deps); err != nil {
			return nil, err
		}
	}

	// v1 path — recursive tree. A non-registry dependency records its spec
	// in "version" (git+https://…#sha, github:x/y#sha, file:…, a tarball
	// URL) and no package version: it is reported with Origin set and NO
	// version, never as a registry coordinate. A file: directory is local
	// code with no version and is not reported (its dependencies are).
	var walk func(v1Deps, bool)
	walk = func(deps v1Deps, parentDev bool) {
		for _, name := range sortedKeys(deps) {
			d := deps[name]
			dev := parentDev || bool(d.Dev)
			version, src := string(d.Version), string(d.Resolved)
			if target, ok := strings.CutPrefix(version, "npm:"); ok {
				// alias: "foo": {"version": "npm:bar@1.2.3"} installs bar@1.2.3
				if i := strings.LastIndex(target, "@"); i > 0 {
					name, version = target[:i], target[i+1:]
				}
			} else if strings.ContainsAny(version, ":/") { // never in a semver
				// resolved, when present, is the exact git commit or URL;
				// a spec is never a registry release whatever it says.
				if src == "" || origin.Classify("npm", src) == origin.Public {
					src = version
				}
				if strings.HasPrefix(version, "file:") && !IsArchive(version) {
					src = ""
				}
				version = ""
			}
			if version != "" || src != "" {
				c.add(pkg(name, version, src, string(d.Integrity), dev))
			}
			if len(d.Dependencies) > 0 {
				walk(d.Dependencies, dev)
			}
		}
	}
	walk(deps, false)
	return c.out, nil
}

// pkg builds a package from an entry's resolved source and integrity. A
// registry tarball URL names the package npm fetches, which is the
// coordinate whatever the entry is called (nodesource.Tarball).
func pkg(name, version, resolved, integrity string, dev bool) ftypes.Package {
	name, version, o := nodesource.Tarball(name, version, resolved)
	return ftypes.Package{Name: name, Version: version, Dev: dev, Hash: IntegrityHash(integrity), Origin: o}
}

// IsRemote: a `resolved` npm fetches from — a URL or a git spec — rather
// than a path in the project ("packages/a", "../lib", "file:…").
func IsRemote(resolved string) bool {
	return strings.Contains(resolved, ":") && nodesource.LocalOrigin(resolved) == ""
}

// IsArchive reports a file: or URL path that names a tarball rather than a
// directory (origin.IsArchive: one list for every consumer).
func IsArchive(p string) bool { return origin.IsArchive(p) }

// collector dedupes copies of one package. npm installs the same name@version
// at several node_modules paths; copies from different sources (a fork and its
// registry namesake) or with different hashes stay apart. A copy is dev only
// when every copy is: one production copy makes the package production.
type collector struct {
	out []ftypes.Package
	idx map[string]int
}

func (c *collector) add(p ftypes.Package) {
	if p.Name == "" || (p.Version == "" && p.Origin == "") {
		return
	}
	if c.idx == nil {
		c.idx = map[string]int{}
	}
	k := p.Name + "\x00" + p.Version + "\x00" + p.Origin + "\x00" + p.Hash
	if i, ok := c.idx[k]; ok {
		c.out[i].Dev = c.out[i].Dev && p.Dev
		return
	}
	c.idx[k] = len(c.out)
	c.out = append(c.out, p)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// IntegrityHash returns every hash of an SRI integrity string
// ("sha512-<b64> sha1-<b64>" — npm, yarn v1, pnpm and bun all write SRI),
// canonical and joined (nodesource.Integrity: "sha1:<hex> sha512:<hex>"),
// or "".
func IntegrityHash(sri string) string { return nodesource.Integrity(sri) }

// deriveNameFromPath takes a node_modules path like
// "node_modules/foo/node_modules/@scope/bar" and returns "@scope/bar".
func deriveNameFromPath(p string) string {
	// Last "node_modules/" is the trailing scope anchor.
	i := strings.LastIndex(p, "node_modules/")
	if i < 0 {
		return p
	}
	return p[i+len("node_modules/"):]
}
