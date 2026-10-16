// Package pnpm parses pnpm-lock.yaml.
//
// Format: YAML. pnpm has evolved the schema across versions 5/6/7/9:
//   - v5/6: package keys like "/foo/1.0.0" or "/foo@1.0.0"
//   - v9:   keys like "foo@1.0.0" (no leading slash); peer contexts moved to
//     a `snapshots` map, which duplicates packages and is not read.
//
// pnpm 10+ can write TWO YAML documents ("---"-separated): the package
// manager's own lock (pnpm itself and its platform binaries, which pnpm
// downloads from the registry to run) and then the project's lock. Every
// document is read; reading only the first lost a whole project (1,255
// packages of vitejs/vite's lockfile, 634 of vuejs/core's).
//
// Where a package comes from is its `resolution`
// (docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources):
//
//   - {integrity} only: the registry. Hash = the integrity (strongest token).
//   - {tarball}: by URL — a registry-shaped tarball on the public registry is
//     public, on another host a mirror or private registry (Origin, decided by
//     hash on the server); codeload / plain tarball URLs are non-registry.
//   - {type: git, repo, commit}: non-registry, Origin git+<repo>#<commit>.
//   - {type: directory} and link:/file: references: the project's own code,
//     Origin "file:<path>".
//
// Aliases need no re-keying: pnpm keys packages by the real name.
//
// Trivy reference: pkg/dependency/parser/nodejs/pnpm/parse.go.
package pnpm

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chain305/chainsaw-core/depparser/origin"
	"github.com/chain305/chainsaw-core/depparser/parser/nodejs/nodesource"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type resolution struct {
	Integrity string `yaml:"integrity"`
	Tarball   string `yaml:"tarball"`
	Path      string `yaml:"path"` // a package inside a monorepo tarball
	Type      string `yaml:"type"`
	Repo      string `yaml:"repo"`
	Commit    string `yaml:"commit"`
	Directory string `yaml:"directory"`
}

type pkgEntry struct {
	Name       string     `yaml:"name"`
	Version    string     `yaml:"version"`
	Resolution resolution `yaml:"resolution"`
}

type lockfile struct {
	Packages map[string]yaml.Node `yaml:"packages"`
}

// Parse reads every document. Scalars of any type decode as strings, as pnpm
// reads them; an entry that still does not decode is an error, returned WITH
// every package that did, so an enforcing caller (the install guard) checks
// those and reports the file as not fully read instead of checking nothing.
func Parse(r io.Reader) ([]ftypes.Package, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []ftypes.Package
	var errs []error
	dec := yaml.NewDecoder(bytes.NewReader(buf))
	for {
		var lf lockfile
		var te *yaml.TypeError
		if err := dec.Decode(&lf); errors.Is(err, io.EOF) {
			break
		} else if errors.As(err, &te) {
			errs = append(errs, err) // the rest of the document decoded
		} else if err != nil {
			return out, errors.Join(append(errs, err)...)
		}
		for key, node := range lf.Packages {
			var body pkgEntry
			if err := node.Decode(&body); err != nil {
				errs = append(errs, fmt.Errorf("packages[%q]: %w", key, err))
				continue
			}
			p := toPackage(key, body)
			// A non-registry package is kept without a version (the scan
			// reports it by name and source); a registry one needs its
			// coordinate.
			if p.Name == "" || (p.Version == "" && p.Origin == "") {
				continue
			}
			// name, version, origin and hash: a git fork and its registry
			// namesake at one version are two packages.
			k := p.Name + "\x00" + p.Version + "\x00" + p.Origin + "\x00" + p.Hash
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, p)
		}
	}
	return out, errors.Join(errs...)
}

func toPackage(key string, body pkgEntry) ftypes.Package {
	name, ref := parseKey(key)
	if body.Name != "" {
		name = body.Name
	}
	version := ref
	if body.Version != "" {
		// v6 non-registry entries, and v9 entries keyed by a URL, carry the
		// package's own version; the key's reference is the URL.
		version = body.Version
	}
	p := ftypes.Package{Name: name, Version: version}
	// pnpm picks the fetcher by resolution.type (directory, git, or none:
	// the tarball), so the type decides — never a stray field. A `directory`
	// beside a tarball, or a file: key, does not make a fetched tarball local.
	res := body.Resolution
	switch {
	case res.Type == "directory":
		p.Origin = nodesource.LocalOrigin("file:" + res.Directory)
	case res.Type == "git" || (res.Repo != "" && res.Tarball == ""):
		src := "git+" + res.Repo
		if res.Commit != "" {
			src += "#" + res.Commit
		}
		p.Origin = origin.Sanitize(src)
	case res.Tarball != "":
		if o := nodesource.LocalOrigin(res.Tarball); o != "" {
			p.Origin = o // a file: tarball
			break
		}
		// A registry tarball URL names the package fetched
		// (nodesource.Tarball); with a `path` it is a monorepo tarball,
		// never the package itself.
		p.Name, p.Version, p.Origin = nodesource.Tarball(name, version, res.Tarball)
		if p.Origin == "" && res.Path != "" {
			p.Origin = "url+" + origin.Sanitize(res.Tarball)
		}
		if p.Origin != "" && res.Path != "" {
			p.Origin += "#path:" + res.Path
		}
		if origin.Classify("npm", p.Origin) != origin.NonRegistry {
			p.Hash = nodesource.Integrity(res.Integrity)
		}
	case nodesource.LocalOrigin(ref) != "":
		p.Origin = nodesource.LocalOrigin(ref) // link:, a file: key with no resolution
	default:
		p.Hash = nodesource.Integrity(res.Integrity)
	}
	if p.Origin != "" && p.Version == ref && strings.ContainsAny(ref, ":/") {
		p.Version = "" // the reference is a path or URL, not a version
	}
	return p
}

// parseKey turns a pnpm packages-map key into (name, reference). Handles:
//
//	/foo/1.0.0                     v5
//	/@scope/foo/1.0.0              v5
//	/foo@1.0.0(peer@2.0.0)         v6
//	foo@1.0.0                      v9
//	foo@https://codeload…/tar.gz/x v9, a URL reference (may contain "@")
//
// The name ends at the first "@" after a scope's leading one — never the
// last, which inside a git+https://git@host URL lands in the URL.
func parseKey(k string) (name, ref string) {
	k = strings.TrimPrefix(k, "/")
	off := 0
	if strings.HasPrefix(k, "@") {
		off = 1
	}
	i := strings.Index(k[off:], "@")
	head := k
	if i >= 0 {
		head = k[:off+i]
	}
	if strings.Count(head, "/") == off {
		if i < 0 {
			return "", ""
		}
		name, ref = head, k[off+i+1:]
		if !strings.Contains(ref, "://") {
			// Strip a peer/patch qualifier: foo@1.0.0(peer@x) → 1.0.0
			ref, _, _ = strings.Cut(ref, "(")
		}
		return name, ref
	}
	// v5 "/" form: "foo/1.0.0", scoped "@scope/foo/1.0.0", with peers
	// appended after "_" ("foo/1.0.0_react@17.0.2").
	parts := strings.SplitN(k, "/", off+2)
	if len(parts) != off+2 {
		return "", ""
	}
	ref, _, _ = strings.Cut(parts[off+1], "_")
	return strings.Join(parts[:off+1], "/"), ref
}
