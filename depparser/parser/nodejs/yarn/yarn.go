// Package yarn parses yarn.lock files from both v1 (Yarn classic) and
// v2+ (Berry) layouts.
//
// v1 is a custom line-oriented format, one block per resolved package:
//
//	"@babel/core@^7.0.0", "@babel/core@~7.1":
//	  version "7.22.0"
//	  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.22.0.tgz#<sha1>"
//	  integrity sha512-…
//
// Berry (v2+) is YAML with a __metadata header and a `resolution` locator
// per entry ("lodash@npm:4.17.21").
//
// Where the package comes from (docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources):
//
//   - v1: the `resolved` URL. On registry.yarnpkg.com / registry.npmjs.org it
//     is the public registry; a registry-shaped tarball on another host is a
//     mirror or private registry (Origin, decided by hash on the server); a
//     git, codeload or plain tarball URL is non-registry (Origin). The hash is
//     `integrity` (SRI, strongest token), else the sha1 in the resolved URL's
//     fragment — never for a git source, where the fragment is a commit.
//   - Berry: the resolution protocol. `npm:` is the registry — which registry
//     lives in .yarnrc.yml, not in the lockfile, so it is taken as the public
//     one. git / https / exec: are non-registry. `patch:` is the patched
//     package plus a local patch: re-keyed to that package. Berry's `checksum`
//     hashes yarn's cache zip, not the registry tarball, and is never a Hash.
//   - Both: link:, workspace:, portal: and file: are the project's own code,
//     Origin "file:<path>". An alias ("foo@npm:bar@^1") is keyed by the
//     package it installs (bar), not the alias.
//
// Trivy reference: pkg/dependency/parser/nodejs/yarn/parse.go.
package yarn

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chain305/chainsaw-core/depparser/origin"
	"github.com/chain305/chainsaw-core/depparser/parser/nodejs/nodesource"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func Parse(r io.Reader) ([]ftypes.Package, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var c collector
	if berry.Match(buf) {
		err = parseBerry(buf, &c)
	} else {
		err = parseV1(buf, &c)
	}
	return c.out, err
}

var berry = regexp.MustCompile(`(?m)^__metadata:\s*$`)

// collector dedupes on name, version, origin AND hash: a lockfile can hold
// the same name@version from the registry and from a git fork
// (discourse's ember-cli-htmlbars@6.3.0), and the two are different packages.
type collector struct {
	out  []ftypes.Package
	seen map[string]bool
}

func (c *collector) add(p ftypes.Package) {
	// A non-registry package is kept without a version (the scan reports
	// it by name and source); a registry one needs its coordinate.
	if p.Name == "" || (p.Version == "" && p.Origin == "") {
		return
	}
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	key := p.Name + "\x00" + p.Version + "\x00" + p.Origin + "\x00" + p.Hash
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.out = append(c.out, p)
}

// ---- v1 ----

func parseV1(buf []byte, c *collector) error {
	sc := bufio.NewScanner(bytes.NewReader(buf))
	// yarn.lock lines can be long for chained descriptors. The whole file is
	// the limit: a line past a fixed cap stopped the scan with
	// bufio.ErrTooLong, losing every block after it.
	sc.Buffer(make([]byte, 0, 64*1024), max(len(buf)+1, 64*1024))

	var (
		descs  []string          // the current block's descriptors
		fields map[string]string // its two-space-indented key/values
	)
	flush := func() {
		if len(descs) > 0 {
			c.add(v1Package(descs, fields))
		}
		descs, fields = nil, nil
	}
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Header: no indentation, ends with ":".
		// e.g. `"@babel/core@^7.0.0", "@babel/core@~7.1":`
		if line[0] != ' ' && line[0] != '\t' {
			flush()
			if strings.HasSuffix(trimmed, ":") {
				for _, d := range strings.Split(strings.TrimSuffix(trimmed, ":"), ",") {
					if d = strings.Trim(strings.TrimSpace(d), `"`); d != "" {
						descs = append(descs, d)
					}
				}
				fields = map[string]string{}
			}
			continue
		}
		// A block's own fields are indented exactly two spaces; deeper lines
		// are its dependencies.
		if len(descs) == 0 || !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		k, v, _ := strings.Cut(trimmed, " ")
		fields[strings.TrimSuffix(k, ":")] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	flush()
	return sc.Err()
}

// sha1Fragment is the tarball sha1 yarn v1 appends to a registry `resolved`.
var sha1Fragment = regexp.MustCompile(`#([0-9a-f]{40})$`)

// gitSpec: a v1 range that names a git repository or URL rather than a
// version range (`user/repo#sha`, `github:x/y`, `git+ssh://…`, `https://…`).
func gitSpec(rng string) bool {
	for _, p := range []string{"git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "http:", "https:", "ssh:"} {
		if strings.HasPrefix(rng, p) {
			return true
		}
	}
	return strings.Contains(rng, "/")
}

// v1Package builds one block's package. descs are ALL of the header's
// descriptors: one block can merge several ("lodash@file:./x",
// "lodash@^4.17.0"), and yarn installs the one artifact the block resolved
// to. So the `resolved` URL decides where it comes from, and the package is
// local code only when that resolution really is local — a local resolved,
// or no resolved and every descriptor local. Reading the first descriptor
// alone let a `file:` descriptor in front hide a tarball from any host.
//
// A registry tarball URL names the package yarn fetches, which is the
// coordinate whatever the descriptors say (nodesource.Tarball):
// elastic/kibana resolves "@emotion/sheet@^1.4.0" to @elastic/emotion-sheet.
func v1Package(descs []string, f map[string]string) ftypes.Package {
	var name, local, git string
	allLocal := true
	for i, d := range descs {
		n, rng := splitDescriptor(d)
		if target, ok := strings.CutPrefix(rng, "npm:"); ok {
			// Alias: "string-width-cjs@npm:string-width@^4.2.0" installs
			// string-width. A bare "npm:pkg" has no range.
			if tn, r := splitDescriptor(target); tn != "" {
				n, rng = tn, r
			}
		}
		if i == 0 {
			name = n
		}
		if o := nodesource.LocalOrigin(rng); o != "" {
			if local == "" {
				local = o
			}
			continue
		}
		allLocal = false
		if git == "" && gitSpec(rng) {
			git = rng
		}
	}
	p := ftypes.Package{Name: name, Version: f["version"]}
	src := f["resolved"]
	if o := nodesource.LocalOrigin(src); o != "" {
		p.Origin = o // resolved to a file: path or archive in the project
		return p
	}
	if src == "" {
		if allLocal && local != "" {
			p.Origin = local
			return p
		}
		src = git
	}
	p.Name, p.Version, p.Origin = nodesource.Tarball(name, p.Version, src)
	if p.Origin != "" && origin.Classify("npm", p.Origin) == origin.NonRegistry {
		return p // a git fragment is a commit, an archive URL's hash is not the registry's
	}
	p.Hash = nodesource.Integrity(f["integrity"])
	if p.Hash == "" {
		if m := sha1Fragment.FindStringSubmatch(src); m != nil {
			p.Hash = "sha1:" + m[1]
		}
	}
	return p
}

// ---- berry ----

type berryEntry struct {
	Version    string `yaml:"version"`
	Resolution string `yaml:"resolution"`
}

// parseBerry decodes entry by entry: scalars of any type read as strings,
// and an entry that still does not decode is an error returned WITH every
// package that did (Parse returns both), never a reason to drop the rest.
func parseBerry(buf []byte, c *collector) error {
	var lf map[string]yaml.Node
	var te *yaml.TypeError
	if err := yaml.Unmarshal(buf, &lf); err != nil && !errors.As(err, &te) {
		return err
	}
	var errs []error
	if te != nil {
		errs = append(errs, te)
	}
	keys := make([]string, 0, len(lf))
	for key := range lf {
		keys = append(keys, key)
	}
	sort.Strings(keys) // a deterministic order, and errors that do not depend on it
	for _, key := range keys {
		node := lf[key]
		if key == "__metadata" {
			continue // lockfile version and cache key, not a package
		}
		var e berryEntry
		if err := node.Decode(&e); err != nil {
			errs = append(errs, fmt.Errorf("%q: %w", key, err))
			continue
		}
		loc := e.Resolution
		if loc == "" {
			// A descriptor, as a fallback: the first non-local one when the
			// key merges several, so a "file:" descriptor in front cannot
			// make the entry read as local code.
			for i, d := range strings.Split(key, ",") {
				d = strings.TrimSpace(d)
				if _, ref := splitDescriptor(d); i == 0 || nodesource.LocalOrigin(ref) == "" {
					loc = d
					if nodesource.LocalOrigin(ref) == "" {
						break
					}
				}
			}
		}
		c.add(berryPackage(strings.TrimSpace(loc), e.Version, e.Resolution != ""))
	}
	return errors.Join(errs...)
}

// berryPackage turns a resolution locator ("name@<protocol>:<ref>") into a
// package. exact: loc is the entry's `resolution`, which is what yarn
// fetches — so its npm: version wins over the `version` field, which yarn
// does not fetch by (a lockfile saying version 3.3.5 beside resolution
// npm:3.3.6 installs 3.3.6). A descriptor fallback holds a range: the
// `version` field then.
func berryPackage(loc, version string, exact bool) ftypes.Package {
	name, ref := splitDescriptor(loc)
	// A package with peer dependencies is resolved once per peer set, as
	// "name@virtual:<hash>#<real ref>".
	if rest, ok := strings.CutPrefix(ref, "virtual:"); ok {
		if _, r, found := strings.Cut(rest, "#"); found {
			ref = r
		}
	}
	// "patch:<url-encoded locator>#<patch>::<params>" is the inner package
	// with a local patch applied: re-keyed to that package, whose own
	// protocol decides where it comes from.
	if rest, ok := strings.CutPrefix(ref, "patch:"); ok {
		inner, _, _ := strings.Cut(rest, "#")
		if dec, err := url.PathUnescape(inner); err == nil {
			inner = dec
		}
		if n, _ := splitDescriptor(inner); n != "" && !strings.HasPrefix(inner, "patch:") {
			return berryPackage(inner, version, exact)
		}
	}
	p := ftypes.Package{Name: name, Version: version}
	if v, ok := strings.CutPrefix(ref, "npm:"); ok {
		// The registry (.yarnrc.yml's, read as the public one). An alias's
		// resolution already names the real package. "::" starts locator
		// parameters; __archiveUrl is the tarball URL yarn fetches instead
		// of the registry's default one, read like any other.
		v, params, _ := strings.Cut(v, "::")
		if exact && v != "" || p.Version == "" {
			p.Version = v
		}
		// The values ParseQuery could read are used even when it reports an
		// error: Node's querystring (what yarn parses with) reads
		// "__archiveUrl=…&a=;" or "…&a=%zz" fine, Go's errors on them.
		q, _ := url.ParseQuery(params)
		if a := q.Get("__archiveUrl"); a != "" {
			p.Name, p.Version, p.Origin = nodesource.Tarball(name, p.Version, a)
		} else if strings.Contains(params, "__archiveUrl") {
			// Named but unreadable: yarn may still fetch it; never the
			// public package.
			p.Origin = "url+" + origin.Sanitize(params)
		}
		return p
	}
	if o := nodesource.LocalOrigin(ref); o != "" {
		p.Origin = o
		return p
	}
	// git (https://…git#commit=…, git+ssh, github:), a tarball URL, exec:.
	p.Name, p.Version, p.Origin = nodesource.Tarball(name, p.Version, ref)
	return p
}

// splitDescriptor: "@babel/core@^7.0.0" → ("@babel/core", "^7.0.0"). The
// name ends at the first "@" after a scope's leading one; everything after
// is the range or reference, which may itself contain "@" (git URLs, alias
// targets).
func splitDescriptor(d string) (string, string) {
	i := strings.Index(d[min(1, len(d)):], "@")
	if i < 0 {
		return d, ""
	}
	i += min(1, len(d))
	return d[:i], d[i+1:]
}
