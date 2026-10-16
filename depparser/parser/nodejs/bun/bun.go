// Package bun parses bun.lock (text format).
//
// Format: a JSON-ish trailing-comma-tolerant syntax Bun calls "jsonc".
// Top-level has:
//
//	{
//	  "lockfileVersion": 1,
//	  "workspaces": { "": {...}, "packages/web": {"name": ..., "version": ...} },
//	  "packages": {
//	    "foo": ["foo@1.2.3", "", {...info}, "sha512-…"],
//	    "x/bar": ["bar@github:owner/bar#abc1234", {...info}, "owner-bar-abc1234"],
//	    "web": ["web@workspace:packages/web"],
//	  }
//	}
//
// Each packages-map entry's first element is "{name}@{resolution}": a
// version for a registry package, otherwise the source (github:, git+…, a
// tarball URL, file:, workspace:, link:). A registry package has four
// elements: [id, registry, info, integrity], registry "" for the default
// one. Bun's binary lockfile (bun.lockb) is a separate format and is not
// parsed.
//
// Where a package comes from (docs/PLANS_INTELLIGENCE.md
// #plan-non-registry-sources): a registry package on a non-default registry,
// and every git/URL/file source, carries Origin; integrity becomes Hash.
// workspace:/link:/file: directories are local code, kept (Origin
// "file:<path>") when they carry a version and dropped otherwise — there is
// no coordinate to report.
//
// Trivy reference: pkg/dependency/parser/nodejs/bun/parse.go.
package bun

import (
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/parser/nodejs/nodesource"
	"github.com/chain305/chainsaw-core/depparser/parser/nodejs/npm"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type lockfile struct {
	LockfileVersion int `json:"lockfileVersion"`
	Workspaces      map[string]struct {
		Version string `json:"version"`
	} `json:"workspaces"`
	Packages map[string][]any `json:"packages"`
}

func Parse(r io.Reader) ([]ftypes.Package, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var lf lockfile
	if err := json.Unmarshal(stripJSONC(raw), &lf); err != nil {
		return nil, err
	}

	keys := make([]string, 0, len(lf.Packages))
	for k := range lf.Packages {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []ftypes.Package
	seen := map[string]bool{}
	for _, key := range keys {
		arr := lf.Packages[key]
		if len(arr) == 0 {
			continue
		}
		id, _ := arr[0].(string)
		// The name ends at the first "@" after a scope's: a git source can
		// hold another ("foo@git+ssh://git@github.com/…").
		at := strings.Index(id[min(1, len(id)):], "@") + 1
		if at <= 0 {
			continue
		}
		name, ref := id[:at], id[at+1:]
		p := ftypes.Package{Name: name} // an alias's key is the alias; id names the real package
		switch {
		case hasAnyPrefix(ref, "workspace:", "link:", "file:", "portal:"):
			src := ref[strings.IndexByte(ref, ':')+1:]
			p.Version = info(arr, "version")
			if strings.HasPrefix(ref, "workspace:") && p.Version == "" {
				p.Version = lf.Workspaces[src].Version
			}
			if p.Version == "" && (!strings.HasPrefix(ref, "file:") || !npm.IsArchive(src)) {
				continue // a local directory with no version: nothing to report
			}
			if strings.HasPrefix(ref, "link:") {
				p.Origin = ref
			} else {
				p.Origin = "file:" + src
			}
		case strings.Contains(ref, ":") || strings.Contains(ref, "/"): // never in a version
			// git, github:, a tarball URL: Bun records no package version
			// unless the info object carries one; reported without one. A
			// registry tarball URL names the package fetched.
			p.Name, p.Version, p.Origin = nodesource.Tarball(name, info(arr, "version"), ref)
		default:
			p.Version = ref
			if len(arr) >= 4 {
				reg, _ := arr[1].(string)
				p.Name, p.Version, p.Origin = nodesource.Tarball(name, ref, tarballURL(reg, name, ref))
				sri, _ := arr[3].(string)
				p.Hash = npm.IntegrityHash(sri)
			}
		}
		if p.Version == "" && p.Origin == "" {
			continue
		}
		// name, version, origin AND hash: a second copy of one coordinate
		// with another integrity is another artifact, never a duplicate.
		k := p.Name + "\x00" + p.Version + "\x00" + p.Origin + "\x00" + p.Hash
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out, nil
}

// tarballURL is where a registry package's tarball comes from: "" for the
// default registry, the URL Bun recorded, or — when Bun recorded a registry
// root ("https://host/path/") — npm's tarball path under it, so the URL
// has the registry shape origin.Classify looks for.
func tarballURL(reg, name, version string) string {
	if !strings.HasSuffix(reg, "/") {
		return reg
	}
	base := name[strings.LastIndex(name, "/")+1:]
	return reg + name + "/-/" + base + "-" + version + ".tgz"
}

// info reads a string field of the entry's info object (the first object
// element), or "".
func info(arr []any, field string) string {
	for _, e := range arr[1:] {
		if m, ok := e.(map[string]any); ok {
			s, _ := m[field].(string)
			return s
		}
	}
	return ""
}

func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// stripJSONC drops `//` line comments and trailing commas so stdlib json
// accepts a bun.lock — but only OUTSIDE string literals. Integrity hashes are
// base64 and routinely contain "//" (feldera/feldera's bun.lock has 14); the
// previous line-based strip cut those strings in half and the whole lockfile
// failed with "invalid character '\n' in string literal".
func stripJSONC(b []byte) []byte {
	out := make([]byte, 0, len(b))
	inString, escaped := false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if inString {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch {
		case c == '"':
			inString = true
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
			if i < len(b) {
				out = append(out, '\n')
			}
			continue
		case c == ',':
			j := i + 1
			for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}
