// Package nodesource reads the source a JavaScript lockfile (yarn, pnpm)
// records for a package, per docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources:
// what Origin a non-registry entry carries, and which content hash stands
// for the artifact.
package nodesource

import (
	"net/url"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/origin"
)

// LocalOrigin is the Origin of a spec that points into the project itself —
// link:, workspace:, portal:, file: — as "file:<path>", the one form every
// consumer reads as local code (the npm parser and the install guard use it
// too); "" for any other spec. A local package is not dropped: it is
// first-party code with no registry coordinate, reported as such, and its
// name@version still gets the known-malicious lookup.
func LocalOrigin(spec string) string {
	for _, p := range []string{"link:", "workspace:", "portal:", "file:"} {
		if rest, ok := strings.CutPrefix(spec, p); ok {
			return origin.Sanitize("file:" + rest)
		}
	}
	return ""
}

// Origin is the Package.Origin for a recorded source: "" when it is the
// public npm registry (or nothing was recorded), else the sanitized source.
func Origin(src string) string {
	if origin.Classify("npm", src) == origin.Public {
		return ""
	}
	return origin.Sanitize(src)
}

// Integrity is the Hash of an SRI string ("sha1-… sha512-…"): EVERY token
// that parses, canonical and joined (origin.JoinHashes), or "" when none
// does. Not just the strongest: npm's ssri accepts the bytes when they match
// ANY token of the strongest algorithm, so "sha512-<public> sha512-<evil>"
// installs either, and keeping the first token would score the evil one as
// the public tarball. The server's hash rule needs every token to be a
// registry digest.
//
// A token ssri reads (a lowercase "<algo>-<digest>") that NormalizeHash
// cannot — sha224, md5, a malformed digest — is kept as
// origin.UnreadableHash(algo), never dropped: ssri ranks sha224 above sha1,
// so "sha1-<public> sha224-<evil>" installs whatever matches sha224, and
// dropping that token left the public sha1 alone to "match". A token with a
// non-lowercase algorithm is ignored, as ssri ignores it.
func Integrity(sri string) string {
	var toks []string
	for _, tok := range strings.Fields(sri) {
		if origin.NormalizeHash(tok) != "" {
			toks = append(toks, tok)
		} else if algo, digest, ok := strings.Cut(tok, "-"); ok && digest != "" && sriAlgo(algo) {
			toks = append(toks, origin.UnreadableHash(algo))
		}
	}
	return origin.JoinHashes(toks...)
}

// sriAlgo: s is an algorithm name as ssri's parser accepts it, [a-z0-9]+.
func sriAlgo(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return s != ""
}

// Tarball is the coordinate and Origin of a package the lockfile keys
// name@version and whose tarball URL it records as src (npm's and yarn v1's
// `resolved`, pnpm's resolution.tarball, a bun URL, berry's __archiveUrl).
//
// The URL is what the package manager fetches, so when its path is an npm
// registry tarball path, …/<n>/-/<basename of n>-<v>.tgz (a scope also as
// "@scope%2fname"), the package IS n@v, whatever the lockfile names it:
// re-keyed like an alias (red-team round 2: node_modules/lodash resolved to
// evil-1.0.0.tgz installs evil@1.0.0, and scoring it as lodash vouched for
// code it never fetched; elastic/kibana's yarn.lock does this honestly,
// resolving two names to @elastic/* forks and one to another @babel
// plugin). On the public registry the Origin is then "", elsewhere the
// sanitized URL (a mirror: the server decides by hash, against n@v).
//
// A URL on the public registry that is NOT a tarball path is "url+<url>":
// non-registry, never scored as name@version (the server reports it high).
// Any other source is origin.Sanitize(src), the coordinate unchanged.
func Tarball(name, version, src string) (string, string, string) {
	class := origin.Classify("npm", src)
	if strings.TrimSpace(src) == "" || class == origin.NonRegistry {
		return name, version, origin.Sanitize(src)
	}
	n, v, rooted, ok := tarballPath(src)
	if class == origin.Public {
		if !ok || !rooted {
			return name, version, "url+" + origin.Sanitize(src)
		}
		return n, v, ""
	}
	if !ok {
		// A mirror path that is not tarball-shaped keeps the lockfile's own
		// coordinate (Artifactory writes scoped tarballs as
		// …/@babel/core/-/@babel/core-7.0.0.tgz) — but only when the path is
		// plain. Dot segments, backslashes and escapes other than a scope's
		// %2f are resolved by the client (WHATWG URL) to some OTHER package's
		// tarball (…/-/x/../evil-1.0.0.tgz), so such a URL is never this
		// package: non-registry, not assessed (red-team round 3).
		if !plainMirrorPath(src) {
			return name, version, "url+" + origin.Sanitize(src)
		}
		n, v = name, version
	}
	return n, v, origin.Sanitize(src)
}

// plainMirrorPath: src's path has no "." or ".." segment, no empty segment,
// no backslash and no percent-escape other than "%2f"/"%2F".
func plainMirrorPath(src string) bool {
	u, err := url.Parse(strings.TrimSpace(src))
	if err != nil {
		return false
	}
	p := u.EscapedPath()
	if strings.Contains(p, `\`) || strings.Contains(strings.ReplaceAll(strings.ReplaceAll(p, "%2f", ""), "%2F", ""), "%") {
		return false
	}
	for _, seg := range strings.Split(strings.TrimPrefix(p, "/"), "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// TarballOrigin is Tarball's Origin alone, for a caller that only needs to
// know whether src is the registry.
func TarballOrigin(name, version, src string) string {
	_, _, o := Tarball(name, version, src)
	return o
}

// tarballPath reads the package coordinate out of an npm registry tarball
// URL: the path's last "/-/" splits the package name (the one or two
// segments before it, two when the first starts with "@") from the file,
// which must be "<basename>-<version>.tgz". Query and fragment are ignored
// (yarn v1 appends "#<sha1>"). Escapes are not decoded except a scope's
// "%2f" — any other escape is not a path the registry writes. rooted: the
// name is the whole path before "/-/", as on the public registry (a mirror
// puts its repository path in front).
func tarballPath(src string) (name, version string, rooted, ok bool) {
	u, err := url.Parse(strings.TrimSpace(src))
	if err != nil {
		return "", "", false, false
	}
	p := u.EscapedPath()
	i := strings.LastIndex(p, "/-/")
	if i < 0 {
		return "", "", false, false
	}
	segs := strings.Split(p[:i], "/")
	file := p[i+3:]
	name = segs[len(segs)-1]
	if scope, base, found := strings.Cut(name, "%2"); found && strings.HasPrefix(scope, "@") && len(base) > 0 && (base[0] == 'f' || base[0] == 'F') {
		name = scope + "/" + base[1:]
	} else if len(segs) >= 2 && strings.HasPrefix(segs[len(segs)-2], "@") {
		name = segs[len(segs)-2] + "/" + name
	}
	base := name[strings.LastIndex(name, "/")+1:]
	version, found := strings.CutPrefix(file, base+"-")
	version, tgz := strings.CutSuffix(version, ".tgz")
	scope, _, scoped := strings.Cut(name, "/")
	if !found || !tgz || version == "" || base == "" || base[0] == '.' || strings.ContainsAny(version, "/%") ||
		strings.Contains(name, "%") || scoped != strings.HasPrefix(name, "@") || (scoped && len(scope) < 2) {
		return "", "", false, false
	}
	rooted = p[:i] == "/"+name || strings.EqualFold(p[:i], "/"+scope+"%2f"+base)
	return name, version, rooted, true
}
