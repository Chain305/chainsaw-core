package origin

import (
	"errors"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// The non_registry_sources policy facts (docs/PLANS_INTELLIGENCE.md
// #plan-non-registry-sources §3.6): whether a non-registry source is pinned
// to immutable content, and the host/path location an org allow-lists.

// vcsPrefixes are the source forms that name a version-control repository
// rather than an artifact. "git+", "hg+"… are the pip/Cargo/lockfile
// prefixes; the shorthands are npm's.
var vcsPrefixes = []string{"git+", "hg+", "svn+", "bzr+", "git://", "ssh://", "github:", "gitlab:", "bitbucket:", "gist:"}

// shorthandHosts are npm's hosted-git shorthands.
var shorthandHosts = map[string]string{"github:": "github.com", "gitlab:": "gitlab.com", "bitbucket:": "bitbucket.org", "gist:": "gist.github.com"}

// Pinned reports whether a non-registry source names immutable content:
//
//   - a version-control source (git+…, git://, ssh://, git@host:path, npm's
//     github:/gitlab:/bitbucket:/gist: and user/repo shorthands): EVERY ref
//     the source carries — the fragment (`#<sha>`; in a key=value fragment
//     only yarn berry's `commit=`, so pip's `egg=` / `subdirectory=` are not
//     refs) and a pip/npm `@<ref>` path suffix — must be a full commit, 40
//     or 64 hex, and there must be at least one. A branch, a tag, a short
//     SHA or no ref at all is mutable, and so is a source carrying a commit
//     beside a branch (`…/x@main#<sha>`: which one the tool reads is the
//     tool's business). A `?rev=` query is NOT a ref: npm ignores it, and
//     Cargo.lock always records the resolved commit in the fragment.
//   - anything else (a URL tarball, a vendored archive, a package from an
//     undeclared registry): a lockfile content hash. hash is a
//     Package.Hash (JoinHashes form); a list with an UnreadableHash
//     placeholder in it does not pin (one listed file has no usable hash).
//
// Cargo.lock, Gemfile.lock, composer.lock and npm/uv/poetry locks record
// the RESOLVED commit in the fragment, so a locked git dependency is
// pinned even when the manifest asked for a branch.
func Pinned(src, hash string) bool {
	s, ok := NormalizeURL(strings.TrimSpace(src))
	if !ok {
		return false
	}
	if isVCS(s) {
		refs := vcsRefs(s)
		for _, ref := range refs {
			if !fullCommit(ref) {
				return false
			}
		}
		return len(refs) > 0
	}
	toks := SplitHashes(hash)
	for _, t := range toks {
		if IsUnreadableHash(t) {
			return false
		}
	}
	return len(toks) > 0
}

// isVCS: s is a version-control source (see Pinned). A bare "user/repo"
// counts — npm reads it as GitHub, and no parser records a relative path
// without its "file:" prefix.
func isVCS(s string) bool {
	lower := strings.ToLower(s)
	for _, p := range vcsPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	if strings.Contains(s, "://") {
		// An archive URL is fetched as that file whatever its fragment says,
		// so it is never VCS: only a content hash pins it
		// (https://npm.corp/x/-/x-1.0.0.tgz#commit=<sha> is not pinned).
		if base, _, _ := strings.Cut(s, "#"); IsArchive(strings.SplitN(base, "?", 2)[0]) {
			return false
		}
		// yarn berry: https://host/x/y.git#commit=<sha> (or head=, tag=).
		rest, frag, _ := strings.Cut(s, "#")
		q, _ := url.ParseQuery(frag)
		if q.Has("commit") || q.Has("head") || q.Has("tag") {
			return true
		}
		_, rest = splitPrefix(rest)
		u, err := url.Parse(rest)
		return err == nil && strings.HasSuffix(strings.ToLower(strings.TrimSuffix(u.Path, "/")), ".git")
	}
	if scpLike(s) {
		return true
	}
	repo, _, _ := strings.Cut(s, "#")
	return strings.Count(repo, "/") == 1 && !strings.ContainsAny(repo, ":@ ") &&
		!strings.HasPrefix(repo, ".") && !strings.HasPrefix(repo, "/") && !strings.HasPrefix(repo, "~") && !IsArchive(repo)
}

// scpLike: "user@host:path" (git's scp syntax), no scheme.
func scpLike(s string) bool {
	at := strings.Index(s, "@")
	colon := strings.Index(s, ":")
	return at > 0 && colon > at+1 && !strings.ContainsAny(s[:colon], "/")
}

// vcsRefs returns every ref a VCS source carries (see Pinned).
func vcsRefs(s string) []string {
	var refs []string
	rest, frag, _ := strings.Cut(s, "#")
	if strings.Contains(frag, "=") {
		// "egg=x&subdirectory=y" (pip), "commit=<sha>" (yarn berry). An
		// unreadable one is kept whole: never a commit, so never pinned.
		q, err := url.ParseQuery(frag)
		if err != nil {
			return []string{frag}
		}
		refs = append(refs, q["commit"]...)
	} else if frag != "" {
		refs = append(refs, frag)
	}
	_, u := splitPrefix(rest)
	if p, err := url.Parse(u); err == nil && p.Host != "" {
		if i := strings.LastIndex(p.Path, "@"); i >= 0 {
			refs = append(refs, p.Path[i+1:]) // pip: …/repo.git@<ref>
		}
	}
	return refs
}

func fullCommit(ref string) bool {
	return (len(ref) == 40 || len(ref) == 64) && isHex(strings.ToLower(ref))
}

// Location is the host/path a non-registry source comes from, the string
// an org's nonRegistryOriginNotIn patterns match: lowercased host (with any
// non-default port), then the path without ".git", a pip "@ref" suffix or a
// trailing slash. No scheme, userinfo, query, fragment or ref — two
// lockfiles naming the same repository at different commits have the same
// Location. npm shorthands resolve to their host (github:x/y and x/y →
// github.com/x/y), git@host:x/y to host/x/y, a "file:" archive to
// "file:<path>" (never host-shaped: file:github.com/myorg/x.tgz is a local
// file, not github.com/myorg/*), a named registry ("registry+NAME") to NAME.
// A source with no agreed reading (NormalizeURL ok=false) is "", which no
// pattern matches.
//
// Built from Sanitize, so userinfo and tokens in the query never survive.
// A token in the PATH (dl.cloudsmith.io/<token>/…) cannot be recognised and
// does: do not print a Location for a source on such a registry.
func Location(src string) string {
	s := Sanitize(src)
	if _, ok := NormalizeURL(s); !ok {
		return ""
	}
	lower := strings.ToLower(s)
	if rest, ok := strings.CutPrefix(lower, "file:"); ok {
		return "file:" + strings.TrimPrefix(s[len(s)-len(rest):], "//")
	}
	for p, host := range shorthandHosts {
		if strings.HasPrefix(lower, p) {
			return host + "/" + trimRepoPath(s[len(p):])
		}
	}
	prefix, rest := splitPrefix(s)
	if !strings.Contains(rest, "://") {
		rest, _, _ = strings.Cut(rest, "#")
		if i := strings.LastIndex(rest, "@"); i >= 0 && !scpLike(rest) {
			rest = rest[i+1:] // never "user:token@…", whatever its shape
		}
		if scpLike(rest) {
			host, p, _ := strings.Cut(rest[strings.Index(rest, "@")+1:], ":")
			return strings.ToLower(host) + "/" + trimRepoPath(p)
		}
		if prefix == "" && isVCS(rest) {
			return "github.com/" + trimRepoPath(rest)
		}
		return rest
	}
	u, err := url.Parse(rest)
	if err != nil || u.Host == "" {
		return rest
	}
	host := strings.ToLower(u.Hostname())
	if !defaultPort(u) {
		host += ":" + u.Port()
	}
	p := u.Path
	if isVCS(s) {
		if i := strings.LastIndex(p, "@"); i >= 0 {
			p = p[:i]
		}
	}
	if p = trimRepoPath(p); p == "" {
		return host
	}
	return host + "/" + p
}

// trimRepoPath drops a ref, leading/trailing slashes and ".git".
func trimRepoPath(p string) string {
	p, _, _ = strings.Cut(p, "#")
	p = strings.Trim(p, "/")
	return strings.TrimSuffix(strings.TrimSuffix(p, ".git"), "/")
}

// MaxLocationPatterns bounds one nonRegistryOriginNotIn list.
const MaxLocationPatterns = 100

// ValidateLocationPattern checks one nonRegistryOriginNotIn entry: a
// Location-shaped glob ("github.com/myorg/*", "git.corp.example/**"). It
// must not be empty or carry a scheme ("https://…", "github:…"), userinfo
// or whitespace — a pattern is matched against Location, which has none,
// so such a pattern could never match and would silently fire for every
// source. Each segment must be valid path.Match syntax.
func ValidateLocationPattern(p string) error {
	q := strconv.Quote(redactUserinfo(p))
	if strings.TrimSpace(p) == "" {
		return errors.New("non-registry origin pattern is empty")
	}
	if strings.Contains(p, "://") {
		return errors.New("non-registry origin pattern " + q + ": give host/path without a scheme, e.g. github.com/myorg/*")
	}
	if strings.Contains(p, "@") {
		return errors.New("non-registry origin pattern " + q + ": must not contain userinfo or a ref (@)")
	}
	if strings.ContainsAny(p, " \t\r\n") {
		return errors.New("non-registry origin pattern " + q + ": must not contain whitespace")
	}
	// Each "**" multiplies MatchLocation's work by the (lockfile-controlled)
	// segment count; two keeps it quadratic.
	doubleStars := 0
	for _, seg := range strings.Split(p, "/") {
		if seg == "**" {
			doubleStars++
		}
	}
	if doubleStars > 2 || len(p) > 512 {
		return errors.New("non-registry origin pattern " + q + ": at most two ** segments and 512 characters")
	}
	host, _, _ := strings.Cut(p, "/")
	if _, port, ok := strings.Cut(host, ":"); ok {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return errors.New("non-registry origin pattern " + q + ": give host/path without a scheme, e.g. github.com/myorg/*")
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if _, err := path.Match(seg, ""); err != nil {
			return errors.New("non-registry origin pattern " + q + ": bad glob syntax")
		}
	}
	return nil
}

func redactUserinfo(s string) string {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return "…@" + s[i+1:]
	}
	return s
}

// MatchLocation reports whether loc (a Location) matches pattern
// (ValidateLocationPattern form), segment by segment on "/": "*" and the
// rest of path.Match's syntax within one segment, "**" alone as a segment
// for zero or more segments. The host segment compares case-insensitively,
// the path case-sensitively. An invalid pattern matches nothing, and so
// does a loc with a ".", ".." or empty segment, raw or percent-decoded:
// clients resolve github.com/myorg/x/../../evil to github.com/evil, so
// "github.com/myorg/**" must not vouch for it.
func MatchLocation(pattern, loc string) bool {
	if !plainLocation(loc) || ValidateLocationPattern(pattern) != nil {
		return false
	}
	return matchSegs(strings.Split(pattern, "/"), strings.Split(loc, "/"), true)
}

func plainLocation(loc string) bool {
	dec, err := url.PathUnescape(loc)
	if loc == "" || err != nil {
		return false
	}
	for _, l := range []string{loc, dec} {
		for _, seg := range strings.Split(l, "/") {
			if seg == "" || seg == "." || seg == ".." {
				return false
			}
		}
	}
	return true
}

func matchSegs(pat, segs []string, host bool) bool {
	if len(pat) == 0 {
		return len(segs) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(segs); i++ {
			if matchSegs(pat[1:], segs[i:], false) {
				return true
			}
		}
		return false
	}
	if len(segs) == 0 {
		return false
	}
	p, s := pat[0], segs[0]
	if host {
		p, s = strings.ToLower(p), strings.ToLower(s)
	}
	if ok, err := path.Match(p, s); err != nil || !ok {
		return false
	}
	return matchSegs(pat[1:], segs[1:], false)
}
