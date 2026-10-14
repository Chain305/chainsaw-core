// Package origin handles the source string a lockfile records for a package
// that does NOT come from its ecosystem's public registry (a git repository,
// an alternate registry): the value of ftypes.Package.Origin.
//
// It exists so every consumer (the server lockfile scan, `chainsaw scan`,
// pr-scan, the install guard) stores and prints the same thing. Two rules:
//
//   - Sanitize before storing. A lockfile source can carry credentials
//     (git+https://user:token@host/…) or tokens in the query string, and the
//     Origin travels into JSON, SARIF, CI logs and stored scan-job rows —
//     including the anonymous public lockfile-scan endpoint.
//   - Label for display: host/path@<short ref> for git, host/path otherwise.
package origin

import (
	"net/url"
	"regexp"
	"strings"
)

// keepQuery is the query parameters a source needs to identify a revision.
// Everything else is dropped: it is where access tokens ride.
var keepQuery = map[string]bool{"rev": true, "tag": true, "branch": true, "ref": true}

// userinfo matches a "user[:password]@" segment after a scheme, for sources
// url.Parse cannot read.
var userinfo = regexp.MustCompile(`(://)[^/@\s]*@`)

// Sanitize returns src without URL userinfo and without query parameters
// other than rev/tag/branch/ref. The scheme prefix Cargo and others put in
// front of the URL ("git+", "registry+", "sparse+") is kept.
func Sanitize(src string) string {
	src = strings.TrimSpace(src)
	if src == "" {
		return ""
	}
	prefix, rest := splitPrefix(src)
	u, err := url.Parse(rest)
	if err != nil || u.Host == "" {
		return userinfo.ReplaceAllString(src, "$1")
	}
	u.User = nil
	if u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			if !keepQuery[k] {
				q.Del(k)
			}
		}
		u.RawQuery = q.Encode()
	}
	return prefix + u.String()
}

// Label shortens a source for display. A git source becomes
// host/path@<commit, rev, tag or branch>, a hex commit cut to 7 characters;
// any other URL becomes host/path. Credentials never survive.
func Label(src string) string {
	src = Sanitize(src)
	prefix, rest := splitPrefix(src)
	u, err := url.Parse(rest)
	if err != nil || u.Host == "" {
		return src
	}
	label := u.Host + strings.TrimSuffix(u.Path, ".git")
	if prefix != "git+" {
		return strings.TrimSuffix(label, "/")
	}
	ref := u.Fragment
	for _, q := range []string{"rev", "tag", "branch", "ref"} {
		if ref == "" {
			ref = u.Query().Get(q)
		}
	}
	if len(ref) > 7 && isHex(ref) {
		ref = ref[:7]
	}
	if ref != "" {
		label += "@" + ref
	}
	return label
}

// splitPrefix separates a "git+" / "registry+" / "sparse+" style prefix from
// the URL that follows it. A plain URL has no prefix.
func splitPrefix(src string) (string, string) {
	if i := strings.Index(src, "+"); i > 0 && i < strings.Index(src+"://", "://") {
		return src[:i+1], src[i+1:]
	}
	return "", src
}

func isHex(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
