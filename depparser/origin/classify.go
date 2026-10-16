package origin

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Class is what a lockfile source string says about where a package comes
// from (docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources §3.1).
//
// The zero value is NonRegistry, the conservative answer: a source nobody
// recognised is never treated as the public registry.
type Class int

const (
	// NonRegistry: git, a local path, a tarball/wheel URL, a workspace or
	// link. A different package from any public namesake; never scored as one.
	NonRegistry Class = iota
	// RegistryOther: the registry protocol on a host that is not the public
	// registry — a MIRROR (Artifactory, Nexus, Verdaccio, devpi, a Chainsaw
	// proxy repository) or a PRIVATE registry. The URL cannot tell which;
	// a content hash can (see the server lockfile scan).
	RegistryOther
	// Public: the ecosystem's public registry under any of its aliases, or
	// no source at all.
	Public
)

func (c Class) String() string {
	switch c {
	case Public:
		return "public"
	case RegistryOther:
		return "registry-other"
	}
	return "non-registry"
}

// publicAliases is each ecosystem's public registry: a host, or host/path
// for registries that live under a path on a shared host (crates.io's git
// index and the CocoaPods Specs repo are on github.com, conda channels on
// conda.anaconda.org). Matched exactly — host case-insensitively, at the
// scheme's default port, path on a segment boundary — never by suffix:
// registry.npmjs.org.evil.example is not npm.
//
// This is the ONE list; the install guard's knownRegistry and the Cargo.lock
// parser read it through Classify.
var publicAliases = map[string][]string{
	"npm":       {"registry.npmjs.org", "registry.yarnpkg.com"},
	"pypi":      {"pypi.org", "files.pythonhosted.org", "pypi.python.org"},
	"cargo":     {"index.crates.io", "crates.io", "static.crates.io", "github.com/rust-lang/crates.io-index"},
	"rubygems":  {"rubygems.org", "index.rubygems.org"},
	"pub":       {"pub.dev", "pub.dartlang.org"},
	"cocoapods": {"cdn.cocoapods.org", "trunk.cocoapods.org", "github.com/CocoaPods/Specs"},
	"nuget":     {"api.nuget.org", "nuget.org", "www.nuget.org"},
	"composer":  {"repo.packagist.org", "packagist.org"},
	"maven":     {"repo1.maven.org", "repo.maven.apache.org"},
	"conda":     {"conda.anaconda.org/conda-forge", "repo.anaconda.com/pkgs/main", "repo.anaconda.com/pkgs/r", "repo.anaconda.com/pkgs/msys2"},
}

// condaChannels are conda's public channels by the bare names environment
// files and conda-lock record instead of a URL.
var condaChannels = map[string]bool{"conda-forge": true, "defaults": true, "main": true, "pkgs/main": true, "pkgs/r": true, "pkgs/msys2": true}

// ecosystemAliases folds the spellings callers use onto publicAliases keys.
var ecosystemAliases = map[string]string{
	"pip": "pypi", "python": "pypi", "crates.io": "cargo", "rust": "cargo",
	"gem": "rubygems", "ruby": "rubygems", "dart": "pub", "packagist": "composer",
	"yarn": "npm", "pnpm": "npm", "bun": "npm",
}

func normEcosystem(eco string) string {
	eco = strings.ToLower(strings.TrimSpace(eco))
	if e, ok := ecosystemAliases[eco]; ok {
		return e
	}
	return eco
}

// archiveSuffixes mark a URL as one artifact (a tarball, wheel, gem, crate…)
// rather than a registry index. The tar family is pip's whole
// ARCHIVE_EXTENSIONS (.tar, .tbz, .txz, .tlz, .tar.lz, .tar.lzma installs
// as readily as .tar.gz): a vendored `./vendor/evilpkg-1.0.tar` is
// third-party code, not the project's own (red-team round 2).
var archiveSuffixes = []string{".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar", ".tbz", ".txz", ".tlz", ".tar.lz", ".tar.lzma", ".zip", ".whl", ".gem", ".crate", ".nupkg", ".jar", ".conda"}

// IsArchive: p (a path or URL, any "?query" or "#fragment" cut off) names
// one artifact file — a tarball, wheel, gem, crate… — case-insensitively.
// A "file:" origin that is an archive is a vendored third-party artifact,
// not the project's own code.
func IsArchive(p string) bool {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = strings.ToLower(p)
	for _, suf := range archiveSuffixes {
		if strings.HasSuffix(p, suf) {
			return true
		}
	}
	return false
}

// Classify decides which Class a lockfile source string is, for ecosystem
// eco (any spelling ecosystemAliases knows). An empty source is Public: the
// lockfile recorded nothing, which every format uses for its default
// registry.
//
// Rules, in order:
//   - "git+" / "path+" prefixes, scp-style and shorthand git specs, file:,
//     link:, workspace: and other non-URL forms: NonRegistry (bare conda
//     channel names excepted).
//   - A URL on a public alias at the default port: Public.
//   - "registry+" / "sparse+" (Cargo's registry protocol): RegistryOther.
//   - A Chainsaw proxy repository URL (…/repository/@<slug>/<repo>/…):
//     RegistryOther. It is a registry protocol whatever the path looks like,
//     but NOT the public registry: any org can create a repository on a
//     shared Chainsaw host with an arbitrary upstream, so only a content
//     hash (or the org's own declaration) can call it a mirror.
//   - npm and PyPI lockfiles record ARTIFACT URLs, so a plain URL there is
//     a tarball/wheel dependency (NonRegistry) unless it has the registry's
//     shape: npm's "/-/<name>-<ver>.tgz", PyPI's "/simple" index.
//     (A GitHub Packages npm URL, …/download/@scope/name/…, has neither and
//     is NonRegistry until P1b teaches it otherwise.)
//   - Other ecosystems record the registry ADDRESS, so a plain URL is
//     RegistryOther unless it ends in an archive suffix.
func Classify(eco, source string) Class {
	s := strings.TrimSpace(source)
	if s == "" {
		return Public
	}
	eco = normEcosystem(eco)
	prefix, rest := splitPrefix(s)
	prefix = strings.ToLower(prefix)
	if prefix != "" && prefix != "registry+" && prefix != "sparse+" {
		return NonRegistry // git+, path+, file+…
	}
	if !strings.Contains(rest, "://") {
		if eco == "conda" && condaChannels[strings.ToLower(strings.TrimSuffix(rest, "/"))] {
			return Public
		}
		return NonRegistry // git@host:x, github:x/y, file:…, ./path, user/repo
	}
	u, err := url.Parse(rest)
	if err != nil || u.Host == "" {
		return NonRegistry
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return NonRegistry // git://, ssh://, file://
	}
	if isPublic(eco, u) {
		return Public
	}
	if prefix != "" || isChainsawRepository(u.Path) {
		return RegistryOther
	}
	p := strings.ToLower(u.Path)
	switch eco {
	case "npm":
		if strings.Contains(p, "/-/") && strings.HasSuffix(p, ".tgz") {
			return RegistryOther
		}
		return NonRegistry
	case "pypi":
		if p == "/simple" || strings.HasSuffix(strings.TrimSuffix(p, "/"), "/simple") || strings.Contains(p, "/simple/") {
			return RegistryOther
		}
		return NonRegistry
	}
	if IsArchive(p) {
		return NonRegistry
	}
	return RegistryOther
}

// isPublic: u's host (at the scheme's default port) and path are one of
// eco's public aliases.
func isPublic(eco string, u *url.URL) bool {
	if !defaultPort(u) {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, a := range publicAliases[eco] {
		aHost, aPath, _ := strings.Cut(a, "/")
		if host != aHost {
			continue
		}
		if aPath == "" {
			return true
		}
		// A path alias is matched on the path the CLIENT requests, and
		// cargo/conda parse URLs WHATWG-style: "..", "%2e%2e" and "\"
		// resolve, so crates.io-index/../../attacker/index is fetched from
		// github.com/attacker. Any dot segment, backslash or escape refuses.
		if !plainPath(u) {
			return false
		}
		p := strings.TrimSuffix(strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git"), "/")
		if strings.EqualFold(p, aPath) {
			return true
		}
		// cargo records the index URL itself; only conda/CocoaPods paths
		// continue below the alias (subdir, package file).
		if eco != "cargo" && len(p) > len(aPath) && strings.EqualFold(p[:len(aPath)], aPath) && p[len(aPath)] == '/' {
			return true
		}
	}
	return false
}

// plainPath: u's path has no ".", ".." or empty segment, no backslash and
// no percent-escape, so every URL parser reads the same path.
func plainPath(u *url.URL) bool {
	if strings.ContainsAny(u.Path, `\%`) || strings.Contains(u.EscapedPath(), "%") {
		return false
	}
	for _, seg := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func defaultPort(u *url.URL) bool {
	port := u.Port()
	return port == "" || (port == "443" && strings.EqualFold(u.Scheme, "https")) || (port == "80" && strings.EqualFold(u.Scheme, "http"))
}

// isChainsawRepository: a Chainsaw proxy repository path,
// [<base>]/repository/@<org slug>/<repo>/….
// Matched on the cleaned, lower-cased path, so "repository/./@x",
// "repository//@x" and %2e forms (u.Path is decoded) cannot slip past the
// exclusion in MirrorHost.
func isChainsawRepository(p string) bool {
	return strings.Contains(strings.ToLower(path.Clean("/"+strings.ReplaceAll(p, `\`, "/"))), "/repository/@")
}

// Host is the host (with any non-default port) of a URL source, lowercased,
// for "via <host>" labels; "" for a non-URL source.
func Host(source string) string {
	_, rest := splitPrefix(strings.TrimSpace(source))
	u, err := url.Parse(rest)
	if err != nil || u.Host == "" {
		return ""
	}
	if defaultPort(u) {
		return strings.ToLower(u.Hostname())
	}
	return strings.ToLower(u.Host)
}

// MaxMirrorHosts bounds an org's or a CLI config's registry_mirrors list.
const MaxMirrorHosts = 50

// NormalizeMirrorHost validates one registry_mirrors entry: a hostname, or
// hostname:port, and nothing else — no scheme, path, userinfo or wildcard,
// because the entry is matched exactly (MirrorHost) and a pattern would be a
// way to declare half the internet a mirror. Returns it lowercased.
func NormalizeMirrorHost(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	host, port, hasPort := strings.Cut(s, ":")
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return "", errors.New("registry mirror " + quoteRedacted(s) + ": port must be 1-65535")
		}
	}
	if host == "" || len(host) > 253 {
		return "", errors.New("registry mirror " + quoteRedacted(s) + ": not a hostname")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("registry mirror " + quoteRedacted(s) + ": not a hostname (give the host only, e.g. artifactory.example.com)")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("registry mirror " + quoteRedacted(s) + ": not a hostname (give the host only, e.g. artifactory.example.com)")
			}
		}
	}
	return s, nil
}

// quoteRedacted quotes an invalid registry_mirrors entry for an error
// message with any userinfo cut off: the message reaches stderr, CI logs and
// API responses, and a pasted URL often carries a token.
func quoteRedacted(s string) string {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = "…@" + s[i+1:]
	}
	return strconv.Quote(s)
}

// MirrorHost returns the entry of mirrors (NormalizeMirrorHost form) that
// source's URL is served from, or "". A bare host matches only at the
// scheme's default port; host:port matches that port. Exact host, never a
// suffix.
//
// A Chainsaw proxy repository URL never matches: a shared Chainsaw host
// serves every org's repositories, each with its own upstream, so declaring
// the host a mirror would vouch for repositories the org does not own.
// Those are decided by content hash.
func MirrorHost(source string, mirrors []string) string {
	if len(mirrors) == 0 {
		return ""
	}
	_, rest := splitPrefix(strings.TrimSpace(source))
	u, err := url.Parse(rest)
	if err != nil || u.Host == "" || isChainsawRepository(u.Path) {
		return ""
	}
	if s := strings.ToLower(u.Scheme); s != "https" && s != "http" {
		return ""
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[strings.ToLower(u.Scheme)]
	}
	for _, m := range mirrors {
		mh, mp, hasPort := strings.Cut(m, ":")
		if host == mh && ((hasPort && port == mp) || (!hasPort && defaultPort(u))) {
			return m
		}
	}
	return ""
}

// Lockfile content hashes.
//
// Canonical form: "<algo>:<lowercase hex>", algo one of sha1, sha256,
// sha384, sha512 — e.g. a Cargo.lock checksum becomes "sha256:<hex>" and an
// npm integrity "sha512-<base64>" becomes "sha512:<hex>". One form for every
// ecosystem so a lockfile hash compares with a stored registry digest by
// string equality.
var hashHexLen = map[string]int{"sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128}

// NormalizeHash returns the canonical form of one hash written as
// "<algo>:<hex>" (also "<algo>=<hex>") or as one SRI token
// "<algo>-<base64>[?opts]", or "" when it is neither or the length does not
// fit the algorithm.
//
// An SRI token's algorithm must be lowercase: npm's ssri matches
// /^([a-z0-9]+)-.../ and skips "SHA512-…", so a token npm never checks must
// not be one we compare (it could vouch for bytes npm does not verify
// against). "<algo>:<hex>" forms stay case-insensitive.
func NormalizeHash(s string) string {
	s = strings.TrimSpace(s)
	if algo, b64, ok := strings.Cut(s, "-"); ok {
		if n, known := hashHexLen[strings.ToLower(algo)]; known {
			if algo != strings.ToLower(algo) {
				return ""
			}
			b64, _, _ = strings.Cut(b64, "?")
			raw, err := base64.StdEncoding.DecodeString(b64)
			if err != nil || len(raw)*2 != n {
				return ""
			}
			return algo + ":" + hex.EncodeToString(raw)
		}
	}
	i := strings.IndexAny(s, ":=")
	if i < 0 {
		return ""
	}
	algo, h := strings.ToLower(s[:i]), strings.ToLower(s[i+1:])
	if hashHexLen[algo] != len(h) || !isHex(h) {
		return ""
	}
	return algo + ":" + h
}

// MaxJoinedHashes bounds the distinct tokens JoinHashes keeps. A real
// release has well under a hundred files; past this the entry reads as
// carrying no usable hash, which never scores as the public package (a
// lockfile that hashes other packages makes a missing hash "not assessed").
const MaxJoinedHashes = 256

// JoinHashes is the Hash of a lockfile entry that records several candidate
// files of ONE release — a requirements line's --hash options, a poetry
// `files` list, uv's sdist and wheels, a Pipfile `hashes` list: the
// installer takes one of them. Each token in canonical form (NormalizeHash),
// unusable ones dropped, deduplicated, sorted (a deterministic dedupe key),
// joined by single spaces; "" past MaxJoinedHashes distinct tokens. One hash
// comes back as itself, so a Cargo checksum's Hash is unchanged. The
// caller's slice is never reordered.
func JoinHashes(hashes ...string) string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hashes {
		if n := hashToken(h); n != "" && !seen[n] {
			if len(out) == MaxJoinedHashes {
				return ""
			}
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

// SplitHashes returns the canonical tokens of a Hash (JoinHashes form, or a
// single hash in any form NormalizeHash reads), UnreadableHash placeholders
// included; other unusable tokens are dropped.
func SplitHashes(s string) []string {
	var out []string
	for _, tok := range strings.Fields(s) {
		if n := hashToken(tok); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// unreadablePrefix marks a hash the lockfile records but we cannot read or
// compare (an algorithm NormalizeHash does not know, a file listed with no
// usable hash). It is kept, never dropped: the installer may verify, or
// fetch, exactly that file, so a hash list that drops it can "match" the
// public release on its other tokens while the unreadable one is what gets
// installed (red-team round 2: "sha1-<public> sha224-<other>" on npm, a uv
// wheel listed without a hash next to a public sdist). The comparison treats
// it as uncomparable, so such a list is at best "unpublished", never a match.
const unreadablePrefix = "unknown:"

// UnreadableHash is the placeholder token for a recorded hash (or file) of
// algorithm algo that cannot be compared; algo is only a label ("" → "none").
func UnreadableHash(algo string) string {
	a := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		}
		return -1
	}, algo)
	if a == "" {
		a = "none"
	}
	if len(a) > 16 {
		a = a[:16]
	}
	return unreadablePrefix + a
}

// IsUnreadableHash: tok is an UnreadableHash placeholder.
func IsUnreadableHash(tok string) bool { return strings.HasPrefix(tok, unreadablePrefix) }

// hashToken is the canonical form of one Hash token: NormalizeHash, or the
// placeholder itself.
func hashToken(tok string) string {
	if IsUnreadableHash(tok) {
		return UnreadableHash(strings.TrimPrefix(tok, unreadablePrefix))
	}
	return NormalizeHash(tok)
}
