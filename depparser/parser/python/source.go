package python

import (
	"net/url"
	"strings"

	pep440 "github.com/aquasecurity/go-pep440-version"

	"github.com/chain305/chainsaw-core/depparser/origin"
)

// source.go: where a Python lockfile says a package comes from, as
// ftypes.Package.Origin (docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources).
// Not part of the Trivy vendor.

// IndexOrigin is the Origin of a package resolved from the package index at
// url: "" for PyPI under any of its aliases, else "registry+<url>",
// sanitised — the index protocol on another host, a mirror or a private
// index, which the server decides by content hash. The "registry+" prefix
// is what makes it a registry source whatever the URL's path looks like
// (devpi's "/+simple", CodeArtifact's "/pypi/<repo>/simple/"): every format
// that records an index records it as one.
func IndexOrigin(url string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return ""
	}
	o := "registry+" + url
	if origin.Classify("pypi", o) == origin.Public {
		return ""
	}
	return origin.Sanitize(o)
}

// VCSOrigin is the Origin of a VCS dependency: "<vcs>+<url>", with the
// revision as the fragment (the grammar origin.Label reads). A url that
// already carries a "git+" style prefix keeps it.
func VCSOrigin(vcs, url, rev string) string {
	url = strings.TrimSpace(url)
	if url == "" {
		return ""
	}
	if i := strings.Index(url, "://"); i > 0 && !strings.Contains(url[:i], "+") {
		url = vcs + "+" + url
	}
	if rev != "" && !strings.Contains(url, "#") {
		url += "#" + rev
	}
	return origin.Sanitize(url)
}

// FileOrigin is the Origin of an artifact location (a wheel or sdist URL, a
// find-links page, or a local path): "" when the URL is on PyPI's own hosts,
// PathOrigin for a path, else the sanitised URL. A URL on PyPI's hosts is
// not yet the registry package: a lock entry's file goes through
// ProjectFileOrigin, which also checks it is that project's file.
func FileOrigin(src string) string {
	src = strings.TrimSpace(src)
	if origin.Classify("pypi", src) == origin.Public {
		return ""
	}
	if !strings.Contains(src, "://") {
		return PathOrigin(src)
	}
	return origin.Sanitize(src)
}

// ProjectFileOrigin is the Origin of lock entry name@version installed from
// the file src. A file on PyPI's own hosts is the registry package ("") only
// when it IS that project's wheel or sdist of that version (ProjectFile):
// files.pythonhosted.org serves every project, so a `requests` entry listing
// .../evilpkg-6.6.6-py3-none-any.whl installs evilpkg, not requests
// (red-team round 2). Any other file there is ForeignFileOrigin.
func ProjectFileOrigin(name, version, src string) string {
	o := FileOrigin(src)
	if o != "" || ProjectFile(name, version, src) {
		return o
	}
	return ForeignFileOrigin(src)
}

// ForeignFileOrigin is the Origin of a file on PyPI's hosts that is not the
// lock entry's own: "url+<sanitised url>". The "url+" prefix makes
// origin.Classify read it NonRegistry (the bare URL would classify Public
// and be scored as the namesake); origin.Label prints host/path.
func ForeignFileOrigin(src string) string {
	return "url+" + origin.Sanitize(strings.TrimSpace(src))
}

// ProjectFile reports whether src is a wheel or sdist of project name
// (PEP 503) at version (PEP 440 equality: "1.0" is "1.0.0"). An empty
// version, or a file name DistFilename cannot read, is never a match.
func ProjectFile(name, version, src string) bool {
	if version == "" {
		return false
	}
	if fn, fv := DistFilename(src); fn != "" && SameProject(fn, name) && SameVersion(fv, version) {
		return true
	}
	// Legacy names DistFilename splits wrongly: an sdist whose version holds
	// a "-" (foo-1.0-beta1.tar.gz for 1.0b1), a pre-PEP 427 wheel whose name
	// holds an unescaped "-" (my-pkg-1.0-py3-none-any.whl). Every split is
	// tried, and one is accepted only when its name IS this project (PEP 503)
	// and its version IS this version (PEP 440) — so another project's file
	// (requests-evil-1.0.tar.gz for requests) still never passes. Without
	// this an honest old lockfile would read "another package's artifact".
	stem, wheel := distStem(src)
	if stem == "" {
		return false
	}
	parts := strings.Split(stem, "-")
	if wheel {
		if len(parts) < 5 {
			return false
		}
		parts = parts[:len(parts)-3] // python, abi and platform tags
	}
	for i := 1; i < len(parts); i++ {
		if !SameProject(strings.Join(parts[:i], "-"), name) {
			continue
		}
		// The version is the rest — or, for a wheel with a build tag, the
		// next part alone.
		if SameVersion(strings.Join(parts[i:], "-"), version) || (wheel && SameVersion(parts[i], version)) {
			return true
		}
	}
	return false
}

// distStem: a distribution file name without its archive extension, and
// whether it is a wheel; "" when src is not a wheel or sdist.
func distStem(src string) (string, bool) {
	if i := strings.IndexAny(src, "?#"); i >= 0 {
		src = src[:i]
	}
	base := src[strings.LastIndexAny(src, `/\`)+1:]
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".whl") {
		return base[:len(base)-4], true
	}
	for _, ext := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar"} {
		if strings.HasSuffix(lower, ext) {
			return base[:len(base)-len(ext)], false
		}
	}
	return "", false
}

// SameVersion reports whether two version strings are one PEP 440 version;
// strings that do not parse must be equal.
func SameVersion(a, b string) bool {
	if a == b {
		return true
	}
	va, err := pep440.Parse(a)
	if err != nil {
		return false
	}
	vb, err := pep440.Parse(b)
	return err == nil && va.Equal(vb)
}

// FileHash is one recorded file's contribution to an entry's Hash: its
// canonical hash, or origin.UnreadableHash when the lock records none that
// NormalizeHash reads (missing, md5, blake2b, a bad length). Never dropped:
// the installer may take exactly that file, and a list without it could
// match the public release on its other files (red-team round 2: a mirror
// uv.lock with a public sdist hash and an unhashed wheel).
func FileHash(h string) string {
	if n := origin.NormalizeHash(h); n != "" {
		return n
	}
	algo := strings.TrimSpace(h)
	if i := strings.IndexAny(algo, ":="); i >= 0 {
		algo = algo[:i]
	} else {
		algo = ""
	}
	return origin.UnreadableHash(algo)
}

// PathOrigin is the Origin of local code (a directory, an editable project,
// a file on disk): "file:<path>", the form every surface reads as a local
// path (the install guard prints it as one rather than as an unknown source).
func PathOrigin(p string) string {
	p = origin.Sanitize(strings.TrimSpace(p))
	if strings.HasPrefix(p, "file:") {
		return p
	}
	return "file:" + p
}

// DistFilename returns the project name and version a wheel or sdist file
// name (the last path segment of src, query and fragment cut) encodes, or
// "", "" when it is neither:
//
//	{name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
//	{name}-{version}.tar.gz (and .zip, .tar.bz2, .tgz …): version after the
//	last "-", starting with a digit (python-dateutil-2.8.2.tar.gz)
func DistFilename(src string) (name, version string) {
	if i := strings.IndexAny(src, "?#"); i >= 0 {
		src = src[:i]
	}
	base := src[strings.LastIndexAny(src, `/\`)+1:]
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".whl") {
		parts := strings.Split(base[:len(base)-4], "-")
		if len(parts) >= 5 {
			return parts[0], parts[1]
		}
		return "", ""
	}
	for _, ext := range []string{".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar"} {
		if !strings.HasSuffix(lower, ext) {
			continue
		}
		stem := base[:len(base)-len(ext)]
		if i := strings.LastIndex(stem, "-"); i > 0 && i+1 < len(stem) && stem[i+1] >= '0' && stem[i+1] <= '9' {
			return stem[:i], stem[i+1:]
		}
		return "", ""
	}
	return "", ""
}

// SameProject reports whether two spellings name one project (PEP 503).
func SameProject(a, b string) bool {
	return NormalizePkgName(a, true) == NormalizePkgName(b, true)
}

// DistFile is one file a lockfile records for an index package: its URL,
// or a path for a wheel or sdist on disk.
type DistFile struct{ URL, Path string }

// IndexFilesOrigin is the Origin of index package name@version that records
// its files (pylock `wheels`/`sdist`, uv `wheels`/`sdist`). The installer
// fetches each file from the URL the lock records, not from the index, so
// EVERY file is read, never just the index or the first file:
//
//   - a file on PyPI's own hosts adds nothing when it is this project's file
//     of this version (ProjectFile); any other file there makes the entry
//     ForeignFileOrigin — not the package it names;
//   - a file on the index's own host adds nothing;
//   - a file on any other host makes the entry come from that host, as an
//     index there ("registry+<scheme>://<host>/": a mirror's lock records its
//     files on the mirror, and the server decides by hash);
//   - a file by path is a vendored artifact: PathOrigin.
//
// A non-registry answer (a path, a foreign PyPI file, a non-HTTP URL) wins
// over another host's index. With no such file the entry comes from its
// index (IndexOrigin, "" for PyPI).
func IndexFilesOrigin(name, version, index string, files []DistFile) string {
	idx := IndexOrigin(index)
	other := ""
	for _, f := range files {
		u := strings.TrimSpace(f.URL)
		if u == "" {
			if strings.TrimSpace(f.Path) != "" {
				return PathOrigin(f.Path)
			}
			continue
		}
		if FileOrigin(u) == "" {
			if ProjectFile(name, version, u) {
				continue
			}
			return ForeignFileOrigin(u)
		}
		if idx != "" && origin.Host(u) == origin.Host(index) {
			continue
		}
		p, err := url.Parse(u)
		if err != nil || p.Host == "" || (p.Scheme != "https" && p.Scheme != "http") {
			return FileOrigin(u)
		}
		if other == "" {
			other = IndexOrigin(p.Scheme + "://" + p.Host + "/")
		}
	}
	if other != "" {
		return other
	}
	return idx
}
