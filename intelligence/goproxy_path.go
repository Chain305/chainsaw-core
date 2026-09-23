package intelligence

// The Go module proxy path for a package ZIP, in one place.
//
// Measured in prod 2026-09-23: **6,093 of 6,139 stored Go reports carry a BARE
// version** ("1.3.0") because both Go lockfile parsers strip the leading "v" so
// their coordinates dedup against each other and match how vulnerability
// databases index semver. The module proxy requires canonical semver, so every
// one of those built a URL the proxy rejects:
//
//	rsc.io/sampler/@v/1.3.0.zip   -> 404
//	rsc.io/sampler/@v/v1.3.0.zip  -> 200
//
// That is exactly the observed coverage: the 46 v-prefixed rows produced all 4
// artifact scans Go has ever had, and the 6,093 bare ones produced zero. The
// artifact path had the prefix problem the METADATA path (runGo) had already
// solved with goProxyVersion, because each rebuilt the URL for itself.
//
// Case-escaping matters for the same reason and was also missing here: the
// proxy lowercases with a "!" sentinel, so github.com/Sirupsen/logrus is
// fetched as github.com/!sirupsen/logrus. x/mod is the authoritative
// implementation of both escapes and is already a direct dependency, so this
// uses it rather than adding to the hand-rolled encodeGoModulePath.

import (
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// GoModuleZipPath returns the proxy-relative path of a module's .zip, and
// whether the coordinate is usable at all.
//
// ok is false rather than a best-effort path for anything the proxy cannot
// answer — an unusable coordinate should skip the fetch, not issue a request
// guaranteed to 404 against a shared upstream we are rate-limited on.
func GoModuleZipPath(modulePath, version string) (string, bool) {
	modulePath = strings.Trim(strings.TrimSpace(modulePath), "/")
	version = goProxyVersion(version)
	if modulePath == "" || version == "" {
		return "", false
	}
	// Reject a version that is not canonical semver even after the prefix is
	// restored — a pseudo-version or "latest" reaching here is a bug upstream,
	// and guessing a path for it wastes an upstream request.
	if !semver.IsValid(version) {
		return "", false
	}
	escPath, err := module.EscapePath(modulePath)
	if err != nil {
		return "", false
	}
	escVer, err := module.EscapeVersion(version)
	if err != nil {
		return "", false
	}
	return escPath + "/@v/" + escVer + ".zip", true
}
