package common

import (
	"path/filepath"
	"strings"
)

// CommonArchiveExtensions enumerates the compound archive suffixes seen across
// language-package ecosystems (pip, composer, rubygems, etc.). Resolvers that
// only care about a subset (e.g. cargo's ".crate" or apt's ".deb") still match
// against the filename directly — this list exists for the generic
// "strip whatever archive extension" path.
//
// Order matters: longer/compound suffixes are checked first so ".tar.gz"
// strips correctly instead of leaving a trailing ".tar".
var CommonArchiveExtensions = []string{
	".tar.gz",
	".tar.bz2",
	".tar.xz",
	".tar.z",
	".tgz",
	".tbz",
	".tbz2",
	".zip",
	".phar",
	".tar",
}

// StripArchiveExtension removes a known archive suffix from filename, falling
// back to filepath.Ext for unknown single-dot extensions. Matching is
// case-insensitive on the suffix but the original case of the leading portion
// is preserved (some resolvers carry case-sensitive identifiers in the stem).
//
// extras is an optional list of caller-specific extensions to try first
// (e.g. pip wants to recognize ".whl" alongside the compound tar variants).
// The shared CommonArchiveExtensions list is always consulted after extras.
func StripArchiveExtension(filename string, extras ...string) string {
	if filename == "" {
		return ""
	}
	lower := strings.ToLower(filename)
	for _, ext := range extras {
		if ext == "" {
			continue
		}
		if strings.HasSuffix(lower, strings.ToLower(ext)) {
			return filename[:len(filename)-len(ext)]
		}
	}
	for _, ext := range CommonArchiveExtensions {
		if strings.HasSuffix(lower, ext) {
			return filename[:len(filename)-len(ext)]
		}
	}
	ext := filepath.Ext(filename)
	if ext == "" {
		return filename
	}
	return strings.TrimSuffix(filename, ext)
}
