package osv

// compare.go exports the package's per-ecosystem version comparator so
// callers outside this package can order two concrete version strings
// under the SAME rules the advisory range matcher uses.
//
// It exists so nobody re-implements the dispatch table. The bundle
// matcher's compareVersions is the only place in the tree that knows
// PyPI needs PEP 440, RubyGems needs Gem ordering, NuGet has a fourth
// numeric segment, and everything else is SemVer; a second copy would
// drift and re-open exactly the false-negative class that motivated the
// NuGet branch (see the compareVersions doc comment).
//
// This file adds no behaviour — it is a one-line re-export.

// CompareVersions orders two concrete versions of a package under the
// named ecosystem's own version grammar, returning -1 / 0 / +1 in the
// conventional shape.
//
// The error is non-nil when either operand cannot be parsed under that
// ecosystem's grammar. Callers MUST treat that as "undecidable" and
// fall back to a conservative answer — never to an assumed ordering.
func CompareVersions(ecosystem, a, b string) (int, error) {
	return compareVersions(ecosystem, a, b)
}
