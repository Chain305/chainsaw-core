// Next-of-kin: internal/formats/cocoapods/resolver.go (sibling Apple-platform pkg mgr).
// TODO(M-ARCH-08): 16 near-identical resolver.go files — extract shared base.
//
// Package swift implements the Swift Package Manager (SPM) proxy surface.
//
// SPM clients interact with a Swift Package Registry (SE-0292) via a small
// set of HTTP endpoints scoped by a case-insensitive `scope.name` identifier.
// This package provides:
//
//   - Resolver: parses SE-0292 URL patterns into (scope.name, version)
//     coordinates for the proxy cache.
//   - Transformer: rewrites upstream host references inside SE-0292 JSON
//     responses and Link headers so clients continue talking to the proxy.
//   - URL mapper: maps cached logical paths back to the upstream registry.
//   - Composite upstream: tries a configured SE-0292 registry first and
//     falls back to a git translator that synthesizes registry responses
//     from github.com tags.
package swift

import (
	"strings"

	"github.com/chain305/chainsaw-core/formats/common"
)

// FormatName is the canonical ecosystem identifier used in
// PackageCoordinate.Format and OSV ecosystem normalization.
const FormatName = "swift"

// Resolver parses Swift Package Registry (SE-0292) URL patterns.
//
// SE-0292 defines six endpoints:
//
//	GET  /{scope}/{name}                            list releases
//	GET  /{scope}/{name}/{version}                  release metadata
//	GET  /{scope}/{name}/{version}/Package.swift    manifest (with optional ?swift-version=)
//	GET  /{scope}/{name}/{version}.zip              source archive
//	GET  /identifiers?url=<git-url>                 reverse lookup
//	PUT  /{scope}/{name}/{version}                  publish (handled by parseSwiftUpload; SE-0391 multipart)
//
// Package identifiers are case-insensitive (SE-0292 §3.5) and encoded as
// lowercased `scope.name` in PackageCoordinate.Name.
type Resolver struct{}

// NewResolver builds a Swift resolver.
func NewResolver() *Resolver {
	return &Resolver{}
}

// Format implements common.CoordinateResolver.
func (Resolver) Format() string { return FormatName }

// Describe implements common.CoordinateResolver.
//
// Returns (coord, true) when the path targets a package artifact or
// metadata document. Returns (zero, false) for /identifiers reverse
// lookups and unrecognized paths so the facet skips policy evaluation
// (there is no package name to gate against in those cases).
func (Resolver) Describe(p string) (common.PackageCoordinate, bool) {
	// Strip query string — cache keying is the facet's concern, but we
	// want to match on the path shape only.
	if q := strings.IndexByte(p, '?'); q >= 0 {
		p = p[:q]
	}
	segments := common.SplitPathSegments(p)
	if len(segments) == 0 {
		return common.PackageCoordinate{}, false
	}

	// /identifiers reverse lookup — no package to gate. Fall through to
	// the cache without coordinates so policies stay inert.
	if len(segments) == 1 && strings.EqualFold(segments[0], "identifiers") {
		return common.PackageCoordinate{}, false
	}

	// /{scope}/{name}/{version}.zip — source archive
	if len(segments) == 3 && strings.HasSuffix(segments[2], ".zip") {
		return buildCoord(segments[0], segments[1], strings.TrimSuffix(segments[2], ".zip"))
	}

	// /{scope}/{name}/{version}/Package.swift — manifest (with optional swift-version)
	if len(segments) == 4 && strings.EqualFold(segments[3], "Package.swift") {
		return buildCoord(segments[0], segments[1], segments[2])
	}

	// /{scope}/{name}/{version} — release metadata
	if len(segments) == 3 {
		return buildCoord(segments[0], segments[1], segments[2])
	}

	// /{scope}/{name} — release list (no version)
	if len(segments) == 2 {
		return buildCoord(segments[0], segments[1], "")
	}

	return common.PackageCoordinate{}, false
}

// buildCoord normalizes scope/name to lowercase and encodes the SPM
// identifier as "scope.name". Returns ok=false if scope or name is empty.
func buildCoord(scope, name, version string) (common.PackageCoordinate, bool) {
	scope = strings.TrimSpace(scope)
	name = strings.TrimSpace(name)
	if scope == "" || name == "" {
		return common.PackageCoordinate{}, false
	}
	return common.PackageCoordinate{
		Name:    NormalizeIdentifier(scope, name),
		Version: strings.TrimSpace(version),
		Format:  FormatName,
	}, true
}

// NormalizeIdentifier converts a scope/name pair into a lowercase
// dot-separated SPM identifier. Per SE-0292 §3.5, scope and name are
// case-insensitive.
func NormalizeIdentifier(scope, name string) string {
	return strings.ToLower(strings.TrimSpace(scope) + "." + strings.TrimSpace(name))
}

// SplitIdentifier returns the (scope, name) components from a normalized
// SPM identifier. Returns empty strings if the input is malformed.
func SplitIdentifier(identifier string) (scope, name string) {
	idx := strings.Index(identifier, ".")
	if idx <= 0 || idx == len(identifier)-1 {
		return "", ""
	}
	return identifier[:idx], identifier[idx+1:]
}
