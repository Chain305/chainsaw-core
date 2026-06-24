// Package common holds the cross-format resolver contract (CoordinateResolver,
// PackageCoordinate) plus a small kit of helpers shared by every per-format
// resolver under internal/formats/<name>/resolver.go.
//
// Helpers live here, not in a separate "resolverbase" package, because every
// format already imports common for the interface and coordinate types. Adding
// a second package in the dependency chain would buy nothing.
//
// # What is shared
//
//   - [SplitPathSegments] — canonical "/"-split with whitespace and empty-segment
//     filtering. Used by 9+ resolvers verbatim.
//   - [StripArchiveExtension] — knows the compound archive suffixes
//     (.tar.gz/.tgz/.zip/.phar/...) that show up in language ecosystems.
//   - [ParseRPMFilename] — the yum/dnf NEVRA decoder; both ecosystems share the
//     identical parser since dnf is a yum successor.
//
// # What is intentionally NOT shared
//
//   - HTTP fetching, hash verification, retry/backoff, auth header injection.
//     These resolvers are pure-string path parsers; they do not touch the
//     network. The HTTP fetch path lives in internal/httpclient and is
//     consumed by the upstream client modules
//     (e.g. internal/formats/docker/client.go, internal/formats/swift/client.go),
//     not by Describe.
//   - Format-specific name normalization. apt lowercases; composer's
//     normalizeForMatch additionally collapses "_" and "." to "-"; pip mirrors
//     PEP 503 normalization. The semantics differ enough per ecosystem that
//     pulling them into a single helper would obscure intent. Each resolver
//     keeps its own normalizer.
//   - Per-format filename grammars (npm tarball naming, Go module case
//     encoding, NuGet's lowercased nupkg paths, Maven's groupId/artifactId/
//     version triple, Swift SE-0292 endpoint shapes, HuggingFace
//     {datasets,spaces}/<org>/<repo> prefix routing, CocoaPods CDN podspec
//     layout, Cargo's /api/v1/crates path, Composer's /dist segment marker,
//     Docker's /v2/<name>/(blobs|manifests)/<ref>). These are the bits that
//     make each resolver useful; they stay in their own package.
package common
