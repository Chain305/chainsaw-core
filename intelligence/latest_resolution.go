package intelligence

// latest_resolution.go dereferences the literal dist-tag NAME `latest`
// into the concrete published version it points at, for the surfaces
// that answer a user's direct question about one coordinate.
//
// THE DEFECT (P8-45). `chainsaw intel package npm lodash latest` is the
// most natural thing a user types, and until this file existed it was
// handed to Scan verbatim. Every packument-shaped runner in
// provider_registrymetadata.go decides absence by asking whether the
// requested string is a KEY of the registry's `versions` map — and
// `latest` is a dist-tag name, never a versions key, so the lookup
// missed every time. The coordinate came back WarnVersionNotFound →
// SignalsUnavailable → VerdictUnknown → `NOT EVALUATED / 0 (F)` for a
// package that is perfectly fine, and `intel scan` exited 2 on it.
//
// The dist-tags were already decoded and in hand at
// provider_registrymetadata.go's npm runner (`release.LatestVersion =
// pack.DistTags["latest"]`), and two other surfaces already resolved
// `latest` — admin inspect via resolveLatestCachedVersion and the
// dependency enqueuer via resolveLatestVersion. Neither was reachable
// from the public intel path.
//
// WHY THE DEP-ENQUEUER SHAPE AND NOT THE ADMIN ONE. resolveLatestCached
// Version (internal/server/admin_intelligence.go) answers from the
// intelligence cache via a SearchQuery that carries NO OrgID while the
// Get it feeds does — a filed tenancy asymmetry (L-02,
// docs/plan_intel_cache_tenancy.md) that is explicitly not fixable in
// isolation because intelligence_reports has no org_id column at all.
// Reaching it from a public surface would widen that asymmetry's blast
// radius. The resolvers here are pure outbound registry reads: no DB, no
// cache, no org dimension to get wrong. One extra registry request on a
// request that was previously guaranteed to produce a useless answer.
//
// WHAT GETS STORED (the reproducibility decision). Resolution happens
// BEFORE Scan, and Scan is what keys and persists the row, so the
// persisted report is keyed on the CONCRETE version. That is deliberate:
// a report keyed on the string `latest` is not reproducible — today's
// `latest` is tomorrow's different version, and an ALLOW recorded under
// `latest` would be attributed to bytes the user never asked about and
// replayed from cache for a version that no longer exists. Keying on the
// resolved version also means the row participates normally in epoch
// invalidation and TTL refresh. The cost is that the user's literal
// input no longer appears as a row, which is why the CLI prints the
// substitution (see core/cli/intel_package.go) instead of silently
// answering a different question.

import (
	"context"
	"strings"
)

// LatestSentinel is the literal string this file dereferences. Matched
// EXACTLY, not case-insensitively: npm dist-tags are case-sensitive, and
// the upper-case `LATEST` is a Maven resolver directive that
// UnevaluableVersionReason already routes to version_not_evaluable.
const LatestSentinel = "latest"

// latestResolvableEcosystems is the set of ecosystems this file can turn
// `latest` into a concrete version for — i.e. the ones with a resolver in
// ResolveLatestVersion below. It is the single source for canAutoResolve
// (dep_enqueuer.go), for ResolvableLatestSentinel, and for the one-shot
// cleanup's population (latest_sentinel_cleanup.go).
//
// One list, three consumers, on purpose: the cleanup issues a DELETE, and
// a second hand-maintained copy of "which ecosystems can we resolve" that
// drifts wider than the resolver deletes rows that would come straight
// back with the same unresolved answer.
//
// Adding an ecosystem here without adding its resolver arm below is the
// one edit that breaks the invariant; TestLatestResolvableSetHasAResolver
// fails on it.
var latestResolvableEcosystems = []string{
	"npm", "yarn", "bun", "pypi", "pip", "cargo", "rubygems",
}

// ResolvableLatestSentinel reports whether this coordinate's version is
// the `latest` sentinel AND this ecosystem is one where dereferencing it
// is the right answer.
//
// TWO EXCLUSIONS, both of which must keep their current behaviour and
// both of which have a negative-control test:
//
//   - docker (and its oci spelling): `latest` is an ORDINARY TAG there.
//     Docker Hub serves a manifest for it, runDocker fetches it, and the
//     coordinate scores normally today. Resolving it would replace a real
//     answer with a guess about which digest the tag pointed at.
//   - the Maven family: `LATEST` is a Maven RESOLVER DIRECTIVE, not a
//     version, which is why version_evaluable.go's mavenNonVersions
//     lists it and routes `maven … latest` to version_not_evaluable.
//     That is the correct answer and this must not take it away.
//
// Beyond those two the gate is canAutoResolve, so an ecosystem with no
// resolver can never reach a nil dereference — and adding a resolver for
// a new ecosystem is what opts it in, in one place.
func ResolvableLatestSentinel(ecosystem, version string) bool {
	if strings.TrimSpace(version) != LatestSentinel {
		return false
	}
	eco := normalizeEcosystemKey(ecosystem)
	switch eco {
	case "docker", "oci":
		return false
	}
	if isMavenFamily(eco) {
		return false
	}
	return canAutoResolve(eco)
}

// ResolveLatestVersion makes a single registry call to discover the
// version an ecosystem currently advertises as latest. Returns "" when
// the registry is unreachable, the package does not exist, or the
// ecosystem has no resolver — callers must treat "" as "leave the
// coordinate alone" rather than as an error.
//
// This is the exported form of the resolver the dependency enqueuer has
// used since it shipped; DefaultService.resolveLatestVersion delegates
// here so there is exactly one implementation and a fix to either
// surface reaches both.
func ResolveLatestVersion(ctx context.Context, ecosystem, name string) string {
	resolveCtx, cancel := context.WithTimeout(ctx, autoDepResolveTimeout)
	defer cancel()
	switch normalizeEcosystemKey(ecosystem) {
	case "npm", "yarn", "bun":
		return resolveNpmLatest(resolveCtx, name)
	case "pypi", "pip":
		return resolvePyPILatest(resolveCtx, name)
	case "cargo":
		return resolveCargoLatest(resolveCtx, name)
	case "rubygems":
		return resolveRubyGemsLatest(resolveCtx, name)
	}
	return ""
}

// ResolveLatestKey returns key with Version replaced by the concrete
// version `latest` points at, or key unchanged when the coordinate is
// not a resolvable sentinel or the registry did not answer.
//
// The second return value is the version that was replaced, so a caller
// can tell the user what substitution was made. It is "" when nothing
// was substituted.
func ResolveLatestKey(ctx context.Context, key Key) (Key, string) {
	if !ResolvableLatestSentinel(key.Ecosystem, key.Version) {
		return key, ""
	}
	resolved := strings.TrimSpace(ResolveLatestVersion(ctx, key.Ecosystem, key.Package))
	if resolved == "" || resolved == key.Version {
		// The registry did not answer, or answered with the sentinel
		// itself. Fall through to the old behaviour rather than invent
		// a version: WarnVersionNotFound on a coordinate we could not
		// resolve is honest, and it is what happened before this file.
		return key, ""
	}
	was := key.Version
	key.Version = resolved
	return key, was
}
