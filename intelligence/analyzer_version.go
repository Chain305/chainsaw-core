package intelligence

// Analyzer versioning — the provenance ledger for byte-derived facts (A-3).
//
// # WHAT PROBLEM THIS SOLVES
//
// Every provider that returns true from NeedsArtifact derives its facts from
// the artifact bytes. Those bytes are immutable for a published version, so
// re-deriving the same facts from the same bytes on every 24h refresh is pure
// repetition — EXCEPT when the deriving code has changed, which is the one
// case the stored row could not express. Before this file the only record of
// "which generation of the analysis code produced these facts" was the global
// CurrentMatcherEpoch, and bumping that retires every row in the corpus
// regardless of which analyzer actually changed.
//
// A-2 is the live instance: installscriptAstEnabled swaps npm/pip between a
// regex and an AST install-script detector at runtime, and the shared
// coordinate row recorded no trace of which one ran.
//
// # WHY AN OPTIONAL INTERFACE AND NOT A SEVENTH Provider METHOD
//
// Provider is implemented about forty times across two packages. Adding a
// required method breaks every implementation to serve the twenty-three that
// read bytes. The optional-extension shape is already the convention here —
// core/blobstore's ContextStore is the same pattern for the same reason.
//
// # FAIL-CLOSED, DELIBERATELY
//
// A byte-reading provider that does not implement VersionedAnalyzer is never
// cached and never reused: it runs on every scan, exactly as it does today. So
// a forgotten method costs a saving and never correctness, which is the safe
// direction for the one mistake most likely to be made. The reverse mistake —
// serving facts from a superseded analyzer — is the one that needs a guard,
// and TestEveryByteProviderDeclaresAnAnalyzerVersion is it.

// AnalyzerNotCacheable is the version a byte-reading provider returns to
// declare, explicitly, that its output is NOT a pure function of the artifact
// bytes and must therefore never be cached or reused.
//
// It exists so that "this provider is excluded" is a statement in the
// provider's own source next to the reason, rather than the silence of a
// missing method — which is indistinguishable from an oversight.
//
// manifestConfusion is the canonical case: it compares the tarball's manifest
// against Request.RegistryMetadataBytes to catch registry-side metadata edited
// AFTER upload, so the same bytes legitimately yield a different answer as the
// registry changes. Caching it on the digest would blind it to the attack it
// exists to detect.
import "strings"

const AnalyzerNotCacheable = 0

// VersionedAnalyzer is implemented by artifact-reading providers to declare
// which generation of their extraction logic produced a result.
//
// Bump the version in the same commit that changes what the provider extracts
// from the bytes. The bump invalidates only that analyzer's cached rows: every
// other analyzer's rows, and every verdict in the corpus, are untouched.
//
// Do NOT bump for a change that cannot alter the output for identical bytes —
// a comment, a refactor, a logging line. The cost of a needless bump is one
// re-analysis per artifact, which is cheap; the cost of a MISSED bump is
// serving facts the current code would no longer produce, which is not.
//
// KNOWN CEILING: the shared archive walk is NOT covered by any version here.
// Every one of these analyzers reads intelligence/artifactmap's decompressed
// view, so changing ITS caps (MaxFiles, MaxRetainedBytes, the payload cap)
// changes what all of them can see — and there is no single constant to bump,
// because the change does not belong to any one analyzer. A cap change
// therefore requires bumping EVERY version in this set by hand. It is called
// out here rather than guarded because the only honest guard would be a source
// pin over artifactmap wired to nineteen constants, and a guard that fires on
// every unrelated edit to that package would be switched off within a week.
// Truncation itself is already safe — persistArtifactAnalyses refuses to store
// a truncated walk — so the exposure is narrowed to a cap change that makes a
// previously COMPLETE walk see more or less.
type VersionedAnalyzer interface {
	AnalyzerVersion() int
}

// ConfiguredAnalyzer is implemented by a cacheable analyzer whose output also
// depends on OPERATOR CONFIGURATION — an environment threshold, a lane flag —
// resolved independently of the artifact bytes and of this binary's version.
//
// The returned string is a short, stable fingerprint of that configuration. It
// becomes part of the cache key, so a different configuration is a different
// row rather than a silent reuse of the answer computed under the old one.
//
// WHY THIS IS NOT FOLDED INTO AnalyzerVersion. Version is ORDERED: the
// selective backfill selects `analyzer_version < current`, which is what makes
// an upgrade rework the rows below it. Configuration has no order — lowering a
// threshold is not a newer generation — so packing it into the version would
// make a threshold DECREASE produce a smaller value and leave the rows written
// under the higher one permanently unselectable. Two different concepts, two
// different key columns.
//
// Keep the fingerprint SHORT and STABLE: it is a primary-key component, so a
// value that changes between processes for the same configuration (a pointer, a
// map iteration order, a timestamp) would mint a new row on every scan and the
// cache would never hit.
type ConfiguredAnalyzer interface {
	AnalyzerConfigFingerprint() string
}

// analyzerConfigOf returns p's configuration fingerprint, or "" when it
// declares none. Empty is the overwhelmingly common case: fifteen of the
// nineteen cacheable analyzers read nothing but the bytes.
func analyzerConfigOf(p Provider) string {
	if ca, ok := p.(ConfiguredAnalyzer); ok {
		return strings.TrimSpace(ca.AnalyzerConfigFingerprint())
	}
	return ""
}

// analyzerVersionOf reports the cacheable version of p's analysis output.
//
// ok is false for a provider that does not read bytes, does not implement
// VersionedAnalyzer, or declares AnalyzerNotCacheable. Callers treat all three
// identically: run the provider, cache nothing.
func analyzerVersionOf(p Provider) (int, bool) {
	if p == nil || !p.NeedsArtifact() {
		return 0, false
	}
	va, ok := p.(VersionedAnalyzer)
	if !ok {
		return 0, false
	}
	v := va.AnalyzerVersion()
	if v <= AnalyzerNotCacheable {
		return 0, false
	}
	return v, true
}
