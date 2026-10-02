package intelligence

// analysis_reuse.go — the scanner's side of the artifact-analysis cache (A-3).
//
// One fan-out's interaction with artifact_analyses is three steps:
//
//  1. planArtifactAnalyses resolves the artifact digest and the manifest of
//     cacheable analyzers at their CURRENT versions.
//  2. reuseArtifactAnalyses merges any stored partials for that digest into
//     the report and returns the providers that still have to run.
//  3. persistArtifactAnalyses records what did run, so the next scan of the
//     same bytes reuses it.
//
// All three are no-ops without a store, without bytes, or on an Ephemeral
// request. The degraded path is exactly today's behaviour: every provider
// runs.

import (
	"context"
	"os"
	"strings"
)

// artifactAnalysisPlan is what one fan-out needs to know about the cache.
//
// A zero plan disables both reuse and persistence, which is how every
// non-cacheable scan is represented — there is no separate "off" flag to get
// out of step with the digest.
type artifactAnalysisPlan struct {
	// digest is the sha256 of the FULL artifact bytes, lowercase hex. Empty
	// when the digest could not be established, which disables the cache.
	digest string
	// ecosystem scopes the key: installscripts branches npm vs pip and
	// capability picks a per-ecosystem scanner, so the same bytes in two
	// ecosystems are two analyses.
	ecosystem string
	// accept maps analyzer name to the version AND configuration fingerprint
	// this binary will accept and write. Only providers that declare a
	// cacheable VersionedAnalyzer appear.
	accept map[string]AcceptedAnalysis
}

func (p artifactAnalysisPlan) enabled() bool {
	return p.digest != "" && p.ecosystem != "" && len(p.accept) > 0
}

// planArtifactAnalyses resolves the cache plan for one scan.
//
// THE DIGEST IS ALWAYS COMPUTED, NEVER TAKEN FROM ArtifactHandle.SHA256.
// That field is caller-declared — it is the value provider_checksum exists to
// CHECK — so trusting it here would let a caller that declares someone else's
// digest read someone else's analysis, or file its own analysis under a
// coordinate it does not own. Computing costs one sha256 pass over bytes that
// are already resident, which is noise beside the archive walk this cache
// exists to avoid.
func planArtifactAnalyses(ctx context.Context, req Request, providers []Provider) artifactAnalysisPlan {
	// Ephemeral (artifact-upload) requests neither read nor write. The bytes
	// are caller-supplied and their coordinate is caller-asserted, so letting
	// them reach shared state is the cache-poisoning threat Options.Ephemeral
	// exists to close — in both directions, as it already does for the
	// coordinate-keyed row and the sticky read.
	if req.Options.Ephemeral || req.Artifact == nil {
		return artifactAnalysisPlan{}
	}

	eco := strings.ToLower(strings.TrimSpace(req.Key.Ecosystem))
	if eco == "" {
		return artifactAnalysisPlan{}
	}

	accept := make(map[string]AcceptedAnalysis, len(providers))
	for _, p := range providers {
		if v, ok := analyzerVersionOf(p); ok {
			accept[p.Name()] = AcceptedAnalysis{Version: v, Config: analyzerConfigOf(p)}
		}
	}
	if len(accept) == 0 {
		return artifactAnalysisPlan{}
	}

	digest := fullArtifactSHA256(ctx, req.Artifact)
	if digest == "" {
		return artifactAnalysisPlan{}
	}
	return artifactAnalysisPlan{digest: digest, ecosystem: eco, accept: accept}
}

// fullArtifactSHA256 returns the sha256 of the artifact, but ONLY when the
// whole artifact was hashed.
//
// computeArtifactSHA256 deliberately hashes a capped PREFIX for a very large
// artifact (maxArtifactBytesForHash, 512 MiB) because a partial digest is
// still useful for comparing against a declared hash. It is not useful as a
// CACHE KEY: two distinct artifacts sharing a 512 MiB prefix would collide,
// and the cache would serve one's analysis for the other. So anything at or
// over the cap returns empty here and simply is not cached.
func fullArtifactSHA256(ctx context.Context, h *ArtifactHandle) string {
	if h == nil {
		return ""
	}
	switch {
	case len(h.Bytes) > 0:
		if len(h.Bytes) >= maxArtifactBytesForHash {
			return ""
		}
	case strings.TrimSpace(h.Path) != "":
		fi, err := os.Stat(h.Path)
		if err != nil || fi.Size() >= maxArtifactBytesForHash {
			return ""
		}
	default:
		return ""
	}
	sum, err := computeArtifactSHA256(ctx, h)
	if err != nil {
		return ""
	}
	return normaliseHex(sum)
}

// reuseArtifactAnalyses merges stored analyses for the planned digest into
// report and returns the subset of providers that still have to run.
//
// MERGED THROUGH mergePartial, the same function the fan-out uses, so a reused
// analysis reaches the report by the identical path a fresh one does. There is
// no second merge semantics to drift, and — load-bearing for P8-71 — this runs
// BEFORE the evaluation, so the stored report and the stored risk_evaluation
// are still snapshots of one set of facts.
//
// A failed lookup reuses nothing and is not an error: every provider runs.
func (s *DefaultService) reuseArtifactAnalyses(
	ctx context.Context, plan artifactAnalysisPlan, report *Report, providers []Provider,
) []Provider {
	if s == nil || s.store == nil || !plan.enabled() || report == nil || len(providers) == 0 {
		return providers
	}
	stored, err := s.store.LoadArtifactAnalyses(ctx, plan.digest, plan.ecosystem, plan.accept)
	if err != nil || len(stored) == 0 {
		if err != nil {
			s.logger.Debug("artifact analysis reuse lookup failed",
				"digest", plan.digest, "error", err)
		}
		return providers
	}

	remaining := make([]Provider, 0, len(providers))
	for _, p := range providers {
		partial, hit := stored[p.Name()]
		if !hit {
			remaining = append(remaining, p)
			continue
		}
		if _, cacheable := analyzerVersionOf(p); !cacheable {
			// Defensive: LoadArtifactAnalyses was asked only for cacheable
			// analyzers, so this cannot fire today. It is here because the
			// cost of being wrong is serving a non-cacheable provider's stale
			// output, and the cost of the check is a map lookup.
			remaining = append(remaining, p)
			continue
		}
		mergePartial(report, partial)
		report.Observation.ReusedAnalyzers = append(report.Observation.ReusedAnalyzers, p.Name())
	}
	return remaining
}

// persistArtifactAnalyses records the output of the providers that ran.
//
// Three refusals, each load-bearing:
//
//   - A provider that ERRORED is not stored. Its partial is empty or partial,
//     and caching it would make one transient failure permanent for those
//     bytes.
//   - A TRUNCATED archive walk is not stored, for ANY provider. A capped walk
//     reports absences it never looked for, and trivialPackage fires when LOC
//     is BELOW a bound, so a cached truncated walk mints a false positive that
//     never expires. Checking here rather than at the reader makes "every row
//     in this table is a complete analysis" an invariant of the writer, so no
//     future reader can forget the filter.
//   - Nothing is stored when the plan is disabled, which covers Ephemeral.
//
// SharedArtifactMap is consulted only when there is something to store. On a
// full-reuse scan no provider ran, so nothing is written and the archive is
// never decompressed — which is the saving.
func (s *DefaultService) persistArtifactAnalyses(
	ctx context.Context, plan artifactAnalysisPlan, req Request, ran []analyzerResult,
) {
	if s == nil || s.store == nil || !plan.enabled() || len(ran) == 0 {
		return
	}
	if req.Artifact != nil && req.Artifact.SharedArtifactMap().Truncated {
		return
	}
	for _, r := range ran {
		accept, ok := plan.accept[r.analyzer]
		if !ok {
			continue
		}
		if err := s.store.SaveArtifactAnalysis(ctx, ArtifactAnalysisKey{
			SHA256:    plan.digest,
			Ecosystem: plan.ecosystem,
			Analyzer:  r.analyzer,
			Version:   accept.Version,
			Config:    accept.Config,
		}, r.partial); err != nil {
			s.logger.Debug("artifact analysis save failed",
				"analyzer", r.analyzer, "digest", plan.digest, "error", err)
		}
	}
}

// analyzerResult is one provider's output captured at the fan-out merge, so it
// can be persisted after the merge has happened.
//
// It carries the provider's OWN partial rather than a slice of the merged
// report, because the merged report cannot be decomposed back into per-provider
// contributions — MergeScan flattens them. That is also why no backfill of the
// existing corpus is possible.
type analyzerResult struct {
	analyzer string
	partial  PartialReport
}
