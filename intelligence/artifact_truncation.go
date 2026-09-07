package intelligence

// N5 — "could not look" is not "looked and found nothing".
//
// artifactmap.Build sets Result.Truncated at three caps: the payload cap
// (artifactmap.go:150), the file-count cap (:196) and the retained-bytes cap
// (:221). All three are pinned by artifactmap_test.go:126-176. Until now
// NOTHING in production read the flag. Six provider call sites take the whole
// artifactmap.Result and use only .Files:
//
//	provider_installscripts.go:447,477   provider_hiddenunicode.go:708
//	provider_shrinkwrap.go:96            provider_manifestconfusion.go:51
//	provider_manifestconfusion_pypi.go:77
//
// So a large artifact was inspected in PART and reported as an absence of
// findings — indistinguishable, to the operator and to every downstream
// consumer, from a full inspection that found nothing. That is the same
// distinction policy.rule.signal_dark already encodes for a signal that could
// not be evaluated, and it was silently missing here.
//
// SCOPE: observability only. This is verdict-neutral by design — no section
// flips, no score moves, no rule fires differently. Whether an incompletely
// inspected artifact should fail CLOSED is a real posture decision with a
// blast radius (every oversized package in the cache), and it is deliberately
// deferred. What ships here is the thing that decision cannot be made without:
// a record that the look was partial.
//
// Not to be confused with core/intelligence/artifact_fallback.go's silent
// 256 MiB truncation. That is a TEST-ONLY path — its own header (:3-10) says
// the production path goes through SharedArtifactMap and the fallback "is
// unreachable from Service.Scan". It is not a production fail-open and does
// not need this treatment.

import (
	"fmt"
	"time"
)

// WarnArtifactTruncated marks a Tier-2 section that was computed over a
// PARTIAL view of the artifact. Stable string; UI and API consumers key on it.
//
// Read it as "absence of findings from this provider is not evidence of
// absence", never as a finding in its own right.
const WarnArtifactTruncated = "artifact_truncated"

// artifactTruncationMessage is the operator-facing sentence. Deliberately says
// what was NOT done rather than naming a risk — the provider found nothing and
// this explains why that may mean nothing.
func artifactTruncationMessage(provider string) string {
	return fmt.Sprintf(
		"artifact not fully inspected: the shared archive map hit a size/file cap, so %s "+
			"examined only part of this package — treat a clean result from it as unknown, not clean",
		provider)
}

// withArtifactTruncationWarning appends the truncation warning to a provider's
// PartialReport when the shared artifact map for this handle was truncated.
//
// Called from every artifact-reading provider's Run wrapper rather than at the
// six SharedArtifactMap() call sites, because most of those sites are shared
// map ACCESSORS (ManifestsFor, sourceFilesFor, textFilesFor) that return a
// map[string][]byte and have no PartialReport to attach anything to. Wrapping
// Run also covers each provider's early returns, which is where the "clean
// absence" is actually emitted.
//
// SharedArtifactMap is memoised behind a sync.Once, so this costs one map
// field read; it never triggers a second decompression.
func withArtifactTruncationWarning(partial PartialReport, provider string, h *ArtifactHandle) PartialReport {
	if h == nil {
		return partial
	}
	if !h.SharedArtifactMap().Truncated {
		return partial
	}
	partial.Warnings = append(partial.Warnings, Warning{
		Provider: provider,
		Code:     WarnArtifactTruncated,
		Message:  artifactTruncationMessage(provider),
		At:       time.Now().UTC(),
	})
	return partial
}
