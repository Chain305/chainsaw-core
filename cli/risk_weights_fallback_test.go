package cli

// risk_weights_fallback_test.go — the preview printed the server's `fallback`
// field verbatim.
//
// That field is a REASON CODE ("empty_corpus"), but one server branch built it
// from err.Error(), and that is how a raw Postgres `SQLSTATE 42703` — column
// names and all — was rendered onto an operator's terminal by a command whose
// whole job is to project a weight change. The server side is being fixed; the
// CLI must also hold against a server that has not been upgraded, or a future
// branch that reintroduces it.

import (
	"strings"
	"testing"
)

// TestSafeFallbackReason_PassesReasonCodes: the legitimate values must survive
// untouched, including codes that do not exist yet. Redacting a real code
// would trade an information leak for an information loss.
func TestSafeFallbackReason_PassesReasonCodes(t *testing.T) {
	for _, code := range []string{
		"empty_corpus",       // internal/simulate/spec.go FallbackEmptyCorpus
		"corpus_unavailable", // internal/simulate/spec.go FallbackCorpusUnavailable
		"corpus_load_failed", // shape of a plausible future sibling
		"sampled",
		"cap_reached_10000",
	} {
		if got := safeFallbackReason(code); got != code {
			t.Errorf("safeFallbackReason(%q) = %q; a reason code must print as itself", code, got)
		}
	}
}

// TestSafeFallbackReason_RedactsRawServerErrors is the finding: anything that
// is not code-shaped is server free text and must not be echoed.
func TestSafeFallbackReason_RedactsRawServerErrors(t *testing.T) {
	leaks := []string{
		`pq: column "trust_score_v2" does not exist (SQLSTATE 42703)`,
		"sql: no rows in result set",
		"dial tcp 10.0.3.14:5432: connect: connection refused",
		"context deadline exceeded",
		"ERROR: relation \"intelligence_reports\" does not exist",
		strings.Repeat("a", 200),
	}
	for _, raw := range leaks {
		got := safeFallbackReason(raw)
		if got != fallbackReasonRedacted {
			t.Errorf("safeFallbackReason(%q) = %q; want the generic line", raw, got)
		}
	}
}

// TestRenderRiskWeightsPreview_DoesNotEchoSQLSTATE drives the real renderer,
// because the guard is only worth anything at the call site.
func TestRenderRiskWeightsPreview_DoesNotEchoSQLSTATE(t *testing.T) {
	resp := riskWeightsSimulateResp{
		Summary:  "preview unavailable: corpus load failed",
		Fallback: `pq: column "trust_score_v2" does not exist (SQLSTATE 42703)`,
	}

	out := captureStdout(t, func() {
		renderRiskWeightsPreview(resp, map[string]int{"malware": 90})
	})

	for _, forbidden := range []string{"SQLSTATE", "42703", "trust_score_v2", "pq:"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("the preview echoed server internals (%q):\n%s", forbidden, out)
		}
	}
	// The operator still learns the projection degraded — redacting the
	// detail must not hide the fact.
	if !strings.Contains(out, "fallback") {
		t.Errorf("the degraded-preview notice disappeared entirely:\n%s", out)
	}
	if !strings.Contains(out, fallbackReasonRedacted) {
		t.Errorf("expected the generic reason line:\n%s", out)
	}
}

// TestRenderRiskWeightsPreview_KeepsAKnownReasonCode is the negative control:
// the guard must not swallow the answer in the normal degraded case.
func TestRenderRiskWeightsPreview_KeepsAKnownReasonCode(t *testing.T) {
	out := captureStdout(t, func() {
		renderRiskWeightsPreview(riskWeightsSimulateResp{
			Summary:  "no intelligence corpus available for this org — preview produced 0 rows",
			Fallback: "empty_corpus",
		}, map[string]int{"malware": 90})
	})
	if !strings.Contains(out, "empty_corpus") {
		t.Errorf("a legitimate reason code was redacted:\n%s", out)
	}
}
