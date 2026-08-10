package coverage

import "testing"

func TestStatusForWarnCode(t *testing.T) {
	cases := []struct {
		raw  string
		want Status
	}{
		// Source was not reached — the only class that can block.
		{"timeout", StatusUnavailable},
		{"context_cancelled", StatusUnavailable},
		{"transport", StatusUnavailable},
		{"breaker_open", StatusUnavailable},
		{"rate_limited", StatusUnavailable},
		{"registry_fetch_exhausted_retries", StatusUnavailable},
		{"mod_fetch_failed", StatusUnavailable},
		{"github_meta_fetch_failed", StatusUnavailable},
		{"gitlab_meta_fetch_failed", StatusUnavailable},
		{"codeberg_meta_fetch_failed", StatusUnavailable},
		{"bitbucket_meta_fetch_failed", StatusUnavailable},
		{"timeline_fetch_failed", StatusUnavailable},
		{"repolink_probe_error", StatusUnavailable},
		{"transitive_dep_not_cached", StatusUnavailable},
		{"http_500", StatusUnavailable},
		{"http_503", StatusUnavailable},
		{"http_401", StatusUnavailable},
		{"http_403", StatusUnavailable},
		{"http_429", StatusUnavailable},

		// A real answer, not an outage.
		{"not_found", StatusOK},
		{"http_404", StatusOK},
		{"", StatusOK},

		// Never blocks.
		{"ecosystem_unsupported", StatusNotApplicable},
		{"needs_artifact", StatusNotApplicable},

		// Our bug, or a code we have never seen. Never blocks.
		{"parse_failed", StatusError},
		{"decode", StatusError},
		{"request_build", StatusError},
		{"feature_disabled", StatusError},
		{"some_code_invented_in_2027", StatusError},
		{"http_", StatusError},
	}
	for _, tc := range cases {
		if got := StatusForWarnCode(tc.raw); got != tc.want {
			t.Errorf("StatusForWarnCode(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// The load-bearing safety property, asserted on its own so it cannot be
// weakened by editing the table above without noticing.
func TestUnknownWarnCodeNeverBlocks(t *testing.T) {
	for _, raw := range []string{"totally_new", "x", "HTTP_500", "http_5"} {
		if got := StatusForWarnCode(raw); got == StatusUnavailable {
			t.Errorf("StatusForWarnCode(%q) = unavailable; unknown codes must never block", raw)
		}
	}
}
