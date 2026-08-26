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
		{"transitive_dep_superseded", StatusUnavailable},
		{"transitive_dep_lookup_error", StatusUnavailable},
		{"http_500", StatusUnavailable},
		{"http_503", StatusUnavailable},
		{"http_401", StatusUnavailable},
		{"http_403", StatusUnavailable},
		{"http_429", StatusUnavailable},

		// A real answer, not an outage.
		{"not_found", StatusOK},
		{"http_404", StatusOK},
		{"version_not_found", StatusOK},
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

// TestStatusForWarnCodeVersionNotFoundIsOK guards the fail-closed
// coverage gate against the L-01 marker.
//
// An unregistered code falls through to StatusError, and the opt-in
// gate reads that as a source it could not evaluate — so a code added
// upstream without a matching entry in okCodes could start REFUSING
// INSTALLS for every org that opted in, over a typo'd version pin.
// version_not_found is the same shape as not_found: the registry
// answered, and the answer was "that version was never published". A
// real answer is never an outage, and the refusal that IS warranted
// comes from the unknown verdict, not from the coverage gate.
//
// Asserted separately from the table above so it cannot be lost in a
// bulk edit.
func TestStatusForWarnCodeVersionNotFoundIsOK(t *testing.T) {
	if got := StatusForWarnCode("version_not_found"); got != StatusOK {
		t.Fatalf("StatusForWarnCode(\"version_not_found\") = %q, want %q — "+
			"an unclassified code would make the fail-closed coverage gate "+
			"refuse installs for a version that simply does not exist", got, StatusOK)
	}
}
