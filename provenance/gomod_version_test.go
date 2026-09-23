package provenance

// The single largest cause of signal_repair S-2. Measured in prod 2026-09-23:
// 5,905 of 6,056 failed Go attestations were HTTP 400 from sum.golang.org --
// 39% of every failed attestation in the corpus -- because the version had no
// leading "v". Confirmed against the live sumdb:
//
//	.../lookup/github.com/spf13/pflag@1.0.3   -> 400
//	.../lookup/github.com/spf13/pflag@v1.0.3  -> 200

import "testing"

func TestCanonicalGoVersionRestoresTheStrippedPrefix(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		// The bug: lockfile parsers strip the "v".
		{"1.0.3", "v1.0.3", true},
		{"0.0.1", "v0.0.1", true},
		// Already canonical: unchanged, not double-prefixed.
		{"v1.0.3", "v1.0.3", true},
		{"  v1.0.3  ", "v1.0.3", true},
		// +incompatible and pseudo-versions are valid semver and the sumdb
		// answers both, so they must NOT be rejected.
		{"v3.2.0+incompatible", "v3.2.0+incompatible", true},
		{"3.2.0+incompatible", "v3.2.0+incompatible", true},
		{"v0.0.0-20210101120000-abcdef123456", "v0.0.0-20210101120000-abcdef123456", true},
		{"0.0.0-20210101120000-abcdef123456", "v0.0.0-20210101120000-abcdef123456", true},
		// Unusable: must be refused rather than turned into a request that is
		// guaranteed to fail against a rate-limited upstream.
		{"", "", false},
		{"latest", "", false},
		{"main", "", false},
		{"not.a.version", "", false},
	}
	for _, c := range cases {
		got, ok := CanonicalGoVersion(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("CanonicalGoVersion(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// A coordinate we never asked about must not be reported as a FAILED
// verification. "failed" on a report reads as "this package's provenance is
// bad"; the truth is that the version string was unusable and no request was
// made. The two need opposite responses.
func TestUncheckableGoVersionIsUnavailableNotFailed(t *testing.T) {
	c := newGomodChecker(nil, nil)
	got := c.Check(t.Context(), "github.com/spf13/pflag", "latest")
	if got.Status == StatusFailed {
		t.Errorf("an unusable version reported StatusFailed; that reads as a provenance failure "+
			"for a package we never asked the sumdb about. result=%+v", got)
	}
	if got.Status != StatusUnavailable {
		t.Errorf("Status = %q, want %q", got.Status, StatusUnavailable)
	}
	if got.Reason == "" {
		t.Error("no Reason set — Status alone conflates this with 'the ecosystem publishes nothing'")
	}
	// And it must not have issued a request: a nil client would panic.
}
