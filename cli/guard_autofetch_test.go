package cli

import "testing"

// TestShouldOfferFeedAutoFetch enumerates the gate for offering to auto-fetch
// the full OpenSSF feed. The offline guarantee is the invariant: a non-TTY run
// (CI/automation) or CHAINSAW_OFFLINE must NEVER trigger a network fetch, even
// when the feed is absent or stale. A present, fresh feed needs no fetch.
func TestShouldOfferFeedAutoFetch(t *testing.T) {
	cases := []struct {
		name                   string
		fullFeedPresent, stale bool
		tty, offline           bool
		want                   bool
	}{
		{"absent feed, interactive, online", false, false, true, false, true},
		{"present but stale, interactive, online", true, true, true, false, true},
		{"present and fresh — nothing to do", true, false, true, false, false},
		{"absent feed but offline — offline guarantee wins", false, false, true, true, false},
		{"stale but offline — offline guarantee wins", true, true, true, true, false},
		{"absent feed but non-TTY — no surprise egress in CI", false, false, false, false, false},
		{"stale but non-TTY — no surprise egress in CI", true, true, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := shouldOfferFeedAutoFetch(c.fullFeedPresent, c.stale, c.tty, c.offline)
			if got != c.want {
				t.Fatalf("shouldOfferFeedAutoFetch(present=%v stale=%v tty=%v offline=%v) = %v, want %v",
					c.fullFeedPresent, c.stale, c.tty, c.offline, got, c.want)
			}
		})
	}
}
