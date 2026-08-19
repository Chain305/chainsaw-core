package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/cli/platform"
)

// TestAutoFetchNeverOffersWhenOfflineOrNonTTY enumerates the gate for offering
// to auto-fetch the full OpenSSF feed. (Supersedes the narrower
// TestShouldOfferFeedAutoFetch, which predates the L-21 backoff arguments.)
//
// The offline guarantee is the invariant: a non-TTY run (CI/automation) or
// CHAINSAW_OFFLINE must NEVER trigger a network fetch, even when the feed is
// absent or stale, and even when a failure backoff has just EXPIRED — the
// expired-backoff rows exist precisely so that a future edit which reorders
// the checks (say, returning "offer" as soon as the backoff clears) fails
// here instead of quietly re-opening egress on an air-gapped box.
func TestAutoFetchNeverOffersWhenOfflineOrNonTTY(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	past := now.Add(-time.Hour).Unix()  // backoff expired
	future := now.Add(time.Hour).Unix() // backoff still in force

	cases := []struct {
		name                   string
		fullFeedPresent, stale bool
		tty, offline           bool
		retryAfterUnix         int64
		want                   bool
	}{
		{"absent feed, interactive, online", false, false, true, false, 0, true},
		{"present but stale, interactive, online", true, true, true, false, 0, true},
		{"present and fresh — nothing to do", true, false, true, false, 0, false},
		{"absent feed but offline — offline guarantee wins", false, false, true, true, 0, false},
		{"stale but offline — offline guarantee wins", true, true, true, true, 0, false},
		{"absent feed but non-TTY — no surprise egress in CI", false, false, false, false, 0, false},
		{"stale but non-TTY — no surprise egress in CI", true, true, false, false, 0, false},

		// L-21 backoff rows.
		{"absent feed, interactive, backoff in force", false, false, true, false, future, false},
		{"stale, interactive, backoff in force", true, true, true, false, future, false},
		{"absent feed, interactive, backoff expired", false, false, true, false, past, true},
		{"stale, interactive, backoff expired", true, true, true, false, past, true},

		// The load-bearing pairs: an EXPIRED backoff must not resurrect the
		// offer on a box the offline guarantee covers.
		{"backoff expired but offline — offline guarantee still wins", false, false, true, true, past, false},
		{"backoff expired but non-TTY — CI still never fetches", false, false, false, false, past, false},
		{"backoff expired, stale, offline", true, true, true, true, past, false},
		{"backoff expired, stale, non-TTY", true, true, false, false, past, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := shouldOfferFeedAutoFetch(c.fullFeedPresent, c.stale, c.tty, c.offline, c.retryAfterUnix, now)
			if got != c.want {
				t.Fatalf("shouldOfferFeedAutoFetch(present=%v stale=%v tty=%v offline=%v retryAfter=%v) = %v, want %v",
					c.fullFeedPresent, c.stale, c.tty, c.offline, c.retryAfterUnix, got, c.want)
			}
		})
	}
}

// fakeAutoFetchClock is a hand-cranked clock so the backoff windows are
// asserted exactly rather than slept through.
type fakeAutoFetchClock struct{ t time.Time }

func (c *fakeAutoFetchClock) now() time.Time          { return c.t }
func (c *fakeAutoFetchClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// newBackoffDeps builds deps whose fetch always fails, over an in-memory
// guardState, driven by a fake clock.
func newBackoffDeps(clock *fakeAutoFetchClock, state *guardState, fetchErr error) (*autoFetchDeps, *int, *int) {
	confirms, fetches := 0, 0
	d := &autoFetchDeps{
		isTTY:     func() bool { return true },
		isOffline: func() bool { return false },
		confirm: func(string) bool {
			confirms++
			return true
		},
		fetch: func() error {
			fetches++
			return fetchErr
		},
		now:       clock.now,
		loadState: func() *guardState { return state },
		saveState: func(st *guardState) { *state = *st },
	}
	return d, &confirms, &fetches
}

// TestAutoFetchBacksOffAfterConsecutiveFailures is the L-21 regression. The QA
// wave observed three consecutive guarded installs each prompting, each
// downloading a few hundred KB, and each failing identically.
func TestAutoFetchBacksOffAfterConsecutiveFailures(t *testing.T) {
	clock := &fakeAutoFetchClock{t: time.Unix(1_700_000_000, 0)}
	state := &guardState{}
	boom := errors.New("tls: certificate signed by unknown authority")
	d, confirms, fetches := newBackoffDeps(clock, state, boom)

	// Attempt 1 — prompts, fetches, fails, records the first backoff.
	if _, _, err := maybeAutoFetchFeed(false, false, d); !errors.Is(err, boom) {
		t.Fatalf("first attempt: want the fetch error, got %v", err)
	}
	if state.FeedFetchFailures != 1 {
		t.Fatalf("failure counter = %d, want 1", state.FeedFetchFailures)
	}
	if *confirms != 1 || *fetches != 1 {
		t.Fatalf("want 1 confirm 1 fetch, got %d/%d", *confirms, *fetches)
	}

	// Immediately afterwards: suppressed, with a notice, and NO second
	// download. This is the whole point of the fix.
	fetched, notice, err := maybeAutoFetchFeed(false, false, d)
	if fetched || err != nil {
		t.Fatalf("want a silent suppression, got fetched=%v err=%v", fetched, err)
	}
	if *confirms != 1 || *fetches != 1 {
		t.Fatalf("a backed-off run re-prompted or re-downloaded: confirms=%d fetches=%d", *confirms, *fetches)
	}
	if notice == "" {
		t.Fatal("a suppressed offer printed nothing — indistinguishable from the feature being broken")
	}
	if !strings.Contains(notice, "chainsaw guard update") {
		t.Fatalf("the suppression notice must name the manual command, got %q", notice)
	}

	// Still inside the first (1h) window.
	clock.advance(59 * time.Minute)
	if _, _, _ = maybeAutoFetchFeed(false, false, d); *fetches != 1 {
		t.Fatalf("fetched again inside the 1h window: fetches=%d", *fetches)
	}

	// Past it: one more attempt is allowed, fails, and the window widens.
	clock.advance(2 * time.Minute)
	if _, _, err := maybeAutoFetchFeed(false, false, d); !errors.Is(err, boom) {
		t.Fatalf("second attempt after the window: want the fetch error, got %v", err)
	}
	if *fetches != 2 || state.FeedFetchFailures != 2 {
		t.Fatalf("want fetches=2 failures=2, got %d/%d", *fetches, state.FeedFetchFailures)
	}

	// The second window is 6h, not another 1h.
	clock.advance(90 * time.Minute)
	if _, _, _ = maybeAutoFetchFeed(false, false, d); *fetches != 2 {
		t.Fatalf("backoff did not widen after the second failure: fetches=%d", *fetches)
	}
}

// TestAutoFetchSuccessClearsTheBackoff is the positive control: without it,
// "does not fetch" could be satisfied by breaking the offer outright.
func TestAutoFetchSuccessClearsTheBackoff(t *testing.T) {
	clock := &fakeAutoFetchClock{t: time.Unix(1_700_000_000, 0)}
	state := &guardState{FeedFetchFailures: 3, FeedFetchRetryAfterUnix: clock.t.Add(-time.Second).Unix()}
	d, _, fetches := newBackoffDeps(clock, state, nil)

	fetched, notice, err := maybeAutoFetchFeed(false, false, d)
	if !fetched || err != nil || notice != "" {
		t.Fatalf("want a clean successful fetch, got fetched=%v notice=%q err=%v", fetched, notice, err)
	}
	if *fetches != 1 {
		t.Fatalf("want exactly one fetch, got %d", *fetches)
	}
	if state.FeedFetchFailures != 0 || state.FeedFetchRetryAfterUnix != 0 {
		t.Fatalf("a success must clear the failure memory, got failures=%d retryAfter=%d",
			state.FeedFetchFailures, state.FeedFetchRetryAfterUnix)
	}
}

// TestExplicitGuardUpdateAlwaysBypassesTheBackoff pins the escape hatch: a user
// who has FIXED whatever broke the fetch reaches for `chainsaw guard update`,
// and must never be told to wait. The clear happens BEFORE the attempt, so even
// a still-failing manual run leaves them able to try again.
func TestExplicitGuardUpdateAlwaysBypassesTheBackoff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv(platform.EnvConfigHome, dir)

	saveGuardState(&guardState{
		FeedFetchFailures:       5,
		FeedFetchRetryAfterUnix: time.Now().Add(168 * time.Hour).Unix(),
		InstallsChecked:         7, // unrelated counters must survive
	})

	// runGuardUpdateExplicit clears first, then delegates. Drive only the
	// clear half here — the fetch half needs the network and is covered by
	// guard_update_test.go.
	clearFeedFetchBackoff()

	st := loadGuardState()
	if st.FeedFetchFailures != 0 || st.FeedFetchRetryAfterUnix != 0 {
		t.Fatalf("explicit guard update did not clear the backoff: failures=%d retryAfter=%d",
			st.FeedFetchFailures, st.FeedFetchRetryAfterUnix)
	}
	if st.InstallsChecked != 7 {
		t.Fatalf("clearing the backoff clobbered unrelated counters: installs=%d", st.InstallsChecked)
	}
}

// TestOldGuardStateWithoutBackoffFieldsDecodesAsNoBackoff is the zero-migration
// guarantee: a guard_state.json written by any earlier chainsaw has neither
// field, and must decode to exactly today's behaviour (offer freely).
func TestOldGuardStateWithoutBackoffFieldsDecodesAsNoBackoff(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv(platform.EnvConfigHome, dir)

	// Byte-for-byte the shape a pre-L-21 binary wrote.
	legacy := `{"installs_checked":12,"packages_scanned":340,"blocks":2,` +
		`"first_run_unix":1690000000,"telemetry_consent":"granted"}`
	if err := os.WriteFile(filepath.Join(configDir(), "guard_state.json"), []byte(legacy), 0o644); err != nil {
		t.Fatalf("seed legacy state: %v", err)
	}

	st := loadGuardState()
	if st.FeedFetchFailures != 0 || st.FeedFetchRetryAfterUnix != 0 {
		t.Fatalf("absent fields must decode to zero, got failures=%d retryAfter=%d",
			st.FeedFetchFailures, st.FeedFetchRetryAfterUnix)
	}
	if st.InstallsChecked != 12 || st.Consent != consentGranted {
		t.Fatalf("legacy fields did not survive the decode: %+v", st)
	}
	if feedFetchBackoffActive(st.FeedFetchRetryAfterUnix, time.Now()) {
		t.Fatal("a legacy state file must not be treated as backed off")
	}
	if !shouldOfferFeedAutoFetch(false, false, true, false, st.FeedFetchRetryAfterUnix, time.Now()) {
		t.Fatal("a legacy state file changed the offer decision — this is a migration, and it must not be")
	}

	// And the round trip must not resurrect them as explicit zeros that a
	// still-older binary would then have to ignore.
	saveGuardState(st)
	b, err := os.ReadFile(filepath.Join(configDir(), "guard_state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "feed_fetch_failures") || strings.Contains(string(b), "feed_fetch_retry_after_unix") {
		t.Fatalf("omitempty was lost — a no-backoff state now writes the fields: %s", b)
	}
}
