package cli

import (
	"fmt"
	"os"
	"time"
)

// guard_autofetch.go — decide whether to OFFER a network refresh of the full
// OpenSSF malicious-package feed. Historically the install path only nudged
// ("run `chainsaw guard update`"); this lets an interactive run offer to fetch
// on the spot when the feed is absent or stale.
//
// The offline guarantee is the hard invariant: the fetch is never automatic in
// automation. shouldOfferFeedAutoFetch returns false whenever the run is
// non-interactive (CI / piped) or CHAINSAW_OFFLINE is set, regardless of feed
// state — so nothing touches the network without a present human's consent.
//
// L-21 adds a second suppression: FAILURE MEMORY. See feedFetchBackoff below.

// feedFetchBackoffSchedule is the capped exponential backoff applied after
// consecutive auto-fetch failures: the Nth consecutive failure suppresses the
// offer for schedule[N-1], and everything past the end holds at the last entry.
//
// Capped rather than unbounded because a week is already long enough to stop
// being a nuisance, and a longer window would silently outlive the fix for
// whatever broke the fetch (a proxy change, an expired corporate CA).
var feedFetchBackoffSchedule = []time.Duration{
	1 * time.Hour,
	6 * time.Hour,
	24 * time.Hour,
	72 * time.Hour,
	168 * time.Hour,
}

// feedFetchBackoffFor returns the suppression window for the failures'th
// consecutive failure. A non-positive count means no backoff.
func feedFetchBackoffFor(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	if failures > len(feedFetchBackoffSchedule) {
		failures = len(feedFetchBackoffSchedule)
	}
	return feedFetchBackoffSchedule[failures-1]
}

// feedFetchBackoffActive reports whether a recorded retry-after instant is
// still in the future. A zero (absent) value is never active, which is what
// makes the persisted fields migration-free.
func feedFetchBackoffActive(retryAfterUnix int64, now time.Time) bool {
	if retryAfterUnix <= 0 {
		return false
	}
	return now.Unix() < retryAfterUnix
}

// shouldOfferFeedAutoFetch reports whether guard should prompt to fetch the full
// feed. It only offers when a human is at the terminal, the box is not pinned
// offline, the feed is either absent (only the embedded floor is loaded) or
// present-but-stale, and no failure backoff is in force.
//
// INVARIANT (offline guarantee): the `offline || !tty` check stays FIRST and
// unchanged, so it remains trivially reviewable that CI and air-gapped boxes
// never fetch. Nothing added below it may be able to move it — the decision
// table in guard_autofetch_test.go deliberately includes rows where the
// backoff has EXPIRED but the box is offline / non-TTY, so a future edit that
// reorders these checks fails loudly instead of quietly re-opening egress.
func shouldOfferFeedAutoFetch(fullFeedPresent, stale, tty, offline bool, retryAfterUnix int64, now time.Time) bool {
	if offline || !tty {
		return false
	}
	if fullFeedPresent && !stale {
		return false
	}
	return !feedFetchBackoffActive(retryAfterUnix, now)
}

// autoFetchDeps are the injectable seams for maybeAutoFetchFeed so the
// prompt/fetch wiring is testable without a real terminal, the network, or a
// real clock.
type autoFetchDeps struct {
	isTTY     func() bool
	isOffline func() bool
	confirm   func(label string) bool // default-Yes prompt
	fetch     func() error            // performs the actual `guard update`
	now       func() time.Time        // fake-able clock for the backoff
	loadState func() *guardState
	saveState func(*guardState)
}

// maybeAutoFetchFeed offers, then (on a yes) performs, a network refresh of the
// full feed. It returns (true, "", nil) only when a fetch actually ran and
// succeeded. When the gate declines to offer, or the human declines the prompt,
// it returns (false, …, nil) and never calls fetch. A fetch error is surfaced.
//
// The middle return value is a NOTICE the caller folds into the guard's
// existing notices channel. It is non-empty only when the offer was suppressed
// by the failure backoff: a silent suppression would look identical to the
// feature being broken, so a suppressed run still names the manual command
// once.
func maybeAutoFetchFeed(fullFeedPresent, stale bool, d *autoFetchDeps) (bool, string, error) {
	tty, offline := d.isTTY(), d.isOffline()
	// INVARIANT (offline guarantee), restated here so the early return is
	// visible at the top of the only function that can reach the network:
	// nothing below this line runs in CI or on an air-gapped box. Deliberately
	// ahead of the state read, so a suppressed automation run does not even
	// touch guard_state.json.
	if offline || !tty {
		return false, "", nil
	}
	if fullFeedPresent && !stale {
		return false, "", nil
	}

	now := d.now()
	st := d.loadState()
	if !shouldOfferFeedAutoFetch(fullFeedPresent, stale, tty, offline, st.FeedFetchRetryAfterUnix, now) {
		// The offline/tty and feed-state arms were both cleared above, so the
		// only remaining reason for a "no" here is the backoff.
		return false, feedFetchBackoffNotice(st, now), nil
	}
	if !d.confirm(feedAutoFetchPrompt(fullFeedPresent)) {
		return false, "", nil
	}
	if err := d.fetch(); err != nil {
		recordFeedFetchFailure(d, st, now)
		return false, "", err
	}
	clearFeedFetchBackoffWith(d.loadState, d.saveState)
	return true, "", nil
}

// recordFeedFetchFailure bumps the consecutive-failure counter and stamps the
// next retry instant. Best-effort: a state file we cannot write means the user
// gets today's (nagging) behaviour, which is strictly better than failing the
// install over a bookkeeping error.
func recordFeedFetchFailure(d *autoFetchDeps, st *guardState, now time.Time) {
	st.FeedFetchFailures++
	st.FeedFetchRetryAfterUnix = now.Add(feedFetchBackoffFor(st.FeedFetchFailures)).Unix()
	d.saveState(st)
}

// clearFeedFetchBackoffWith resets the failure memory. Called on any successful
// fetch AND, crucially, at the START of an explicit `chainsaw guard update` —
// see runGuardUpdateExplicit. Re-reads state rather than reusing a caller's
// copy so it cannot clobber counters written in between.
func clearFeedFetchBackoffWith(load func() *guardState, save func(*guardState)) {
	st := load()
	if st.FeedFetchFailures == 0 && st.FeedFetchRetryAfterUnix == 0 {
		return
	}
	st.FeedFetchFailures = 0
	st.FeedFetchRetryAfterUnix = 0
	save(st)
}

// clearFeedFetchBackoff is the production entry point for the reset.
func clearFeedFetchBackoff() {
	clearFeedFetchBackoffWith(loadGuardState, saveGuardState)
}

// feedFetchBackoffNotice is the ONE line a suppressed offer prints. It states
// what happened, that we are not going to keep asking, and the manual escape
// hatch — which also clears the backoff, so the line is a complete recovery
// path rather than an apology.
func feedFetchBackoffNotice(st *guardState, now time.Time) string {
	wait := time.Duration(st.FeedFetchRetryAfterUnix-now.Unix()) * time.Second
	return fmt.Sprintf("feed refresh failed %s; not asking again for %s — run `chainsaw guard update` to retry now",
		pluralAttempts(st.FeedFetchFailures), roundBackoffForHumans(wait))
}

func pluralAttempts(n int) string {
	if n == 1 {
		return "on the last attempt"
	}
	return fmt.Sprintf("%d times in a row", n)
}

// roundBackoffForHumans renders the remaining window coarsely. Nobody needs
// "5h59m12s" from a nudge line.
func roundBackoffForHumans(d time.Duration) string {
	if d < time.Minute {
		return "a moment"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 48*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours())/24)
}

// prodAutoFetchDeps wires maybeAutoFetchFeed to real behavior: the stdin TTY
// check, the CHAINSAW_OFFLINE kill switch, the default-Yes confirm prompt, and
// the existing `guard update` fetch (conditional ETag, so a stale refresh is a
// fast 304 when nothing changed).
//
// NOTE the fetch calls runGuardUpdate DIRECTLY, not the cobra RunE wrapper —
// that is what keeps the auto path and the explicit path distinguishable
// without any caller sniffing. See runGuardUpdateExplicit.
func prodAutoFetchDeps() *autoFetchDeps {
	return &autoFetchDeps{
		isTTY:     stdinIsTerminal,
		isOffline: func() bool { return envTruthy(os.Getenv("CHAINSAW_OFFLINE")) },
		confirm:   PromptConfirmDefaultYes,
		fetch:     func() error { return runGuardUpdate(guardUpdateCmd, nil) },
		now:       time.Now,
		loadState: loadGuardState,
		saveState: saveGuardState,
	}
}

// feedAutoFetchPrompt phrases the offer around whichever condition triggered it.
func feedAutoFetchPrompt(fullFeedPresent bool) string {
	if fullFeedPresent {
		return "  Refresh the malicious-package feed now? (one network fetch)"
	}
	return "  Download the full OpenSSF malicious-package feed now? (one network fetch)"
}
