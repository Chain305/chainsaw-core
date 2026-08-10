package cli

import "os"

// guard_autofetch.go — decide whether to OFFER a network refresh of the full
// OpenSSF malicious-package feed. Historically the install path only nudged
// ("run `chainsaw guard update`"); this lets an interactive run offer to fetch
// on the spot when the feed is absent or stale.
//
// The offline guarantee is the hard invariant: the fetch is never automatic in
// automation. shouldOfferFeedAutoFetch returns false whenever the run is
// non-interactive (CI / piped) or CHAINSAW_OFFLINE is set, regardless of feed
// state — so nothing touches the network without a present human's consent.

// shouldOfferFeedAutoFetch reports whether guard should prompt to fetch the full
// feed. It only offers when a human is at the terminal, the box is not pinned
// offline, and the feed is either absent (only the embedded floor is loaded) or
// present-but-stale.
func shouldOfferFeedAutoFetch(fullFeedPresent, stale, tty, offline bool) bool {
	if offline || !tty {
		return false
	}
	return !fullFeedPresent || stale
}

// autoFetchDeps are the injectable seams for maybeAutoFetchFeed so the
// prompt/fetch wiring is testable without a real terminal or the network.
type autoFetchDeps struct {
	isTTY     func() bool
	isOffline func() bool
	confirm   func(label string) bool // default-Yes prompt
	fetch     func() error            // performs the actual `guard update`
}

// maybeAutoFetchFeed offers, then (on a yes) performs, a network refresh of the
// full feed. It returns (true, nil) only when a fetch actually ran and
// succeeded. When the gate declines to offer, or the human declines the prompt,
// it returns (false, nil) and never calls fetch. A fetch error is surfaced.
func maybeAutoFetchFeed(fullFeedPresent, stale bool, d *autoFetchDeps) (bool, error) {
	if !shouldOfferFeedAutoFetch(fullFeedPresent, stale, d.isTTY(), d.isOffline()) {
		return false, nil
	}
	if !d.confirm(feedAutoFetchPrompt(fullFeedPresent)) {
		return false, nil
	}
	if err := d.fetch(); err != nil {
		return false, err
	}
	return true, nil
}

// prodAutoFetchDeps wires maybeAutoFetchFeed to real behavior: the stdin TTY
// check, the CHAINSAW_OFFLINE kill switch, the default-Yes confirm prompt, and
// the existing `guard update` fetch (conditional ETag, so a stale refresh is a
// fast 304 when nothing changed).
func prodAutoFetchDeps() *autoFetchDeps {
	return &autoFetchDeps{
		isTTY:     stdinIsTerminal,
		isOffline: func() bool { return envTruthy(os.Getenv("CHAINSAW_OFFLINE")) },
		confirm:   PromptConfirmDefaultYes,
		fetch:     func() error { return runGuardUpdate(guardUpdateCmd, nil) },
	}
}

// feedAutoFetchPrompt phrases the offer around whichever condition triggered it.
func feedAutoFetchPrompt(fullFeedPresent bool) string {
	if fullFeedPresent {
		return "  Refresh the malicious-package feed now? (one network fetch)"
	}
	return "  Download the full OpenSSF malicious-package feed now? (one network fetch)"
}
