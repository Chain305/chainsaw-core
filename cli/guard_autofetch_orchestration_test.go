package cli

import (
	"errors"
	"testing"
	"time"
)

// TestMaybeAutoFetchFeed_Orchestration verifies the prompt/fetch wiring around
// the pure gate: it prompts only when a fetch is offered, fetches only on a
// yes, and never touches the fetch path when declined or when the gate says no.
func TestMaybeAutoFetchFeed_Orchestration(t *testing.T) {
	newDeps := func(tty, offline, confirmYes bool, fetchErr error) (*autoFetchDeps, *int, *int) {
		confirms, fetches := 0, 0
		// L-21: the backoff seams are stubbed against an in-memory state so
		// these cases keep asserting the ORCHESTRATION only, with no failure
		// memory in play and no config directory touched.
		state := &guardState{}
		d := &autoFetchDeps{
			isTTY:     func() bool { return tty },
			isOffline: func() bool { return offline },
			confirm: func(string) bool {
				confirms++
				return confirmYes
			},
			fetch: func() error {
				fetches++
				return fetchErr
			},
			now:       time.Now,
			loadState: func() *guardState { return state },
			saveState: func(st *guardState) { state = st },
		}
		return d, &confirms, &fetches
	}

	t.Run("absent feed, confirmed → fetch runs", func(t *testing.T) {
		d, confirms, fetches := newDeps(true, false, true, nil)
		fetched, _, err := maybeAutoFetchFeed(false, false, d)
		if err != nil || !fetched {
			t.Fatalf("want fetched=true err=nil, got fetched=%v err=%v", fetched, err)
		}
		if *confirms != 1 || *fetches != 1 {
			t.Fatalf("want 1 confirm 1 fetch, got confirms=%d fetches=%d", *confirms, *fetches)
		}
	})

	t.Run("offered but declined → no fetch", func(t *testing.T) {
		d, confirms, fetches := newDeps(true, false, false, nil)
		fetched, _, err := maybeAutoFetchFeed(false, false, d)
		if err != nil || fetched {
			t.Fatalf("want fetched=false err=nil, got fetched=%v err=%v", fetched, err)
		}
		if *confirms != 1 || *fetches != 0 {
			t.Fatalf("want 1 confirm 0 fetch, got confirms=%d fetches=%d", *confirms, *fetches)
		}
	})

	t.Run("gate says no (present+fresh) → never prompts", func(t *testing.T) {
		d, confirms, fetches := newDeps(true, false, true, nil)
		fetched, _, err := maybeAutoFetchFeed(true, false, d)
		if err != nil || fetched {
			t.Fatalf("want fetched=false err=nil, got fetched=%v err=%v", fetched, err)
		}
		if *confirms != 0 || *fetches != 0 {
			t.Fatalf("want 0 confirm 0 fetch, got confirms=%d fetches=%d", *confirms, *fetches)
		}
	})

	t.Run("offline → never prompts even if absent", func(t *testing.T) {
		d, confirms, fetches := newDeps(true, true, true, nil)
		fetched, _, _ := maybeAutoFetchFeed(false, false, d)
		if fetched || *confirms != 0 || *fetches != 0 {
			t.Fatalf("offline must not prompt/fetch, got fetched=%v confirms=%d fetches=%d", fetched, *confirms, *fetches)
		}
	})

	t.Run("fetch error is surfaced", func(t *testing.T) {
		wantErr := errors.New("network down")
		d, _, fetches := newDeps(true, false, true, wantErr)
		fetched, _, err := maybeAutoFetchFeed(false, false, d)
		if fetched || !errors.Is(err, wantErr) {
			t.Fatalf("want fetched=false err=network down, got fetched=%v err=%v", fetched, err)
		}
		if *fetches != 1 {
			t.Fatalf("want fetch attempted once, got %d", *fetches)
		}
	})
}
