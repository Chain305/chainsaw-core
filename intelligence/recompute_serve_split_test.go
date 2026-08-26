package intelligence

import (
	"os"
	"strings"
	"testing"
)

// The serve floor must never suppress a recompute.
//
// MinServeableEpoch exists so a staged deploy can keep SERVING rows at the
// old epoch while they recompute to the new one. But Scan's cache
// short-circuit asked MatcherStale(), which follows that floor — so with the
// floor held at 5, an epoch-5 row was "not stale", Scan returned it
// untouched, and the recompute sweep counted it as done.
//
// Production, three consecutive sweeps during the v0.21.9 deploy:
//
//	recompute sweep complete backlog=3453 recomputed=1500 failed=0 truncated=true
//
// 1,500 rows "recomputed", zero failures, backlog unchanged at 3,453. The
// staging mechanism had disabled the backfill it was staging for.
func TestServeFloorDoesNotSuppressRecompute(t *testing.T) {
	t.Setenv("CHAINSAW_INTELLIGENCE_MIN_SERVEABLE_EPOCH", "5")
	saved := MinServeableEpoch
	MinServeableEpoch = envMinServeableEpoch()
	defer func() { MinServeableEpoch = saved }()

	if MinServeableEpoch != 5 {
		t.Fatalf("setup: MinServeableEpoch = %d, want 5", MinServeableEpoch)
	}
	// A row stamped at the lowered floor: servable, but still superseded.
	row := &Report{Observation: ObservationSection{MatcherEpoch: 5}}

	if row.MatcherStale() {
		t.Error("a row at the serve floor must be SERVABLE during a staged backfill")
	}
	if !row.MatcherSupersededForRecompute() {
		t.Fatalf("a row below CurrentMatcherEpoch (%d) must still be RECOMPUTED even when "+
			"the serve floor is lowered to %d.\nThis is the exact bug that stalled the "+
			"v0.21.9 drain: Scan short-circuited on the serve floor and never recomputed.",
			CurrentMatcherEpoch, MinServeableEpoch)
	}
}

// With no staged backfill the two questions coincide, so the split must not
// change steady-state behaviour.
func TestRecomputeAndServeAgreeWhenNoBackfillIsStaged(t *testing.T) {
	if MinServeableEpoch != CurrentMatcherEpoch {
		t.Skip("a staged backfill override is active in this process")
	}
	for _, epoch := range []int{0, 1, CurrentMatcherEpoch - 1, CurrentMatcherEpoch, CurrentMatcherEpoch + 1} {
		r := &Report{Observation: ObservationSection{MatcherEpoch: epoch}}
		if r.MatcherStale() != r.MatcherSupersededForRecompute() {
			t.Errorf("epoch %d: serve=%v recompute=%v — the two must agree outside a staged backfill",
				epoch, r.MatcherStale(), r.MatcherSupersededForRecompute())
		}
	}
}

// Scan's cache short-circuit must ask the recompute question, not the serve
// question. Source-level: reaching Scan needs a store and a provider set.
func TestScanCacheShortCircuitUsesTheStampEpoch(t *testing.T) {
	b, err := os.ReadFile("scanner.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if strings.Contains(src, "cached.MatcherStale()") {
		t.Error("scanner.go still gates a cache short-circuit on MatcherStale().\n" +
			"That follows the SERVE floor, so a lowered floor makes Scan return a " +
			"superseded row untouched and the recompute sweep reports success while " +
			"draining nothing. Use MatcherSupersededForRecompute().")
	}
	if !strings.Contains(src, "MatcherSupersededForRecompute()") {
		t.Error("scanner.go no longer consults MatcherSupersededForRecompute() — " +
			"the recompute decision has lost its epoch check entirely")
	}
}
