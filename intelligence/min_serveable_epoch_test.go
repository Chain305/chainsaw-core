package intelligence

import (
	"os"
	"strings"
	"testing"
)

// The serve floor is lowered only for the duration of a staged backfill.
// Leaving it lowered means the cache keeps serving verdicts a later epoch
// has already retired — silently, because every read path just sees a
// non-stale row. Ship-blocking by default.
func TestMinServeableEpochIsNotLeftLowered(t *testing.T) {
	if os.Getenv("CHAINSAW_INTELLIGENCE_MIN_SERVEABLE_EPOCH") != "" {
		t.Skip("explicit staged-backfill override set for this process")
	}
	if MinServeableEpoch != CurrentMatcherEpoch {
		t.Fatalf("MinServeableEpoch = %d, want CurrentMatcherEpoch (%d).\n"+
			"The serve floor is lowered. If a backfill is in flight this is expected\n"+
			"IN THE DEPLOY ENVIRONMENT ONLY, via CHAINSAW_INTELLIGENCE_MIN_SERVEABLE_EPOCH —\n"+
			"never committed as the compiled-in default.",
			MinServeableEpoch, CurrentMatcherEpoch)
	}
}

// A bad or hostile value must not widen what the cache will serve.
func TestEnvMinServeableEpochRejectsOutOfRange(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{"", CurrentMatcherEpoch},
		{"   ", CurrentMatcherEpoch},
		{"banana", CurrentMatcherEpoch},
		{"0", CurrentMatcherEpoch},
		{"-3", CurrentMatcherEpoch},
		{"999", CurrentMatcherEpoch},                    // above current: refuse to widen
		{"9999999999999999999999", CurrentMatcherEpoch}, // overflow
		{"5", 5},
		{"1", 1},
	} {
		t.Setenv("CHAINSAW_INTELLIGENCE_MIN_SERVEABLE_EPOCH", tc.raw)
		if got := envMinServeableEpoch(); got != tc.want {
			t.Errorf("envMinServeableEpoch(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

// The sweep must target every row below the CURRENT epoch, and the
// operator's backlog count must report the same population — otherwise a
// lowered serve floor would also shrink the backlog, the drain would stop
// early, and the deploy would "complete" with rows still behind.
//
// Source-level because the predicates are SQL strings; there is no way to
// assert this from behaviour without a populated database, and a skipped
// DB test reports its package ok.
func TestDrainPredicatesTrackCurrentEpochNotServeFloor(t *testing.T) {
	for _, f := range []string{"store_recompute.go", "store.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(b)
		for i, line := range strings.Split(src, "\n") {
			if !strings.Contains(line, "MinServeableEpoch") {
				continue
			}
			t.Errorf("%s:%d uses MinServeableEpoch: %s\n"+
				"Drain-side predicates (the recompute walk, its COUNT, the Facets\n"+
				"backlog and the Search \"recompute pending\" flag) must stay on\n"+
				"CurrentMatcherEpoch. Following the serve floor would shrink the\n"+
				"backlog in lockstep and strand rows below the current epoch.",
				f, i+1, strings.TrimSpace(line))
		}
	}
	// ...and confirm they do reference CurrentMatcherEpoch, so this test
	// cannot pass by the predicates having been deleted.
	b, err := os.ReadFile("store_recompute.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "CurrentMatcherEpoch") {
		t.Error("store_recompute.go no longer references CurrentMatcherEpoch — the drain predicate is gone")
	}
}

// The serve gate is Report.MatcherStale and nothing else. If a read path
// starts comparing the epoch inline against CurrentMatcherEpoch it will
// keep refusing rows during a staged backfill, which is the degradation
// MinServeableEpoch exists to avoid.
func TestMatcherStaleUsesTheServeFloor(t *testing.T) {
	t.Setenv("CHAINSAW_INTELLIGENCE_MIN_SERVEABLE_EPOCH", "5")
	saved := MinServeableEpoch
	MinServeableEpoch = envMinServeableEpoch()
	defer func() { MinServeableEpoch = saved }()

	if MinServeableEpoch != 5 {
		t.Fatalf("setup: MinServeableEpoch = %d, want 5", MinServeableEpoch)
	}
	at5 := &Report{Observation: ObservationSection{MatcherEpoch: 5}}
	if at5.MatcherStale() {
		t.Error("a row at the lowered serve floor must be servable during a staged backfill")
	}
	at4 := &Report{Observation: ObservationSection{MatcherEpoch: 4}}
	if !at4.MatcherStale() {
		t.Error("a row below the serve floor must still be refused")
	}
}
