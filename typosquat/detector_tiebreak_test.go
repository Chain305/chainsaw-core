package typosquat

// detector_tiebreak_test.go — Check must be a pure function of (corpus, query).
//
// BKTree.Search walks `range node.children`, a Go map, so its result order is
// randomized per run. Check used to keep the first minimum-distance match and
// replace it only on a strictly SMALLER distance, which made EQUIDISTANT
// targets a per-run coin flip. That was invisible while every tied target
// produced the same verdict downstream; it stopped being invisible the moment
// a consumer keyed a decision off SimilarTo/TargetRank — the install guard's
// block-lane gate demotes on target length and edit shape, so `args` (distance
// 1 from both `yargs` and `arg`) refused an install on roughly a third of runs
// and allowed it on the rest.

import (
	"context"
	"fmt"
	"testing"
)

// tiebreakCorpus reproduces the shape of the npm case: three corpus names at
// distance 1 from one query, at very different ranks.
func tiebreakCorpus() []PopularPackage {
	// Filler FIRST. The tied names must not land at the BK-tree root: the root
	// is visited before any map iteration happens, so a corpus whose first
	// entry is one of the tied names is accidentally stable even with an
	// order-dependent selection. Burying them under a wide tree is what makes
	// this test able to fail.
	var pkgs []PopularPackage
	for i := 0; i < 400; i++ {
		pkgs = append(pkgs, PopularPackage{
			Name: fmt.Sprintf("fill%03d%c%c", i, 'a'+rune(i%26), 'a'+rune((i*7)%26)),
			Rank: 3000 + i,
		})
	}
	// Three corpus names at distance 1 from "args", at very different ranks —
	// the real npm shape (yargs #70, arg #263, dargs #2827).
	return append(pkgs,
		PopularPackage{Name: "yargs", Rank: 70},
		PopularPackage{Name: "arg", Rank: 263},
		PopularPackage{Name: "dargs", Rank: 2827},
		PopularPackage{Name: "lodash", Rank: 101},
	)
}

// TestCheckEquidistantTieBreakIsDeterministic runs the same query many times
// in one process; each iteration re-walks the BK-tree.
//
// HONEST SCOPE: on a corpus this small the traversal happens to be stable even
// with the order-dependent selection, so this test alone does NOT reproduce
// the defect — it guards the invariant, not the bug. The bug reproduces on the
// shipped npm seed, and TestGuardTyposquatArgsTieBreakIsDeterministic in
// core/cli is the test that fails without betterEditMatch (verified: it
// reports `arg` #263 where the first run reported `yargs` #70, within one
// iteration). Keep both.
func TestCheckEquidistantTieBreakIsDeterministic(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", tiebreakCorpus())
	ctx := context.Background()

	first := d.Check(ctx, "npm", "args")
	if !first.IsSuspected {
		t.Fatalf("fixture no longer fires: %+v", first)
	}
	for i := 0; i < 500; i++ {
		got := d.Check(ctx, "npm", "args")
		if got.SimilarTo != first.SimilarTo || got.TargetRank != first.TargetRank || got.Distance != first.Distance {
			t.Fatalf("run %d returned %q (#%d, d=%d); first run returned %q (#%d, d=%d) — "+
				"the equidistant tie-break is order-dependent again",
				i, got.SimilarTo, got.TargetRank, got.Distance,
				first.SimilarTo, first.TargetRank, first.Distance)
		}
	}
}

// TestCheckTieBreakPrefersThePopularTarget pins WHICH member of a tie wins.
// Popularity is the right tie-break for this question: a squat is aimed at the
// name with the installs behind it, so among equally-near corpus names the
// most-downloaded one is the target worth naming in the verdict.
func TestCheckTieBreakPrefersThePopularTarget(t *testing.T) {
	d := NewDetector(nil)
	d.LoadEcosystem("npm", tiebreakCorpus())

	got := d.Check(context.Background(), "npm", "args")
	if got.SimilarTo != "yargs" || got.TargetRank != 70 {
		t.Errorf("Check(args) = %q (#%d), want \"yargs\" (#70) — the most popular of the tied targets",
			got.SimilarTo, got.TargetRank)
	}
	// A nearer target still beats a more popular far one: distance is the
	// primary key, popularity only breaks ties.
	if near := d.Check(context.Background(), "npm", "lodahs"); near.SimilarTo != "lodash" {
		t.Errorf("Check(lodahs) = %q, want \"lodash\" — distance must outrank popularity", near.SimilarTo)
	}
}

// TestBetterEditMatchTotalOrder exercises the comparison directly, including
// the unranked case: rank 0 means "not in the rank index" and must sort LAST,
// never first, or an unranked corpus entry would shadow a ranked one.
func TestBetterEditMatchTotalOrder(t *testing.T) {
	ranks := map[string]int{"yargs": 70, "arg": 263, "unranked": 0}
	cases := []struct {
		name       string
		cand, best SearchResult
		want       bool
	}{
		{"nearer wins", SearchResult{"arg", 1}, SearchResult{"yargs", 2}, true},
		{"farther loses", SearchResult{"arg", 2}, SearchResult{"yargs", 1}, false},
		{"more popular wins a tie", SearchResult{"yargs", 1}, SearchResult{"arg", 1}, true},
		{"less popular loses a tie", SearchResult{"arg", 1}, SearchResult{"yargs", 1}, false},
		{"ranked beats unranked", SearchResult{"arg", 1}, SearchResult{"unranked", 1}, true},
		{"unranked loses to ranked", SearchResult{"unranked", 1}, SearchResult{"arg", 1}, false},
		{"lexicographic breaks a rank tie", SearchResult{"aaa", 1}, SearchResult{"bbb", 1}, true},
		{"identical is not better", SearchResult{"arg", 1}, SearchResult{"arg", 1}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := betterEditMatch(c.cand, c.best, ranks); got != c.want {
				t.Errorf("betterEditMatch(%+v, %+v) = %v, want %v", c.cand, c.best, got, c.want)
			}
		})
	}
}
