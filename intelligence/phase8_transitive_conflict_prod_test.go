package intelligence

// J-1 / P8-08 — the prod-corpus pin for constraint reconciliation.
//
// The hermetic tests in transitive_constraint_conflict_test.go prove the
// rule on a fixture. This one proves it on the real corpus, because the
// defect it fixes was invisible to every fixture we had: it needed a
// 2018 gem, a 2026 grandchild, and a cache that happened to hold the
// wrong rack. It reuses transitiveCorpusStore from
// phase8_transitive_snapshot_prod_test.go verbatim so resolution,
// satisfiers, BFS and the matcher-stale skip all come from the product.
//
// THE INVARIANT: after a full production replay, no coordinate in any
// root's TransitiveBlame may violate an actionable constraint that same
// root declares on that same dependency name. That is the property the
// vendor's row violated, stated so it cannot come back.
//
// Opt-in: CHAINSAW_FLIP_CORPUS=/abs/reports.jsonl, the same export the
// snapshot harness takes. THE SKIP IS NOT A PASS — a run without the env
// var proves nothing, which is why the hermetic tests carry the gate and
// this one carries the evidence.
//
// Measured on the 2026-09-02 export (7,756 rows, epoch 11): 0 violations
// after the fix; 43 roots' closures shrank by 233 nodes in total; 4 blame
// lists changed; 1 rolled-up score changed; and ZERO verdicts moved.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
)

func TestPhase8TransitiveBlameRespectsRootConstraints(t *testing.T) {
	path := os.Getenv("CHAINSAW_FLIP_CORPUS")
	if path == "" {
		t.Skip("set CHAINSAW_FLIP_CORPUS=<jsonl> to replay the production corpus")
	}
	t.Setenv(TransitiveDepthEnv, "5")

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	store := newTransitiveCorpusStore(6000)
	var rows []transitiveCorpusRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var r transitiveCorpusRow
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		store.add(r)
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		_ = f.Close()
		t.Fatalf("scan corpus: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close corpus: %v", err)
	}
	store.finalise()

	ctx := context.Background()
	var (
		replayed   int
		withBlame  int
		blameNodes int
		violations []string
		refusals   int
		rootsRef   int
	)
	for _, r := range rows {
		var rep Report
		if err := json.Unmarshal(r.Report, &rep); err != nil {
			continue
		}
		ComputeTrustScoreForOrg(&rep, "")
		if rep.Risk == nil {
			continue
		}
		before := len(rep.Observation.Warnings)
		evaluateTransitiveRisk(ctx, store, "", &rep)
		ReapplyKnownFixAfterTransitive(&rep, "")
		replayed++

		refusedHere := 0
		for _, w := range rep.Observation.Warnings[min3warn(before, len(rep.Observation.Warnings)):] {
			if w.Code == WarnTransitiveDepConstraintConflict {
				refusedHere++
			}
		}
		refusals += refusedHere
		if refusedHere > 0 {
			rootsRef++
		}

		blame := rep.Risk.Resolution.TransitiveBlame
		if len(blame) == 0 {
			continue
		}
		withBlame++
		blameNodes += len(blame)
		idx := buildRootConstraintIndex(rep.Dependencies.Direct, rep.Identity.Ecosystem)
		for _, b := range blame {
			if c, bad := violatesDeclaredRootConstraint(idx, b.Ecosystem, b.Package, b.Version); bad {
				violations = append(violations, fmt.Sprintf(
					"%s/%s@%s blames %s/%s@%s which violates its own declared constraint %q",
					r.Eco, r.Pkg, r.Ver, b.Ecosystem, b.Package, b.Version, c))
			}
		}
	}

	sort.Strings(violations)
	t.Logf("TRANSITIVE CONSTRAINT PIN: replayed=%d roots_with_blame=%d blamed_nodes=%d "+
		"conflict_warnings=%d across %d roots violations=%d",
		replayed, withBlame, blameNodes, refusals, rootsRef, len(violations))
	if len(violations) > 0 {
		for i, v := range violations {
			if i >= 25 {
				t.Errorf("... and %d more", len(violations)-25)
				break
			}
			t.Errorf("%s", v)
		}
		t.Fatalf("%d blamed coordinates violate a constraint their own root declares (P8-08 regression)", len(violations))
	}
	// A pin that can pass on an empty measurement is not a pin. The
	// corpus must actually have exercised the walker.
	if withBlame == 0 {
		t.Fatalf("no root produced any TransitiveBlame — the corpus resolved nothing and this run proves nothing")
	}
}

// min3warn clamps the warning-slice start index. Defensive only: nothing
// in the replay shortens Observation.Warnings, but a panic here would be
// read as an engine defect.
func min3warn(before, now int) int {
	if before > now {
		return now
	}
	return before
}
