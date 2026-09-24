package risk

// Audit harness for docs/DESIGNS.md#designs-audit-score-inversion (2026-09-21).
//
// Two shipped behaviours can make a WORSE package score BETTER:
//
//  1. applyMaxImpactCeiling returns early when any compound rule fired, so
//     the per-signal MaxImpact ceiling is deleted by the very evidence that
//     should tighten it.
//  2. sc.provenance_verified is a +15 reward with no negative counterpart,
//     so signing an artifact can only ever raise its score.
//
// TestCeilingBypassInvertsScore pins (1) as a unit. TestAuditProdCorpus
// replays a corpus exported from production with the REAL registry and the
// REAL applyMaxImpactCeiling / ComputeOverallWithWeights; it is skipped
// unless CHAINSAW_AUDIT_CORPUS points at the export (the SQL that produces
// it is in the design doc).

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
)

// compoundSet builds fired compound records from CompoundRules (compound
// rules are NOT in Registry, and their Severity is what drives the
// critical-signal escalation in resolveVerdict).
func compoundSet(ids ...string) map[string]FiredSignal {
	byID := make(map[string]CompoundRule, len(CompoundRules))
	for _, c := range CompoundRules {
		byID[c.ID] = c
	}
	out := make(map[string]FiredSignal, len(ids))
	for _, id := range ids {
		c, ok := byID[id]
		if !ok {
			panic("unknown compound rule in corpus: " + id)
		}
		out[id] = FiredSignal{ID: id, Category: c.Category, Severity: c.Severity, Weight: c.Weight, Compound: true}
	}
	return out
}

func firedSet(ids ...string) map[string]FiredSignal {
	out := make(map[string]FiredSignal, len(ids))
	for _, id := range ids {
		sig := Registry[id]
		out[id] = FiredSignal{ID: id, Category: sig.Category, Severity: sig.Severity, Weight: sig.Weight}
	}
	return out
}

// TestCeilingBypassIsClosed was TestCeilingBypassInvertsScore, and the
// rewrite is the point (S-7, docs/PLANS_INTELLIGENCE.md#plan-signal-repair).
//
// The old version ASSERTED the bug. It required
// `withCompound == rollup` — the uncapped number — and then required
// `withCompound > without`, i.e. it went red the moment anyone fixed the
// inversion and stayed green the entire time it was live. A
// characterization test is a legitimate thing to write while auditing;
// leaving one in place afterwards means the defect has a guard holding it
// open. It was cited in the plan index as "the red test exists but
// nothing gates the ceiling bypass" — it was neither red nor a gate.
//
// What it asserts now is the property the repair establishes: a compound
// rule must not raise the score, and the primitive ceiling must still
// bind when one fires.
func TestCeilingBypassIsClosed(t *testing.T) {
	prim := firedSet(SignalSCHiddenUnicode)
	if Registry[SignalSCHiddenUnicode].MaxImpact != maxImpactWarnTop {
		t.Fatalf("fixture assumes sc.hidden_unicode ceilings at %d, got %d",
			maxImpactWarnTop, Registry[SignalSCHiddenUnicode].MaxImpact)
	}
	const rollup = 73 // real value: npm|webpack|5.111.0, prod 2026-09-21

	withCompound, pinnedWith := applyMaxImpactCeiling(rollup, prim,
		map[string]FiredSignal{CompoundSCEnvNetInstall: {ID: CompoundSCEnvNetInstall, Compound: true}})
	without, pinnedWithout := applyMaxImpactCeiling(rollup, prim, nil)

	if withCompound > without {
		t.Errorf("INVERSION: compound-present scored %d, better than compound-absent %d. "+
			"More evidence of malice must never produce a better score.", withCompound, without)
	}
	if withCompound != maxImpactWarnTop || pinnedWith != SignalSCHiddenUnicode {
		t.Errorf("compound path: want %d pinned by %s, got %d/%q — the ceiling must bind "+
			"through a compound, not be deleted by it",
			maxImpactWarnTop, SignalSCHiddenUnicode, withCompound, pinnedWith)
	}
	if without != maxImpactWarnTop || pinnedWithout != SignalSCHiddenUnicode {
		t.Errorf("no-compound path: want %d pinned by %s, got %d/%q",
			maxImpactWarnTop, SignalSCHiddenUnicode, without, pinnedWithout)
	}
	// The band this used to flip across. 73 is an allow; the ceiling puts
	// it at 59, a warn. Both paths must land on the strict side.
	if withCompound >= ThresholdWarn {
		t.Errorf("compound path scored %d, at or above the warn threshold %d — "+
			"this is the allow the bypass was producing", withCompound, ThresholdWarn)
	}
}

// TestMaxImpactCeilingIsMonotoneInCompounds is the general form, so the
// guard does not depend on one fixture's numbers.
//
// For any rollup and any primitive set, adding compound rules must never
// raise the result. The bypass violated this for every rollup above the
// ceiling; a fixed-value test would only have caught it at 73.
func TestMaxImpactCeilingIsMonotoneInCompounds(t *testing.T) {
	prim := firedSet(SignalSCHiddenUnicode)
	comp := map[string]FiredSignal{
		CompoundSCEnvNetInstall: {ID: CompoundSCEnvNetInstall, Compound: true},
	}
	for rollup := 0; rollup <= 100; rollup++ {
		with, _ := applyMaxImpactCeiling(rollup, prim, comp)
		without, _ := applyMaxImpactCeiling(rollup, prim, nil)
		if with > without {
			t.Fatalf("rollup %d: compound-present %d > compound-absent %d", rollup, with, without)
		}
		if with > rollup {
			t.Fatalf("rollup %d: ceiling raised the score to %d", rollup, with)
		}
	}
}

type auditRow struct {
	K     string            `json:"k"`
	V     string            `json:"v"`
	D     int               `json:"d"`
	R     int               `json:"r"`
	Ceil  string            `json:"ceil"`
	Prim  []string          `json:"prim"`
	Comp  []string          `json:"comp"`
	Cat   map[string][2]any `json:"cat"`
	SCRaw int               `json:"scraw"`
}

func (a auditRow) cats(scOverride *int) map[Category]CategoryScore {
	out := make(map[Category]CategoryScore, len(a.Cat))
	for k, v := range a.Cat {
		score := int(v[0].(float64))
		avail, _ := v[1].(bool)
		if Category(k) == CategorySupplyChain && scOverride != nil {
			score = clamp100(*scOverride)
		}
		out[Category(k)] = CategoryScore{Score: score, DataAvailable: avail}
	}
	return out
}

func clamp100(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func band(v int) string {
	switch {
	case v < ThresholdQuarantine:
		return "band1(quarantine)"
	case v < ThresholdWarn:
		return "band2(warn)"
	}
	return "band3(allow)"
}

func TestAuditProdCorpus(t *testing.T) {
	path := os.Getenv("CHAINSAW_AUDIT_CORPUS")
	if path == "" {
		t.Skip("set CHAINSAW_AUDIT_CORPUS to the production export")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var rows []auditRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var r auditRow
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("%s: %v", sc.Text(), err)
		}
		rows = append(rows, r)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}

	var (
		scMismatch, overallMismatch, overallOK int
		compoundRows, ceilWouldBind            int
		provRows, provMoved, provMovedBand     int
		provClampAbsorbed, provSCMoved         int
		bothRows                               int
		flips, drops, verdictFlips             []string
		provList                               []string
	)

	for _, r := range rows {
		// --- re-derivability self-checks -----------------------------------
		if cs, ok := r.Cat["supply_chain"]; ok {
			if int(cs[0].(float64)) != clamp100(r.SCRaw) {
				scMismatch++
			}
		}
		if r.Ceil == "" {
			if got := ComputeOverallWithWeights(r.cats(nil), nil); got == r.D {
				overallOK++
			} else {
				overallMismatch++
			}
		}

		hasProv := false
		for _, id := range r.Prim {
			if id == SignalSCProvenanceVerified {
				hasProv = true
			}
		}
		prim := firedSet(r.Prim...)
		comp := compoundSet(r.Comp...)

		// --- behaviour 1: ceiling bypass ------------------------------------
		if len(comp) > 0 {
			compoundRows++
			if hasProv {
				bothRows++
			}
			// Stored r.D IS the uncapped rollup: with a compound present the
			// real applyMaxImpactCeiling returns `overall` untouched.
			if live, _ := applyMaxImpactCeiling(r.D, prim, comp); live != r.D {
				t.Fatalf("%s: compound path should be a no-op, got %d vs %d", r.K, live, r.D)
			}
			corrected, pinner := applyMaxImpactCeiling(r.D, prim, nil)
			if corrected < r.D {
				ceilWouldBind++
				// A Critical signal already forces a non-Allow verdict in
				// EVERY band (resolveVerdict band-3 escalation), so for those
				// rows the bypass inflates the SCORE but cannot have changed
				// the VERDICT. Only non-critical rows can actually flip.
				crit := hasCriticalSignal(prim, comp)
				line := fmt.Sprintf("%-52s stored=%-17s direct %3d -> %3d  (%s -> %s)  pinned by %-28s critical=%v",
					r.K, r.V, r.D, corrected, band(r.D), band(corrected), pinner, crit)
				drops = append(drops, line)
				if band(r.D) != band(corrected) {
					flips = append(flips, line)
					if !crit && r.V == string(VerdictAllow) {
						verdictFlips = append(verdictFlips, line)
					}
				}
			}
		}

		// --- behaviour 2: provenance reward ----------------------------------
		if hasProv {
			provRows++
			less := r.SCRaw - int(Registry[SignalSCProvenanceVerified].Weight)
			if clamp100(less) == clamp100(r.SCRaw) {
				provClampAbsorbed++
				continue // the +15 was eaten by the [0,100] clamp: no effect at all
			}
			provSCMoved++
			withoutOverall := ComputeOverallWithWeights(r.cats(&less), nil)
			withoutOverall, _ = applyMaxImpactCeiling(withoutOverall, prim, comp)
			if withoutOverall != r.D {
				provMoved++
				if band(withoutOverall) != band(r.D) {
					provMovedBand++
				}
				provList = append(provList, fmt.Sprintf(
					"%-52s verdict=%-17s direct %3d -> %3d  (%s -> %s)  sc %d -> %d",
					r.K, r.V, r.D, withoutOverall, band(r.D), band(withoutOverall),
					clamp100(r.SCRaw), clamp100(less)))
			}
		}
	}

	sort.Strings(drops)
	sort.Strings(flips)
	sort.Strings(verdictFlips)
	sort.Strings(provList)

	fmt.Printf("\n=== corpus: %d evaluated reports ===\n", len(rows))
	fmt.Printf("re-derivability: supply_chain score mismatches %d; overall (non-ceilinged) ok %d, mismatch %d\n",
		scMismatch, overallOK, overallMismatch)
	fmt.Printf("\nBEHAVIOUR 1 (ceiling bypass): %d reports had >=1 compound fire\n", compoundRows)
	fmt.Printf("  of those, %d would score LOWER with the ceiling applied; %d cross a verdict band\n",
		ceilWouldBind, len(flips))
	for _, l := range drops {
		fmt.Println("   ", l)
	}
	fmt.Printf("\n  BAND FLIPS (%d):\n", len(flips))
	for _, l := range flips {
		fmt.Println("   ", l)
	}
	fmt.Printf("\n  VERDICT FLIPS -- stored allow, no critical signal, would leave allow (%d):\n", len(verdictFlips))
	for _, l := range verdictFlips {
		fmt.Println("   ", l)
	}
	fmt.Printf("\nBEHAVIOUR 2 (provenance reward): %d reports fired sc.provenance_verified (weight %+v)\n",
		provRows, Registry[SignalSCProvenanceVerified].Weight)
	fmt.Printf("  of those, the +15 was absorbed by the [0,100] category clamp on %d (no effect possible);\n"+
		"  it genuinely raised the supply_chain subscore on %d; of those %d change overall, %d cross a band\n",
		provClampAbsorbed, provSCMoved, provMoved, provMovedBand)
	for _, l := range provList {
		fmt.Println("   ", l)
	}
	fmt.Printf("\nINTERACTION: %d reports carry BOTH a compound firing and the provenance reward\n", bothRows)
}
