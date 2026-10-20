package cli

// guard_typosquat_interior_floor_test.go — end-to-end pins for the interior
// family's target-length floor (guardTyposquatInteriorMinTargetLen, see
// guard_typosquat_gate.go). The pure-predicate pins live in
// TestTyposquatTargetLongEnough; these run the REAL evaluate() ladder over
// the embedded npm corpus, which is what an install actually consults.
//
// The trade this file pins, both halves (re-measured 2026-10-19):
//
//   - DEMOTE: the five ADJUDICATED feed names (inxi/miz/pmg/tiar by interior
//     insert, m5d by transposition — priced on the OpenSSF recall harness at
//     exactly five demotions, 1,030 → 1,025). Every one an interior edit
//     against a 2-3-rune target, and none is established (they are squats).
//   - CLEARED, not demoted: the measured false-block class pug (of pg #1434)
//     and md-5 (of md5 #2202) — same shapes as the squats above, but both
//     carry established-table rows (pug ~2M weekly downloads; md-5 a
//     long-lived RustCrypto crate), so the clear wins before the floor is
//     ever consulted. Belt-and-suspenders: even without their table rows the
//     interior floor would demote them.
//   - KEEP BLOCKING: uudi (transposition of uuid #44, a 4-rune target) and
//     loadash (interior insert of lodash, a 6-rune target) — the recall
//     class the floor must not touch.

import (
	"context"
	"testing"
)

// TestGuardInteriorFloorAdjudicatedDemotions: every feed-squat name demotes
// to the WARN lane (severity guardSeverityTyposquatDemoted — printed even
// under --quiet), never a block, never silence.
func TestGuardInteriorFloorAdjudicatedDemotions(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	for _, name := range []string{
		"inxi", // interior insert of ini  (#278)  — feed name, adjudicated
		"tiar", // interior insert of tar  (#363)  — feed name, adjudicated
		"miz",  // interior insert of mz   (#542)  — feed name, adjudicated
		"pmg",  // interior insert of pg   (#1428) — feed name, adjudicated
		"m5d",  // transposition of md5    (#2196) — feed name, adjudicated
	} {
		v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: name})
		if v.Block {
			t.Errorf("npm:%s must NOT block (interior edit against a <4-rune target): %+v", name, v)
		}
		if v.Severity != guardSeverityTyposquatDemoted {
			t.Errorf("npm:%s must land in the DEMOTED warn lane so --quiet still prints it, got %+v", name, v)
		}
	}
}

// TestGuardInteriorFloorFalseBlockClassClears: the measured false-block
// names take the established clear (no block, no warn, ClearedReason set)
// — the floor is their fallback, not their verdict.
func TestGuardInteriorFloorFalseBlockClassClears(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	for _, c := range []struct{ eco, name string }{
		{"npm", "pug"},  // interior insert of pg — ~2M weekly downloads
		{"cargo", "md-5"}, // interior delete of md5 — long-lived RustCrypto crate
	} {
		v := g.evaluate(ctx, packageSpec{Ecosystem: c.eco, Name: c.name})
		if v.Block || v.Severity != "" || v.ClearedReason == "" {
			t.Errorf("%s:%s must CLEAR via the established table (no block, no warn, ClearedReason set), got %+v",
				c.eco, c.name, v)
		}
	}
}

// TestGuardInteriorFloorKeepsFourRuneTargetsBlocking: the recall half. A
// 4-rune target in an interior shape still refuses — uudi/uuid is the class
// the recall suite gates on — and so does every 5+-rune interior target.
func TestGuardInteriorFloorKeepsFourRuneTargetsBlocking(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	for _, c := range []struct{ name, target string }{
		{"uudi", "uuid"},      // transposition, 4-rune target (#44)
		{"loadash", "lodash"}, // interior insert, 6-rune target
	} {
		v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: c.name})
		if !v.Block || v.Severity != guardSeverityTyposquatHigh {
			t.Errorf("npm:%s (squat of %s) must keep BLOCKING — the interior floor starts at 4 runes, got %+v",
				c.name, c.target, v)
		}
	}
}
