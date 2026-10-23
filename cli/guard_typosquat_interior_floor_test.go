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
//   - CLEARED when pinned, demoted otherwise: the measured false-block class
//     pug (of pg #1434) and md-5 (of md5 #2202) — same shapes as the squats
//     above, but both carry established-table rows (pug ~2M weekly
//     downloads; md-5 a long-lived RustCrypto crate). An exact pin of a
//     build-time release clears silently; anything else keeps the floor's
//     printed warning (the established clear is silent only for a release
//     the table saw).
//   - KEEP BLOCKING: uudi (transposition of uuid #44, a 4-rune target) and
//     loadash (interior insert of lodash, a 6-rune target) — the recall
//     class the floor must not touch.

import (
	"context"
	"testing"
	"time"
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
// names never block. An exact pin of a release the established table saw
// takes the silent clear (no warn, ClearedReason set); an unpinned install
// keeps the floor's printed warning, because a clear is silent only for a
// build-time release (guard_established.go, THE VERSION GATE).
func TestGuardInteriorFloorFalseBlockClassClears(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	for _, c := range []struct{ eco, name string }{
		{"npm", "pug"},    // interior insert of pg — ~2M weekly downloads
		{"cargo", "md-5"}, // interior delete of md5 — long-lived RustCrypto crate
	} {
		v := g.evaluate(ctx, packageSpec{Ecosystem: c.eco, Name: c.name})
		if v.Block || v.Severity != guardSeverityTyposquatDemoted || v.ClearedReason != "" {
			t.Errorf("%s:%s unpinned must WARN (demoted, printed under --quiet), never block or clear silently, got %+v",
				c.eco, c.name, v)
		}
		_, row, ok := establishedClears(c.eco, c.name, time.Now(), true)
		if !ok || len(row.Releases) == 0 {
			t.Fatalf("%s:%s has no clearing row with a release set in the embedded table — regenerate it", c.eco, c.name)
		}
		pin := ""
		for r := range row.Releases {
			pin = r
			break
		}
		v = g.evaluate(ctx, packageSpec{Ecosystem: c.eco, Name: c.name, Version: pin})
		if v.Block || v.Severity != "" || v.ClearedReason == "" {
			t.Errorf("%s:%s@%s (a build-time release) must CLEAR silently (no warn, ClearedReason set), got %+v",
				c.eco, c.name, pin, v)
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
