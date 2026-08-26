package intelligence

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// TestTransitiveCVEJSONPathMatchesTheSQL pins the JSONB path in
// transitiveCVEExpr against the struct tags that produce it. A rename in
// core/risk/evaluation.go would leave the expression reading SQL NULL for
// every row — which COALESCEs to 0, so the transitive half of the has-CVE
// facet would silently revert to the direct-only number that D8-2 fixed.
// Nothing would fail; the count would just quietly get smaller again.
//
// THE PATH IS EXTRACTED FROM THE CONST, NOT RETYPED. Writing
// decoded["resolution"].(map[string]any)["transitiveSeverity"] here would make
// the test assert against a private copy of the answer: rename a tag and the
// SQL breaks while this test keeps passing, because it is walking its own
// literals rather than the ones the query uses.
func TestTransitiveCVEJSONPathMatchesTheSQL(t *testing.T) {
	t.Parallel()

	// Pull `->'segment'` and `->>'segment'` out of the actual const.
	segRe := regexp.MustCompile(`->>?'([a-zA-Z]+)'`)
	matches := segRe.FindAllStringSubmatch(transitiveCVEExpr, -1)
	if len(matches) == 0 {
		t.Fatal("no JSON path segments found in transitiveCVEExpr — if the predicate " +
			"stopped being a JSONB extract, update this guard; do not delete it")
	}

	// The four tiers repeat the same prefix, so collect the distinct paths.
	// Every one must resolve on a marshalled Evaluation.
	var paths [][]string
	var cur []string
	for _, m := range matches {
		seg := m[1]
		cur = append(cur, seg)
		// A leaf is one of the count fields; everything before it is prefix.
		if len(seg) > 5 && seg[len(seg)-5:] == "Count" {
			p := make([]string, len(cur))
			copy(p, cur)
			paths = append(paths, p)
			cur = nil
		}
	}
	if len(paths) != 4 {
		t.Fatalf("expected 4 tier paths in transitiveCVEExpr, parsed %d: %v.\n"+
			"If a tier was added or removed, this guard and the predicate must move together.",
			len(paths), paths)
	}

	// One evaluation carrying a distinct value per tier, so a path that
	// lands on the WRONG tier is caught rather than passing on a shared value.
	want := map[string]int{"criticalCount": 1, "highCount": 2, "mediumCount": 3, "lowCount": 4}

	// The four leaves must be DISTINCT and must cover every tier.
	//
	// Counting paths alone is not enough, and this is not hypothetical: an
	// earlier draft of this test passed when `mediumCount` in the predicate
	// was replaced by a second `highCount`. Four paths still parsed, each
	// still resolved, each still matched the value for the tier it named —
	// so a predicate that silently ignored every medium-severity transitive
	// CVE looked correct.
	seen := map[string]bool{}
	for _, path := range paths {
		leaf := path[len(path)-1]
		if seen[leaf] {
			t.Errorf("transitiveCVEExpr reads tier %q more than once — a tier it names "+
				"twice is a tier it does not count at all", leaf)
		}
		seen[leaf] = true
	}
	for tier := range want {
		if !seen[tier] {
			t.Errorf("transitiveCVEExpr never reads tier %q; transitive CVEs at that "+
				"severity are invisible to the has-CVE facet and filter", tier)
		}
	}
	eval := &risk.Evaluation{
		Resolution: risk.Resolution{
			TransitiveSeverity: risk.TransitiveSeverity{
				CriticalCount: 1, HighCount: 2, MediumCount: 3, LowCount: 4,
			},
		},
	}
	blob, err := json.Marshal(eval)
	if err != nil {
		t.Fatalf("marshal evaluation: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatalf("unmarshal evaluation: %v", err)
	}

	for _, path := range paths {
		node := any(decoded)
		for i, seg := range path {
			obj, ok := node.(map[string]any)
			if !ok {
				t.Fatalf("path %v: segment %q has no object to descend into (stopped at depth %d). "+
					"The SQL reads NULL here for every row.", path, seg, i)
			}
			node, ok = obj[seg]
			if !ok {
				t.Fatalf("path %v: key %q absent. The SQL reads NULL for every row, "+
					"COALESCEs to 0, and the transitive half of the has-CVE facet "+
					"silently reverts to direct-only. keys=%v", path, seg, keysOf(obj))
			}
		}
		leaf := path[len(path)-1]
		got, _ := node.(float64)
		if int(got) != want[leaf] {
			t.Errorf("path %v resolved to %v, want %d — the predicate is reading the wrong tier",
				path, node, want[leaf])
		}
	}

	// The predicate must NOT count malware or blocked descendants: those
	// are "a dependency is malicious" and "a dependency has no way out",
	// neither of which is a CVE. Folding them in would make the has-CVE
	// facet a has-any-transitive-problem facet.
	for _, forbidden := range []string{"malwareCount", "blockedCount"} {
		if regexp.MustCompile(`'` + forbidden + `'`).MatchString(transitiveCVEExpr) {
			t.Errorf("transitiveCVEExpr counts %q, which is not a CVE tier", forbidden)
		}
	}

	// Zero counts are dropped by omitempty — which is exactly why the SQL
	// wraps each extract in NULLIF/COALESCE. If that ever changes the
	// wrapping stops being load-bearing for NEW rows, but legacy rows and
	// NULL risk_evaluation still need it.
	zeroBlob, _ := json.Marshal(&risk.Evaluation{})
	var zeroDecoded map[string]any
	_ = json.Unmarshal(zeroBlob, &zeroDecoded)
	if res, ok := zeroDecoded["resolution"].(map[string]any); ok {
		if ts, ok := res["transitiveSeverity"].(map[string]any); ok {
			if _, present := ts["criticalCount"]; present {
				t.Error("criticalCount is now emitted at zero — harmless, but the " +
					"NULLIF/COALESCE in transitiveCVEExpr is no longer load-bearing " +
					"for new rows; legacy rows still need it, so do not remove it")
			}
		}
	}
}
