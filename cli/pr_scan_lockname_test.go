package cli

// Regression tests for G5b — package-lock.json name resolution — and the
// false-positive MEASUREMENT that gates part B (nested-path derivation).
//
// Part A (alias) is a straight correctness fix and ships enabled.
//
// Part B newly exposes every TRANSITIVE dependency in a lockfile to the offline
// typosquat ladder, a surface that had never been measured, so it ships behind
// prScanNestedLockNames (DEFAULT OFF).
// TestParsePackageLockJSON_NestedNamesTyposquatFPRate is the measurement that
// informs that constant; it runs regardless of how the constant is set. The
// measured rate is 22 signals / 1,200 real popular npm names = 1.83%, zero of
// them blocking. Read the comment on prScanNestedLockNames before flipping it —
// a warn-level FP on ~1 in 55 ordinary dependencies on a MERGE GATE is the shape
// of the 742-FP incident, and warnings that fire constantly get ignored along
// with the real ones.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// popularNPMNames returns the first n entries of the embedded download-ranked
// npm corpus (comments stripped). Line order is rank.
func popularNPMNames(t *testing.T, skip, n int) []string {
	t.Helper()
	var out []string
	seen := 0
	for _, line := range strings.Split(string(npmPopularSeed), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		seen++
		if seen <= skip {
			continue
		}
		out = append(out, line)
		if len(out) == n {
			break
		}
	}
	if len(out) < n {
		t.Fatalf("corpus too small: wanted %d names after skipping %d, got %d", n, skip, len(out))
	}
	return out
}

// buildNestedLockfile renders a package-lock.json v3 whose entries are laid out
// the way npm actually dedups a real tree: a flat top layer plus a nested layer
// under a handful of parents (the shape create-react-app and Next.js produce
// when two dependents need incompatible ranges of the same package).
func buildNestedLockfile(names []string, parents []string) []byte {
	packages := map[string]map[string]string{
		"": {"version": "1.0.0"},
	}
	for i, n := range names {
		if i%3 == 0 && len(parents) > 0 {
			parent := parents[i%len(parents)]
			packages["node_modules/"+parent+"/node_modules/"+n] = map[string]string{"version": "1.0.0"}
			continue
		}
		packages["node_modules/"+n] = map[string]string{"version": "1.0.0"}
	}
	body, err := json.Marshal(map[string]any{
		"name":            "app",
		"lockfileVersion": 3,
		"packages":        packages,
	})
	if err != nil {
		panic(err)
	}
	return body
}

// prScanNestedFPBudget is the measured false-positive ceiling for G5b part B.
//
// Baseline at the time of measurement: 22 signals over 1,200 real popular npm
// names (1.83%). The budget sits just above it so a genuine regression in the
// typosquat ladder or the curated seed list trips this test, while ordinary
// corpus refreshes do not. Raising it is a decision, not a fix — read the
// comment on prScanNestedLockNames first.
const prScanNestedFPBudget = 0.025

// TestParsePackageLockJSON_NestedNamesTyposquatFPRate is the G5b part-B
// measurement gate. It resolves the names part B exposes and runs the offline
// typosquat ladder over every one of them.
//
// It deliberately runs whether or not prScanNestedLockNames is set: the number
// is the input to the decision about setting it, so it must stay live in CI
// rather than disappearing behind the flag it informs.
func TestParsePackageLockJSON_NestedNamesTyposquatFPRate(t *testing.T) {
	trees := []struct {
		name    string
		names   []string
		parents []string
	}{
		{
			// create-react-app-shaped: react-scripts and the webpack/babel/jest
			// toolchain own most of the nesting.
			name:    "create-react-app",
			names:   popularNPMNames(t, 0, 600),
			parents: []string{"react-scripts", "webpack", "jest", "babel-loader", "eslint"},
		},
		{
			// Next.js-shaped: a different slice of the corpus under the next /
			// swc / postcss toolchain.
			name:    "nextjs",
			names:   popularNPMNames(t, 600, 600),
			parents: []string{"next", "postcss", "styled-jsx", "webpack", "typescript"},
		},
	}

	totalScanned, totalSignals := 0, 0
	var blocking int
	for _, tree := range trees {
		data := buildNestedLockfile(tree.names, tree.parents)
		var root struct {
			Packages map[string]struct{} `json:"packages"`
		}
		if err := json.Unmarshal(data, &root); err != nil {
			t.Fatalf("%s: fixture is not valid JSON: %v", tree.name, err)
		}

		var hits []string
		for path := range root.Packages {
			if path == "" {
				continue
			}
			// Exercise part B's derivation directly so the measurement is
			// independent of prScanNestedLockNames.
			name := lockEntryNameNested(path)
			if name == "" {
				t.Errorf("%s: %q resolved to an empty name", tree.name, path)
				continue
			}
			if strings.Contains(name, "node_modules/") {
				t.Errorf("%s: %q still carries a node_modules segment", tree.name, name)
			}
			totalScanned++
			sig, ok := checkTyposquat("npm", name)
			if !ok {
				continue
			}
			totalSignals++
			if sig.Severity == "block" {
				blocking++
			}
			hits = append(hits, fmt.Sprintf("%s (%s)", name, sig.Reason))
		}
		t.Logf("%s: %d/%d real popular packages produced a typosquat signal: %v",
			tree.name, len(hits), len(root.Packages)-1, hits)
	}

	rate := float64(totalSignals) / float64(totalScanned)
	t.Logf("G5b part-B FP measurement: %d typosquat signals over %d real popular npm names (%.2f%%); %d blocking",
		totalSignals, totalScanned, rate*100, blocking)

	// The hard requirement: part B must never put a real popular package on a
	// BLOCKING verdict. pr-scan emits no "block" severity at all today, so this
	// also guards against a future promotion landing without a re-measurement.
	if blocking != 0 {
		t.Fatalf("%d real popular packages would BLOCK under part B — do not enable it", blocking)
	}
	// The soft budget: warn-level noise on a merge gate.
	if rate > prScanNestedFPBudget {
		t.Fatalf("typosquat FP rate on real popular packages = %.2f%% (%d/%d), budget %.2f%% — "+
			"the ladder or the curated seed list regressed",
			rate*100, totalSignals, totalScanned, prScanNestedFPBudget*100)
	}
}

// TestParsePackageLockJSON_NestedNamesGateIsExplicit documents that part B is
// held behind a constant on purpose, so that flipping it is a deliberate act
// paired with a fresh look at the measurement above.
func TestParsePackageLockJSON_NestedNamesGateIsExplicit(t *testing.T) {
	if prScanNestedLockNames {
		t.Log("G5b part B is ENABLED — re-read TestParsePackageLockJSON_NestedNamesTyposquatFPRate's " +
			"logged rate before shipping")
	}
	// Whichever way the constant is set, the derivation itself must be correct.
	cases := map[string]string{
		"node_modules/foo":                            "foo",
		"node_modules/foo/node_modules/electorn":      "electorn",
		"node_modules/@scope/bar/node_modules/@o/baz": "@o/baz",
		"packages/app/node_modules/@babel/core":       "@babel/core",
	}
	for in, want := range cases {
		if got := lockEntryNameNested(in); got != want {
			t.Errorf("lockEntryNameNested(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParsePackageLockJSON_AliasUsesRealName pins G5b part A: an aliased
// dependency must be scanned as the package npm installs, not as the alias.
// Before the fix, `"node_modules/react": {"name": "electorn"}` was reported as
// "react" — a corpus member, exempt from the typosquat ladder and clean in the
// malware index — while npm put electorn's code in node_modules/react.
func TestParsePackageLockJSON_AliasUsesRealName(t *testing.T) {
	data := []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/react": {"name": "electorn", "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/electorn/-/electorn-1.0.0.tgz"},
    "node_modules/chalk": {"version": "5.3.0"}
  }
}`)
	got, err := parsePackageLockJSON(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := got["electorn"]; !ok {
		t.Errorf("aliased dependency should be scanned as electorn; got %v", got)
	}
	if _, ok := got["react"]; ok {
		t.Errorf("the alias %q must not be reported as the installed package; got %v", "react", got)
	}
	if got["chalk"] != "5.3.0" {
		t.Errorf("unaliased entry lost: %v", got)
	}
}

// TestParsePackageLockJSON_NestedTransitiveIsScanned pins G5b part B on the
// minimal case: a transitively-deduped entry must resolve to its own name.
// Before the fix it resolved to "foo/node_modules/electorn", which matches
// nothing in any index — so transitive deps went unscanned in ORDINARY trees,
// no attacker required.
func TestParsePackageLockJSON_NestedTransitiveIsScanned(t *testing.T) {
	if !prScanNestedLockNames {
		t.Skip("nested-path name derivation is disabled")
	}
	data := []byte(`{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/foo": {"version": "2.0.0"},
    "node_modules/foo/node_modules/electorn": {"version": "1.0.0"},
    "node_modules/@scope/bar/node_modules/@other/baz": {"version": "3.0.0"}
  }
}`)
	got, err := parsePackageLockJSON(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got["electorn"] != "1.0.0" {
		t.Errorf("nested transitive dep should resolve to electorn@1.0.0; got %v", got)
	}
	if _, bad := got["foo/node_modules/electorn"]; bad {
		t.Errorf("un-matchable path-shaped name still emitted: %v", got)
	}
	if got["@other/baz"] != "3.0.0" {
		t.Errorf("nested scoped dep should resolve to @other/baz; got %v", got)
	}
}

// TestParsePackageLockJSON_BOMTolerated pins the C3 BOM strip on the lockfile
// parser too: npm parses a BOM-prefixed lockfile, so a spurious Go parse error
// there would report a manifest as broken when it is not.
func TestParsePackageLockJSON_BOMTolerated(t *testing.T) {
	data := append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"lockfileVersion":3,"packages":{"node_modules/chalk":{"version":"5.3.0"}}}`)...)
	got, err := parsePackageLockJSON(data)
	if err != nil {
		t.Fatalf("BOM-prefixed lockfile should parse: %v", err)
	}
	if got["chalk"] != "5.3.0" {
		t.Errorf("got %v", got)
	}
}
