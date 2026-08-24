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
	"sort"
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
	// BLOCKING verdict.
	//
	// This assertion used to be nearly vacuous and said so: pr-scan emitted no
	// "block" severity at all, so nothing could fail it. That changed when
	// SurfacePR was wired to the policy DSL (see prScanPolicyLane in
	// pr_scan.go) — a rule can now raise a signal to "block" and make exit 20
	// reachable. The measurement below is still the HEURISTIC path with no
	// bundle loaded, which is exactly the baseline that must stay permissive:
	// policy tightens on top of it, so a popular package blocking HERE would
	// mean the floor itself moved.
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

// TestLockNameModeSplitsGuardFromReport is BLOCKER 3's aggravating factor: the
// guard's install path was wired through the parser in pr-scan's REPORT-ROW
// naming mode, so a nested entry became "node-sass-legacy/node_modules/
// color-convert" — a coordinate no npm cache key and no registry URL can ever
// match. Guaranteed O(1) miss, guaranteed fall-through to the fallback scan,
// and the fallback scan matched on tarball basename alone.
//
// The 40-line rationale on prScanNestedLockNames reasons entirely about
// pr-scan's report rows and their noise floor on a merge gate. It says nothing
// about the guard surface it had been wired into, and the two want different
// answers. This test pins that they get different answers.
func TestLockNameModeSplitsGuardFromReport(t *testing.T) {
	const lock = `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root", "version": "0.0.0"},
	    "node_modules/color-convert": {"version": "2.0.1", "integrity": "sha512-AAA="},
	    "node_modules/node-sass-legacy/node_modules/color-convert": {"version": "1.9.3", "integrity": "sha512-BBB="},
	    "node_modules/@scope/pkg": {"version": "3.0.0", "integrity": "sha512-CCC="}
	  }
	}`

	report, _, err := parsePackageLockIntegrityJSONMode([]byte(lock), lockNamesReport)
	if err != nil {
		t.Fatal(err)
	}
	// pr-scan's shipped row identity, unchanged. Flipping it is the product
	// decision prScanNestedLockNames gates; this fix must not make it silently.
	wantNested := "node-sass-legacy/node_modules/color-convert"
	if prScanNestedLockNames {
		wantNested = "color-convert"
	}
	if _, ok := report[wantNested]; !ok {
		t.Fatalf("pr-scan report naming changed: %v does not contain %q", lockNameKeys(report), wantNested)
	}

	installed, integrity, err := parsePackageLockIntegrityJSONMode([]byte(lock), lockNamesInstalled)
	if err != nil {
		t.Fatal(err)
	}
	// The guard sees the name npm actually installs, at both paths.
	if _, ok := installed["color-convert"]; !ok {
		t.Fatalf("the guard must resolve a nested entry to the installed name, got %v", lockNameKeys(installed))
	}
	if _, ok := installed["node-sass-legacy/node_modules/color-convert"]; ok {
		t.Fatalf("the guard must never see a dedup path as a package name, got %v", lockNameKeys(installed))
	}
	if got := installed["@scope/pkg"]; got != "3.0.0" {
		t.Fatalf("a scoped entry must keep its scope, got %q", got)
	}
	// The integrity map is keyed on the same names, or the anchor never pairs.
	if integrity[lockIntegrityKey("color-convert", installed["color-convert"])] == "" {
		t.Fatalf("the lockfile anchor must be reachable under the installed name, got %v", integrity)
	}
	// The workspace root has no installed identity and no registry tarball, so
	// the guard skips it rather than inventing a coordinate.
	if _, ok := installed["root"]; ok {
		t.Fatal("the workspace root must not become a guard spec")
	}
}

func lockNameKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestParsePackageLockCoordinates_DuplicateNamesAllSurvive is the
// regression pin for the defect that made the guard's byte scan
// non-reproducible.
//
// The guard used to consume map[name]version. A real npm tree installs
// the same name at several versions routinely — a measured ui_new
// lockfile carries 40 such names, a landing lockfile 46 — so the map
// dropped ~5% of installed coordinates (924 entries became 851), and
// because Go randomises map iteration, WHICH version survived changed
// between runs of the same binary over the same bytes.
//
// TestLockNameModeSplitsGuardFromReport builds this exact fixture and
// asserts only that the KEY exists. That is why the defect lived: the
// test could not see it. This one asserts the versions.
func TestParsePackageLockCoordinates_DuplicateNamesAllSurvive(t *testing.T) {
	lock := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "root", "version": "1.0.0"},
	    "node_modules/color-convert": {"version": "2.0.1", "integrity": "sha512-AAAA=="},
	    "node_modules/pkg-a/node_modules/color-convert": {"version": "1.9.3", "integrity": "sha512-BBBB=="},
	    "node_modules/pkg-b/node_modules/color-convert": {"version": "0.5.3", "integrity": "sha512-CCCC=="},
	    "node_modules/solo": {"version": "3.0.0", "integrity": "sha512-DDDD=="}
	  }
	}`)

	coords, err := parsePackageLockCoordinates(lock)
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]string{}
	for _, c := range coords {
		got[c.Name+"@"+c.Version] = c.Integrity
	}
	for _, want := range []struct{ coord, sri string }{
		{"color-convert@2.0.1", "sha512-AAAA=="},
		{"color-convert@1.9.3", "sha512-BBBB=="},
		{"color-convert@0.5.3", "sha512-CCCC=="},
		{"solo@3.0.0", "sha512-DDDD=="},
	} {
		sri, ok := got[want.coord]
		if !ok {
			t.Errorf("coordinate %s was dropped — the guard would never analyze it", want.coord)
			continue
		}
		if sri != want.sri {
			t.Errorf("%s anchored to %q, want %q — a wrong anchor manufactures a digest mismatch on a clean install",
				want.coord, sri, want.sri)
		}
	}
	if len(coords) != 4 {
		t.Errorf("got %d coordinates, want 4: %+v", len(coords), coords)
	}

	// Determinism. The old map form produced a different survivor per run,
	// so guard coverage was a coin flip and a gap never reproduced twice.
	first := fmt.Sprintf("%v", coords)
	for i := 0; i < 20; i++ {
		again, err := parsePackageLockCoordinates(lock)
		if err != nil {
			t.Fatal(err)
		}
		if s := fmt.Sprintf("%v", again); s != first {
			t.Fatalf("non-deterministic across parses of identical bytes:\n first: %s\n now:   %s", first, s)
		}
	}
}

// TestParsePackageLockCoordinates_ConflictingAnchorsCollapse: two entries
// claiming the SAME coordinate with different SRIs must yield NO anchor,
// not an arbitrary one. A wrong anchor is worse than none — it
// manufactures a digest mismatch on an honest install.
func TestParsePackageLockCoordinates_ConflictingAnchorsCollapse(t *testing.T) {
	lock := []byte(`{
	  "lockfileVersion": 3,
	  "packages": {
	    "node_modules/dup": {"version": "1.0.0", "integrity": "sha512-AAAA=="},
	    "node_modules/x/node_modules/dup": {"version": "1.0.0", "integrity": "sha512-ZZZZ=="}
	  }
	}`)
	coords, err := parsePackageLockCoordinates(lock)
	if err != nil {
		t.Fatal(err)
	}
	if len(coords) != 1 {
		t.Fatalf("one coordinate expected, got %+v", coords)
	}
	if coords[0].Integrity != "" {
		t.Errorf("conflicting anchors must collapse to none, got %q", coords[0].Integrity)
	}
}
