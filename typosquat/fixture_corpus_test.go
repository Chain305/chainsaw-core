package typosquat_test

// End-to-end fixture corpus for the typosquat detector.
//
// Mirrors the pattern in internal/installscripts/ast_test.go's
// `TestNPMASTHistoricMaliciousCorpus`: each fixture lives on disk under
// testing/fixtures/typosquat/<shape>/ with (a) the manifest the
// attacker would publish, (b) a README explaining the attack shape, and
// (c) an expected.json that pins the detector booleans the contract is
// supposed to emit.
//
// The fixtures are inputs to the *name-based* detectors — the manifest
// is present for parity with the historic_malicious/ corpus and to
// stand up a realistic on-disk shape, but the detection signal lives
// entirely in the package name + (for depconfusion) the
// reservedNamespaces policy. No live exfil URLs, no executable install
// hooks; the lifecycle scripts present are placeholder echoes so the
// JSON parses without secondarily firing the install-script detector.
//
// SCOPE — FREE: this test exercises ONLY the free typosquat detector and
// must never import any enterprise internal/ package (open-core boundary,
// enforced by internal/opencore/boundary_test.go). The shared corpus also
// contains depconfusion-only and dual ("both") fixtures whose detection
// signal involves the enterprise internal/depconfusion checker; those are
// exercised from the enterprise side in
// internal/depconfusion/corpus_test.go. This file deliberately filters the
// corpus down to detector=="typosquat" fixtures and asserts only the
// typosquat arm, so core/typosquat keeps its own free coverage without
// reaching across the seam.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/chain305/chainsaw-core/typosquat"
)

// expectedFixture is the schema for testing/fixtures/typosquat/<dir>/expected.json.
// The file also carries depconfusion / "both" shapes; this free-side test
// reads only the typosquat-relevant fields (and Detector, to filter the
// corpus). The enterprise-side test (internal/depconfusion/corpus_test.go)
// owns the depconfusion-shaped fields.
type expectedFixture struct {
	PackageName  string   `json:"packageName"`
	Ecosystem    string   `json:"ecosystem"`
	Detector     string   `json:"detector"` // "typosquat" | "depconfusion" | "both"
	PopularSeeds []string `json:"popularSeeds,omitempty"`

	// Single-detector shape. Used when Detector == "typosquat".
	IsSuspected bool   `json:"isSuspected,omitempty"`
	Method      string `json:"method,omitempty"`
	SimilarTo   string `json:"similarTo,omitempty"`
	Distance    int    `json:"distance,omitempty"`
	Confidence  string `json:"confidence,omitempty"`

	// Dual-detector shape. Used when Detector == "both"; only the typosquat
	// branch is read here.
	Typosquat *expectedTyposquatBranch `json:"typosquat,omitempty"`
}

type expectedTyposquatBranch struct {
	IsSuspected bool   `json:"isSuspected"`
	Method      string `json:"method"`
	SimilarTo   string `json:"similarTo"`
	MaxDistance int    `json:"maxDistance"`
}

// fixtureRoot walks up from the test cwd to find testing/fixtures/typosquat.
// Mirrors fixtureBytes() in internal/installscripts/detect_test.go so the
// test works whether invoked from the package directory or the repo root.
func fixtureRoot(t *testing.T) string {
	t.Helper()
	start, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := start
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "testing", "fixtures", "typosquat")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("testing/fixtures/typosquat not found starting from %s", start)
	return ""
}

func loadExpected(t *testing.T, fixtureDir string) expectedFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, "expected.json"))
	if err != nil {
		t.Fatalf("read expected.json from %s: %v", fixtureDir, err)
	}
	var exp expectedFixture
	if err := json.Unmarshal(data, &exp); err != nil {
		t.Fatalf("parse expected.json from %s: %v", fixtureDir, err)
	}
	return exp
}

// TestTyposquatFixtureCorpus runs every subdirectory of
// testing/fixtures/typosquat/ whose detector exercises the typosquat arm
// (Detector == "typosquat" or "both") through the typosquat detector and
// asserts on the booleans recorded in the fixture's expected.json.
// depconfusion-only fixtures are skipped here — they belong to the
// enterprise corpus test (internal/depconfusion/corpus_test.go), which
// keeps the free product from importing enterprise internal/ packages.
//
// The case table is explicit (rather than walking the dir) so that an
// accidentally-added fixture without a matching test row fails the
// "all fixtures accounted for" check below.
func TestTyposquatFixtureCorpus(t *testing.T) {
	root := fixtureRoot(t)

	cases := []struct {
		name string
		dir  string
	}{
		{"npm_lod_ash", "npm_lod_ash"},
		{"pypi_internal_shadow", "pypi_internal_shadow"},
		{"npm_scoped_unscoped_react_dom", "npm_scoped_unscoped_react_dom"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixtureDir := filepath.Join(root, tc.dir)
			exp := loadExpected(t, fixtureDir)

			switch exp.Detector {
			case "typosquat":
				assertTyposquat(t, exp)
			case "both":
				assertTyposquatBranch(t, exp)
			case "depconfusion":
				// Enterprise-only detector — exercised in
				// internal/depconfusion/corpus_test.go. Skip on the free side.
				t.Skipf("depconfusion-only fixture exercised by the enterprise corpus test")
			default:
				t.Fatalf("unknown detector %q in %s/expected.json", exp.Detector, tc.dir)
			}
		})
	}

	// Belt-and-braces: walk the dir and assert every subdirectory is
	// present in the case table. A new fixture added without a
	// corresponding case row is a silent gap, so we'd rather fail loud.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("readdir %s: %v", root, err)
	}
	known := map[string]struct{}{}
	for _, c := range cases {
		known[c.dir] = struct{}{}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, ok := known[e.Name()]; !ok {
			t.Errorf("fixture %s/%s has no case row in TestTyposquatFixtureCorpus — add it", root, e.Name())
		}
	}
}

func assertTyposquat(t *testing.T, exp expectedFixture) {
	t.Helper()
	d := typosquat.NewDetector(nil)
	d.LoadEcosystem(exp.Ecosystem, popularSeedsToPackages(exp.PopularSeeds))

	got := d.Check(context.Background(), exp.Ecosystem, exp.PackageName)
	if got.IsSuspected != exp.IsSuspected {
		t.Errorf("typosquat IsSuspected: got %v, want %v (full result: %+v)", got.IsSuspected, exp.IsSuspected, got)
	}
	if exp.Method != "" && got.Method != exp.Method {
		t.Errorf("typosquat Method: got %q, want %q", got.Method, exp.Method)
	}
	if exp.SimilarTo != "" && got.SimilarTo != exp.SimilarTo {
		t.Errorf("typosquat SimilarTo: got %q, want %q", got.SimilarTo, exp.SimilarTo)
	}
	if exp.Distance != 0 && got.Distance != exp.Distance {
		t.Errorf("typosquat Distance: got %d, want %d", got.Distance, exp.Distance)
	}
	if exp.Confidence != "" && got.Confidence != exp.Confidence {
		t.Errorf("typosquat Confidence: got %q, want %q", got.Confidence, exp.Confidence)
	}
}

// assertTyposquatBranch checks only the typosquat arm of a dual ("both")
// fixture. The depconfusion arm is asserted by the enterprise corpus test.
func assertTyposquatBranch(t *testing.T, exp expectedFixture) {
	t.Helper()
	if exp.Typosquat == nil {
		t.Fatalf("detector=both requires a typosquat branch in expected.json")
	}

	d := typosquat.NewDetector(nil)
	d.LoadEcosystem(exp.Ecosystem, popularSeedsToPackages(exp.PopularSeeds))
	got := d.Check(context.Background(), exp.Ecosystem, exp.PackageName)
	if got.IsSuspected != exp.Typosquat.IsSuspected {
		t.Errorf("typosquat IsSuspected: got %v, want %v (full result: %+v)", got.IsSuspected, exp.Typosquat.IsSuspected, got)
	}
	if exp.Typosquat.Method != "" && got.Method != exp.Typosquat.Method {
		t.Errorf("typosquat Method: got %q, want %q", got.Method, exp.Typosquat.Method)
	}
	if exp.Typosquat.SimilarTo != "" && got.SimilarTo != exp.Typosquat.SimilarTo {
		t.Errorf("typosquat SimilarTo: got %q, want %q", got.SimilarTo, exp.Typosquat.SimilarTo)
	}
	if exp.Typosquat.MaxDistance != 0 && got.Distance > exp.Typosquat.MaxDistance {
		t.Errorf("typosquat Distance: got %d, want <= %d", got.Distance, exp.Typosquat.MaxDistance)
	}
}

func popularSeedsToPackages(seeds []string) []typosquat.PopularPackage {
	out := make([]typosquat.PopularPackage, 0, len(seeds))
	for i, name := range seeds {
		out = append(out, typosquat.PopularPackage{Name: name, Rank: i})
	}
	return out
}
