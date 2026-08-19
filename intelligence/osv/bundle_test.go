package osv

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// gzippedJSON is a small helper that turns advisory records into the
// gzip'd JSON shape Load expects. Keeps the tests free of testdata
// files for variants that only need a couple of records.
func gzippedJSON(t *testing.T, advs []Advisory) []byte {
	t.Helper()
	raw, err := json.Marshal(advs)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func TestLoadAndLookup_PyPIIdnaCVE(t *testing.T) {
	// Fixture is checked in so the test exercises the on-disk loader
	// path too — same code the runtime hits on boot.
	path := filepath.Join("testdata", "sample.json")
	idx, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if idx.Total() == 0 {
		t.Fatalf("expected non-empty index, got 0 advisories")
	}

	hits := idx.Lookup("pypi", "idna", "3.15")
	if len(hits) == 0 {
		t.Fatalf("expected CVE hit for (pypi, idna, 3.15), got none")
	}

	// At least one hit must surface CVE-2024-3651 (the canonical fixture
	// advisory) via aliases.
	var found bool
	for _, a := range hits {
		for _, alias := range a.Aliases {
			if alias == "CVE-2024-3651" {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatalf("expected CVE-2024-3651 in aliases, got hits: %+v", hits)
	}

	// "pip" is a caller-facing alias for "pypi" — must resolve via
	// CanonicalEcosystem.
	if got := idx.Lookup("pip", "idna", "3.15"); len(got) == 0 {
		t.Fatalf("ecosystem alias 'pip' must resolve to pypi")
	}
}

func TestLookup_EcosystemIsolation(t *testing.T) {
	// Same package name in a different ecosystem must NOT match.
	path := filepath.Join("testdata", "sample.json")
	idx, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if got := idx.Lookup("npm", "idna", "3.15"); len(got) != 0 {
		t.Fatalf("npm/idna must not match pypi/idna advisory, got %d hits", len(got))
	}
}

func TestLookup_CleanVersionStillTracked(t *testing.T) {
	// When the index knows the package but the requested version is
	// not in the affected list, Lookup returns nil but HasPackage is
	// true. The provider uses this to set Vulns to a non-nil empty
	// VulnSection (we scanned, clean) instead of leaving it nil
	// (didn't scan).
	bundle := gzippedJSON(t, []Advisory{
		{
			Ecosystem:          "PyPI",
			Package:            "idna",
			VulnerableVersions: []string{"3.15"},
			AdvisoryID:         "GHSA-jjg7-2v4v-x38h",
			Aliases:            []string{"CVE-2024-3651"},
		},
	})
	idx, err := Load(bytes.NewReader(bundle))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := idx.Lookup("pypi", "idna", "3.7"); len(got) != 0 {
		t.Fatalf("3.7 should be clean, got %d hits", len(got))
	}
	if !idx.HasPackage("pypi", "idna") {
		t.Fatalf("HasPackage must report true for indexed package even when version is clean")
	}
	if idx.HasPackage("pypi", "definitely-not-real") {
		t.Fatalf("HasPackage must report false for uncovered package")
	}
}

func TestCanonicalEcosystem(t *testing.T) {
	cases := map[string]string{
		"npm":         "npm",
		"yarn":        "npm",
		"bun":         "npm",
		"pip":         "pypi",
		"PyPI":        "pypi",
		"Maven":       "maven",
		"gradle":      "maven",
		"cargo":       "cargo",
		"crates.io":   "cargo",
		"rubygems":    "rubygems",
		"nuget":       "nuget",
		"composer":    "packagist",
		"packagist":   "packagist",
		"go":          "go",
		"gomod":       "go",
		"Go":          "go",
		"docker":      "",
		"huggingface": "",
		"":            "",
		"   ":         "",
		"NotAnEcosys": "",
	}
	for in, want := range cases {
		if got := CanonicalEcosystem(in); got != want {
			t.Errorf("CanonicalEcosystem(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLoad_EmptyBundleIsValid(t *testing.T) {
	// An empty advisory list must produce an Index with zero entries —
	// the runtime treats this as "loaded but no coverage" rather than
	// erroring the boot path.
	bundle := gzippedJSON(t, []Advisory{})
	idx, err := Load(bytes.NewReader(bundle))
	if err != nil {
		t.Fatalf("Load empty: %v", err)
	}
	if idx.Total() != 0 {
		t.Fatalf("empty bundle should have Total()=0, got %d", idx.Total())
	}
	if got := idx.Lookup("pypi", "anything", "1.0"); got != nil {
		t.Fatalf("empty index lookup must return nil, got %+v", got)
	}
}

func TestLoadFile_Missing(t *testing.T) {
	_, err := LoadFile(filepath.Join(os.TempDir(), "does-not-exist-osv-bundle.json.gz"))
	if err == nil {
		t.Fatalf("expected error for missing file, got nil")
	}
}

func TestAdvisory_PreferredCVE(t *testing.T) {
	a := Advisory{
		AdvisoryID: "GHSA-jjg7-2v4v-x38h",
		Aliases:    []string{"OTHER-1", "CVE-2024-3651", "CVE-2024-9999"},
	}
	if got := a.PreferredCVE(); got != "CVE-2024-3651" {
		t.Errorf("PreferredCVE = %q, want CVE-2024-3651", got)
	}

	// Falls back to AdvisoryID when no CVE alias is present.
	b := Advisory{AdvisoryID: "GHSA-only"}
	if got := b.PreferredCVE(); got != "GHSA-only" {
		t.Errorf("PreferredCVE = %q, want GHSA-only", got)
	}
}

// TestAdvisoryAffects_LodashOvercountRegression pins the precision fix
// that took lodash 4.17.20's CVE count from 10 (over-count) down to 5
// (matches OSV live API + Socket). The bundle entries for the five
// false-positive advisories carry `vulnerable_versions: []` plus a
// range `[introduced=0, fixed="4.17.5"]`. Previously the matcher
// treated empty versions as "matches everything", so every patched-
// in-4.17.5 advisory falsely fired on 4.17.20. After this fix:
//
//   - empty versions + [0, 4.17.5) + query 4.17.20 → no match
//   - empty versions + [0, 4.17.5) + query 4.17.0  → match (still
//     vulnerable on an old version)
//   - empty versions + empty ranges + non-empty fixed_versions →
//     no match (failsafe — we don't have enough info to fire)
func TestAdvisoryAffects_LodashOvercountRegression(t *testing.T) {
	a := Advisory{
		Ecosystem: "npm", Package: "lodash",
		VulnerableRanges: []VulnerableRange{{Introduced: "0", Fixed: "4.17.5"}},
		FixedVersions:    []string{"4.17.5"},
		AdvisoryID:       "GHSA-fvqr-27wr-82fm",
		Aliases:          []string{"CVE-2018-3721"},
	}
	if advisoryAffects(a, "4.17.20") {
		t.Errorf("4.17.20 must NOT match [0, 4.17.5) — this is the lodash over-count regression")
	}
	if !advisoryAffects(a, "4.17.0") {
		t.Errorf("4.17.0 must match [0, 4.17.5) — old vulnerable version")
	}
	if advisoryAffects(a, "4.17.5") {
		t.Errorf("4.17.5 is the fix version — must NOT match (exclusive upper bound)")
	}
	if !advisoryAffects(a, "4.17.4") {
		t.Errorf("4.17.4 < 4.17.5 — must match")
	}
}

func TestAdvisoryAffects_OpenEndedRange(t *testing.T) {
	// No fix yet — every version since `introduced` is vulnerable.
	a := Advisory{
		Ecosystem: "npm", Package: "vulnpkg",
		VulnerableRanges: []VulnerableRange{{Introduced: "1.0.0"}},
	}
	if !advisoryAffects(a, "1.0.0") {
		t.Errorf("1.0.0 (introduced) must match an open-ended range")
	}
	if !advisoryAffects(a, "5.0.0") {
		t.Errorf("5.0.0 must match an open-ended range starting at 1.0.0")
	}
	if advisoryAffects(a, "0.9.0") {
		t.Errorf("0.9.0 < introduced=1.0.0 must not match")
	}
}

func TestAdvisoryAffects_LastAffectedInclusive(t *testing.T) {
	// last_affected is the inclusive upper bound shape OSV uses for
	// some advisories. Test the boundary explicitly.
	a := Advisory{
		Ecosystem: "npm", Package: "vulnpkg",
		VulnerableRanges: []VulnerableRange{{Introduced: "1.0.0", LastAffected: "2.5.0"}},
	}
	if !advisoryAffects(a, "2.5.0") {
		t.Errorf("2.5.0 must match — last_affected is inclusive")
	}
	if advisoryAffects(a, "2.5.1") {
		t.Errorf("2.5.1 must NOT match — past the inclusive upper bound")
	}
}

func TestAdvisoryAffects_NoVersionInfoFailsClosed(t *testing.T) {
	// An advisory with neither versions nor ranges must default to
	// "no match" — previously this returned true and over-fired on
	// every version. Failsafe regression guard.
	a := Advisory{
		Ecosystem: "npm", Package: "vulnpkg",
		AdvisoryID: "GHSA-no-info",
	}
	if advisoryAffects(a, "1.0.0") {
		t.Errorf("advisory with no version info must NOT match (failsafe)")
	}
}

func TestAdvisoryAffects_ExplicitVersionsStillWork(t *testing.T) {
	// Backward compatibility: bundles that pre-date the ranges field
	// (only carry an explicit versions list) must continue matching.
	a := Advisory{
		Ecosystem: "PyPI", Package: "idna",
		VulnerableVersions: []string{"3.6", "3.5"},
		AdvisoryID:         "PYSEC-2024-60",
	}
	if !advisoryAffects(a, "3.6") {
		t.Errorf("exact-version match still must work for legacy bundles")
	}
	if advisoryAffects(a, "3.15") {
		t.Errorf("3.15 not in the explicit list — must not match")
	}
}

func TestAdvisoryAffects_MultipleRanges(t *testing.T) {
	// OSV can ship multiple ranges per advisory (e.g. a fix branched
	// into two major lines). The matcher must check each one.
	a := Advisory{
		Ecosystem: "npm", Package: "vulnpkg",
		VulnerableRanges: []VulnerableRange{
			{Introduced: "1.0.0", Fixed: "1.5.0"},
			{Introduced: "2.0.0", Fixed: "2.3.0"},
		},
	}
	cases := map[string]bool{
		"1.2.0": true,
		"1.4.9": true,
		"1.5.0": false, // exclusive
		"1.6.0": false, // between ranges
		"2.0.0": true,
		"2.2.9": true,
		"2.3.0": false,
		"3.0.0": false,
	}
	for v, want := range cases {
		if got := advisoryAffects(a, v); got != want {
			t.Errorf("advisoryAffects(%q) = %v, want %v", v, got, want)
		}
	}
}

func TestRangeAffects_ZeroValueIsApplyToAll(t *testing.T) {
	// A fully-zero VulnerableRange is the explicit "applies to every
	// published version" sentinel for OSV's unfixed-yet, no-version-
	// listed advisories. Distinct from an Advisory with no ranges at
	// all (which fails closed per TestAdvisoryAffects_NoVersionInfo
	// FailsClosed). The build.sh flattener emits a zero-value
	// VulnerableRange in that case.
	a := Advisory{
		Ecosystem: "npm", Package: "wildpkg",
		VulnerableRanges: []VulnerableRange{{}},
	}
	if !advisoryAffects(a, "1.2.3") {
		t.Errorf("zero-value range must match every version")
	}
}

// TestAdvisoryAffects_PerEcosystemSemantics pins the ecosystem-aware
// version-compare dispatch. Each sub-case exercises a version string
// that npm-flavoured Masterminds/semver gets WRONG, where the
// per-ecosystem library is the source of truth.
//
// Without the dispatch, all of these would fall back to exact-string
// match (safe but lossy) or — worse, on Masterminds' lenient path —
// produce an incorrect compare result.
func TestAdvisoryAffects_PerEcosystemSemantics(t *testing.T) {
	t.Run("PyPI PEP 440 pre-release ordering", func(t *testing.T) {
		// PEP 440: "1.0.0rc1" < "1.0.0" < "1.0.0.post1".
		// Masterminds would refuse to parse "1.0.0rc1" without a dash
		// or would mis-order "1.0.0.post1".
		a := Advisory{
			Ecosystem: "PyPI", Package: "p",
			VulnerableRanges: []VulnerableRange{{Introduced: "0", Fixed: "1.0.0"}},
		}
		if !advisoryAffects(a, "1.0.0rc1") {
			t.Errorf("1.0.0rc1 < 1.0.0 per PEP 440 — must match [0, 1.0.0)")
		}
		if advisoryAffects(a, "1.0.0") {
			t.Errorf("1.0.0 is the exclusive upper bound — must NOT match")
		}
		if advisoryAffects(a, "1.0.0.post1") {
			t.Errorf("1.0.0.post1 > 1.0.0 per PEP 440 — must NOT match [0, 1.0.0)")
		}
	})

	t.Run("PyPI dev releases", func(t *testing.T) {
		// "1.0.dev1" < "1.0a1" < "1.0b1" < "1.0rc1" < "1.0"
		a := Advisory{
			Ecosystem: "pypi", Package: "p",
			VulnerableRanges: []VulnerableRange{{Introduced: "1.0", Fixed: "2.0"}},
		}
		if advisoryAffects(a, "1.0.dev1") {
			t.Errorf("1.0.dev1 < 1.0 per PEP 440 — must NOT match [1.0, 2.0)")
		}
		if !advisoryAffects(a, "1.5") {
			t.Errorf("1.5 in [1.0, 2.0) — must match")
		}
	})

	t.Run("RubyGems Gem::Version pre-release", func(t *testing.T) {
		// Gem::Version: "1.0.0.beta1" < "1.0.0"
		a := Advisory{
			Ecosystem: "RubyGems", Package: "rails",
			VulnerableRanges: []VulnerableRange{{Introduced: "0", Fixed: "7.0.0"}},
		}
		if !advisoryAffects(a, "7.0.0.beta1") {
			t.Errorf("7.0.0.beta1 < 7.0.0 per Gem::Version — must match [0, 7.0.0)")
		}
		if advisoryAffects(a, "7.0.0") {
			t.Errorf("7.0.0 is exclusive upper — must NOT match")
		}
	})

	t.Run("Maven SNAPSHOT ordering", func(t *testing.T) {
		// Maven: "1.0-SNAPSHOT" < "1.0" (qualifier ranks below release)
		a := Advisory{
			Ecosystem: "Maven", Package: "p",
			VulnerableRanges: []VulnerableRange{{Introduced: "0", Fixed: "1.0"}},
		}
		if !advisoryAffects(a, "1.0-SNAPSHOT") {
			t.Errorf("1.0-SNAPSHOT < 1.0 per Maven order — must match [0, 1.0)")
		}
		if advisoryAffects(a, "1.0") {
			t.Errorf("1.0 is exclusive upper — must NOT match")
		}
	})

	t.Run("Maven qualifier ladder", func(t *testing.T) {
		// "1.0-alpha" < "1.0-beta" < "1.0-milestone" < "1.0-rc" <
		// "1.0-snapshot" < "1.0"
		a := Advisory{
			Ecosystem: "maven", Package: "p",
			VulnerableRanges: []VulnerableRange{{Introduced: "1.0-alpha", Fixed: "1.0-rc"}},
		}
		if !advisoryAffects(a, "1.0-beta") {
			t.Errorf("1.0-beta in [1.0-alpha, 1.0-rc) — must match")
		}
		if advisoryAffects(a, "1.0-rc") {
			t.Errorf("1.0-rc is exclusive upper — must NOT match")
		}
		if advisoryAffects(a, "1.0") {
			t.Errorf("1.0 > 1.0-rc — must NOT match")
		}
	})

	t.Run("npm SemVer pre-release", func(t *testing.T) {
		// SemVer: "1.0.0-rc.1" < "1.0.0".
		a := Advisory{
			Ecosystem: "npm", Package: "p",
			VulnerableRanges: []VulnerableRange{{Introduced: "0", Fixed: "1.0.0"}},
		}
		if !advisoryAffects(a, "1.0.0-rc.1") {
			t.Errorf("1.0.0-rc.1 < 1.0.0 per SemVer — must match [0, 1.0.0)")
		}
		if advisoryAffects(a, "1.0.0") {
			t.Errorf("1.0.0 is exclusive upper — must NOT match")
		}
	})

	t.Run("cargo SemVer", func(t *testing.T) {
		// Cargo is strict SemVer.
		a := Advisory{
			Ecosystem: "cargo", Package: "p",
			VulnerableRanges: []VulnerableRange{{Introduced: "1.0.0", Fixed: "2.0.0"}},
		}
		if !advisoryAffects(a, "1.5.0") {
			t.Errorf("1.5.0 in [1.0.0, 2.0.0) — must match")
		}
		if advisoryAffects(a, "2.0.0") {
			t.Errorf("2.0.0 is exclusive upper — must NOT match")
		}
	})

	t.Run("Composer Maven-flavoured fallback", func(t *testing.T) {
		// Composer pre-release tags rank similar to Maven.
		a := Advisory{
			Ecosystem: "Packagist", Package: "p",
			VulnerableRanges: []VulnerableRange{{Introduced: "0", Fixed: "1.0.0"}},
		}
		if !advisoryAffects(a, "0.9.0") {
			t.Errorf("0.9.0 < 1.0.0 — must match [0, 1.0.0)")
		}
	})

	t.Run("Ecosystem alias canonicalisation", func(t *testing.T) {
		// 'pip' must dispatch to the PyPI comparator.
		a := Advisory{
			Ecosystem: "pip", Package: "p",
			VulnerableRanges: []VulnerableRange{{Introduced: "0", Fixed: "1.0"}},
		}
		if !advisoryAffects(a, "1.0rc1") {
			t.Errorf("pip alias must dispatch to PyPI/PEP 440 (1.0rc1 < 1.0)")
		}
	})
}

// TestAdvisoryAffects_LodashRetainsFix re-runs the lodash regression
// guard under the new dispatch to make sure the per-ecosystem refactor
// didn't break the original precision fix.
func TestAdvisoryAffects_LodashRetainsFix(t *testing.T) {
	a := Advisory{
		Ecosystem:        "npm",
		Package:          "lodash",
		VulnerableRanges: []VulnerableRange{{Introduced: "0", Fixed: "4.17.5"}},
		FixedVersions:    []string{"4.17.5"},
		AdvisoryID:       "GHSA-fvqr-27wr-82fm",
		Aliases:          []string{"CVE-2018-3721"},
	}
	if advisoryAffects(a, "4.17.20") {
		t.Errorf("lodash 4.17.20 over-count regression must stay fixed")
	}
	if !advisoryAffects(a, "4.17.0") {
		t.Errorf("4.17.0 must still match [0, 4.17.5) under new dispatch")
	}
}

// TestLookup_GoEcosystem covers the Go-module advisory path (G8).
// OSV.dev publishes Go advisories under the "Go" ecosystem; the proxy
// resolver emits "go" or "gomod" — both must canonicalise to the same
// key. Go modules use SemVer with a leading `v` (e.g. "v1.4.0"), which
// the existing parseSemver wrapper strips before dispatch.
func TestLookup_GoEcosystem(t *testing.T) {
	bundle := gzippedJSON(t, []Advisory{
		{
			Ecosystem:        "Go",
			Package:          "github.com/foo/bar",
			VulnerableRanges: []VulnerableRange{{Introduced: "0", Fixed: "v1.5.0"}},
			AdvisoryID:       "GHSA-go-foo-bar",
			Aliases:          []string{"CVE-2024-0001"},
			FixedVersions:    []string{"v1.5.0"},
		},
	})
	idx, err := Load(bytes.NewReader(bundle))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !idx.HasPackage("go", "github.com/foo/bar") {
		t.Fatalf("HasPackage(go, github.com/foo/bar) must be true")
	}
	if hits := idx.Lookup("go", "github.com/foo/bar", "v1.4.0"); len(hits) != 1 {
		t.Fatalf("v1.4.0 should match [0, v1.5.0) — got %d hits", len(hits))
	}
	if hits := idx.Lookup("go", "github.com/foo/bar", "v1.5.0"); len(hits) != 0 {
		t.Fatalf("v1.5.0 is the exclusive fix — got %d hits", len(hits))
	}
	// gomod alias must canonicalise to the same key.
	if hits := idx.Lookup("gomod", "github.com/foo/bar", "v1.4.0"); len(hits) != 1 {
		t.Fatalf("gomod alias must dispatch to go (v1.4.0) — got %d hits", len(hits))
	}
	// Go module paths are case-sensitive per the OSV schema.
	if idx.HasPackage("go", "github.com/Foo/Bar") {
		t.Fatalf("Go module paths must be case-sensitive — case-folded lookup should miss")
	}
}

// TestAdvisory_CVSSScoreFromVectorIsCarried pins the G9 contract on the
// bundle.go side: the build-time CVSS vector parser fills in cvss_score
// numerically, and the runtime loader carries that field through to
// the Advisory struct unchanged. The vector-string parsing itself is
// exercised by dockerized/build.sh's Python; here we assert the
// downstream plumbing doesn't drop the value.
func TestAdvisory_CVSSScoreFromVectorIsCarried(t *testing.T) {
	// 7.5 is the canonical "HIGH" score for CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H.
	bundle := gzippedJSON(t, []Advisory{
		{
			Ecosystem:          "npm",
			Package:            "vecpkg",
			VulnerableVersions: []string{"1.0.0"},
			AdvisoryID:         "GHSA-vec-1",
			Aliases:            []string{"CVE-2024-9999"},
			CVSSScore:          7.5,
			Severity:           "HIGH",
		},
	})
	idx, err := Load(bytes.NewReader(bundle))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	hits := idx.Lookup("npm", "vecpkg", "1.0.0")
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if hits[0].CVSSScore != 7.5 {
		t.Errorf("CVSSScore = %v, want 7.5 (must survive load round-trip)", hits[0].CVSSScore)
	}
	if hits[0].Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", hits[0].Severity)
	}
}

// TestAdvisoryAffects_Lodash41721FixBoundary pins the production false
// positive measured on the universal intelligence row: lodash 4.17.21
// carrying CVE-2021-23337, an advisory FIXED in 4.17.21.
//
// The suspected cause — "fixed == queried version matches" — was NOT
// the bug; the exclusive-fix boundary has been correct since the
// range-aware matcher landed, and the first subtest pins that so it
// stays correct. The real cause is the second subtest: an OSV record
// carries several ranges, and a GIT range (commit bounds, frequently
// with no closing fix event) flattens into a version range with an OPEN
// upper bound. advisoryAffects ORs its ranges, so that one bogus
// open range outvoted the correct [0, 4.17.21).
func TestAdvisoryAffects_Lodash41721FixBoundary(t *testing.T) {
	lodash := func(ranges []VulnerableRange) Advisory {
		return Advisory{
			Ecosystem:        "npm",
			Package:          "lodash",
			VulnerableRanges: ranges,
			FixedVersions:    []string{"4.17.21"},
			AdvisoryID:       "GHSA-35jh-r3h4-6jhm",
			Aliases:          []string{"CVE-2021-23337"},
		}
	}

	t.Run("exclusive fix boundary", func(t *testing.T) {
		a := lodash([]VulnerableRange{{Introduced: "0", Fixed: "4.17.21"}})
		if advisoryAffects(a, "4.17.21") {
			t.Errorf("4.17.21 == fixed and fixed is exclusive — must NOT match")
		}
		if !advisoryAffects(a, "4.17.20") {
			t.Errorf("4.17.20 < 4.17.21 — must still match")
		}
	})

	t.Run("open GIT range must not outvote the semver fix", func(t *testing.T) {
		a := lodash([]VulnerableRange{
			{Introduced: "0"}, // flattened GIT range, no fix commit recorded
			{Introduced: "0", Fixed: "4.17.21"},
		})
		if advisoryAffects(a, "4.17.21") {
			t.Errorf("advisory declares fixed_versions=[4.17.21]; an open sibling range must not resurrect it")
		}
		if !advisoryAffects(a, "4.17.20") {
			t.Errorf("4.17.20 is genuinely affected — the clamp must not over-clear")
		}
	})

	t.Run("fully-open sentinel is clamped by the declared fix", func(t *testing.T) {
		a := lodash([]VulnerableRange{{}})
		if advisoryAffects(a, "4.17.21") {
			t.Errorf("zero-value sentinel must still respect the advisory's own fix version")
		}
		if !advisoryAffects(a, "4.17.20") {
			t.Errorf("4.17.20 must remain affected under the sentinel")
		}
	})

	t.Run("no declared fix leaves the open range open", func(t *testing.T) {
		// The clamp is evidence-driven. An advisory with no patched
		// release must keep matching every version at or above its
		// lower bound — clamping on absent evidence would be the
		// mirror-image false negative.
		a := Advisory{
			Ecosystem:        "npm",
			Package:          "lodash",
			VulnerableRanges: []VulnerableRange{{Introduced: "0"}},
			AdvisoryID:       "GHSA-open",
			Aliases:          []string{"CVE-2099-0001"},
		}
		if !advisoryAffects(a, "4.17.21") {
			t.Errorf("unfixed advisory must keep matching")
		}
	})

	t.Run("multi-branch advisory clamps only its own branch", func(t *testing.T) {
		// Fixed on the 1.x line, still open on 2.x. The 1.2.3 fix is
		// not above the 2.x range's introduced bound, so 2.x stays
		// affected.
		a := Advisory{
			Ecosystem: "npm", Package: "p",
			VulnerableRanges: []VulnerableRange{
				{Introduced: "0", Fixed: "1.2.3"},
				{Introduced: "2.0.0"},
			},
			FixedVersions: []string{"1.2.3"},
			AdvisoryID:    "GHSA-multi",
		}
		if advisoryAffects(a, "1.2.3") {
			t.Errorf("1.2.3 is the fix on the 1.x branch — must not match")
		}
		if !advisoryAffects(a, "2.5.0") {
			t.Errorf("2.x branch is unfixed — 2.5.0 must still match")
		}
	})
}

// TestLookupEx_UndecidableIsNotClean pins the third state: a range whose
// bound cannot be ordered under the ecosystem's grammar is neither a hit
// (a false positive we would then have to retract) nor a veto (a silent
// false negative that would delete a real finding).
func TestLookupEx_UndecidableIsNotClean(t *testing.T) {
	bundle := gzippedJSON(t, []Advisory{
		{
			Ecosystem: "npm", Package: "p",
			// A git SHA where a version belongs — unorderable.
			VulnerableRanges: []VulnerableRange{{Introduced: "0", Fixed: "3f9c1a5deadbeef"}},
			AdvisoryID:       "GHSA-undecidable",
			Aliases:          []string{"CVE-2024-9001"},
		},
		{
			Ecosystem: "npm", Package: "p",
			VulnerableRanges: []VulnerableRange{{Introduced: "0", Fixed: "1.0.0"}},
			FixedVersions:    []string{"1.0.0"},
			AdvisoryID:       "GHSA-clean",
			Aliases:          []string{"CVE-2024-9002"},
		},
		{
			Ecosystem: "npm", Package: "p",
			VulnerableRanges: []VulnerableRange{{Introduced: "0", Fixed: "3.0.0"}},
			FixedVersions:    []string{"3.0.0"},
			AdvisoryID:       "GHSA-hit",
			Aliases:          []string{"CVE-2024-9003"},
		},
	})
	idx, err := Load(bytes.NewReader(bundle))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	hits, cleared, undecidable := idx.LookupEx("npm", "p", "2.0.0")
	if len(hits) != 1 || hits[0].AdvisoryID != "GHSA-hit" {
		t.Fatalf("hits = %+v, want only GHSA-hit", hits)
	}
	if len(cleared) != 1 || cleared[0].AdvisoryID != "GHSA-clean" {
		t.Fatalf("cleared = %+v, want only GHSA-clean", cleared)
	}
	if len(undecidable) != 1 || undecidable[0].AdvisoryID != "GHSA-undecidable" {
		t.Fatalf("undecidable = %+v, want only GHSA-undecidable", undecidable)
	}
	// The undecidable advisory must NOT appear in cleared — that is the
	// false negative the third state exists to prevent.
	for _, a := range cleared {
		if a.AdvisoryID == "GHSA-undecidable" {
			t.Fatalf("an unparseable range was reported as evaluated-clean")
		}
	}
	// An advisory with no version data at all is DECIDED clean, not
	// undecidable — bundle silence is a shape, not a parse failure.
	quiet := Advisory{Ecosystem: "npm", Package: "p", AdvisoryID: "GHSA-quiet"}
	if affects, undecided := advisoryAffectsEx(quiet, "2.0.0"); affects || undecided {
		t.Fatalf("no-version-data advisory: affects=%v undecidable=%v, want false/false", affects, undecided)
	}
}

// TestCompareVersions_NuGetFourSegment pins FN-2: NuGet's fourth numeric
// segment is significant. Routing it through the SemVer default dropped
// that segment, collapsing "1.2.3.4" and a fix at "1.2.3.5" to the same
// version — query >= fixed — which cleared an advisory that does affect
// the package. A false negative on a security tool.
func TestCompareVersions_NuGetFourSegment(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3.4", "1.2.3.5", -1},
		{"1.2.3.5", "1.2.3.4", 1},
		{"1.2.3.4", "1.2.3.4", 0},
		{"1.2.3", "1.2.3.0", 0},     // trailing zero revision is the same version
		{"1.2.3", "1.2.3.1", -1},    // ...but a non-zero revision is newer
		{"1.2.3.4", "1.2.4", -1},    // patch still outranks revision
		{"2.0.0.0", "10.0.0.0", -1}, // numeric, not lexical
		{"1.0.0-beta", "1.0.0", -1}, // pre-release below release
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-rc.2", "1.0.0-rc.10", -1}, // numeric identifiers compare numerically
	}
	for _, c := range cases {
		got, err := compareVersions("nuget", c.a, c.b)
		if err != nil {
			t.Errorf("compareVersions(nuget, %q, %q): %v", c.a, c.b, err)
			continue
		}
		if got != c.want {
			t.Errorf("compareVersions(nuget, %q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}

	// End-to-end: the advisory shape that used to be silently cleared.
	a := Advisory{
		Ecosystem: "NuGet", Package: "Some.Package",
		VulnerableRanges: []VulnerableRange{{Introduced: "1.2.3.0", Fixed: "1.2.3.5"}},
		FixedVersions:    []string{"1.2.3.5"},
		AdvisoryID:       "GHSA-nuget-4seg",
	}
	if !advisoryAffects(a, "1.2.3.4") {
		t.Errorf("1.2.3.4 is inside [1.2.3.0, 1.2.3.5) — must match")
	}
	if advisoryAffects(a, "1.2.3.5") {
		t.Errorf("1.2.3.5 is the exclusive fix — must NOT match")
	}
}

// TestFlattenRecord_SkipsGitRanges pins the flattener half of the
// lodash 4.17.21 fix: a GIT range must never become a version range.
// The runtime clamp is defence in depth for bundles already built by a
// flattener that lacked this filter.
func TestFlattenRecord_SkipsGitRanges(t *testing.T) {
	rec := osvRecord{
		ID:      "GHSA-35jh-r3h4-6jhm",
		Aliases: []string{"CVE-2021-23337"},
		Affected: []osvAffected{{
			Package: osvPackage{Ecosystem: "npm", Name: "lodash"},
			Ranges: []osvRangeIn{
				{Type: "GIT", Events: []map[string]string{{"introduced": "0"}}},
				{Type: "SEMVER", Events: []map[string]string{{"introduced": "0"}, {"fixed": "4.17.21"}}},
			},
		}},
	}
	advs := flattenRecord(rec)
	if len(advs) != 1 {
		t.Fatalf("flattenRecord: got %d advisories, want 1", len(advs))
	}
	got := advs[0].VulnerableRanges
	if len(got) != 1 || got[0].Introduced != "0" || got[0].Fixed != "4.17.21" {
		t.Fatalf("ranges = %+v, want only the SEMVER [0, 4.17.21)", got)
	}
	if advisoryAffects(advs[0], "4.17.21") {
		t.Errorf("lodash 4.17.21 must be clean of an advisory fixed in 4.17.21")
	}
	if !advisoryAffects(advs[0], "4.17.20") {
		t.Errorf("lodash 4.17.20 must still be affected")
	}

	// A range with no declared type is treated as a version range —
	// our own fixtures and older dumps omit the field.
	untyped := osvRecord{
		ID: "GHSA-untyped",
		Affected: []osvAffected{{
			Package: osvPackage{Ecosystem: "npm", Name: "p"},
			Ranges:  []osvRangeIn{{Events: []map[string]string{{"introduced": "0"}, {"fixed": "2.0.0"}}}},
		}},
	}
	if got := flattenRecord(untyped)[0].VulnerableRanges; len(got) != 1 {
		t.Fatalf("untyped range must be kept, got %+v", got)
	}
}
