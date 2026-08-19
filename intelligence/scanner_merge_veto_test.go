package intelligence

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/intelligence/osv"
)

// These tests pin the veto channel on mergeVulns. Before it existed the
// merge could only ADD, so a false positive from any vulnerability
// source was permanent — and because intelligence_reports is keyed by
// (ecosystem, package, version) with no org column, permanent AND
// global. The measured case was lodash 4.17.21 carrying CVE-2021-23337,
// an advisory fixed in 4.17.21.
//
// The invariant under test is a distinction, not a mechanism:
// "I evaluated and say no" clears; "I have nothing to say" does not.

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// newOSVTestBundle builds the advisory set these tests reason about.
// Plain JSON (Load auto-detects gzip vs. raw), so the fixture stays
// readable in the diff.
//
//   - lodash: one advisory fixed in 4.17.21 alongside one that is live
//     at 4.17.21 and shares no id with it, plus a THIRD record that
//     reuses CVE-2026-4800 but is already fixed — the "same id via
//     several advisories" case the veto must not trip on.
//   - murky: a range bounded by a git SHA, which no ecosystem
//     comparator can order.
func newOSVTestBundle(t *testing.T) *bytes.Reader {
	t.Helper()
	advs := []osv.Advisory{
		{
			Ecosystem: "npm", Package: "lodash",
			VulnerableRanges: []osv.VulnerableRange{{Introduced: "0", Fixed: "4.17.21"}},
			FixedVersions:    []string{"4.17.21"},
			AdvisoryID:       "GHSA-35jh-r3h4-6jhm",
			Aliases:          []string{"CVE-2021-23337"},
			CVSSScore:        7.2,
		},
		{
			Ecosystem: "npm", Package: "lodash",
			VulnerableRanges: []osv.VulnerableRange{{Introduced: "4.17.0", Fixed: "4.17.23"}},
			FixedVersions:    []string{"4.17.23"},
			AdvisoryID:       "GHSA-live-2026",
			Aliases:          []string{"CVE-2026-4800"},
			CVSSScore:        8.1,
		},
		{
			Ecosystem: "npm", Package: "lodash",
			VulnerableRanges: []osv.VulnerableRange{{Introduced: "0", Fixed: "4.17.10"}},
			FixedVersions:    []string{"4.17.10"},
			AdvisoryID:       "GHSA-dup-id",
			Aliases:          []string{"CVE-2026-4800"},
			CVSSScore:        8.1,
		},
		{
			Ecosystem: "npm", Package: "murky",
			VulnerableRanges: []osv.VulnerableRange{{Introduced: "0", Fixed: "3f9c1a5deadbeef"}},
			AdvisoryID:       "GHSA-undecidable",
			Aliases:          []string{"CVE-2024-9001"},
		},
	}
	raw, err := json.Marshal(advs)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	return bytes.NewReader(raw)
}

func TestMergeVulns_VetoRemovesAFalsePositive(t *testing.T) {
	dst := VulnSection{
		IsVulnerable: true,
		CVSSScore:    7.2,
		CVEs:         []string{"CVE-2021-23337", "CVE-2026-4800"},
		CVEDetails: []CVEDetail{
			{CVE: "CVE-2021-23337", CVSS: 7.2},
			{CVE: "CVE-2026-4800", CVSS: 5.3},
		},
	}
	// A source that range-evaluated lodash 4.17.21 and concluded the
	// 2021 advisory does not apply.
	mergeVulns(&dst, VulnSection{ClearedCVEs: []string{"CVE-2021-23337"}})

	if got := sortedCopy(dst.CVEs); !reflect.DeepEqual(got, []string{"CVE-2026-4800"}) {
		t.Fatalf("CVEs = %v, want the vetoed id removed", got)
	}
	if len(dst.CVEDetails) != 1 || dst.CVEDetails[0].CVE != "CVE-2026-4800" {
		t.Fatalf("CVEDetails = %+v, want only CVE-2026-4800", dst.CVEDetails)
	}
	if !dst.IsVulnerable {
		t.Errorf("a real CVE survives — IsVulnerable must stay true")
	}
}

// The score is the field the policy engine and the max_cvss column
// actually read. Dropping the CVE that WAS the max must lower it;
// leaving it stale would keep the package quarantined for a finding
// that no longer exists.
func TestMergeVulns_VetoRecomputesScore(t *testing.T) {
	dst := VulnSection{
		IsVulnerable: true,
		CVSSScore:    9.8,
		EPSSScore:    0.42,
		CVEs:         []string{"CVE-A", "CVE-B"},
		CVEDetails: []CVEDetail{
			{CVE: "CVE-A", CVSS: 9.8},
			{CVE: "CVE-B", CVSS: 4.1},
		},
	}
	mergeVulns(&dst, VulnSection{ClearedCVEs: []string{"CVE-A"}})

	if dst.CVSSScore != 4.1 {
		t.Fatalf("CVSSScore = %v, want 4.1 (the max after the veto)", dst.CVSSScore)
	}

	t.Run("last CVE vetoed clears every rollup", func(t *testing.T) {
		scanned := time.Now().UTC()
		d := VulnSection{
			IsVulnerable:    true,
			CVSSScore:       9.8,
			EPSSScore:       0.42,
			KnownExploited:  true,
			ScannedAt:       &scanned,
			ScannerDBDigest: "osv-bundle",
			CVEs:            []string{"CVE-A"},
			CVEDetails:      []CVEDetail{{CVE: "CVE-A", CVSS: 9.8}},
			KEVEntries:      []KEVEntry{{CVE: "CVE-A"}},
		}
		mergeVulns(&d, VulnSection{ClearedCVEs: []string{"CVE-A"}})

		if d.IsVulnerable || d.CVSSScore != 0 || d.EPSSScore != 0 || d.KnownExploited {
			t.Fatalf("rollups not cleared: %+v", d)
		}
		// ScannedAt / digest must survive: the scan DID run. Clearing
		// them would flip VulnDataAvailable false and read as "no
		// vulnerability coverage", which the opt-in fail-closed
		// coverage gate turns into refused installs.
		if d.ScannedAt == nil || d.ScannerDBDigest == "" {
			t.Fatalf("scan provenance must survive a full veto: %+v", d)
		}
	})

	t.Run("partial per-CVE score coverage does not zero the aggregate", func(t *testing.T) {
		// The Trivy-backed path carries no per-CVE score, so the max
		// over what we know is not the max over what exists. Lowering
		// to it would under-report severity on a package that still
		// has CVEs.
		d := VulnSection{
			IsVulnerable: true,
			CVSSScore:    9.8,
			CVEs:         []string{"CVE-A", "CVE-B"},
			CVEDetails: []CVEDetail{
				{CVE: "CVE-A", CVSS: 9.8},
				{CVE: "CVE-B"}, // no score
			},
		}
		mergeVulns(&d, VulnSection{ClearedCVEs: []string{"CVE-A"}})
		if d.CVSSScore != 9.8 {
			t.Fatalf("CVSSScore = %v, want the prior aggregate held at 9.8", d.CVSSScore)
		}
	})
}

// KEVEntries are derived from the CVE list by kevProvider. A vetoed id
// surviving there would resurrect KnownExploited — the highest-weight
// vulnerability signal in the risk engine — for a CVE we just
// established does not apply.
func TestMergeVulns_VetoDropsKEVEntries(t *testing.T) {
	dst := VulnSection{
		IsVulnerable:   true,
		KnownExploited: true,
		CVEs:           []string{"CVE-A", "CVE-B"},
		CVEDetails:     []CVEDetail{{CVE: "CVE-A", CVSS: 9.8}, {CVE: "CVE-B", CVSS: 6.0}},
		KEVEntries:     []KEVEntry{{CVE: "CVE-A", DateAdded: "2024-01-01"}},
	}
	mergeVulns(&dst, VulnSection{ClearedCVEs: []string{"CVE-A"}})

	if len(dst.KEVEntries) != 0 {
		t.Fatalf("KEVEntries = %+v, want the vetoed entry dropped", dst.KEVEntries)
	}
	if dst.KnownExploited {
		t.Errorf("KnownExploited must fall with its last KEV entry")
	}
}

// Silence is the common case: almost every provider writes a
// PartialReport that says nothing about CVEs. If an empty list were read
// as an exclusion, a registry-metadata tick would delete every real
// finding.
func TestMergeVulns_SilenceIsNotAVeto(t *testing.T) {
	scanned := time.Now().UTC()
	dst := VulnSection{
		IsVulnerable: true,
		CVSSScore:    7.2,
		CVEs:         []string{"CVE-2026-4800"},
		CVEDetails:   []CVEDetail{{CVE: "CVE-2026-4800", CVSS: 7.2}},
	}
	// A contributor with nothing to say about vulnerabilities.
	mergeVulns(&dst, VulnSection{})
	// A contributor that scanned and found nothing, but evaluated
	// nothing either (nil ClearedCVEs) — e.g. an empty Trivy row.
	mergeVulns(&dst, VulnSection{ScannedAt: &scanned})

	if len(dst.CVEs) != 1 || dst.CVEs[0] != "CVE-2026-4800" {
		t.Fatalf("CVEs = %v, want the real finding preserved", dst.CVEs)
	}
	if dst.CVSSScore != 7.2 || !dst.IsVulnerable {
		t.Fatalf("aggregates disturbed by silence: %+v", dst)
	}
}

// The Tier-1 fan-out merges partials in non-deterministic order, so the
// verdict must not depend on whether the veto arrives before or after
// the assertion it withdraws.
func TestMergeVulns_VetoIsOrderIndependent(t *testing.T) {
	assertion := VulnSection{
		IsVulnerable: true,
		CVSSScore:    9.1,
		CVEs:         []string{"CVE-2021-23337"},
		CVEDetails:   []CVEDetail{{CVE: "CVE-2021-23337", CVSS: 9.1}},
	}
	veto := VulnSection{ClearedCVEs: []string{"CVE-2021-23337"}}

	t.Run("veto last", func(t *testing.T) {
		var dst VulnSection
		mergeVulns(&dst, assertion)
		mergeVulns(&dst, veto)
		if len(dst.CVEs) != 0 {
			t.Fatalf("CVEs = %v, want empty", dst.CVEs)
		}
	})
	t.Run("veto first", func(t *testing.T) {
		var dst VulnSection
		mergeVulns(&dst, veto)
		mergeVulns(&dst, assertion)
		if len(dst.CVEs) != 0 {
			t.Fatalf("CVEs = %v, want empty — a veto must survive a later assertion", dst.CVEs)
		}
		if dst.IsVulnerable {
			t.Errorf("IsVulnerable must not be left set by the withdrawn assertion")
		}
	})
}

// A CVE can arrive via several advisory records for the same package.
// One record evaluating clean must not cancel a dirty sibling — which
// is why the producer subtracts its own hits before publishing a veto.
func TestOSVProvider_VetoExcludesItsOwnHits(t *testing.T) {
	idx, err := osv.Load(newOSVTestBundle(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := &osvProvider{idx: idx}
	out, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Vulns == nil {
		t.Fatal("covered package must produce a non-nil VulnSection")
	}
	// CVE-2021-23337 is fixed in 4.17.21 → vetoed.
	if !contains(out.Vulns.ClearedCVEs, "CVE-2021-23337") {
		t.Errorf("ClearedCVEs = %v, want the fixed advisory vetoed", out.Vulns.ClearedCVEs)
	}
	// CVE-2026-4800 genuinely affects 4.17.21 → a hit, never a veto,
	// even though a second, already-fixed advisory shares the id.
	if !contains(out.Vulns.CVEs, "CVE-2026-4800") {
		t.Errorf("CVEs = %v, want the live advisory reported", out.Vulns.CVEs)
	}
	if contains(out.Vulns.ClearedCVEs, "CVE-2026-4800") {
		t.Errorf("an id that matched another advisory must not be vetoed: %v", out.Vulns.ClearedCVEs)
	}

	// End-to-end: the veto retracts a stuck false positive that a
	// previous, buggy bundle already persisted into the universal row.
	stuck := VulnSection{
		IsVulnerable: true,
		CVSSScore:    7.2,
		CVEs:         []string{"CVE-2021-23337"},
		CVEDetails:   []CVEDetail{{CVE: "CVE-2021-23337", CVSS: 7.2}},
	}
	mergeVulns(&stuck, *out.Vulns)
	if contains(stuck.CVEs, "CVE-2021-23337") {
		t.Fatalf("stuck false positive survived the merge: %v", stuck.CVEs)
	}
	if !contains(stuck.CVEs, "CVE-2026-4800") {
		t.Fatalf("real finding lost: %v", stuck.CVEs)
	}
}

// A dormant index and an uncovered package have evaluated nothing, so
// they must stay silent on ClearedCVEs.
func TestOSVProvider_NoVetoWithoutEvaluation(t *testing.T) {
	t.Run("dormant index", func(t *testing.T) {
		p := &osvProvider{}
		out, err := p.Run(context.Background(), Request{
			Key: Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
		}, nil)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if out.Vulns != nil {
			t.Fatalf("dormant provider must not touch Vulns: %+v", out.Vulns)
		}
	})
	t.Run("package not covered", func(t *testing.T) {
		idx, err := osv.Load(newOSVTestBundle(t))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		p := &osvProvider{idx: idx}
		out, err := p.Run(context.Background(), Request{
			Key: Key{Ecosystem: "npm", Package: "not-in-bundle", Version: "1.0.0"},
		}, nil)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if out.Vulns != nil {
			t.Fatalf("uncovered package must not veto: %+v", out.Vulns)
		}
	})
}

// An advisory whose range cannot be ordered is surfaced as a warning and
// appears in neither the hit list nor the veto list.
func TestOSVProvider_UndecidableWarnsWithoutVerdict(t *testing.T) {
	idx, err := osv.Load(newOSVTestBundle(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := &osvProvider{idx: idx}
	out, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "murky", Version: "2.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Vulns == nil {
		t.Fatal("covered package must produce a non-nil VulnSection")
	}
	if contains(out.Vulns.CVEs, "CVE-2024-9001") {
		t.Errorf("an unparseable range must not be counted as a hit")
	}
	if contains(out.Vulns.ClearedCVEs, "CVE-2024-9001") {
		t.Errorf("an unparseable range must not be counted as a veto")
	}
	var found bool
	for _, w := range out.Warnings {
		if w.Code == WarnVulnRangeUndecidable {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %+v, want a %s entry", out.Warnings, WarnVulnRangeUndecidable)
	}
}

func containsCVE(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
