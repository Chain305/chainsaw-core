package intelligence

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/intelligence/osv"
	"github.com/chain305/chainsaw-core/metadata"
)

// advisoryFakeService is fakeService plus the optional capability the gate
// looks for. Deliberately a separate type: fakeService does NOT implement
// AdvisoryCorpus, which is what keeps every pre-existing refresher test on the
// dormant path and proves the gate cannot change behaviour where no corpus is
// reachable.
type advisoryFakeService struct {
	*fakeService
	idx *osv.Index
}

func (f *advisoryFakeService) AdvisoryCorpus() *osv.Index { return f.idx }

// loadAdvisories builds a REAL osv.Index from bundle JSON rather than mocking
// the lookup. That is the point of the exercise: the gate must route through
// the production LookupEx and the production canonicalKey, so a test that
// stubbed either would pass while the ecosystem alias mapping or the PEP 503
// fold was broken underneath it.
func loadAdvisories(t *testing.T, body string) *osv.Index {
	t.Helper()
	idx, err := osv.Load(strings.NewReader(body))
	if err != nil {
		t.Fatalf("load advisories: %v", err)
	}
	return idx
}

func advisoryGateRefresher(t *testing.T, idx *osv.Index, maxRows int) *Refresher {
	t.Helper()
	return NewRefresher(RefresherConfig{
		Service:             &advisoryFakeService{fakeService: &fakeService{}, idx: idx},
		Metadata:            &fakeMetadataSource{},
		MaxStaleness:        24 * time.Hour,
		Concurrency:         1,
		PageSize:            10,
		AdvisoryGateMaxRows: maxRows,
	})
}

func advisoryGateRow() metadata.PackageMetadataRow {
	return metadata.PackageMetadataRow{
		OrgID: "org1",
		PackageMetadata: metadata.PackageMetadata{
			Repository: "npmjs",
			Package:    "lodash",
			Version:    "4.17.21",
		},
	}
}

// storedReport is a report that is FRESH — younger than MaxStaleness — which
// is the only population the gate speaks about. collectedAt is relative to the
// index's own load time, because osv.Index stamps loadedAt from the wall clock
// at Load and exposes no seam to set it.
func storedReport(collectedAt time.Time, cves ...string) *Report {
	return &Report{
		Observation:     ObservationSection{CollectedAt: collectedAt},
		Vulnerabilities: VulnSection{CVEs: cves},
	}
}

const lodashAdvisory = `[{
  "ecosystem": "npm",
  "package": "lodash",
  "advisory_id": "GHSA-test-lodash",
  "aliases": ["CVE-2026-0001"],
  "vulnerable_versions": ["4.17.21"],
  "modified": "2026-10-01T00:00:00Z"
}]`

// TestAdvisoryGateOpensOnNewAdvisory is the core behaviour: a fresh report
// that predates the live bundle, and a bundle that asserts a CVE the report
// does not carry, must NOT be skipped.
func TestAdvisoryGateOpensOnNewAdvisory(t *testing.T) {
	t.Parallel()
	idx := loadAdvisories(t, lodashAdvisory)
	ref := advisoryGateRefresher(t, idx, 10)

	prior := storedReport(idx.LoadedAt().Add(-1 * time.Hour))
	if !ref.advisoryGateOpen(advisoryGateRow(), "npm", prior) {
		t.Fatal("gate stayed shut on an advisory the stored report does not carry.\n" +
			"This is the whole intervention: without it the advisory reaches the " +
			"row only when the coordinate is next rescanned for some unrelated " +
			"reason — for a row the primary walk keeps fresh that is the " +
			"stale-report sweep's cycle, measured at ~2.6 days across the " +
			"production corpus.")
	}
}

// TestAdvisoryGateClosedWhenReportPostdatesBundle pins the convergence bound.
//
// Without it the gate is not convergent: a CVE the corpus asserts and the
// merge vetoes (provider_osv's ClearedCVEs, or a sibling provider's) would
// never appear in the stored section, so the gate would re-open on every tick
// for that coordinate, forever. That is the v0.22.14 defect shape — ~27 Scans
// per real refresh because the two ends of a gate measured different things.
func TestAdvisoryGateClosedWhenReportPostdatesBundle(t *testing.T) {
	t.Parallel()
	idx := loadAdvisories(t, lodashAdvisory)
	ref := advisoryGateRefresher(t, idx, 10)

	// Collected AFTER the bundle loaded: OSV already had its say on this row,
	// so a hit it still lacks is a veto and rescanning cannot change it.
	prior := storedReport(idx.LoadedAt().Add(1 * time.Hour))
	if ref.advisoryGateOpen(advisoryGateRow(), "npm", prior) {
		t.Fatal("gate opened for a report collected AFTER the bundle loaded.\n" +
			"The gate is now unbounded: a vetoed CVE re-opens it every tick for " +
			"this coordinate and the forced rescan changes nothing, which is an " +
			"infinite rescan loop that every other test in this file would pass.")
	}
}

// TestAdvisoryGateIgnoresCVEsAbsentFromCorpus pins the one-directionality.
//
// The stored section is a cross-provider merge, so a Trivy-only finding is
// indistinguishable from a retracted OSV one at this layer. Firing on "the
// report carries a CVE the corpus does not" would rescan every Trivy-covered
// row on every tick.
func TestAdvisoryGateIgnoresCVEsAbsentFromCorpus(t *testing.T) {
	t.Parallel()
	// Empty corpus for this ecosystem's package: the bundle covers npm but
	// not this coordinate's advisories.
	idx := loadAdvisories(t, `[{
	  "ecosystem": "npm",
	  "package": "some-other-package",
	  "advisory_id": "GHSA-test-other",
	  "vulnerable_versions": ["1.0.0"]
	}]`)
	ref := advisoryGateRefresher(t, idx, 10)

	// The report carries a CVE no advisory in the corpus asserts — exactly
	// what a Trivy-sourced finding looks like from here.
	prior := storedReport(idx.LoadedAt().Add(-1*time.Hour), "CVE-2020-8203")
	if ref.advisoryGateOpen(advisoryGateRow(), "npm", prior) {
		t.Fatal("gate opened on a CVE the corpus does not assert.\n" +
			"Every row covered by the Trivy-backed cveProvider now forces a " +
			"rescan on every tick, because its findings are not in the OSV " +
			"bundle and never will be.")
	}
}

// TestAdvisoryGateMatchesStoredCVEByFold pins that a hit the report ALREADY
// carries does not re-open the gate. The two sides must fold identically —
// DiffReports uses ToUpper(TrimSpace(..)) and so must this.
func TestAdvisoryGateMatchesStoredCVEByFold(t *testing.T) {
	t.Parallel()
	idx := loadAdvisories(t, lodashAdvisory)
	ref := advisoryGateRefresher(t, idx, 10)

	// Same CVE as lodashAdvisory's alias, differently cased and padded.
	prior := storedReport(idx.LoadedAt().Add(-1*time.Hour), "  cve-2026-0001 ")
	if ref.advisoryGateOpen(advisoryGateRow(), "npm", prior) {
		t.Fatal("gate opened for a CVE the stored report already carries.\n" +
			"The two sides of the comparison fold differently, so every row " +
			"whose CVE id differs only in case or whitespace rescans forever.")
	}
}

// TestAdvisoryGateFoldsPyPIPackageNames pins requirement that the lookup
// routes through canonicalKey rather than a hand-rolled match.
//
// PEP 503 collapses runs of [-_.] to a single '-' AND lowercases, so
// `zope.interface` and `zope_interface` are the same package. A second
// normalisation in the gate — or none — silently misses every PyPI row, which
// is the exact defect Phase 11 §6b already fixed once at canonicalKey. The
// test asserts the gate inherits the fold instead of re-deriving it.
func TestAdvisoryGateFoldsPyPIPackageNames(t *testing.T) {
	t.Parallel()
	idx := loadAdvisories(t, `[{
	  "ecosystem": "PyPI",
	  "package": "zope_interface",
	  "advisory_id": "GHSA-test-zope",
	  "aliases": ["CVE-2026-0002"],
	  "vulnerable_versions": ["5.4.0"]
	}]`)
	ref := advisoryGateRefresher(t, idx, 10)

	row := metadata.PackageMetadataRow{
		OrgID: "org1",
		PackageMetadata: metadata.PackageMetadata{
			Repository: "pypi",
			// Dotted spelling; the advisory is keyed with an underscore.
			Package: "zope.interface",
			Version: "5.4.0",
		},
	}
	// "pip" rather than "pypi" on purpose: CanonicalEcosystem maps the
	// caller-facing alias the proxy resolver emits, and the gate must inherit
	// that mapping too.
	prior := storedReport(idx.LoadedAt().Add(-1 * time.Hour))
	if !ref.advisoryGateOpen(row, "pip", prior) {
		t.Fatal("gate missed a PyPI advisory keyed under a different separator " +
			"spelling, or did not resolve the 'pip' ecosystem alias.\n" +
			"The gate is no longer routing through osv.canonicalKey, so PyPI " +
			"rows — and any row whose ecosystem arrives under an alias — are " +
			"invisible to it while every other test here passes.")
	}
}

// TestAdvisoryGateRespectsPerTickBudget pins the row budget. A bundle swap
// that lands an advisory on a widely-depended-upon package must not turn one
// 6-hourly swap into a scan of every affected row at once.
func TestAdvisoryGateRespectsPerTickBudget(t *testing.T) {
	t.Parallel()
	idx := loadAdvisories(t, lodashAdvisory)
	ref := advisoryGateRefresher(t, idx, 1)

	row := advisoryGateRow()
	prior := storedReport(idx.LoadedAt().Add(-1 * time.Hour))

	if !ref.advisoryGateOpen(row, "npm", prior) {
		t.Fatal("first call should open the gate and spend the single budget unit")
	}
	if ref.advisoryGateOpen(row, "npm", prior) {
		t.Fatal("gate opened past its per-tick budget of 1.\n" +
			"A popular advisory can now force a scan of every stored row that " +
			"depends on the package in a single tick, which is the unbounded " +
			"write storm the budget exists to prevent.")
	}

	// And the budget is per-TICK, not per-process: RunOnce resets it, or the
	// gate shuts permanently after the first busy tick.
	ref.advisoryForced.Store(0)
	if !ref.advisoryGateOpen(row, "npm", prior) {
		t.Fatal("gate did not reopen after the per-tick counter was reset")
	}
}

// TestAdvisoryGateDormantWithoutCorpus pins the degradation contract: a
// Service that cannot answer leaves the walk behaving exactly as it did before
// this file existed. Covers the airgapped / dormant-bundle / trimmed-build
// cases, and the plain fakeService that every other test in this package uses.
func TestAdvisoryGateDormantWithoutCorpus(t *testing.T) {
	t.Parallel()
	prior := storedReport(time.Now().Add(-1 * time.Hour))
	row := advisoryGateRow()

	// No AdvisoryCorpus method at all.
	plain := NewRefresher(RefresherConfig{
		Service: &fakeService{}, Metadata: &fakeMetadataSource{},
		MaxStaleness: 24 * time.Hour, Concurrency: 1, PageSize: 10,
	})
	if plain.advisoryGateOpen(row, "npm", prior) {
		t.Fatal("gate opened against a Service with no advisory corpus")
	}

	// Method present, nil index (bundle absent or unreadable).
	nilIdx := advisoryGateRefresher(t, nil, 10)
	if nilIdx.advisoryGateOpen(row, "npm", prior) {
		t.Fatal("gate opened against a nil index — a dormant bundle must never " +
			"force work, only decline to claim coverage")
	}

	// Explicitly disabled.
	off := NewRefresher(RefresherConfig{
		Service: &advisoryFakeService{
			fakeService: &fakeService{},
			idx:         loadAdvisories(t, lodashAdvisory),
		},
		Metadata: &fakeMetadataSource{}, MaxStaleness: 24 * time.Hour,
		Concurrency: 1, PageSize: 10, AdvisoryGateDisabled: true,
	})
	if off.advisoryGateOpen(row, "npm", storedReport(time.Now().Add(-1*time.Hour))) {
		t.Fatal("AdvisoryGateDisabled did not turn the gate off")
	}
}

// TestAdvisoryGateIgnoresNilPriorReport — the gate only ever speaks about rows
// that were about to be SKIPPED, and a row with no stored report is already a
// row the walk scans. Firing here would double-count it against the budget.
func TestAdvisoryGateIgnoresNilPriorReport(t *testing.T) {
	t.Parallel()
	ref := advisoryGateRefresher(t, loadAdvisories(t, lodashAdvisory), 10)
	if ref.advisoryGateOpen(advisoryGateRow(), "npm", nil) {
		t.Fatal("gate opened with no prior report; that row scans anyway and " +
			"would spend budget a genuinely-skipped row needs")
	}
}

// TestAdvisoryRefreshStalenessForcesFanout guards a fail-SILENT.
//
// scanFederated substitutes DefaultMaxStaleness whenever req.Options.
// MaxStaleness <= 0. The gate only ever fires on a row whose report is FRESH —
// that freshness is why the walk was about to skip it — so a zero here means
// Scan's cache-first read serves the cached report and the forced refresh is a
// no-op that still consumed a tick, a budget unit and a log line claiming it
// worked. Nothing else in this package would go red.
func TestAdvisoryRefreshStalenessForcesFanout(t *testing.T) {
	t.Parallel()
	if advisoryRefreshStaleness <= 0 {
		t.Fatalf("advisoryRefreshStaleness is %v; scanFederated replaces any "+
			"value <= 0 with DefaultMaxStaleness (%v), so every advisory-forced "+
			"Scan would be answered from the cache it is meant to replace",
			advisoryRefreshStaleness, DefaultMaxStaleness)
	}
	if advisoryRefreshStaleness >= time.Second {
		t.Fatalf("advisoryRefreshStaleness is %v; it must be shorter than any "+
			"report age the gate can see, or a just-written row escapes the "+
			"forced fan-out", advisoryRefreshStaleness)
	}
}

// TestDefaultServiceExposesAdvisoryCorpus is half of the dead-code guard.
//
// The gate reaches the index through an optional capability on the configured
// Service. If *DefaultService stops satisfying it — a rename, a move to a
// different receiver, a signature change — the assertion fails at RUNTIME,
// silently, and the gate goes dormant in production while every behavioural
// test above keeps passing because they inject their own implementation.
func TestDefaultServiceExposesAdvisoryCorpus(t *testing.T) {
	t.Parallel()
	var svc Service = &DefaultService{}
	if _, ok := svc.(advisoryCorpusProvider); !ok {
		t.Fatal("*DefaultService no longer satisfies advisoryCorpusProvider.\n" +
			"The advisory gate resolves the live OSV index through this " +
			"assertion and fails CLOSED when it does not hold, so the gate is " +
			"now dormant in production. Nothing else goes red.")
	}
	// A nil-provider service answers nil rather than panicking: Bootstrap can
	// produce a provider list with no osvProvider (offline builds).
	if got := (&DefaultService{}).AdvisoryCorpus(); got != nil {
		t.Fatalf("AdvisoryCorpus on a provider-less service = %v, want nil", got)
	}
}

// TestAdvisoryGateIsConsultedAtBothSkipSites is the other half of the dead-code
// guard, and the more important one.
//
// refreshRow has TWO skip returns, and the second is not the rare path: it is
// the one a row with a newer version upstream takes, which in production was
// 626 of the 934 rows the walk touched each hour. A gate wired into only the
// first leaks the majority of the population, and no behavioural test in this
// package can see that — priorReport is loaded through RefresherConfig.Store,
// a concrete *Store over a live database, so refreshRow cannot be driven to a
// non-nil prior report without one. Written as a source assertion for the same
// reason TestRecomputeSweepIsCalledFromRunOnce is: the failure being guarded
// is a deletion.
//
// Stated limit: this checks that both sites CALL the gate and that neither
// returns actionSkipped unconditionally. It cannot check that the forced path
// reaches the alerter — see the assertion on the Scan/alerter ordering below
// for the part of that it can reach.
func TestAdvisoryGateIsConsultedAtBothSkipSites(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile(filepath.Clean("refresher.go"))
	if err != nil {
		t.Fatalf("read refresher.go: %v", err)
	}
	text := string(src)

	start := strings.Index(text, "func (r *Refresher) refreshRow(ctx context.Context, row metadata.PackageMetadataRow) refreshAction {")
	if start < 0 {
		t.Fatal("refreshRow is no longer declared in refresher.go with the " +
			"expected signature — re-point this guard at wherever the per-row " +
			"decision now lives, and confirm BOTH skip sites still consult the " +
			"advisory gate")
	}
	body := text[start:]
	if next := regexp.MustCompile(`\nfunc `).FindStringIndex(body[1:]); next != nil {
		body = body[:next[0]+1]
	}

	// Every skip return in refreshRow must be gated. Count both sides rather
	// than asserting a single call: the point of the guard is that NEITHER
	// site is left ungated, so the two numbers have to agree.
	skips := strings.Count(body, "return actionSkipped")
	gates := strings.Count(body, "r.advisoryGateOpen(row, ecosystem, priorReport)")
	if gates != skips {
		t.Fatalf("refreshRow has %d `return actionSkipped` sites and %d "+
			"advisory-gate calls.\n"+
			"Every skip has to consult the gate. The second site is the one a "+
			"row with a newer version upstream takes — 626 of the 934 rows the "+
			"production walk touched per hour — so a gate on only the first "+
			"leaks the majority of the population while every behavioural test "+
			"in this file still passes.", skips, gates)
	}
	if skips == 0 {
		t.Fatal("refreshRow no longer skips any row; this guard is measuring " +
			"nothing. Re-point it at the new skip mechanism.")
	}

	// The forced path must FALL THROUGH to the Scan, not return. If it
	// returned, the row would be neither skipped nor refreshed and the
	// alerter — the only path to a recall.alert row — would never run.
	// Counted, not merely present. A `strings.Contains` here PASSES on the
	// real bug: replacing one site's `forcedByAdvisory = true` with a bare
	// `return` leaves the other site's assignment in the file, so the
	// substring is still found while that path silently stops refreshing and
	// stops alerting. Proven: that mutation passed the Contains form of this
	// assertion. Every gate call must be paired with a fall-through.
	forced := strings.Count(body, "forcedByAdvisory = true")
	if forced != gates {
		t.Fatalf("refreshRow has %d advisory-gate calls but %d "+
			"`forcedByAdvisory = true` assignments.\n"+
			"Every open gate must FALL THROUGH to the Scan below. A branch that "+
			"returns instead refreshes nothing and dispatches nothing, while "+
			"reporting the row as handled — rows silently fresher and nobody "+
			"told, which is the outcome this item exists to avoid.", gates, forced)
	}
	if !strings.Contains(body, "req.Options.MaxStaleness = advisoryRefreshStaleness") {
		t.Fatal("the advisory-forced Scan no longer overrides MaxStaleness.\n" +
			"The row is fresh by construction, so Scan's cache-first read will " +
			"answer from the cache and the forced refresh becomes a no-op that " +
			"still spends a budget unit and logs success.")
	}
	if !strings.Contains(body, "r.alerter.OnRefreshedReport(ctx, row, ecosystem, priorReport, nextReport)") {
		t.Fatal("refreshRow no longer calls the alerter.\n" +
			"DiffReports and DiffSupplyChain are reachable from nowhere else, " +
			"so the gate would make rows silently fresher and notify no one — " +
			"the worst available outcome for this change.")
	}
}
