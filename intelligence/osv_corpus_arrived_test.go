package intelligence

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/intelligence/osv"
)

// 2026-10-05 Feldera Cargo.lock: the live OSV index lost crates.io for a
// refresher tick, 1,220 cargo rows were stored with osv_bundle_dormant and
// scored allow/100 (rsa@0.9.10, RUSTSEC-2023-0071), and nothing re-matched
// them when the corpus came back — they served the gap verdict for ~38h.

func swapInOSVCorpus(t *testing.T, ecosystems ...string) {
	t.Helper()
	var advs []osv.Advisory
	for _, eco := range ecosystems {
		advs = append(advs, osv.Advisory{
			Ecosystem: eco, Package: "rsa", AdvisoryID: "RUSTSEC-2023-0071",
			VulnerableRanges: []osv.VulnerableRange{{Introduced: "0"}},
		})
	}
	raw, err := json.Marshal(advs)
	if err != nil {
		t.Fatal(err)
	}
	idx, err := osv.Load(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	(&osvProvider{logger: slog.Default()}).SwapIndex(idx)
}

func resetOSVCorpus(t *testing.T) {
	liveOSVCorpus.Store(nil)
	t.Cleanup(func() { liveOSVCorpus.Store(nil) })
}

func dormantCargoReport(at time.Time) *Report {
	r := &Report{Identity: IdentitySection{Ecosystem: "cargo", Package: "rsa", Version: "0.9.10"}}
	r.Observation.CollectedAt = at
	r.Observation.Warnings = []Warning{{Provider: "osv", Code: warnOSVBundleDormant}}
	return r
}

// A row stored while the index had no corpus for its ecosystem is due the
// moment the live index covers that ecosystem — on every read path: Scan's
// cache-first read (freshFor) and Store.Get readers such as the lockfile
// scan's AggregateCached (RetryDue).
func TestDormantOSVRowIsDueOnceCorpusArrives(t *testing.T) {
	resetOSVCorpus(t)
	gap := time.Now().Add(-time.Hour)
	rep := dormantCargoReport(gap)
	swapInOSVCorpus(t, "crates.io")

	if !rep.RetryDue(time.Now()) {
		t.Fatal("a dormant cargo row must be retry-due once the live index covers cargo")
	}
	if got := rep.freshFor(DefaultMaxStaleness); got != 0 {
		t.Fatalf("freshFor = %v, want 0 so Scan's cache-first read rescans", got)
	}
}

// Airgapped / no bundle ever, or a bundle that never carries the ecosystem:
// the warning is the truth, so the row settles at the normal window instead
// of rescanning on every read.
func TestDormantOSVRowWithNoCorpusDoesNotChurn(t *testing.T) {
	resetOSVCorpus(t)
	rep := dormantCargoReport(time.Now().Add(-time.Hour))
	if rep.RetryDue(time.Now()) || rep.freshFor(DefaultMaxStaleness) != DefaultMaxStaleness {
		t.Fatal("no live index: a dormant row must not be retry-due")
	}
	swapInOSVCorpus(t, "npm")
	if rep.RetryDue(time.Now()) || rep.freshFor(DefaultMaxStaleness) != DefaultMaxStaleness {
		t.Fatal("live index without cargo: a dormant cargo row must not be retry-due")
	}
}

// A row scanned AFTER the covering corpus was published and still dormant
// was not produced by the gap; treating it as due would rescan on every read.
// So would a row that never carried the warning.
func TestOSVCorpusArrivalIsBoundedToRowsFromTheGap(t *testing.T) {
	resetOSVCorpus(t)
	swapInOSVCorpus(t, "crates.io")
	after := dormantCargoReport(time.Now().Add(time.Second))
	if after.RetryDue(time.Now().Add(time.Minute)) {
		t.Fatal("a dormant row collected after the corpus was published must not loop")
	}
	clean := dormantCargoReport(time.Now().Add(-time.Hour))
	clean.Observation.Warnings = nil
	if clean.RetryDue(time.Now()) {
		t.Fatal("a row with an OSV answer is not affected")
	}
}
