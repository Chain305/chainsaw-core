package intelligence

// The refresher's skip gate must measure the REPORT's age, not
// package_metadata.updated_at.
//
// It read row.UpdatedAt, justified by a comment asserting "the refresher's own
// Scan writes update both". Measured against production 2026-09-24: **zero
// package_metadata rows were touched in any two-hour window** while ticks ran,
// while scanFederated gates its own cache-first read on the report's
// Observation.CollectedAt. Two clocks. Three consecutive ticks logged
// byte-identical scanned=934 / skipped=1661 / new_versions=626 on three
// different images against ~35 rows actually written in the hour.
//
// Both directions are pinned, because the gate was wrong both ways and only one
// of them merely wastes work.

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestReportIsFresh(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	staleAfter := now.Add(-24 * time.Hour)
	fresh := now.Add(-1 * time.Hour)
	stale := now.Add(-9 * 24 * time.Hour)

	report := func(ts time.Time) *Report {
		r := &Report{}
		r.Observation.CollectedAt = ts
		return r
	}

	cases := []struct {
		name         string
		prior        *Report
		haveStore    bool
		rowUpdatedAt time.Time
		want         bool
		why          string
	}{
		{
			name:  "report fresh, package_metadata stale -> SKIP",
			prior: report(fresh), haveStore: true, rowUpdatedAt: stale, want: true,
			why: "293 production pairs were in this state; each fetched an artifact and ran a Scan " +
				"every tick only to be answered from cache",
		},
		{
			name:  "report stale, package_metadata fresh -> SCAN",
			prior: report(stale), haveStore: true, rowUpdatedAt: fresh, want: false,
			why: "15 production pairs were in this state and were skipped every tick, so they never " +
				"refreshed at all — this is the half that loses data rather than wasting work",
		},
		{
			name:  "no report stored -> SCAN",
			prior: nil, haveStore: true, rowUpdatedAt: fresh, want: false,
			why: "a coordinate with no stored report must be scanned, or it never gets one",
		},
		{
			name:  "no store configured, column fresh -> SKIP",
			prior: nil, haveStore: false, rowUpdatedAt: fresh, want: true,
			why: "with no store there is nothing better to go on; preserves the previous behaviour",
		},
		{
			name:  "no store configured, column stale -> SCAN",
			prior: nil, haveStore: false, rowUpdatedAt: stale, want: false,
			why: "with no store there is nothing better to go on",
		},
		{
			name:  "report exactly at the bound -> SCAN",
			prior: report(staleAfter), haveStore: true, rowUpdatedAt: fresh, want: false,
			why: "After() is strict, so a report exactly at the staleness bound is not fresh",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := reportIsFresh(c.prior, c.haveStore, c.rowUpdatedAt, staleAfter)
			if got != c.want {
				t.Errorf("reportIsFresh = %v, want %v — %s", got, c.want, c.why)
			}
		})
	}
}

// The gate must not read the package_metadata column at all when a store is
// present. If it fell back on a nil prior, the 15 never-refreshing pairs would
// stay broken while looking fixed.
func TestReportIsFreshIgnoresPackageMetadataWhenAStoreIsPresent(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	staleAfter := now.Add(-24 * time.Hour)
	for _, rowTime := range []time.Time{now, now.Add(-1 * time.Hour), now.Add(-100 * 24 * time.Hour)} {
		if reportIsFresh(nil, true, rowTime, staleAfter) {
			t.Errorf("a nil prior with rowUpdatedAt=%v was called fresh; the package_metadata column "+
				"must not decide anything once a store is available", rowTime)
		}
	}
}

// A SOURCE guard on the call site, and labelled as one.
//
// reportIsFresh is pure and fully covered above, and that is not sufficient:
// reverting refreshRow to `row.UpdatedAt.After(staleAfter)` leaves every test
// above green, because a correct helper nobody calls changes nothing. That
// mutation survives the entire package suite without this.
//
// It cannot be caught behaviourally here. RefresherConfig.Store is a concrete
// *Store over a live database, so the branch that consults the stored report
// is unreachable from a unit test — which is precisely why the original bug
// sat in a comment ("the refresher's own Scan writes update both") that was
// false for as long as anyone had looked.
func TestRefreshRowUsesTheReportStalenessGate(t *testing.T) {
	src, err := os.ReadFile("refresher.go")
	if err != nil {
		t.Fatalf("read refresher.go: %v", err)
	}
	text := string(src)

	if !strings.Contains(text, "reportIsFresh(priorReport,") {
		t.Fatal("refreshRow does not call reportIsFresh. Measuring staleness on " +
			"package_metadata.updated_at rescans rows whose report is fresh (293 production pairs, " +
			"each fetching an artifact first) and skips rows whose report is stale (15 pairs, which " +
			"then never refresh at all).")
	}
	if strings.Contains(text, "reportFresh := row.UpdatedAt.After(staleAfter)") {
		t.Error("refreshRow still derives reportFresh straight from the package_metadata column")
	}
}
