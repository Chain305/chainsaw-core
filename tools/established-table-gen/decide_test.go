package main

import (
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
	"github.com/chain305/chainsaw-core/typosquat"
)

var testNow = time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)

// TestAdmitCensusLines: both halves of a line, always — age AND downloads.
func TestAdmitCensusLines(t *testing.T) {
	feed := map[string]map[string]bool{"npm": {"evil": true}}
	for _, c := range []struct {
		name  string
		r     row
		block bool
		want  bool
		why   string
	}{
		// jsonp: on npm since 2012, 419k/week — admitted.
		{"old and busy", row{Name: "jsonp", Weekly: 419_678, First: "2012-07-04", HasData: true}, false, true, ""},
		// has-own: 2 versions, dormant since 2019, 108k/week — admitted; the
		// guard still warns on an unpinned install.
		{"dormant old, 2 versions", row{Name: "has-own", Weekly: 108_008, Versions: 2, First: "2014-07-26", Last: "2019-12-17", HasData: true}, false, true, ""},
		{"pumped young", row{Name: "young", Weekly: 5_000_000, First: "2025-06-01", HasData: true}, false, false, "under 2 years"},
		// as-number: on npm since 2014, 47k/week — under the 100k line, admitted
		// by the old-package line (5+ years AND >= 1k/week).
		{"old, modest traffic", row{Name: "as-number", Weekly: 47_551, First: "2014-09-17", HasData: true}, true, true, ""},
		// Block tier needs 20k: loadash (lodash, 2016, 2 versions, 14.4k/week)
		// and expres (express, 2012, 2.9k/week) are typo-catchers.
		{"block tier, loadash", row{Name: "loadash", Weekly: 14_436, Versions: 2, First: "2016-09-22", Last: "2017-08-12", HasData: true}, true, false, "block tier"},
		{"block tier, expres", row{Name: "expres", Weekly: 2_902, Versions: 5, First: "2012-10-10", Last: "2013-07-16", HasData: true}, true, false, "under 20000"},
		{"block tier at 20k", row{Name: "old-20k", Weekly: 20_000, First: "2014-01-01", HasData: true}, true, true, ""},
		{"5y+ at 1k", row{Name: "old-1k", Weekly: 1_000, First: "2021-10-20", HasData: true}, false, true, ""},
		{"5y+ at 500", row{Name: "old-500", Weekly: 500, First: "2012-01-01", HasData: true}, false, false, "under 1000"},
		{"3y at 50k", row{Name: "mid-50k", Weekly: 50_000, First: "2023-10-01", HasData: true}, false, false, "under 5 years"},
		{"a day under 5y at 99k", row{Name: "almost", Weekly: 99_999, First: "2021-10-23", HasData: true}, false, false, "under 100000"},
		// A squat-shaped dormant name: two versions, last release 2019, 1.2k a
		// week. Admitted as a warn-tier row — the guard still warns on every
		// install but an exact pin of one of its two build-time releases
		// (cli.TestEstablishedOldLineDormantSquatOnlyWarns); refused as block tier.
		{"dormant old 2-version at 1.2k", row{Name: "lodahs", Weekly: 1_200, Versions: 2, First: "2018-03-01", Last: "2019-02-01", HasData: true}, false, true, ""},
		{"same row, block tier", row{Name: "lodahs", Weekly: 1_200, Versions: 2, First: "2018-03-01", Last: "2019-02-01", HasData: true}, true, false, "block tier"},
		{"old placeholder at 1k", row{Name: "http", Weekly: 5_000, First: "2014-01-22", HasData: true, Placeholder: true}, false, false, "placeholder"},
		{"old feed name at 1k", row{Name: "evil", Weekly: 5_000, First: "2015-01-01", HasData: true}, false, false, "known-malicious"},
		{"version count only", row{Name: "create-jst", Weekly: 0, Versions: 300, First: "2020-01-01", HasData: true}, false, false, "downloads/week"},
		{"feed name", row{Name: "evil", Weekly: 900_000, First: "2015-01-01", HasData: true}, false, false, "known-malicious"},
		{"placeholder", row{Name: "http", Weekly: 121_896, First: "2014-01-22", HasData: true, Placeholder: true}, false, false, "placeholder"},
		{"no data", row{Name: "gone", Weekly: 200_000}, false, false, "no registry data"},
		{"unknown age", row{Name: "x", Weekly: 500_000, HasData: true}, false, false, "unknown"},
	} {
		got, why := admitCensus("npm", c.r, c.block, feed, testNow)
		if got != c.want || (!c.want && !strings.Contains(why, c.why)) {
			t.Errorf("%s: admit=%v (%q), want %v containing %q", c.name, got, why, c.want, c.why)
		}
	}
}

// TestMayAdmit: the fetch-skipping prefilter never drops a row admitCensus
// would admit.
func TestMayAdmit(t *testing.T) {
	for _, c := range []struct {
		first  string
		weekly int64
		want   bool
	}{
		{"2014-01-01", 1_000, true},
		{"2014-01-01", 999, false},
		{"2023-10-01", 50_000, false},
		{"2023-10-01", 100_000, true},
		{"2025-01-01", 5_000_000, false},
		{"", 5_000_000, false},
	} {
		if got := mayAdmit(c.first, c.weekly, testNow); got != c.want {
			t.Errorf("mayAdmit(%s, %d) = %v, want %v", c.first, c.weekly, got, c.want)
		}
		admitted, _ := admitCensus("npm", row{Name: "x", Weekly: c.weekly, First: c.first, HasData: true}, false, nil, testNow)
		if admitted && !c.want {
			t.Errorf("mayAdmit(%s, %d) skips a row admitCensus admits", c.first, c.weekly)
		}
	}
}

// TestLinesMatchTheGuard: the census lines are the guard's runtime table
// clear (risk.EstablishedTableClear); a drift admits rows that never clear.
func TestLinesMatchTheGuard(t *testing.T) {
	if weeklyDownloadsLine != risk.EstablishedWeeklyDownloads || oldWeeklyDownloadsLine != risk.EstablishedCensusOldWeeklyDownloads ||
		oldBlockWeeklyDownloadsLine != risk.EstablishedCensusOldBlockWeeklyDownloads || censusOldAge != risk.EstablishedLongLivedPackageAge || censusMinAge != risk.EstablishedMinAge {
		t.Fatal("census admission lines drifted from core/risk")
	}
}

func TestCensusSelfTestPasses(t *testing.T) {
	if !censusSelfTest(testNow) {
		t.Fatal("census self-test failed")
	}
}

// TestNPMPlaceholder: held only when the -security release sorts highest.
func TestNPMPlaceholder(t *testing.T) {
	for _, c := range []struct {
		versions []string
		want     bool
	}{
		{[]string{"0.0.0", "0.0.1-security"}, true},                    // npm:http
		{[]string{"0.0.1-security"}, true},                             // security-only
		{[]string{"0.0.1-security", "1.14.1", "2.8.1"}, false},         // tslib
		{[]string{"0.0.1-security", "0.0.2-security", "3.4.0"}, false}, // mariadb
		{[]string{"1.0.0", "2.0.0"}, false},
	} {
		if got := npmPlaceholder(c.versions); got != c.want {
			t.Errorf("npmPlaceholder(%v) = %v, want %v", c.versions, got, c.want)
		}
	}
}

// TestDropPseudonyms: the second guard behind "public lists only" —
// internal-<8 hex> never survives; a real internal-* name does.
func TestDropPseudonyms(t *testing.T) {
	got := dropEmptyAndPseudonyms("npm", []string{"requests", "internal-138c6f47", "internal-slot", "", "internal-zzzzzzzz"})
	if strings.Join(got, ",") != "requests,internal-slot,internal-zzzzzzzz" {
		t.Fatalf("dropEmptyAndPseudonyms = %v", got)
	}
}

// TestCensusCandidates: a name is a candidate iff the guard's own detector
// flags it at medium or high confidence; the tier says whether that hit can
// block (d=1 of a target within the cutoff) or only warn.
func TestCensusCandidates(t *testing.T) {
	corpus := []typosquat.PopularPackage{{Name: "lodash", Rank: 101}, {Name: "deep-target", Rank: 4000}, {Name: "express-session", Rank: 300}}
	got := censusCandidates("npm", corpus, []string{"lodahs", "lodash", "unrelated-name", "deep-targer", "exprss-sesion", "internal-lodash"})
	tiers := map[string]string{}
	for _, c := range got {
		tiers[c.Name] = c.Tier
	}
	want := map[string]string{"lodahs": "block", "deep-targer": "warn", "exprss-sesion": "warn"}
	if len(tiers) != len(want) {
		t.Fatalf("candidates = %+v, want exactly %v", got, want)
	}
	for n, tier := range want {
		if tiers[n] != tier {
			t.Errorf("%s: tier %q, want %q (all: %+v)", n, tiers[n], tier, got)
		}
	}
}

func TestSortedReleases(t *testing.T) {
	if got := sortedReleases([]string{"1.1.0", "1.0.0", "1.0.0", "", "bad,ver"}); got != "1.0.0,1.1.0" {
		t.Fatalf("sortedReleases = %q", got)
	}
}

func TestCargoIndexPath(t *testing.T) {
	for in, want := range map[string]string{"a": "1/a", "ab": "2/ab", "abc": "3/a/abc", "Serde": "se/rd/serde", "md-5": "md/-5/md-5"} {
		if got := cargoIndexPath(in); got != want {
			t.Errorf("cargoIndexPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestKeepBlockedNeverAdmitted: every reviewed keep-blocked name is refused
// even when it clears a line by a wide margin, under any spelling the
// detector folds to it.
func TestKeepBlockedNeverAdmitted(t *testing.T) {
	if len(keepBlocked["npm"]) == 0 || len(keepBlocked["pypi"]) == 0 {
		t.Fatal("keep-blocked list is empty")
	}
	for eco, names := range keepBlocked {
		for name := range names {
			for _, spelling := range []string{name, strings.ToUpper(name)} {
				for _, block := range []bool{false, true} {
					r := row{Name: spelling, Weekly: 5_000_000, Versions: 300, First: "2010-01-01", HasData: true}
					if ok, why := admitCensus(eco, r, block, nil, testNow); ok || !strings.Contains(why, "kept blocked by review") {
						t.Errorf("%s:%s (block tier %v) admitted (%q)", eco, spelling, block, why)
					}
				}
			}
		}
	}
}
