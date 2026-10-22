package main

import (
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/typosquat"
)

var testNow = time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)

// TestAdmitCensusLines: both halves, always — age AND downloads.
func TestAdmitCensusLines(t *testing.T) {
	feed := map[string]map[string]bool{"npm": {"evil": true}}
	for _, c := range []struct {
		name string
		r    row
		want bool
		why  string
	}{
		// jsonp: on npm since 2012, 419k/week — admitted.
		{"old and busy", row{Name: "jsonp", Weekly: 419_678, First: "2012-07-04", HasData: true}, true, ""},
		// has-own: 2 versions, dormant since 2019, 108k/week — admitted; the
		// guard still warns on an unpinned install.
		{"dormant old, 2 versions", row{Name: "has-own", Weekly: 108_008, Versions: 2, First: "2014-07-26", Last: "2019-12-17", HasData: true}, true, ""},
		{"pumped young", row{Name: "young", Weekly: 5_000_000, First: "2025-06-01", HasData: true}, false, "under 2 years"},
		{"old but quiet", row{Name: "as-number", Weekly: 47_551, First: "2014-09-17", HasData: true}, false, "downloads/week"},
		{"version count only", row{Name: "create-jst", Weekly: 0, Versions: 300, First: "2020-01-01", HasData: true}, false, "downloads/week"},
		{"feed name", row{Name: "evil", Weekly: 900_000, First: "2015-01-01", HasData: true}, false, "known-malicious"},
		{"placeholder", row{Name: "http", Weekly: 121_896, First: "2014-01-22", HasData: true, Placeholder: true}, false, "placeholder"},
		{"no data", row{Name: "gone", Weekly: 200_000}, false, "no registry data"},
		{"unknown age", row{Name: "x", Weekly: 500_000, HasData: true}, false, "unknown"},
	} {
		got, why := admitCensus("npm", c.r, feed, testNow)
		if got != c.want || (!c.want && !strings.Contains(why, c.why)) {
			t.Errorf("%s: admit=%v (%q), want %v containing %q", c.name, got, why, c.want, c.why)
		}
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
