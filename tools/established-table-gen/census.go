package main

// census.go — the census table (2026-10-21).
//
// The guard consults this table for any name its typosquat lane flags at
// medium or high confidence. So the census reads the registry's full public
// name list, runs the guard's own detector over every name (censusCandidates),
// and admits a flagged name only on registry evidence that it is a
// long-standing, used package in its own right — either line:
//
//   - first published >= 2 years before the build AND the downloads line
//     (>= 100,000 a week, or the ecosystem's equivalent), or
//   - the old-package line (2026-10-22): first published >= 5 years before
//     the build AND >= 1,000 a week — >= 20,000 for a block-tier candidate,
//     since at 1,000 it admitted typo-catchers of the most popular names
//     (loadash, expres) and lowered their blocks to warnings.
//
// The old-package line is low on purpose: downloads are cheap to inflate and
// old dormant names get taken over, so it is acceptable only because a row
// never clears silently unpinned (below). The guard's runtime clear takes the
// same line (risk.EstablishedTableClear); the server's does not.
//
// The same lines for both tiers: a "block" candidate (the d=1 lookalike of a
// target within the block cutoff) and a "warn" candidate (every other
// medium/high hit). A warn-tier row only ever silences a warning on an exact
// build-time pin; it cannot lower a block the block-tier rules would not.
//
// Both, always. Downloads alone is a pumped young package; a version count
// alone is cheap (create-jst shipped 28 versions in 30 days). Never admitted:
// a name in the known-malicious feed, an npm security placeholder, a name
// with no registry data.
//
// This replaces rail 3 (hold every d=1 neighbour of a popular seed drawing
// under 1% of its traffic), which held out exactly the long-standing packages
// the table exists for (jsonp/json5, is-blob/is-glob, js-logger/bs-logger).
// What made rail 3 necessary is gone: a table row no longer clears silently —
// an unpinned install warns, and only an exact pin of a release in the row's
// build-time release set is quiet.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/typosquat"
)

const (
	// blockRankCutoff mirrors cli.guardTyposquatBlockRankCutoff: a d=1 hit
	// against a target ranked deeper than this never reaches the block lane.
	blockRankCutoff = 2500
	// guardMaxRelativeDistance mirrors cli.guardMaxRelativeDistance.
	guardMaxRelativeDistance = 0.35
	// censusMinAge is the age half of the downloads line.
	censusMinAge = 2 * 365 * 24 * time.Hour
	// censusOldAge is the age half of the old-package line,
	// risk.EstablishedLongLivedPackageAge.
	censusOldAge = 5 * 365 * 24 * time.Hour
)

// censusCandidate is a registry name the guard's typosquat lane flags at
// medium or high confidence: Tier "block" when the hit is the d=1 lookalike
// of a block-eligible target, "warn" for every other non-low hit (distance 2
// or 3 within the detector's thresholds, a reorder match, a d=1 hit on a
// target past the block cutoff).
type censusCandidate struct {
	Name, Target string
	TargetRank   int
	Tier         string
	Method       string
	Distance     int
}

// censusCandidates runs the detector itself — configured exactly as the
// guard configures it — over every registry name, in parallel. There is no
// separate prefilter heuristic to drift from the detector: a name is a
// candidate iff the guard's own Check flags it at medium or high confidence
// (homoglyph hits excluded: the guard decides them before any table is read).
func censusCandidates(eco string, corpus []typosquat.PopularPackage, names []string) []censusCandidate {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := typosquat.NewDetectorWithConfig(quiet, typosquat.ThresholdConfig{MaxRelativeDistance: guardMaxRelativeDistance})
	d.LoadEcosystem(eco, corpus)
	workers := runtime.NumCPU()
	results := make([][]censusCandidate, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < len(names); i += workers {
				if c, ok := censusCheck(d, eco, names[i]); ok {
					results[w] = append(results[w], c)
				}
			}
		}(w)
	}
	wg.Wait()
	var out []censusCandidate
	for _, r := range results {
		out = append(out, r...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// censusCheck is the per-name candidate decision.
func censusCheck(d *typosquat.Detector, eco, name string) (censusCandidate, bool) {
	res := d.Check(context.Background(), eco, name)
	if !res.IsSuspected || res.Confidence == "low" || res.Method == "homoglyph" {
		return censusCandidate{}, false
	}
	tier := "warn"
	if res.Method == "edit-distance" && res.Distance == 1 && res.TargetRank > 0 && res.TargetRank <= blockRankCutoff {
		tier = "block"
	}
	return censusCandidate{Name: name, Target: res.SimilarTo, TargetRank: res.TargetRank, Tier: tier,
		Method: res.Method, Distance: res.Distance}, true
}

// censusVerdict is one candidate's admission decision and why.
type censusVerdict struct {
	Row    row
	Target string
	Tier   string
	Admit  bool
	Reason string
}

// keepBlocked is the reviewed keep-blocked list: names that meet a line but an
// expert hand-review found to be typo-catchers — their traffic is mis-installs
// of the target — so they stay hard-blocked. Applied after admission. Keyed by
// the detector's normalization; each entry is the reason and review date.
var keepBlocked = map[string]map[string]string{
	"npm": {
		"user": "0.0.0 only (2014), code returns 'soon...', no repo, thousands of direct dependents: a mis-install magnet and takeover target (reviewed 2026-10-23)",
	},
	"pypi": {
		"websocket":     "abandoned 2010 gevent code; downloads are websocket-client's import name typed as a package (reviewed 2026-10-23)",
		"config-parser": "2019 project, homepage 404, installs module configs; downloads are configparser typos (reviewed 2026-10-23)",
		"slack":         "2014 DI container with no Slack code, broken on Python 3.11+; downloads are slack-sdk/slackclient typos (reviewed 2026-10-23)",
		"google-oauth":  "abandoned 2016; downloads are google-auth mis-installs (reviewed 2026-10-23)",
	},
}

// admitCensus decides one candidate row: the lines (admitLines), then the
// reviewed keep-blocked list. now is the build time; blockTier is the
// candidate's tier (censusCheck).
func admitCensus(eco string, r row, blockTier bool, feed map[string]map[string]bool, now time.Time) (bool, string) {
	ok, why := admitLines(eco, r, blockTier, feed, now)
	if reason := keepBlocked[eco][typosquat.NormalizerForFormat(eco)(r.Name)]; ok && reason != "" {
		return false, "kept blocked by review: " + reason
	}
	return ok, why
}

// admitLines applies the admission lines.
func admitLines(eco string, r row, blockTier bool, feed map[string]map[string]bool, now time.Time) (bool, string) {
	// Downloads are decided before the registry doc is needed, so a
	// candidate under the lower line is refused without fetching its doc
	// (most of the warn tier). A pumped young package still fails on age below.
	first := parseDate(r.First)
	switch {
	case feed[eco][typosquat.NormalizerForFormat(eco)(r.Name)]:
		return false, "listed in the known-malicious feed"
	case r.Weekly < oldWeeklyDownloadsLine:
		return false, fmt.Sprintf("%d downloads/week, under %d", r.Weekly, oldWeeklyDownloadsLine)
	case !r.HasData:
		return false, "no registry data"
	case r.Placeholder:
		return false, "npm security placeholder"
	case first.IsZero():
		return false, "first publish unknown"
	case now.Sub(first) >= censusOldAge && (!blockTier || r.Weekly >= oldBlockWeeklyDownloadsLine):
		return true, fmt.Sprintf("first published %s (5+ years), %d downloads/week", r.First, r.Weekly)
	case now.Sub(first) >= censusOldAge && r.Weekly < weeklyDownloadsLine:
		return false, fmt.Sprintf("block tier: first published %s (5+ years) but %d downloads/week, under %d", r.First, r.Weekly, oldBlockWeeklyDownloadsLine)
	case r.Weekly < weeklyDownloadsLine:
		return false, fmt.Sprintf("first published %s, under 5 years, and %d downloads/week, under %d", r.First, r.Weekly, weeklyDownloadsLine)
	case now.Sub(first) < censusMinAge:
		return false, fmt.Sprintf("first published %s, under 2 years", r.First)
	}
	return true, fmt.Sprintf("first published %s, %d downloads/week", r.First, r.Weekly)
}

// mayAdmit is admitCensus's age-and-downloads half, for skipping fetches a
// candidate cannot use: false only when no line can admit it.
func mayAdmit(first string, weekly int64, now time.Time) bool {
	t := parseDate(first)
	if t.IsZero() || weekly < oldWeeklyDownloadsLine {
		return false
	}
	age := now.Sub(t)
	return age >= censusOldAge || (age >= censusMinAge && weekly >= weeklyDownloadsLine)
}

// censusSelfTest runs synthetic rows through admitCensus: the profiles the
// admission lines exist to refuse, and the one they exist to admit.
func censusSelfTest(now time.Time) bool {
	ago := func(d time.Duration) string { return now.Add(-d).Format("2006-01-02") }
	year := 365 * 24 * time.Hour
	feed := map[string]map[string]bool{"npm": {"evil-feed-name": true}}
	cases := []struct {
		r     row
		block bool
		want  bool
	}{
		{row{Name: "pumped-young", Weekly: 5_000_000, Versions: 40, First: ago(year / 2), HasData: true}, false, false},
		{row{Name: "old-quiet", Weekly: 500, Versions: 1, First: ago(12 * year), HasData: true}, false, false},
		{row{Name: "mid-modest", Weekly: 50_000, Versions: 9, First: ago(3 * year), HasData: true}, false, false},
		{row{Name: "old-modest", Weekly: 1_000, Versions: 2, First: ago(5*year + 24*time.Hour), Last: ago(4 * year), HasData: true}, false, true},
		{row{Name: "busy-versions", Weekly: 0, Versions: 300, First: ago(5 * year), HasData: true}, false, false},
		{row{Name: "evil-feed-name", Weekly: 900_000, First: ago(6 * year), HasData: true}, false, false},
		{row{Name: "held", Weekly: 120_000, First: ago(10 * year), HasData: true, Placeholder: true}, false, false},
		{row{Name: "dormant-old", Weekly: 150_000, Versions: 2, First: ago(11 * year), Last: ago(9 * year), HasData: true}, false, true},
		// Block tier: loadash (one edit from lodash, 2016, 14.4k/week) is refused;
		// as-number's shape at 47k/week is admitted.
		{row{Name: "old-busy-typo", Weekly: 14_436, Versions: 2, First: ago(10 * year), Last: ago(9 * year), HasData: true}, true, false},
		{row{Name: "old-block-20k", Weekly: 47_551, Versions: 1, First: ago(12 * year), Last: ago(12 * year), HasData: true}, true, true},
	}
	pass := true
	for _, c := range cases {
		got, why := admitCensus("npm", c.r, c.block, feed, now)
		fmt.Fprintf(os.Stderr, "census self-test: %-14s admit=%-5v want=%-5v (%s)\n", c.r.Name, got, c.want, why)
		if got != c.want {
			pass = false
		}
	}
	return pass
}

// censusSentinels are measured false blocks that must be ADMITTED: losing one
// means the inputs changed shape, not that the package stopped being
// established.
var censusSentinels = map[string][]string{
	"npm": {"pug", "jsonp", "is-blob"},
	"pub": {"dartx"},
}

// censusCanaries are the guard's canary squats (cli
// TestEstablishedCanarySquatsStillBlock): admitting one lowers a canonical
// squat's block to a warning, so the run is refused. loadash and expres are
// why the old-package line has a block-tier bar.
var censusCanaries = map[string][]string{
	"npm":   {"lodahs", "loadash", "crossenv", "expres", "chalkk"},
	"pypi":  {"reqeusts", "beautifulsoup5"},
	"cargo": {"proc-macro1"},
}

// censusReport prints every non-admitted candidate in measured-name lists
// and a reason histogram.
func censusReport(eco string, verdicts []censusVerdict) {
	reasons := map[string]int{}
	admitted := 0
	for _, v := range verdicts {
		if v.Admit {
			admitted++
			continue
		}
		k := v.Reason
		switch {
		case strings.Contains(k, "under 2 years"):
			k = "first published under 2 years before the build"
		case strings.HasPrefix(k, "kept blocked by review:"):
			k = "kept blocked by review"
		case strings.HasPrefix(k, "block tier:"):
			k = "block tier: 5+ years but under the 20k downloads line"
		case strings.Contains(k, "under 5 years"):
			k = "under 5 years and under the 100k downloads line"
		case strings.Contains(k, "downloads/week"):
			k = "under the 1k downloads line"
		}
		reasons[k]++
	}
	fmt.Fprintf(os.Stderr, "%s census: %d candidates, %d admitted\n", eco, len(verdicts), admitted)
	for k, n := range reasons {
		fmt.Fprintf(os.Stderr, "  refused %5d  %s\n", n, k)
	}
}
