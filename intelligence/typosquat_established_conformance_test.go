package intelligence

import (
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
)

// conformanceNow mirrors the guard-side table in core/cli
// (guard_established_test.go): same clock, same rows, so a divergence between
// the server's clear and risk.EstablishedClear fails HERE while the guard's
// copy of the same assertion fails there.
var conformanceNow = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)

func confDay(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// conformanceRows are representative rows chosen to hit every line and both
// sides of every threshold — the production shapes from the 2026-10
// measurements (csrf 1.28M/week; dbsp 299 versions since 2023-08; the rev6
// stratum E long-lived benign names; expres/chalkk the real squats) plus the
// at-the-line and one-below boundaries.
var conformanceRows = []risk.EstablishedRow{
	{Name: "csrf", WeeklyDownloads: 1_277_456},
	{Name: "gaxios", WeeklyDownloads: 130_138_095},
	{Name: "weekly at line", WeeklyDownloads: risk.EstablishedWeeklyDownloads},
	{Name: "weekly one below", WeeklyDownloads: risk.EstablishedWeeklyDownloads - 1},
	{Name: "expres (real squat)", WeeklyDownloads: 8_167},
	{Name: "dbsp", VersionCount: 299, FirstPublished: confDay("2023-08-23")},
	{Name: "versions at line", VersionCount: risk.EstablishedMinVersions, FirstPublished: confDay("2024-10-19")},
	{Name: "versions one below count", VersionCount: risk.EstablishedMinVersions - 1, FirstPublished: confDay("2020-01-01")},
	{Name: "jamespath (stratum E)", FirstPublished: confDay("2013-11-27"), LastPublished: confDay("2013-11-27")},
	{Name: "rage (stratum E)", FirstPublished: confDay("2018-09-18"), LastPublished: confDay("2024-12-18")},
	{Name: "long-lived at line", FirstPublished: confDay("2021-10-20"), LastPublished: confDay("2025-10-19")},
	{Name: "long-lived last unknown", FirstPublished: confDay("2010-01-01")},
	{Name: "sleeper (fresh release)", FirstPublished: confDay("2015-01-01"), LastPublished: confDay("2026-06-01")},
	{Name: "no data"},
}

// rowToReport maps an EstablishedRow onto the Report fields the SERVER path
// reads — the same mapping core/cli/guard_established.go performs implicitly
// by feeding the row straight to risk.EstablishedClear. This test pins the
// two routes to ONE decision.
func rowToReport(row risk.EstablishedRow) *Report {
	r := &Report{}
	r.SupplyChain.TyposquatStatus = "suspected"
	r.SupplyChain.TyposquatConfidence = "high"
	r.SupplyChain.TyposquatSimilarTo = "lookalike"
	r.Identity.Version = "1.0.0"
	if row.WeeklyDownloads != 0 {
		w := int(row.WeeklyDownloads)
		r.Maintenance.WeeklyDownloads = &w
	}
	r.Maintenance.VersionCount = row.VersionCount
	if !row.FirstPublished.IsZero() {
		first := row.FirstPublished
		r.Maintenance.FirstPublishedAt = &first
	}
	if !row.LastPublished.IsZero() {
		last := row.LastPublished
		r.Release.PublishedAt = &last
	}
	return r
}

// TestServerClearMatchesEstablishedClear is the conformance half of "ONE
// definition of every clear rule": for every representative row, the server
// path's decision (clearEstablishedTyposquat, which routes through
// risk.EstablishedReason and longLivedReason) must equal
// risk.EstablishedClear's decision — the function the offline guard's table
// consults. The guard never had these rules and blocked 28 established
// packages (pug, jsdoc, uglify-es) because its copy of them did not exist;
// this test is what makes "cannot diverge again" a testable property rather
// than a hope.
//
// The server's report-specific exclusions (NuGet's 1900 sentinel, npm's
// 0.0.1-security holding package) are OUTSIDE this table by construction —
// the rows here carry real dates and a normal version — and are pinned in
// their own right by TestClearLongLivedTyposquat.
func TestServerClearMatchesEstablishedClear(t *testing.T) {
	for _, row := range conformanceRows {
		row := row
		t.Run(row.Name, func(t *testing.T) {
			wantReason, wantCleared := risk.EstablishedClear(row, conformanceNow)
			r := rowToReport(row)
			clearEstablishedTyposquat(r, conformanceNow)
			gotCleared := r.SupplyChain.TyposquatStatus == "clean"
			if gotCleared != wantCleared {
				t.Errorf("server cleared=%v, risk.EstablishedClear cleared=%v (reason %q) — the definitions diverged on %+v",
					gotCleared, wantCleared, wantReason, row)
			}
			if !gotCleared {
				return
			}
			// A cleared row must carry the explaining warning, so the clear
			// is auditable on the report, not silent.
			if n := len(r.Observation.Warnings); n != 1 || r.Observation.Warnings[0].Code != WarnTyposquatClearedEstablished {
				t.Errorf("cleared without the explaining warning: %+v", r.Observation.Warnings)
			}
		})
	}
}
