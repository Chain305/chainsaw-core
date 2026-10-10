package intelligence

import (
	"context"
	"testing"
	"time"
)

func squatReport(downloads *int, similarTo string) *Report {
	r := &Report{}
	r.SupplyChain.TyposquatStatus = "suspected"
	r.SupplyChain.TyposquatConfidence = "high"
	r.SupplyChain.TyposquatSimilarTo = similarTo
	r.Maintenance.WeeklyDownloads = downloads
	return r
}

// TestClearEstablishedTyposquat uses the production rows from 2026-10-06:
// csrf, mpath and gaxios were high-confidence QUARANTINES with 1.3M-130M
// weekly downloads; expres (8,167) and chalkk (1) are real squats.
func TestClearEstablishedTyposquat(t *testing.T) {
	for _, tc := range []struct {
		name      string
		downloads *int
		cleared   bool
	}{
		{"gaxios", dlPtr(130_138_095), true},
		{"csrf", dlPtr(1_277_456), true},
		{"mpath", dlPtr(7_704_417), true},
		{"at-threshold", dlPtr(establishedTyposquatWeeklyDownloads), true},
		{"chan", dlPtr(25_517), false},
		{"expres", dlPtr(8_167), false},
		{"chalkk", dlPtr(1), false},
		{"fetch-failed", dlPtr(-1), false},
		{"never-fetched", nil, false},
	} {
		r := squatReport(tc.downloads, "lookalike")
		clearEstablishedTyposquat(r, time.Now())
		cleared := r.SupplyChain.TyposquatStatus == "clean"
		if cleared != tc.cleared {
			t.Errorf("%s: cleared=%v, want %v (status %q)", tc.name, cleared, tc.cleared, r.SupplyChain.TyposquatStatus)
		}
		if cleared {
			if r.SupplyChain.TyposquatConfidence != "" || r.SupplyChain.TyposquatSimilarTo != "" {
				t.Errorf("%s: cleared but confidence/similarTo left set: %+v", tc.name, r.SupplyChain)
			}
			if n := len(r.Observation.Warnings); n != 1 || r.Observation.Warnings[0].Code != WarnTyposquatClearedEstablished {
				t.Errorf("%s: cleared without the explaining warning: %+v", tc.name, r.Observation.Warnings)
			}
			if in := ProjectToRiskInput(r); in.IsSuspectedTyposquat {
				t.Errorf("%s: risk input still reads suspected after clearing", tc.name)
			}
		} else if r.SupplyChain.TyposquatConfidence != "high" {
			t.Errorf("%s: not cleared but confidence changed to %q", tc.name, r.SupplyChain.TyposquatConfidence)
		}
	}
}

// TestClearEstablishedTyposquatLeavesOtherStatusesAlone: only a "suspected"
// verdict is cleared; a clean row gains no warning.
func TestClearEstablishedTyposquatLeavesOtherStatusesAlone(t *testing.T) {
	r := squatReport(dlPtr(50_000_000), "")
	r.SupplyChain.TyposquatStatus = "clean"
	clearEstablishedTyposquat(r, time.Now())
	if len(r.Observation.Warnings) != 0 {
		t.Fatalf("clean row gained a warning: %+v", r.Observation.Warnings)
	}
}

func dlPtr(n int) *int { return &n }

// TestClearEstablishedTyposquat90Day: crates.io publishes only a 90-day count,
// so before the 90-day line no crate could clear. typedmap (204,545, flagged
// against type-map) and termbg (94,361) are production false positives from
// 2026-10-07; faster_log's whole-life 7,181 is the busiest crates.io squat on
// record; s2-common (42,887) stays flagged by design.
func TestClearEstablishedTyposquat90Day(t *testing.T) {
	for _, tc := range []struct {
		name    string
		count   int
		window  string
		cleared bool
	}{
		{"typedmap", 204_545, DownloadWindow90Days, true},
		{"termbg", 94_361, DownloadWindow90Days, true},
		{"at-threshold", establishedTyposquat90DayDownloads, DownloadWindow90Days, true},
		{"s2-common", 42_887, DownloadWindow90Days, false},
		{"faster_log", 7_181, DownloadWindow90Days, false},
		{"fetch-failed", -1, DownloadWindow90Days, false},
		// No measured line for these windows yet: nothing clears.
		{"packagist-month", 5_000_000, DownloadWindowMonth, false},
		{"rubygems-total", 500_000_000, DownloadWindowTotal, false},
	} {
		r := squatReport(nil, "type-map")
		r.Maintenance.Downloads = &DownloadCount{Count: tc.count, Window: tc.window}
		clearEstablishedTyposquat(r, time.Now())
		if cleared := r.SupplyChain.TyposquatStatus == "clean"; cleared != tc.cleared {
			t.Errorf("%s (%d/%s): cleared=%v, want %v", tc.name, tc.count, tc.window, cleared, tc.cleared)
		}
	}
}

// TestScanClearsEstablishedTyposquat goes through Scan, so a correct helper
// that the scanner stops calling fails here: the typosquat provider is
// name-only and the download count arrives from a different provider in the
// same tier, so only the post-merge step can see both.
func TestScanClearsEstablishedTyposquat(t *testing.T) {
	for _, tc := range []struct {
		pkg       string
		downloads int
		want      string
	}{
		{"gaxios", 130_138_095, "clean"},
		{"expres", 8_167, "suspected"},
	} {
		squat := &fakeProvider{name: "fake-typosquat", signal: SignalTyposquat, partial: PartialReport{
			SupplyChain: &SupplyChainSection{TyposquatStatus: "suspected", TyposquatConfidence: "high", TyposquatSimilarTo: "axios"},
		}}
		meta := &fakeProvider{name: "fake-metadata", signal: SignalMalware, partial: PartialReport{
			Maintenance: &MaintenanceSection{WeeklyDownloads: dlPtr(tc.downloads)},
		}}
		svc := New(Config{Providers: []Provider{squat, meta}})
		report, err := svc.Scan(context.Background(), Request{
			Key:   Key{Ecosystem: "npm", Package: tc.pkg, Version: "1.0.0"},
			OrgID: "org-default",
		})
		if err != nil {
			t.Fatalf("%s: Scan: %v", tc.pkg, err)
		}
		if got := report.SupplyChain.TyposquatStatus; got != tc.want {
			t.Errorf("%s (%d/week): TyposquatStatus %q, want %q", tc.pkg, tc.downloads, got, tc.want)
		}
	}
}

// TestScanClearsEstablishedCrate is the Scan-level twin for crates.io: the
// count arrives as Maintenance.Downloads with a 90-day window and no
// WeeklyDownloads, which is the shape that never cleared before.
func TestScanClearsEstablishedCrate(t *testing.T) {
	for _, tc := range []struct {
		count int
		want  string
	}{
		{204_545, "clean"},
		{7_181, "suspected"},
	} {
		squat := &fakeProvider{name: "fake-typosquat", signal: SignalTyposquat, partial: PartialReport{
			SupplyChain: &SupplyChainSection{TyposquatStatus: "suspected", TyposquatConfidence: "high", TyposquatSimilarTo: "type-map"},
		}}
		meta := &fakeProvider{name: "fake-metadata", signal: SignalMalware, partial: PartialReport{
			Maintenance: &MaintenanceSection{Downloads: &DownloadCount{Count: tc.count, Window: DownloadWindow90Days}},
		}}
		svc := New(Config{Providers: []Provider{squat, meta}})
		report, err := svc.Scan(context.Background(), Request{
			Key:   Key{Ecosystem: "cargo", Package: "typedmap", Version: "0.3.1"},
			OrgID: "org-default",
		})
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if got := report.SupplyChain.TyposquatStatus; got != tc.want {
			t.Errorf("typedmap at %d/90d: TyposquatStatus %q, want %q", tc.count, got, tc.want)
		}
	}
}

// TestClearEstablishedTyposquatHistory uses production rows from 2026-10-07.
// dbsp is the false positive (299 versions since 2023-08, 24,227 per 90 days,
// below the download line); the other suspected rows carry at most 28
// versions. (avada and expres are not squats either: the long-lived rule
// clears them once their version date is known, see
// TestClearLongLivedTyposquat.)
func TestClearEstablishedTyposquatHistory(t *testing.T) {
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	day := func(s string) *time.Time {
		d, err := time.Parse("2006-01-02", s)
		if err != nil {
			t.Fatal(err)
		}
		return &d
	}
	for _, tc := range []struct {
		name     string
		versions int
		first    *time.Time
		cleared  bool
	}{
		{"dbsp", 299, day("2023-08-23"), true},
		{"at-threshold", establishedTyposquatMinVersions, day("2024-10-07"), true},
		{"one-day-short", establishedTyposquatMinVersions, day("2024-10-08"), false},
		{"s2-common: young", 60, day("2026-01-09"), false},
		{"avada", 28, day("2020-11-24"), false},
		{"expres", 5, day("2012-10-10"), false},
		{"no first publish", 299, nil, false},
		{"timeline-only count (core build)", -1, day("2023-08-23"), true},
	} {
		r := squatReport(nil, "dasp")
		r.Maintenance.Downloads = &DownloadCount{Count: 24_227, Window: DownloadWindow90Days}
		if tc.versions < 0 {
			// No premium VersionCount writer: only the timeline knows.
			r.Maintenance.VersionTimeline = make([]VersionRelease, 299)
		} else {
			r.Maintenance.VersionCount = tc.versions
		}
		r.Maintenance.FirstPublishedAt = tc.first
		clearEstablishedTyposquat(r, now)
		if cleared := r.SupplyChain.TyposquatStatus == "clean"; cleared != tc.cleared {
			t.Errorf("%s: cleared=%v, want %v", tc.name, cleared, tc.cleared)
		}
	}
}

// TestScanClearsLongHistoryCrate goes through Scan: the history arrives from
// the metadata provider, after the name-only typosquat provider has flagged.
func TestScanClearsLongHistoryCrate(t *testing.T) {
	first := time.Date(2023, 8, 23, 0, 0, 0, 0, time.UTC)
	squat := &fakeProvider{name: "fake-typosquat", signal: SignalTyposquat, partial: PartialReport{
		SupplyChain: &SupplyChainSection{TyposquatStatus: "suspected", TyposquatConfidence: "high", TyposquatSimilarTo: "dasp"},
	}}
	meta := &fakeProvider{name: "fake-metadata", signal: SignalMalware, partial: PartialReport{
		Maintenance: &MaintenanceSection{
			Downloads:        &DownloadCount{Count: 24_227, Window: DownloadWindow90Days},
			VersionCount:     299,
			FirstPublishedAt: &first,
		},
	}}
	svc := New(Config{Providers: []Provider{squat, meta}})
	report, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "cargo", Package: "dbsp", Version: "0.363.0"},
		OrgID: "org-default",
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := report.SupplyChain.TyposquatStatus; got != "clean" {
		t.Errorf("dbsp: TyposquatStatus %q, want clean", got)
	}
}

// TestClearLongLivedTyposquat: the eleven rev6 stratum E quarantines
// (2026-10-10), each one edit from a popular name and each a distinct,
// benign project, carry the dates below. The negatives are the shapes the
// rule must not clear: npm's holding package left where a squat was removed
// (chalkk and lodahs, both in prod), a sleeper's fresh release, a squat that
// lived a year (jeIlyfish), and dates that prove nothing.
func TestClearLongLivedTyposquat(t *testing.T) {
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	day := func(s string) *time.Time {
		d, err := time.Parse("2006-01-02", s)
		if err != nil {
			t.Fatal(err)
		}
		return &d
	}
	for _, tc := range []struct {
		name, version string
		first, pub    *time.Time
		cleared       bool
	}{
		{"pypi hacs (yacs)", "1.0.0a1", day("2016-05-01"), day("2016-05-01"), true},
		{"pypi pwsgi (uwsgi)", "0.1.10", day("2016-10-31"), day("2017-07-08"), true},
		{"pypi pyisa (pyvisa)", "1.0.2", day("2018-09-03"), day("2018-09-03"), true},
		{"pypi tta (ta)", "0.2.0", day("2015-07-29"), day("2015-07-29"), true},
		{"rubygems bst (ast)", "0.0.3", day("2015-05-04"), day("2015-05-04"), true},
		{"rubygems jamespath (jmespath)", "0.5.0", day("2013-11-27"), day("2013-11-27"), true},
		{"rubygems litc (lita)", "1.0.3", day("2009-10-08"), day("2010-02-16"), true},
		{"rubygems redrock (redlock)", "0.1.2", day("2010-08-19"), day("2010-12-28"), true},
		{"rubygems set_version (sem_version)", "0.1.2.1", day("2015-02-11"), day("2015-02-11"), true},
		{"cargo rage 0.11.1 (age)", "0.11.1", day("2018-09-18"), day("2024-12-18"), true},
		{"cargo rage 0.6.1 (age)", "0.6.1", day("2018-09-18"), day("2024-12-18"), true},
		{"at both lines", "1.0.0", day("2021-10-11"), day("2025-10-10"), true},

		{"npm chalkk holding package", "0.0.1-security", day("2019-07-24"), day("2019-07-24"), false},
		{"npm lodahs holding package", "0.0.1-securitY", day("2019-11-25"), day("2019-11-25"), false},
		{"sleeper: old name, fresh release", "2.0.0", day("2015-01-01"), day("2026-06-01"), false},
		{"jeIlyfish shape: a year old", "0.7.2", day("2025-10-01"), day("2025-10-01"), false},
		{"package one day short", "1.0.0", day("2021-10-12"), day("2021-10-12"), false},
		{"version one day short", "1.0.0", day("2015-01-01"), day("2025-10-11"), false},
		{"nuget unlisted sentinel", "1.0.0", day("1900-01-01"), day("1900-01-01"), false},
		{"no version date", "1.0.0", day("2013-11-27"), nil, false},
		{"no first publish", "1.0.0", nil, day("2013-11-27"), false},
	} {
		r := squatReport(nil, "lookalike")
		r.Identity.Version = tc.version
		r.Maintenance.FirstPublishedAt = tc.first
		r.Release.PublishedAt = tc.pub
		clearEstablishedTyposquat(r, now)
		cleared := r.SupplyChain.TyposquatStatus == "clean"
		if cleared != tc.cleared {
			t.Errorf("%s: cleared=%v, want %v", tc.name, cleared, tc.cleared)
		}
		if cleared && (len(r.Observation.Warnings) != 1 || r.Observation.Warnings[0].Code != WarnTyposquatClearedEstablished) {
			t.Errorf("%s: cleared without the explaining warning: %+v", tc.name, r.Observation.Warnings)
		}
	}
}

// TestScanClearsLongLivedTyposquat goes through Scan: the version date and
// first release arrive from the metadata provider, after the name-only
// typosquat provider has flagged.
func TestScanClearsLongLivedTyposquat(t *testing.T) {
	first := time.Date(2013, 11, 27, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		pub  time.Time
		want string
	}{
		{first, "clean"},
		{time.Now().Add(-24 * time.Hour), "suspected"},
	} {
		pub := tc.pub
		squat := &fakeProvider{name: "fake-typosquat", signal: SignalTyposquat, partial: PartialReport{
			SupplyChain: &SupplyChainSection{TyposquatStatus: "suspected", TyposquatConfidence: "high", TyposquatSimilarTo: "jmespath"},
		}}
		meta := &fakeProvider{name: "fake-metadata", signal: SignalMalware, partial: PartialReport{
			Release:     &ReleaseSection{PublishedAt: &pub},
			Maintenance: &MaintenanceSection{FirstPublishedAt: &first},
		}}
		svc := New(Config{Providers: []Provider{squat, meta}})
		report, err := svc.Scan(context.Background(), Request{
			Key:   Key{Ecosystem: "rubygems", Package: "jamespath", Version: "0.5.0"},
			OrgID: "org-default",
		})
		if err != nil {
			t.Fatalf("Scan: %v", err)
		}
		if got := report.SupplyChain.TyposquatStatus; got != tc.want {
			t.Errorf("jamespath published %s: TyposquatStatus %q, want %q", pub.Format("2006-01-02"), got, tc.want)
		}
	}
}
