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
