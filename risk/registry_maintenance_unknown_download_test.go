package risk

import "testing"

// TestUnknownDownloadCountIsNotReportedAsLowAdoption pins the distinction
// between "we measured a low number" and "we could not measure".
//
// The live defect: lodash — tens of millions of weekly downloads — rendered
// an alert headed "Very low download count" with a MAINTENANCE badge, because
// the download fetch failed and the signal's unknown arm kept the registered
// title. The detail line said "unavailable"; the title, which is what a
// reader sees first and what a screenshot carries, asserted the opposite.
//
// Two properties, and the second is the one that was silently dead:
//
//  1. the unknown arm reports a title that does not claim a measurement;
//  2. severity_override is actually APPLIED. The signal had been emitting
//     that key since it was written and nothing consumed it, so it shipped
//     as SevInfo while its own registration comment claimed SevUnknown.
//
// Break either by deleting the matching branch in applySignalOverrides.
func TestUnknownDownloadCountIsNotReportedAsLowAdoption(t *testing.T) {
	unknown := unknownDownloadsSentinel
	low := 3

	// Fetch failed: no claim about adoption may survive to the reader.
	fired := runNamedPrimitiveSignals(
		Input{Ecosystem: "npm", WeeklyDownloads: &unknown},
		nil, SignalMaintUnpopularPackage,
	)
	got, ok := fired[SignalMaintUnpopularPackage]
	if !ok {
		t.Fatal("signal did not fire on the sentinel; the unknown arm is the point of it")
	}
	if got.Title == "Very low download count" {
		t.Error("an UNFETCHED download count is titled as a low one — absence of " +
			"evidence rendered as evidence")
	}
	if got.Severity != SevUnknown {
		t.Errorf("severity=%q, want %q — severity_override is emitted but not applied",
			got.Severity, SevUnknown)
	}
	// The override keys are control data, not findings, and every evidence
	// key is rendered to the reader.
	if _, leaked := got.Evidence["severity_override"]; leaked {
		t.Error("severity_override leaked into rendered evidence")
	}
	if _, leaked := got.Evidence["title_override"]; leaked {
		t.Error("title_override leaked into rendered evidence")
	}

	// A genuinely measured low count keeps the adverse title and stays info.
	firedLow := runNamedPrimitiveSignals(
		Input{Ecosystem: "npm", WeeklyDownloads: &low},
		nil, SignalMaintUnpopularPackage,
	)
	gotLow, ok := firedLow[SignalMaintUnpopularPackage]
	if !ok {
		t.Fatal("signal did not fire on a measured low count")
	}
	if gotLow.Title != "Very low download count" {
		t.Errorf("measured-low title = %q, want the registered title — the fix "+
			"must not mute a real finding", gotLow.Title)
	}
	if gotLow.Severity != SevInfo {
		t.Errorf("measured-low severity = %q, want %q", gotLow.Severity, SevInfo)
	}
	if gotLow.Evidence["weekly_downloads"] != 3 {
		t.Errorf("measured-low evidence lost its count: %v", gotLow.Evidence)
	}
}
