package osv

import (
	"encoding/json"
	"testing"
)

// TestFlattenRecordDropsWithdrawn pins the F-6 fix at the RUNTIME
// flattener, which is the one production actually executes.
//
// WHY THIS TEST EXISTS. dockerized/build.sh bakes a bundle into the
// image and its Python flattener filters withdrawn advisories. That is
// not the bundle prod serves: startOSVRefresher re-downloads all.zip at
// boot and atomic-renames over /system/osv-bundle.json.gz, so the image
// copy survives roughly one minute. Fixing only build.sh looked correct,
// deployed clean, and changed nothing observable — verified live on
// 2026-09-13, where nokogiri@1.19.4 kept scoring warn/40 on three
// WITHDRAWN GHSAs after the image-only fix rolled out.
//
// Upstream never deletes a withdrawn record from all.zip; it only stamps
// the `withdrawn` timestamp. So "absent from the feed" is not a state
// that ever arrives, and dropping the record is our job.
//
// Break it like this: delete the `strings.TrimSpace(rec.Withdrawn)`
// guard in flattenRecord, or drop the Withdrawn field from osvRecord
// (which silently makes the guard read the zero value). Either must
// turn this red.
func TestFlattenRecordDropsWithdrawn(t *testing.T) {
	affected := []osvAffected{{
		Package:  osvPackage{Ecosystem: "RubyGems", Name: "nokogiri"},
		Versions: []string{"1.19.4"},
	}}

	withdrawn := osvRecord{
		ID:        "GHSA-5jhf-fpp7-v2pv",
		Published: "2026-01-01T00:00:00Z",
		Withdrawn: "2026-02-01T00:00:00Z",
		Affected:  affected,
	}
	if got := flattenRecord(withdrawn); len(got) != 0 {
		t.Fatalf("withdrawn advisory produced %d rows, want 0: %+v", len(got), got)
	}

	// The control arm matters as much as the assertion above: without it
	// a flattenRecord that returns nil for EVERYTHING would pass.
	live := withdrawn
	live.Withdrawn = ""
	if got := flattenRecord(live); len(got) == 0 {
		t.Fatal("non-withdrawn advisory produced 0 rows; the filter is over-broad")
	}
}

// TestOSVRecordDecodesWithdrawn guards the decode, not the filter.
// osvRecord drops unknown fields silently, so a struct that never
// declares `withdrawn` makes the guard above read "" for every record
// and pass vacuously while filtering nothing.
func TestOSVRecordDecodesWithdrawn(t *testing.T) {
	const raw = `{"id":"GHSA-x","withdrawn":"2026-02-01T00:00:00Z"}`
	rec, err := decodeOSVRecordForTest(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec.Withdrawn == "" {
		t.Fatal("osvRecord did not decode the `withdrawn` field; the filter is dead code")
	}
}

func decodeOSVRecordForTest(raw string) (osvRecord, error) {
	var rec osvRecord
	err := json.Unmarshal([]byte(raw), &rec)
	return rec, err
}
