package intelligence

import (
	"os"
	"strings"
	"testing"
	"time"
)

// A timeline fetch that failed this scan leaves the release history empty;
// the stored row's history is carried so the verdict sees it, and a fetched
// value always wins.
func TestCarryReleaseHistory(t *testing.T) {
	first := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	latest := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	prior := MaintenanceSection{
		VersionTimeline:  []VersionRelease{{Version: "1.0.0", PublishedAt: first}, {Version: "2.0.0", PublishedAt: latest}},
		FirstPublishedAt: &first,
		LatestReleaseAt:  &latest,
	}

	var failed MaintenanceSection // timeline_fetch_failed: nothing read
	carryReleaseHistory(&failed, prior)
	if len(failed.VersionTimeline) != 2 || failed.FirstPublishedAt == nil || failed.LatestReleaseAt == nil || !failed.LatestReleaseAt.Equal(latest) {
		t.Fatalf("an empty history must be carried from the stored row: %+v", failed)
	}

	newer := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	fetched := MaintenanceSection{
		VersionTimeline: []VersionRelease{{Version: "3.0.0", PublishedAt: newer}},
		LatestReleaseAt: &newer,
	}
	carryReleaseHistory(&fetched, prior)
	if len(fetched.VersionTimeline) != 1 || !fetched.LatestReleaseAt.Equal(newer) {
		t.Fatalf("a fetched history must win over the stored one: %+v", fetched)
	}
	if fetched.FirstPublishedAt == nil || !fetched.FirstPublishedAt.Equal(first) {
		t.Fatal("a field the fetch left empty is still carried")
	}
}

// The scan applies it before scoring, so the verdict and the stored row read
// the same history. runFanout needs the DB store to reach it, so this reads
// the source.
func TestScanCarriesReleaseHistoryBeforeScoring(t *testing.T) {
	b, err := os.ReadFile("scanner.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	carry := strings.Index(src, "carryReleaseHistory(&report.Maintenance, prior.Maintenance)")
	score := strings.Index(src, "ComputeTrustScore(report)")
	if carry < 0 || score < 0 || carry > score {
		t.Fatalf("scanner.go must carry the release history before ComputeTrustScore (carry at %d, score at %d)", carry, score)
	}
}
