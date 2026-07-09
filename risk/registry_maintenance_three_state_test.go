package risk

import (
	"testing"
	"time"
)

// TestAbandonedRepo_RepoArchivedThreeState locks in the three-state
// behavior of Input.RepoArchived at the abandoned-repo signal:
//
//   - &true  → suppress the abandoned signal (intentional read-only).
//   - &false → fire when LastRepoCommitAt is past the threshold.
//   - nil    → fire when LastRepoCommitAt is past the threshold (we
//     couldn't probe archive status; the commit-staleness signal
//     alone is enough). The headline behavior change vs. the
//     old deref-collapse path: nil no longer needs to be
//     fabricated as &false to keep this signal armed.
func TestAbandonedRepo_RepoArchivedThreeState(t *testing.T) {
	old := time.Now().Add(-2 * AbandonedRepoThreshold) // way past 12mo
	tru := true
	fls := false

	cases := []struct {
		name     string
		archived *bool
		wantFire bool
	}{
		{"archived=true suppresses", &tru, false},
		{"archived=false fires on stale commit", &fls, true},
		{"archived=nil fires on stale commit", nil, true},
	}
	for _, tc := range cases {
		in := Input{
			LastRepoCommitAt: &old,
			RepoArchived:     tc.archived,
		}
		got := EvaluatePackage(in, Options{})
		fired := false
		for _, cat := range got.DirectScore.Categories {
			for _, fs := range cat.FiredSignals {
				if fs.ID == SignalMaintAbandonedRepo {
					fired = true
				}
			}
		}
		if fired != tc.wantFire {
			t.Errorf("%s: abandoned-repo fired=%v, want=%v", tc.name, fired, tc.wantFire)
		}
	}
}
