package cli

// guard_bytescan_notice_test.go — the guard's coverage claim about ITSELF.
//
// The notice this replaces was built at guard construction from two env vars
// (CHAINSAW_GUARD_ARTIFACT_DIR, CHAINSAW_GUARD_DEEP) and said "behavioral byte
// scan not run" whenever both were unset. But guardArtifactBytes tries five
// sources and three of them — npmCacheArtifactBytes, cargoCacheArtifactBytes,
// pipCacheArtifactBytes — are fully offline and need neither variable. On any
// machine with a warm package-manager cache the guard ran analyzeArtifact over
// real bytes and told the user, in the same sentence, that it had not.
//
// These tests pin the replacement to ACQUISITION OUTCOMES.
//
// NEGATIVE CONTROL: restore the env-var-derived notice (append the old string
// in newLocalGuard when both vars are unset, and delete byteScanNotice's
// counters) and TestByteScanNoticeReportsWhatActuallyHappened fails on the
// "all analyzed" and "partial" arms — the exact cases the old notice lied
// about. Counts recorded in the final report.

import (
	"strings"
	"testing"
)

func TestByteScanNoticeReportsWhatActuallyHappened(t *testing.T) {
	tests := []struct {
		name            string
		attempted       int
		analyzed        int
		worst           acquireResult
		wantEmpty       bool
		wantContains    []string
		wantNotContains []string
	}{
		{
			// Nothing reached the acquisition step: every package was decided
			// by an earlier lane, or the coverage gate refused the run. Saying
			// anything about byte coverage would be noise about work nobody
			// asked for.
			name:      "no spec reached acquisition",
			attempted: 0,
			wantEmpty: true,
		},
		{
			// THE DEFECT. A warm npm/cargo/pip cache means bytes were read and
			// analyzed with neither env var set. The notice must say so.
			name:         "every package analyzed",
			attempted:    3,
			analyzed:     3,
			wantContains: []string{"analyzed the bytes of all 3 packages", "offline"},
			// The old, false claim must be impossible to produce here.
			wantNotContains: []string{"not run", "name/feed/typosquat checks only"},
		},
		{
			name:            "single package analyzed uses singular noun",
			attempted:       1,
			analyzed:        1,
			wantContains:    []string{"all 1 package"},
			wantNotContains: []string{"1 packages", "not run"},
		},
		{
			name:            "partial coverage reports both numbers",
			attempted:       5,
			analyzed:        2,
			wantContains:    []string{"analyzed 2 of 5 packages", "no bytes on this machine"},
			wantNotContains: []string{"not run"},
		},
		{
			// The one case where "not run" is TRUE, and it is derived from
			// zero analyzed packages, not from an env var.
			name:            "nothing analyzed still says not run",
			attempted:       4,
			analyzed:        0,
			wantContains:    []string{"not run", "no local bytes for any of 4 packages", "name/feed/typosquat checks only"},
			wantNotContains: []string{"analyzed the bytes of all"},
		},
		{
			// A degraded acquisition is the attacker-influenceable outcome and
			// must never be folded into the benign "had no bytes".
			name:         "incomplete acquisition is called out",
			attempted:    2,
			analyzed:     1,
			worst:        acquireIncomplete,
			wantContains: []string{"analyzed 1 of 2 packages", "could not be fully acquired"},
		},
		{
			name:         "digest mismatch is called out distinctly",
			attempted:    2,
			analyzed:     1,
			worst:        acquireDigestMismatch,
			wantContains: []string{"did not match the digest"},
			// Must not be collapsed into the incomplete wording.
			wantNotContains: []string{"could not be fully acquired"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := &localGuard{
				scanAttempted: tc.attempted,
				scanAnalyzed:  tc.analyzed,
				scanWorst:     tc.worst,
			}
			got := g.byteScanNotice()
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("byteScanNotice() = %q, want empty", got)
				}
				return
			}
			if got == "" {
				t.Fatal("byteScanNotice() = empty, want a notice")
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("notice %q does not contain %q", got, want)
				}
			}
			for _, bad := range tc.wantNotContains {
				if strings.Contains(got, bad) {
					t.Errorf("notice %q must not contain %q", got, bad)
				}
			}
		})
	}
}

// TestNewLocalGuardMakesNoByteScanCoverageClaim is the regression rail for the
// defect itself: construction happens before any package is examined, so no
// notice produced there may assert whether the byte scan ran. The deep-mode
// network warning is deliberately exempt — it describes a CONFIGURED posture
// that waives the offline guarantee, which IS knowable up front and must stay
// exactly as loud.
func TestNewLocalGuardMakesNoByteScanCoverageClaim(t *testing.T) {
	t.Setenv(guardArtifactDirEnv, "")
	t.Setenv("CHAINSAW_GUARD_DEEP", "")

	g := newLocalGuard()
	for _, n := range g.notices {
		if strings.Contains(n, "byte scan") {
			t.Errorf("construction-time notice claims byte-scan coverage before any package was examined: %q", n)
		}
	}
	// And the guard has not yet examined anything, so it says nothing.
	if got := g.byteScanNotice(); got != "" {
		t.Errorf("byteScanNotice() on a fresh guard = %q, want empty", got)
	}
}

// TestDeepModeNetworkWarningStaysLoud pins the notice that must NOT be
// softened by this change: deep mode waives the offline guarantee, and that is
// the guard's single most important disclosure.
func TestDeepModeNetworkWarningStaysLoud(t *testing.T) {
	t.Setenv("CHAINSAW_GUARD_DEEP", "1")

	g := newLocalGuard()
	var found string
	for _, n := range g.notices {
		if strings.Contains(n, "deep mode") {
			found = n
		}
	}
	if found == "" {
		t.Fatal("deep mode is on but no deep-mode notice was emitted")
	}
	for _, want := range []string{"NETWORK", "offline guarantee waived"} {
		if !strings.Contains(found, want) {
			t.Errorf("deep-mode notice %q lost %q", found, want)
		}
	}
}

// TestByteScanAccountingFollowsAcquisition proves the counters are driven by
// evaluate() rather than by configuration: with no artifact dir, no deep mode
// and a spec no cache can satisfy, acquisition is attempted and misses — so
// the guard reports "not run" because it MEASURED that, and the count matches
// the number of specs that reached the step.
func TestByteScanAccountingFollowsAcquisition(t *testing.T) {
	t.Setenv(guardArtifactDirEnv, t.TempDir()) // empty dir: every lookup misses
	t.Setenv("CHAINSAW_GUARD_DEEP", "")

	g := newLocalGuard()
	if g.scanAttempted != 0 || g.scanAnalyzed != 0 {
		t.Fatalf("fresh guard has non-zero accounting: attempted=%d analyzed=%d", g.scanAttempted, g.scanAnalyzed)
	}

	specs := []packageSpec{
		{Ecosystem: "npm", Name: "chainsaw-nonexistent-benign-a", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "chainsaw-nonexistent-benign-b", Version: "1.0.0"},
	}
	for _, s := range specs {
		g.evaluate(t.Context(), s)
	}

	if g.scanAttempted != len(specs) {
		t.Errorf("scanAttempted = %d, want %d", g.scanAttempted, len(specs))
	}
	if g.scanAnalyzed != 0 {
		t.Errorf("scanAnalyzed = %d, want 0 (nothing is staged or cached for these names)", g.scanAnalyzed)
	}
	notice := g.byteScanNotice()
	if !strings.Contains(notice, "not run") {
		t.Errorf("notice %q should report the measured miss", notice)
	}
	if !strings.Contains(notice, "2 packages") {
		t.Errorf("notice %q should report the measured count", notice)
	}
}
