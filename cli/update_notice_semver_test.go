package cli

// update_notice_semver_test.go — R11.
//
// The notice compared versions with `==`, so ANY different string fired it —
// including "v1.2.3" vs "1.2.3", which would have printed "a newer version
// (v1.2.3) is available; you're on 1.2.3", and an OLDER published version.
// Its --quiet gate also matched neither -q nor CHAINSAW_QUIET.

import (
	"os"
	"testing"

	"github.com/spf13/viper"
)

func TestIsNewerVersion(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
		why             string
	}{
		{"1.2.4", "1.2.3", true, "a genuine upgrade"},
		{"v1.2.4", "1.2.3", true, "leading v on the latest side"},
		{"1.2.4", "v1.2.3", true, "leading v on the current side"},
		{"v1.2.3", "1.2.3", false, "SAME version, different spelling — the exact false positive"},
		{"1.2.3", "1.2.3", false, "identical"},
		{"1.2.2", "1.2.3", false, "an OLDER published version must never nag"},
		{"1.10.0", "1.9.0", true, "numeric, not lexicographic, ordering"},
		{"1.9.0", "1.10.0", false, "numeric, not lexicographic, ordering"},
		{"garbage", "1.2.3", true, "unparseable falls back to string inequality (pre-existing behaviour)"},
		{"1.2.3", "dev", true, "an ad-hoc build stamp is not semver"},
		{"dev", "dev", false, "unparseable but equal"},
	}
	for _, tc := range cases {
		if got := isNewerVersion(tc.latest, tc.current); got != tc.want {
			t.Errorf("isNewerVersion(%q, %q) = %v, want %v — %s", tc.latest, tc.current, got, tc.want, tc.why)
		}
	}
}

func TestMaybeNotifyUpdateAvailable_QuietGates(t *testing.T) {
	prevLatest := latestKnownVersion
	prevTTY := updateNoticeStderrIsTerminal
	prevWriter := updateNoticeWriter
	t.Cleanup(func() {
		latestKnownVersion = prevLatest
		updateNoticeStderrIsTerminal = prevTTY
		updateNoticeWriter = prevWriter
	})
	latestKnownVersion = func() string { return "99.0.0" }
	updateNoticeStderrIsTerminal = func() bool { return true }

	// Capture the hint in a temp file so the "notice fires" cases don't
	// scribble on the test runner's stderr.
	sink, err := os.CreateTemp(t.TempDir(), "notice")
	if err != nil {
		t.Fatalf("temp sink: %v", err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	updateNoticeWriter = func() *os.File { return sink }

	cases := []struct {
		name  string
		setup func(t *testing.T)
		want  bool
	}{
		{"no quiet signal", func(t *testing.T) {}, true},
		{"CHAINSAW_QUIET=1", func(t *testing.T) { t.Setenv("CHAINSAW_QUIET", "1") }, false},
		{"CHAINSAW_QUIET=true", func(t *testing.T) { t.Setenv("CHAINSAW_QUIET", "true") }, false},
		// A falsy value is not a request for silence.
		{"CHAINSAW_QUIET=0", func(t *testing.T) { t.Setenv("CHAINSAW_QUIET", "0") }, true},
		{"viper quiet (the bound --quiet flag)", func(t *testing.T) { viper.Set("quiet", true) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			t.Setenv("CHAINSAW_OFFLINE", "")
			t.Setenv("CHAINSAW_QUIET", "")
			withOSArgs(t, []string{"chainsaw", "version"})
			tc.setup(t)

			if got := maybeNotifyUpdateAvailable(); got != tc.want {
				t.Errorf("maybeNotifyUpdateAvailable() = %v, want %v", got, tc.want)
			}
		})
	}
}
