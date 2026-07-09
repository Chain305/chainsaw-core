package cli

import "testing"

// TestMaybeNotifyUpdateAvailable_Gates exercises each safety gate. The default
// latestKnownVersion stub returns "", so even with all gates open nothing is
// printed — proving the hook is dormant until a real source is wired in.
func TestMaybeNotifyUpdateAvailable_Gates(t *testing.T) {
	// Force the TTY gate open for the duration; restore after.
	origTTY := updateNoticeStderrIsTerminal
	origLatest := latestKnownVersion
	defer func() {
		updateNoticeStderrIsTerminal = origTTY
		latestKnownVersion = origLatest
	}()
	updateNoticeStderrIsTerminal = func() bool { return true }

	t.Run("dormant stub never prints", func(t *testing.T) {
		t.Setenv("CHAINSAW_OFFLINE", "")
		latestKnownVersion = func() string { return "" }
		if maybeNotifyUpdateAvailable() {
			t.Error("dormant stub (latest=\"\") must not print")
		}
	})

	t.Run("offline opt-out suppresses even when newer is known", func(t *testing.T) {
		t.Setenv("CHAINSAW_OFFLINE", "1")
		latestKnownVersion = func() string { return "v999.0.0" }
		if maybeNotifyUpdateAvailable() {
			t.Error("CHAINSAW_OFFLINE set must suppress the notice")
		}
	})

	t.Run("non-tty suppresses even when newer is known", func(t *testing.T) {
		t.Setenv("CHAINSAW_OFFLINE", "")
		updateNoticeStderrIsTerminal = func() bool { return false }
		latestKnownVersion = func() string { return "v999.0.0" }
		if maybeNotifyUpdateAvailable() {
			t.Error("non-TTY stderr must suppress the notice")
		}
		updateNoticeStderrIsTerminal = func() bool { return true }
	})
}

// TestArgvHasQuiet covers the --quiet detection used as a gate.
func TestArgvHasQuiet(t *testing.T) {
	cases := []struct {
		argv []string
		want bool
	}{
		{[]string{"chainsaw", "scan", "--quiet"}, true},
		{[]string{"chainsaw", "--quiet=true", "scan"}, true},
		{[]string{"chainsaw", "scan"}, false},
		{[]string{"chainsaw", "npm", "install", "--", "--quiet"}, false}, // after -- it's the wrapped tool's flag
		{[]string{"chainsaw", "scan", "-q"}, false},                      // bare -q intentionally not matched
	}
	for _, tc := range cases {
		if got := argvHasQuiet(tc.argv); got != tc.want {
			t.Errorf("argvHasQuiet(%v) = %v; want %v", tc.argv, got, tc.want)
		}
	}
}
