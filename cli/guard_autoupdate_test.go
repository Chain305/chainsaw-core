package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

type fakeAutoUpdate struct {
	state       guardState
	interactive bool
	offline     bool
	answer      bool
	asked       int
	spawned     int
	spawnErr    error
	now         time.Time
}

func (f *fakeAutoUpdate) deps() *feedAutoUpdateDeps {
	return &feedAutoUpdateDeps{
		interactive: func() bool { return f.interactive },
		offline:     func() bool { return f.offline },
		confirm:     func(string) bool { f.asked++; return f.answer },
		spawn: func() (string, error) {
			f.spawned++
			return "/tmp/guard-update.log", f.spawnErr
		},
		now:  func() time.Time { return f.now },
		load: func() *guardState { st := f.state; return &st },
		save: func(st *guardState) { f.state = *st },
	}
}

const testStale = "known-malicious feed last refreshed on 2026-07-14 (120 days ago)"

func TestStaleFeedAskOnceThenRemember(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

	// Yes: consent stored, refresh started now, install not blocked.
	f := &fakeAutoUpdate{interactive: true, answer: true, now: now}
	lines := staleFeedLines(testStale, false, f.deps())
	if f.asked != 1 || f.spawned != 1 || f.state.FeedAutoUpdate != feedAutoUpdateOn {
		t.Fatalf("yes: asked=%d spawned=%d consent=%q", f.asked, f.spawned, f.state.FeedAutoUpdate)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "refreshing it in the background") {
		t.Fatalf("yes: want a background-refresh line, got %q", lines)
	}
	// Next stale install within the window: not asked, not spawned again.
	lines = staleFeedLines(testStale, false, f.deps())
	if f.asked != 1 || f.spawned != 1 || !strings.Contains(strings.Join(lines, "\n"), "background refresh was started") {
		t.Fatalf("within window: asked=%d spawned=%d lines=%q", f.asked, f.spawned, lines)
	}
	// After the window: spawned again, still not asked.
	f.now = now.Add(feedAutoUpdateEvery + time.Minute)
	staleFeedLines(testStale, false, f.deps())
	if f.asked != 1 || f.spawned != 2 {
		t.Fatalf("after window: asked=%d spawned=%d", f.asked, f.spawned)
	}

	// No: stored as off; never asked again; the age and the manual command shown.
	f = &fakeAutoUpdate{interactive: true, answer: false, now: now}
	lines = staleFeedLines(testStale, false, f.deps())
	if f.asked != 1 || f.spawned != 0 || f.state.FeedAutoUpdate != feedAutoUpdateOff {
		t.Fatalf("no: asked=%d spawned=%d consent=%q", f.asked, f.spawned, f.state.FeedAutoUpdate)
	}
	staleFeedLines(testStale, false, f.deps())
	joined := strings.Join(lines, "\n")
	if f.asked != 1 || !strings.Contains(joined, "120 days ago") || !strings.Contains(joined, "chainsaw guard auto-update on") {
		t.Fatalf("no: want one ask, the age and how to turn it on; asked=%d lines=%q", f.asked, lines)
	}
}

func TestStaleFeedNeverAsksWithoutAHuman(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	for name, f := range map[string]*fakeAutoUpdate{
		"non-interactive": {interactive: false, answer: true, now: now},
		"quiet":           {interactive: true, answer: true, now: now},
	} {
		lines := staleFeedLines(testStale, name == "quiet", f.deps())
		if f.asked != 0 || f.spawned != 0 || f.state.FeedAutoUpdate != "" {
			t.Fatalf("%s: must not ask, spawn or record consent (asked=%d spawned=%d consent=%q)", name, f.asked, f.spawned, f.state.FeedAutoUpdate)
		}
		if !strings.Contains(strings.Join(lines, "\n"), testStale) {
			t.Fatalf("%s: the age line must still be shown, got %q", name, lines)
		}
	}
	// --quiet hides chatter, never a refresh the user consented to.
	f := &fakeAutoUpdate{state: guardState{FeedAutoUpdate: feedAutoUpdateOn}, now: now}
	staleFeedLines(testStale, true, f.deps())
	if f.spawned != 1 {
		t.Fatalf("quiet + consent on: want the refresh started, spawned=%d", f.spawned)
	}
}

func TestStaleFeedOfflineNeverSpawns(t *testing.T) {
	f := &fakeAutoUpdate{state: guardState{FeedAutoUpdate: feedAutoUpdateOn}, interactive: true, offline: true, now: time.Now()}
	if lines := staleFeedLines(testStale, false, f.deps()); f.spawned != 0 || f.asked != 0 || len(lines) != 1 {
		t.Fatalf("offline: spawned=%d asked=%d lines=%q", f.spawned, f.asked, lines)
	}
	f = &fakeAutoUpdate{interactive: true, offline: true, now: time.Now()}
	if staleFeedLines(testStale, false, f.deps()); f.asked != 0 {
		t.Fatal("offline: must not ask for consent to a refresh that cannot run")
	}
}

func TestStaleFeedSpawnFailureSaysHowToRefresh(t *testing.T) {
	f := &fakeAutoUpdate{state: guardState{FeedAutoUpdate: feedAutoUpdateOn}, spawnErr: errors.New("exec: no such file"), now: time.Now()}
	lines := strings.Join(staleFeedLines(testStale, false, f.deps()), "\n")
	if !strings.Contains(lines, "could not start") || !strings.Contains(lines, "chainsaw guard update") {
		t.Fatalf("spawn failure must say so and give the manual command, got %q", lines)
	}
}

func TestFeedAgeLevel(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		age  time.Duration
		want feedAgeSeverity
	}{
		{time.Hour, feedAgeFresh},
		{guardFeedStaleAfter, feedAgeFresh},
		{guardFeedStaleAfter + time.Hour, feedAgeAging},
		{feedAgeOldAfter, feedAgeAging},
		{feedAgeOldAfter + time.Hour, feedAgeOld},
		{-72 * time.Hour, feedAgeOld}, // dated in the future
	}
	for _, c := range cases {
		if got := feedAgeLevel(now.Add(-c.age), now); got != c.want {
			t.Errorf("age %v: got %v want %v", c.age, got, c.want)
		}
	}
	if feedAgeColor(feedAgeFresh) != ansiGreen || feedAgeColor(feedAgeAging) != ansiYellow || feedAgeColor(feedAgeOld) != ansiRed {
		t.Fatal("colours must be green / yellow / red by age")
	}
}

func TestGuardAutoUpdateCommand(t *testing.T) {
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())
	run := func(args ...string) (string, error) {
		cmd := &cobra.Command{RunE: guardAutoUpdateCmd.RunE, Args: guardAutoUpdateCmd.Args}
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), err
	}
	if out, err := run(); err != nil || !strings.Contains(out, "not set") {
		t.Fatalf("show unset: out=%q err=%v", out, err)
	}
	if _, err := run("on"); err != nil || loadGuardState().FeedAutoUpdate != feedAutoUpdateOn {
		t.Fatalf("on: err=%v state=%q", err, loadGuardState().FeedAutoUpdate)
	}
	if _, err := run("OFF"); err != nil || loadGuardState().FeedAutoUpdate != feedAutoUpdateOff {
		t.Fatalf("off: err=%v state=%q", err, loadGuardState().FeedAutoUpdate)
	}
	if _, err := run("maybe"); err == nil {
		t.Fatal("invalid value must be rejected")
	}
}

func TestGuardStatusShowsAutoUpdate(t *testing.T) {
	withIsolatedConfigHome(t)
	t.Setenv(guardDBEnv, filepath.Join(t.TempDir(), "absent.json"))
	saveGuardState(&guardState{FeedAutoUpdate: feedAutoUpdateOn})

	got := jsonResultViaOutputFile(t, &cobra.Command{Use: "status"}, func(c *cobra.Command) error { return runGuardStatus(c, nil) })
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("status --json: %v\n%s", err, got)
	}
	if m["feed_auto_update"] != feedAutoUpdateOn {
		t.Fatalf("want feed_auto_update=on, got %v", m["feed_auto_update"])
	}
}

// --- doctor: only the current shell counts ------------------------------------

func doctorTable(t *testing.T, rcs ...string) string {
	t.Helper()
	prev := shellRCCandidates
	shellRCCandidates = func() []string { return rcs }
	t.Cleanup(func() { shellRCCandidates = prev })
	cmd := newDoctorCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	_ = cmd.Flags().Set("no-color", "true")
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("doctor: %v\n%s", err, errb.String())
	}
	return out.String()
}

func TestDoctorOnlyCountsCurrentShell(t *testing.T) {
	withHookEnv(t)
	t.Setenv(guardSkipEnv, "")
	dir := t.TempDir()
	zshrc := filepath.Join(dir, ".zshrc")
	bashrc := filepath.Join(dir, ".bashrc")
	if err := os.WriteFile(zshrc, []byte("eval \"$(CHAINSAW_GUARD_SKIP=npm chainsaw guard init zsh)\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bashrc, []byte("eval \"$(chainsaw guard init bash)\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// zsh user: the old plain line in .bashrc must not make npm look guarded.
	t.Setenv("SHELL", "/bin/zsh")
	out := doctorTable(t, zshrc, bashrc)
	if !rowHasState(t, out, "npm", "skipped") || !rowHasState(t, out, "pip", "shim") {
		t.Fatalf("zsh: want npm skipped, pip shim:\n%s", out)
	}
	if !strings.Contains(out, "also set up for other shells in "+bashrc) {
		t.Fatalf("zsh: want the other-shell line naming %s:\n%s", bashrc, out)
	}

	// bash user: .bashrc's line wraps npm.
	t.Setenv("SHELL", "/bin/bash")
	if out := doctorTable(t, zshrc, bashrc); !rowHasState(t, out, "npm", "shim") {
		t.Fatalf("bash: want npm shim:\n%s", out)
	}

	// fish user, guard only set up for zsh: say so plainly, not a bare "no".
	t.Setenv("SHELL", "/usr/local/bin/fish")
	out = doctorTable(t, zshrc)
	if !rowHasState(t, out, "npm", "no") || !strings.Contains(out, "your current shell is fish") {
		t.Fatalf("fish: want npm no and the wrong-shell note:\n%s", out)
	}
}

// TestInstallPathHandlesStaleFeed pins the wiring: a guarded install hands a
// stale cache to staleFeedLines (ask once / background refresh / age line).
// A source guard because runGuardedPassthrough execs the real tool.
func TestInstallPathHandlesStaleFeed(t *testing.T) {
	src, err := os.ReadFile("guard_install.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(src, []byte("staleFeedLines(guard.staleNotice, isQuiet, prodFeedAutoUpdateDeps())")) {
		t.Fatal("guard_install.go must pass a stale cache to staleFeedLines")
	}
}
