package cli

// Consent-gated background refresh of the `chainsaw guard update` cache.
//
// A stale cache (guardFeedStaleAfter) is never refreshed IN the install: a
// refresh after a week is almost never a 304, and a ~46 MB download plus a
// re-index would stall the user's install. Instead, the first time a guarded
// install in a terminal finds the cache stale, the user is asked ONCE whether
// to keep the feed updated automatically. The answer is stored:
//
//   - "on":  each later stale install starts `chainsaw guard update` as a
//     detached background process (at most once per feedAutoUpdateEvery) and
//     goes on with the install.
//   - "off": each stale install says how old the feed is and how to refresh it
//     by hand, and how to turn auto-update on.
//
// CHAINSAW_OFFLINE wins over consent: nothing starts on an offline box.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	feedAutoUpdateOn  = "on"
	feedAutoUpdateOff = "off"
	// feedAutoUpdateEvery caps background refreshes, so a burst of installs
	// (or a refresh that keeps failing) starts at most one per window.
	feedAutoUpdateEvery = 6 * time.Hour
)

// feedAgeSeverity buckets a feed's age for colour: fresh (within
// guardFeedStaleAfter), aging (up to 30 days) and old (beyond).
type feedAgeSeverity int

const (
	feedAgeFresh feedAgeSeverity = iota
	feedAgeAging
	feedAgeOld
)

const feedAgeOldAfter = 30 * 24 * time.Hour

func feedAgeLevel(checked, now time.Time) feedAgeSeverity {
	switch {
	case !guardFeedIsStale(checked, now):
		return feedAgeFresh
	case now.Sub(checked) > feedAgeOldAfter || checked.After(now):
		return feedAgeOld
	default:
		return feedAgeAging
	}
}

// feedAgeColor is the ANSI colour for a feed's age: green, yellow, red.
func feedAgeColor(level feedAgeSeverity) string {
	switch level {
	case feedAgeOld:
		return ansiRed
	case feedAgeAging:
		return ansiYellow
	default:
		return ansiGreen
	}
}

type feedAutoUpdateDeps struct {
	interactive func() bool             // a human can answer a prompt (stdin AND stderr are terminals)
	offline     func() bool             // CHAINSAW_OFFLINE
	confirm     func(label string) bool // default-No prompt
	spawn       func() (string, error)  // starts the detached refresh; returns its log path
	now         func() time.Time
	load        func() *guardState
	save        func(*guardState)
}

// staleFeedLines decides what a guarded install does about a stale `guard
// update` cache and returns the lines to show (the caller colours and prints
// them, and drops them under --quiet). staleNotice is the age line from
// newLocalGuard. quiet suppresses the one-time question, never a consented
// refresh.
func staleFeedLines(staleNotice string, quiet bool, d *feedAutoUpdateDeps) []string {
	if d.offline() {
		// guard update refuses offline; the notice already names the remedy.
		return []string{staleNotice}
	}
	consent := d.load().FeedAutoUpdate
	if consent == "" && !quiet && d.interactive() {
		yes := d.confirm("  The malicious-package feed is out of date. Keep it updated automatically in the background?")
		consent = feedAutoUpdateOff
		if yes {
			consent = feedAutoUpdateOn
		}
		st := d.load() // reload: the prompt may have waited on a human
		st.FeedAutoUpdate = consent
		d.save(st)
		if !yes {
			return []string{staleNotice, "auto-update is off (change with `chainsaw guard auto-update on`)"}
		}
	}
	switch consent {
	case feedAutoUpdateOn:
		now := d.now()
		st := d.load()
		if last := time.Unix(st.FeedAutoUpdateSpawnUnix, 0); st.FeedAutoUpdateSpawnUnix != 0 && now.Sub(last) < feedAutoUpdateEvery && !last.After(now) {
			return []string{staleNotice, fmt.Sprintf("a background refresh was started at %s; if it failed, run `chainsaw guard update`", last.Local().Format("15:04"))}
		}
		st.FeedAutoUpdateSpawnUnix = now.Unix()
		d.save(st)
		log, err := d.spawn()
		if err != nil {
			return []string{staleNotice, "auto-update could not start a background refresh (" + err.Error() + "); run `chainsaw guard update`"}
		}
		return []string{"known-malicious feed is out of date; refreshing it in the background (log: " + log + ")"}
	case feedAutoUpdateOff:
		return []string{staleNotice, "auto-update is off (change with `chainsaw guard auto-update on`)"}
	default:
		// Never asked and nobody to ask (CI, piped, --quiet).
		return []string{staleNotice, "or turn on background refresh: `chainsaw guard auto-update on`"}
	}
}

func prodFeedAutoUpdateDeps() *feedAutoUpdateDeps {
	return &feedAutoUpdateDeps{
		interactive: guardPromptInteractive,
		offline:     func() bool { return envTruthy(os.Getenv(guardUpdateOfflineEnv)) },
		confirm:     func(label string) bool { return promptOnStderr(label, false) },
		spawn:       spawnBackgroundGuardUpdate,
		now:         time.Now,
		load:        loadGuardState,
		save:        saveGuardState,
	}
}

// guardPromptInteractive reports whether a guard prompt can reach a human:
// stdin to read the answer AND stderr to show the question. Stdout is
// deliberately not required — `npm install --json > out.json` redirects it,
// and a question written there would corrupt the output and hang unseen.
func guardPromptInteractive() bool {
	return stdinIsTerminal() && term.IsTerminal(int(os.Stderr.Fd()))
}

// promptOnStderr asks a yes/no question on stderr and reads stdin. Empty input
// takes defYes.
func promptOnStderr(label string, defYes bool) bool {
	hint := "[y/N]"
	if defYes {
		hint = "[Y/n]"
	}
	fmt.Fprintf(os.Stderr, "%s %s: ", label, hint)
	sc := bufio.NewScanner(os.Stdin)
	sc.Scan()
	switch strings.ToLower(strings.TrimSpace(sc.Text())) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return defYes
	}
}

// guardUpdateLogPath is where a background refresh writes its output.
func guardUpdateLogPath() string {
	if db := guardDBPath(); db != "" {
		return filepath.Join(filepath.Dir(db), "guard-update.log")
	}
	return filepath.Join(os.TempDir(), "chainsaw-guard-update.log")
}

// spawnBackgroundGuardUpdate starts `chainsaw guard update` detached from the
// install: its own session/process group, no stdin, output to a log file. The
// install does not wait for it. The cache is replaced atomically
// (writeFileAtomic, brew_verify.go), so a concurrent install never reads a
// half-written file.
func spawnBackgroundGuardUpdate() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	logPath := guardUpdateLogPath()
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return "", err
	}
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", err
	}
	defer logf.Close()
	cmd := exec.Command(exe, "guard", "update")
	cmd.Stdin = nil
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = detachedProcAttr()
	if err := cmd.Start(); err != nil {
		return "", err
	}
	_ = cmd.Process.Release()
	return logPath, nil
}

var guardAutoUpdateCmd = &cobra.Command{
	Use:   "auto-update [on|off]",
	Short: "Turn background refresh of the malicious-package feed on or off",
	Long: `Turn background refresh of the malicious-package feed on or off.

When on, a guarded install that finds the feed more than 7 days old starts
"chainsaw guard update" in the background and carries on; the install never
waits for the download. When off, the install says how old the feed is and how
to refresh it by hand. With no argument, prints the current setting.

You are asked once, the first time a guarded install in a terminal finds the
feed out of date. Nothing starts when CHAINSAW_OFFLINE is set.`,
	Args:         cobra.MaximumNArgs(1),
	ValidArgs:    []string{feedAutoUpdateOn, feedAutoUpdateOff},
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		st := loadGuardState()
		out := cmd.OutOrStdout()
		if len(args) == 0 {
			fmt.Fprintf(out, "feed auto-update: %s\n", feedAutoUpdateLabel(st.FeedAutoUpdate))
			return nil
		}
		v := strings.ToLower(strings.TrimSpace(args[0]))
		if v != feedAutoUpdateOn && v != feedAutoUpdateOff {
			return fmt.Errorf("want on or off, got %q", args[0])
		}
		st.FeedAutoUpdate = v
		saveGuardState(st)
		if v == feedAutoUpdateOn {
			fmt.Fprintln(out, "feed auto-update: on — a stale feed refreshes in the background during guarded installs. Refresh now with: chainsaw guard update")
		} else {
			fmt.Fprintln(out, "feed auto-update: off — refresh with: chainsaw guard update")
		}
		return nil
	},
}

func feedAutoUpdateLabel(v string) string {
	switch v {
	case feedAutoUpdateOn:
		return "on"
	case feedAutoUpdateOff:
		return "off"
	default:
		return "not set (asked the first time a guarded install finds the feed out of date)"
	}
}

func init() { guardCmd.AddCommand(guardAutoUpdateCmd) }
