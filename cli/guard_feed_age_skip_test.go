package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/coverage"
	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/malware"
	"github.com/spf13/cobra"
)

// --- feed age ----------------------------------------------------------------

func writeFeedMeta(t *testing.T, cache string, m guardUpdateMeta) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(guardUpdateMetaPath(cache), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeTinyCache(t *testing.T) string {
	t.Helper()
	cache := filepath.Join(t.TempDir(), "known_malicious.json")
	if err := os.WriteFile(cache, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	return cache
}

func TestGuardFeedCheckedAtEvidenceOrder(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "known_malicious.json")
	if got := guardFeedCheckedAt(cache); !got.IsZero() {
		t.Fatalf("no cache: want zero time, got %v", got)
	}
	// A meta whose cache is gone must not date anything.
	writeFeedMeta(t, cache, guardUpdateMeta{Checked: "2026-11-01T00:00:00Z"})
	if got := guardFeedCheckedAt(cache); !got.IsZero() {
		t.Fatalf("meta without cache: want zero time, got %v", got)
	}

	if err := os.WriteFile(cache, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(cache, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(guardUpdateMetaPath(cache))
	if got := guardFeedCheckedAt(cache); !got.Equal(mtime) {
		t.Fatalf("no meta: want mtime %v, got %v", mtime, got)
	}

	// A pre-Checked, pre-Size meta (every cache written before this change)
	// falls back to Updated.
	writeFeedMeta(t, cache, guardUpdateMeta{Updated: "2026-07-14T12:37:20Z"})
	if got := guardFeedCheckedAt(cache).Format(time.RFC3339); got != "2026-07-14T12:37:20Z" {
		t.Fatalf("legacy meta: want Updated, got %s", got)
	}

	writeFeedMeta(t, cache, guardUpdateMeta{Updated: "2026-07-14T12:37:20Z", Checked: "2026-11-01T00:00:00Z", Size: 2})
	if got := guardFeedCheckedAt(cache).Format(time.RFC3339); got != "2026-11-01T00:00:00Z" {
		t.Fatalf("want Checked to win over Updated, got %s", got)
	}

	// The file was swapped or truncated after the meta was written: the meta
	// no longer describes it, so its dates are ignored.
	writeFeedMeta(t, cache, guardUpdateMeta{Checked: "2026-11-01T00:00:00Z", Size: 999})
	if got := guardFeedCheckedAt(cache); !got.Equal(mtime) {
		t.Fatalf("size mismatch: want mtime %v, got %v", mtime, got)
	}
}

func TestGuardFeedIsStaleBoundary(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	if guardFeedIsStale(time.Time{}, now) {
		t.Error("unknown age must not be called stale")
	}
	if guardFeedIsStale(now.Add(-guardFeedStaleAfter), now) {
		t.Error("exactly at the window is still fresh")
	}
	if !guardFeedIsStale(now.Add(-guardFeedStaleAfter-time.Minute), now) {
		t.Error("past the window must be stale")
	}
	if guardFeedIsStale(now.Add(time.Hour), now) {
		t.Error("an hour of clock skew must not be stale")
	}
	if !guardFeedIsStale(now.Add(48*time.Hour), now) {
		t.Error("a date days in the future must not keep the feed fresh")
	}
}

// TestGuardUpdateNotModifiedResetsAge: a 304 confirms the copy is current.
// Without stamping Checked, a quiet upstream would leave the cache "stale"
// forever.
func TestGuardUpdateNotModifiedResetsAge(t *testing.T) {
	cache := writeTinyCache(t)
	t.Setenv(guardDBEnv, cache)
	t.Setenv(guardUpdateOfflineEnv, "")
	writeFeedMeta(t, cache, guardUpdateMeta{ETag: `W/"x"`, Entries: 231864, Updated: "2026-07-14T12:37:20Z", Size: 2})

	old := syncGuardDataset
	syncGuardDataset = func(*malware.Syncer, context.Context) error { return malware.ErrNotModified }
	defer func() { syncGuardDataset = old }()

	cmd := &cobra.Command{}
	cmd.Flags().Bool("force", false, "")
	cmd.Flags().Bool("allow-network", false, "")
	cmd.SetContext(context.Background())
	var err error
	captureStderr(t, func() { err = runGuardUpdate(cmd, nil) })
	if err != nil {
		t.Fatalf("runGuardUpdate: %v", err)
	}

	m := readGuardUpdateMeta(guardUpdateMetaPath(cache))
	if m.ETag != `W/"x"` || m.Entries != 231864 || m.Updated != "2026-07-14T12:37:20Z" || m.Size != 2 {
		t.Fatalf("304 must keep etag/entries/updated/size, got %+v", m)
	}
	if guardFeedIsStale(guardFeedCheckedAt(cache), time.Now()) {
		t.Fatalf("after a 304 the feed must read fresh, meta = %+v", m)
	}
}

// TestBoundMetaDropsOrphans: the meta only short-circuits a download (its ETag
// reaches If-None-Match) while it still describes the file on disk. Otherwise a
// 304 would print "already up to date" over a deleted or truncated cache.
func TestBoundMetaDropsOrphans(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "known_malicious.json")
	writeFeedMeta(t, cache, guardUpdateMeta{ETag: `W/"x"`, Entries: 5, Size: 2})
	if m, _ := readBoundGuardUpdateMeta(cache); m.ETag != "" {
		t.Fatalf("deleted cache: meta must be dropped, got %+v", m)
	}
	// Empty cache with a legacy (size-less) meta: only the emptiness check
	// can catch it.
	if err := os.WriteFile(cache, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	writeFeedMeta(t, cache, guardUpdateMeta{ETag: `W/"x"`, Entries: 5})
	if m, _ := readBoundGuardUpdateMeta(cache); m.ETag != "" {
		t.Fatalf("empty cache: meta must be dropped, got %+v", m)
	}
	writeFeedMeta(t, cache, guardUpdateMeta{ETag: `W/"x"`, Entries: 5, Size: 2})
	if err := os.WriteFile(cache, []byte("[1]"), 0o644); err != nil {
		t.Fatal(err)
	}
	if m, _ := readBoundGuardUpdateMeta(cache); m.ETag != "" {
		t.Fatalf("size mismatch: meta must be dropped, got %+v", m)
	}
	if err := os.WriteFile(cache, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	if m, _ := readBoundGuardUpdateMeta(cache); m.ETag != `W/"x"` {
		t.Fatalf("matching cache: meta must be kept, got %+v", m)
	}
}

func TestReadGuardFeedStatus(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	cache := filepath.Join(t.TempDir(), "known_malicious.json")

	t.Setenv(intelligence.BundleEnvVar, "")
	fs := readGuardFeedStatus(cache, now)
	if fs.Present || !strings.Contains(fs.Label, "embedded floor only") {
		t.Fatalf("absent cache: got %+v", fs)
	}
	t.Setenv(intelligence.BundleEnvVar, "/opt/intel.tar.gz")
	if fs = readGuardFeedStatus(cache, now); !strings.Contains(fs.Label, "/opt/intel.tar.gz") {
		t.Fatalf("absent cache with a bundle configured must name it, got %+v", fs)
	}

	if err := os.WriteFile(cache, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeFeedMeta(t, cache, guardUpdateMeta{Entries: 231864, Updated: "2026-07-14T12:37:20Z"})
	fs = readGuardFeedStatus(cache, now)
	if !fs.Stale || !strings.Contains(fs.Label, "231,864 entries") ||
		!strings.Contains(fs.Label, "2026-07-14") || !strings.Contains(fs.Label, "STALE") {
		t.Fatalf("old cache: got %+v", fs)
	}

	writeFeedMeta(t, cache, guardUpdateMeta{Entries: 231864, Size: 2, Checked: now.Add(-2 * time.Hour).Format(time.RFC3339)})
	fs = readGuardFeedStatus(cache, now)
	if fs.Stale || strings.Contains(fs.Label, "STALE") || !strings.Contains(fs.Label, "today") {
		t.Fatalf("fresh cache: got %+v", fs)
	}

	// Offline: guard update refuses there, so status must not send the user to it.
	writeFeedMeta(t, cache, guardUpdateMeta{Entries: 231864, Updated: "2026-07-14T12:37:20Z"})
	t.Setenv(guardUpdateOfflineEnv, "1")
	if fs = readGuardFeedStatus(cache, now); strings.Contains(fs.Label, "run `chainsaw guard update`") || !strings.Contains(fs.Label, guardDBEnv) {
		t.Fatalf("offline status must point at the delivered file, got %q", fs.Label)
	}
	t.Setenv(guardUpdateOfflineEnv, "")

	// Below the plausibility floor the guard does not count it as the full set.
	writeFeedMeta(t, cache, guardUpdateMeta{Entries: 3, Size: 2, Checked: now.Format(time.RFC3339)})
	if fs = readGuardFeedStatus(cache, now); !strings.Contains(fs.Label, "PARTIAL") {
		t.Fatalf("sub-floor cache must read as partial, got %q", fs.Label)
	}

	// A meta for a different file must not lend its entry count or date.
	writeFeedMeta(t, cache, guardUpdateMeta{Entries: 231864, Size: 999, Checked: now.Format(time.RFC3339)})
	if fs = readGuardFeedStatus(cache, now); fs.Entries != 0 || strings.Contains(fs.Label, "231,864") {
		t.Fatalf("mismatched meta must not be trusted, got %+v", fs)
	}
}

// TestNewLocalGuardFlagsStaleCache is the end-to-end claim: a full-size cache
// last confirmed a month ago makes the guard say so and mark the feed stale,
// and the coverage ledger reports the feed's real age, not "now".
func TestNewLocalGuardFlagsStaleCache(t *testing.T) {
	cache := writeMalwareEntriesFile(t, guardMalwareFeedFloor)
	t.Setenv(guardDBEnv, cache)
	t.Setenv(guardUpdateOfflineEnv, "")
	t.Setenv(intelligence.BundleEnvVar, "")

	old := time.Now().Add(-20 * 24 * time.Hour).UTC().Truncate(time.Second)
	writeFeedMeta(t, cache, guardUpdateMeta{Checked: old.Format(time.RFC3339)})
	g := newLocalGuard()
	if !g.fullFeed || !g.feedStale {
		t.Fatalf("20-day-old full cache: fullFeed=%v feedStale=%v, want both true", g.fullFeed, g.feedStale)
	}
	if !strings.Contains(g.staleNotice, "known-malicious feed last refreshed on ") || !strings.Contains(g.staleNotice, "chainsaw guard update") {
		t.Fatalf("want a stale-feed notice naming guard update, got %q", g.staleNotice)
	}
	if g.feedAge != feedAgeAging {
		t.Fatalf("20 days old is aging (yellow), got %v", g.feedAge)
	}
	if e := guardLedger(g, time.Now())[coverage.SourceMalware]; e.Status != coverage.StatusOK || !e.LastOKAt.Equal(old) {
		t.Fatalf("ledger: want OK with LastOKAt=%v, got %+v", old, e)
	}

	// Offline: guard update refuses, so the notice must not send the user there.
	t.Setenv(guardUpdateOfflineEnv, "1")
	if n := newLocalGuard().staleNotice; strings.Contains(n, "run `chainsaw guard update`") || !strings.Contains(n, guardDBEnv) {
		t.Fatalf("offline stale notice must point at the delivered file, got %q", n)
	}
	t.Setenv(guardUpdateOfflineEnv, "")

	writeFeedMeta(t, cache, guardUpdateMeta{Checked: time.Now().UTC().Format(time.RFC3339)})
	g = newLocalGuard()
	if !g.fullFeed || g.feedStale {
		t.Fatalf("fresh full cache: fullFeed=%v feedStale=%v, want true/false", g.fullFeed, g.feedStale)
	}
	if g.staleNotice != "" || strings.Contains(strings.Join(g.notices, "\n"), "last refreshed") {
		t.Fatalf("fresh cache must not print the stale notice, got %q / %q", g.staleNotice, g.notices)
	}
}

// TestFreshBundleCoversStaleCache: the feed is stale only when EVERY source
// carrying it is stale.
func TestFreshBundleCoversStaleCache(t *testing.T) {
	cache := writeMalwareEntriesFile(t, guardMalwareFeedFloor)
	t.Setenv(guardDBEnv, cache)
	writeFeedMeta(t, cache, guardUpdateMeta{Checked: time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339)})
	b, err := intelligence.LoadBundle(context.Background(), writeMalwareBundle(t, guardMalwareFeedFloor, true), intelligence.BundleVerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	prev := intelligence.SetActiveBundle(b)
	t.Cleanup(func() { intelligence.SetActiveBundle(prev) })

	g := newLocalGuard()
	if g.feedStale {
		t.Fatal("a fresh verified bundle must cover a stale cache")
	}
	if g.staleNotice != "" {
		t.Fatalf("no stale notice when the bundle is fresh, got %q", g.staleNotice)
	}
	if time.Since(g.feedCheckedAt) > time.Hour {
		t.Fatalf("feedCheckedAt must be the fresher source (the bundle), got %v", g.feedCheckedAt)
	}
}

func TestGuardFeedDate(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	cache := now.Add(-30 * 24 * time.Hour)
	if got := guardFeedDate(cache, 0, now); !got.Equal(cache) {
		t.Fatalf("undated bundle must not date the feed: got %v want %v", got, cache)
	}
	if got := guardFeedDate(cache, -time.Hour, now); !got.Equal(cache) {
		t.Fatalf("future-dated bundle must not date the feed: got %v want %v", got, cache)
	}
	if got := guardFeedDate(cache, 24*time.Hour, now); !got.Equal(now.Add(-24 * time.Hour)) {
		t.Fatalf("a fresher bundle wins: got %v", got)
	}
	if got := guardFeedDate(cache, 90*24*time.Hour, now); !got.Equal(cache) {
		t.Fatalf("an older bundle does not win: got %v", got)
	}
	if got := guardFeedDate(time.Time{}, 0, now); !got.IsZero() {
		t.Fatalf("no dated source: want zero, got %v", got)
	}
}

// TestInstallPathNeverPromptsForStaleFeed pins the decision that a stale feed
// is notice-only: the install path offers a download only when the feed is
// absent. A source guard because runGuardedPassthrough execs the real tool.
func TestInstallPathNeverPromptsForStaleFeed(t *testing.T) {
	src, err := os.ReadFile("guard_install.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(src, []byte("maybeAutoFetchFeed(guard.fullFeed, false, prodAutoFetchDeps())")) {
		t.Fatal("guard_install.go must call maybeAutoFetchFeed with stale=false (stale feed is notice-only, decided 2026-11-11)")
	}
}

// --- per-manager skip -----------------------------------------------------------

func runGuardInitForTest(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := &cobra.Command{RunE: runGuardInit}
	cmd.Flags().Bool("install", false, "")
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().StringSlice("skip", nil, "")
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errb.String(), err
}

func TestGuardInitSkip(t *testing.T) {
	t.Setenv(guardSkipEnv, "")
	out, _, err := runGuardInitForTest(t, "zsh", "--skip", "npm,pip")
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"npm()", "pip()", "pip3()"} {
		if strings.Contains(out, "\n"+gone) {
			t.Errorf("--skip npm,pip must drop %s:\n%s", gone, out)
		}
	}
	for _, kept := range []string{"go()", "brew()", "pnpm()", "yarn()"} {
		if !strings.Contains(out, "\n"+kept) {
			t.Errorf("%s must stay wrapped:\n%s", kept, out)
		}
	}

	// pip3 alone leaves pip wrapped.
	out, _, _ = runGuardInitForTest(t, "bash", "--skip", "pip3")
	if strings.Contains(out, "\npip3()") || !strings.Contains(out, "\npip()") {
		t.Errorf("--skip pip3 must drop only pip3:\n%s", out)
	}

	// The env form (what --install writes) is honoured the same way.
	t.Setenv(guardSkipEnv, "brew, go")
	out, _, _ = runGuardInitForTest(t, "zsh")
	if strings.Contains(out, "\nbrew()") || strings.Contains(out, "\ngo()") || !strings.Contains(out, "\nnpm()") {
		t.Errorf("%s=brew,go must drop brew and go only:\n%s", guardSkipEnv, out)
	}
}

// TestGuardInitSkipTypoFailsSafe: at shell startup an error would print no
// functions and unguard EVERY manager over one typo. It must warn and keep
// wrapping everything else.
func TestGuardInitSkipTypoFailsSafe(t *testing.T) {
	t.Setenv(guardSkipEnv, "")
	out, errOut, err := runGuardInitForTest(t, "zsh", "--skip", "nmp")
	if err != nil {
		t.Fatalf("eval-time typo must not fail: %v", err)
	}
	if !strings.Contains(errOut, `"nmp"`) {
		t.Errorf("want a warning naming the typo, got %q", errOut)
	}
	if strings.Count(out, "() { command chainsaw") != len(guardedTools) {
		t.Errorf("typo must leave every manager wrapped:\n%s", out)
	}
}

func TestGuardShimSkipsParsesEveryShellLine(t *testing.T) {
	cases := map[string][]string{
		`eval "$(CHAINSAW_GUARD_SKIP=npm,brew chainsaw guard init zsh)"`:                    {"npm", "brew"},
		`env CHAINSAW_GUARD_SKIP=npm chainsaw guard init fish | source`:                     {"npm"},
		`$env:CHAINSAW_GUARD_SKIP = 'go,pip'; chainsaw guard init pwsh | Invoke-Expression`: {"go", "pip", "pip3"},
		`eval "$(chainsaw guard init zsh --skip npm,brew)"`:                                 {"npm", "brew"},
		`eval "$(chainsaw guard init zsh --skip=pip)"`:                                      {"pip", "pip3"},
		`eval "$(chainsaw guard init zsh --skip "npm, brew")"`:                              {"npm", "brew"},
		`chainsaw guard init fish --skip npm | source`:                                      {"npm"},
		`eval "$(chainsaw guard init zsh)"`:                                                 nil,
		`eval "$(chainsaw guard init zsh)"; alias x='--skip npm'`:                           nil,
	}
	for line, want := range cases {
		got := guardShimSkips(line)
		if len(got) != len(want) {
			t.Errorf("%s: got %v, want %v", line, got, want)
			continue
		}
		for _, fn := range want {
			if !got[fn] {
				t.Errorf("%s: missing %s in %v", line, fn, got)
			}
		}
	}
	// The written line must round-trip through the parser, in every shell.
	for _, shell := range []string{"zsh", "bash", "fish", "pwsh", "powershell"} {
		line := shellSourceLine(shell, []string{"npm", "brew"})
		if !strings.Contains(line, guardShimMarker) || !sameSkipSet(guardShimSkips(line), []string{"npm", "brew"}) {
			t.Errorf("%s line %q does not round-trip", shell, line)
		}
		if strings.Contains(line, "--skip") {
			t.Errorf("%s line %q must carry the list as %s, not a flag an older chainsaw rejects", shell, line, guardSkipEnv)
		}
	}
	// PowerShell's $env: is process-wide: the line must restore it.
	if line := shellSourceLine("pwsh", []string{"npm"}); !strings.HasSuffix(line, "$env:"+guardSkipEnv+" = $__chainsawSkip") {
		t.Errorf("pwsh line must restore %s afterwards, got %q", guardSkipEnv, line)
	}
}

// TestGuardShimSkipsIntersectsLines: a later line with a skip list does not
// unset what an earlier line defined, so a function is unwrapped only when
// every active line skips it.
func TestGuardShimSkipsIntersectsLines(t *testing.T) {
	got := guardShimSkips(
		`eval "$(CHAINSAW_GUARD_SKIP=npm,brew chainsaw guard init zsh)"`,
		`eval "$(CHAINSAW_GUARD_SKIP=npm chainsaw guard init zsh)"`,
	)
	if !got["npm"] || got["brew"] || len(got) != 1 {
		t.Fatalf("want only npm skipped, got %v", got)
	}
	if got := guardShimSkips(`eval "$(CHAINSAW_GUARD_SKIP=npm chainsaw guard init zsh)"`, `eval "$(chainsaw guard init zsh)"`); len(got) != 0 {
		t.Fatalf("an unskipped line wraps everything, got %v", got)
	}
}

func TestInstallGuardInitSkip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rc := filepath.Join(home, ".zshrc")

	install := func(skip []string, explicit bool) (string, error) {
		c := &cobra.Command{}
		var buf bytes.Buffer
		c.SetOut(&buf)
		err := installGuardInit(c, "zsh", skip, explicit)
		return buf.String(), err
	}

	if _, err := install([]string{"npm"}, true); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(rc)
	if !strings.Contains(string(data), `eval "$(CHAINSAW_GUARD_SKIP=npm chainsaw guard init zsh)"`) {
		t.Fatalf("rc missing skip line:\n%s", data)
	}

	if out, err := install([]string{"npm"}, true); err != nil || !strings.Contains(out, "nothing to do") {
		t.Fatalf("same skip list must be a no-op: out=%q err=%v", out, err)
	}

	// The installers re-run a bare `guard init --install` on every upgrade.
	// That must leave the line and its skip list alone and exit 0.
	before, _ := os.ReadFile(rc)
	out, err := install(nil, false)
	if err != nil || !strings.Contains(out, "nothing to do") || !strings.Contains(out, "npm") {
		t.Fatalf("installer re-run must be a no-op naming the skip list: out=%q err=%v", out, err)
	}

	// An explicitly different list must refuse, name the replacement, and
	// leave rc alone.
	_, err = install([]string{"npm", "brew"}, true)
	if err == nil || !strings.Contains(err.Error(), "CHAINSAW_GUARD_SKIP=npm,brew") {
		t.Fatalf("different skip list must refuse with the replacement line, got %v", err)
	}
	after, _ := os.ReadFile(rc)
	if !bytes.Equal(before, after) {
		t.Fatal("refused or no-op install must not modify the rc file")
	}
}

func TestDoctorHonoursGuardSkip(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	withHookEnv(t)
	t.Setenv(guardSkipEnv, "")
	rc := filepath.Join(t.TempDir(), ".zshrc")
	if err := os.WriteFile(rc, []byte("eval \"$(CHAINSAW_GUARD_SKIP=npm chainsaw guard init zsh)\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := shellRCCandidates
	shellRCCandidates = func() []string { return []string{rc} }
	defer func() { shellRCCandidates = prev }()

	cmd := newDoctorCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	_ = cmd.Flags().Set("no-color", "true")
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
	}
	if !rowHasState(t, out.String(), "npm", "skipped") || !strings.Contains(out.String(), "skipped = left out of the shell guard") {
		t.Fatalf("skipped npm must show skipped, with its footnote:\n%s", out.String())
	}
	if !rowHasState(t, out.String(), "pip", "shim") {
		t.Fatalf("pip must still show shim:\n%s", out.String())
	}
}

func TestNoteShellGuardStillRoutes(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	t.Setenv(guardSkipEnv, "")
	rc := filepath.Join(t.TempDir(), ".zshrc")
	prev := shellRCCandidates
	shellRCCandidates = func() []string { return []string{rc} }
	defer func() { shellRCCandidates = prev }()

	note := func(m string) string {
		var b bytes.Buffer
		noteShellGuardStillRoutes(&b, m)
		return b.String()
	}

	if got := note("npm"); got != "" {
		t.Fatalf("no shim: want silence, got %q", got)
	}
	_ = os.WriteFile(rc, []byte("eval \"$(chainsaw guard init zsh)\"\n"), 0o644)
	if got := note("npm"); !strings.Contains(got, "still checked by the shell guard") ||
		!strings.Contains(got, `eval "$(CHAINSAW_GUARD_SKIP=npm chainsaw guard init zsh)"`) {
		t.Fatalf("shimmed npm: want the note with the replacement line, got %q", got)
	}
	// pip is two functions; the session-only advice must cover both.
	if got := note("pip"); !strings.Contains(got, "unset -f pip pip3") || !strings.Contains(got, "CHAINSAW_GUARD_SKIP=pip,pip3") {
		t.Fatalf("pip note must cover pip3 too, got %q", got)
	}
	_ = os.WriteFile(rc, []byte("eval \"$(CHAINSAW_GUARD_SKIP=npm chainsaw guard init zsh)\"\n"), 0o644)
	if got := note("npm"); got != "" {
		t.Fatalf("skipped npm: want silence, got %q", got)
	}
	// The replacement line keeps what was already skipped.
	if got := note("brew"); !strings.Contains(got, "CHAINSAW_GUARD_SKIP=npm,brew") {
		t.Fatalf("replacement line must keep the existing skip, got %q", got)
	}
	// uninstall-hook --all: ONE note with one combined line, not one per manager.
	var b bytes.Buffer
	noteShellGuardStillRoutes(&b, "npm", "brew", "go", "maven")
	if got := b.String(); strings.Count(got, "note:") != 1 || !strings.Contains(got, "CHAINSAW_GUARD_SKIP=npm,go,brew") {
		t.Fatalf("want one combined note, got %q", got)
	}
}

// TestExportedSkipEnvOnlyAppliesToLinesWithoutTheirOwn: a line written by
// --install assigns CHAINSAW_GUARD_SKIP inline, which replaces an exported
// value for that guard init; only plain or --skip lines inherit the export.
func TestExportedSkipEnvOnlyAppliesToLinesWithoutTheirOwn(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	installed := `eval "$(CHAINSAW_GUARD_SKIP=npm chainsaw guard init zsh)"`
	if got := guardShimSkipsWithEnv("pip", installed); got["pip"] || !got["npm"] {
		t.Fatalf("inline assignment must override the export: got %v", got)
	}
	if got := guardShimSkipsWithEnv("pip", `eval "$(chainsaw guard init zsh)"`); !got["pip"] || !got["pip3"] {
		t.Fatalf("a plain line inherits the export: got %v", got)
	}
	if got := guardShimSkipsWithEnv("pip", `eval "$(chainsaw guard init zsh --skip npm)"`); !got["pip"] || !got["npm"] {
		t.Fatalf("a --skip line merges flag and export, as guard init does: got %v", got)
	}

	// uninstall-hook pip must still name the shell guard, and its replacement
	// line must not bake the exported value in.
	rc := filepath.Join(t.TempDir(), ".zshrc")
	if err := os.WriteFile(rc, []byte(installed+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := shellRCCandidates
	shellRCCandidates = func() []string { return []string{rc} }
	defer func() { shellRCCandidates = prev }()
	t.Setenv(guardSkipEnv, "brew")
	var b bytes.Buffer
	noteShellGuardStillRoutes(&b, "pip")
	if got := b.String(); !strings.Contains(got, "CHAINSAW_GUARD_SKIP=npm,pip,pip3 chainsaw") {
		t.Fatalf("want a note whose line keeps npm, adds pip, and omits the exported brew, got %q", got)
	}
}

// TestInstallIgnoresExportedSkipEnv: with CHAINSAW_GUARD_SKIP exported, an
// installer re-run of a bare `guard init --install` must stay a no-op (exit 0),
// not treat the environment as a conflicting request.
func TestInstallIgnoresExportedSkipEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/zsh")
	rc := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(rc, []byte("eval \"$(chainsaw guard init zsh)\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(guardSkipEnv, "npm")
	out, _, err := runGuardInitForTest(t, "zsh", "--install")
	if err != nil || !strings.Contains(out, "nothing to do") {
		t.Fatalf("exported %s must not make --install refuse: out=%q err=%v", guardSkipEnv, out, err)
	}
	// A line WITH a skip list plus an exported variable: still a no-op.
	if err := os.WriteFile(rc, []byte("eval \"$(CHAINSAW_GUARD_SKIP=brew chainsaw guard init zsh)\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, _, err := runGuardInitForTest(t, "zsh", "--install"); err != nil || !strings.Contains(out, "nothing to do") {
		t.Fatalf("skip line + exported %s must not make --install refuse: out=%q err=%v", guardSkipEnv, out, err)
	}

	// Fresh rc: the written line must not bake the exported variable in.
	if err := os.WriteFile(rc, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runGuardInitForTest(t, "zsh", "--install"); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(rc); strings.Contains(string(data), guardSkipEnv) || !strings.Contains(string(data), `eval "$(chainsaw guard init zsh)"`) {
		t.Fatalf("--install must not bake an exported variable into the rc line:\n%s", data)
	}
}

// TestUninstallHookNamesShellGuard is the reported scenario end to end:
// `uninstall-hook npm` on a machine where npm is only shell-shimmed said
// "nothing to do" and nothing else, so the user could not find what was still
// routing npm through the guard.
func TestUninstallHookNamesShellGuard(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	npmrc, _, _ := withHookEnv(t)
	t.Setenv(guardSkipEnv, "")
	if err := os.WriteFile(npmrc, []byte("registry=https://registry.npmjs.org/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rc := filepath.Join(t.TempDir(), ".zshrc")
	if err := os.WriteFile(rc, []byte("eval \"$(chainsaw guard init zsh)\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev := shellRCCandidates
	shellRCCandidates = func() []string { return []string{rc} }
	defer func() { shellRCCandidates = prev }()

	cmd := newUninstallHookCmd()
	cmd.SetArgs([]string{"npm"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if !strings.Contains(errb.String(), "nothing to do") || !strings.Contains(errb.String(), "CHAINSAW_GUARD_SKIP=npm") {
		t.Fatalf("want the no-op line AND the shell-guard note, got: %q", errb.String())
	}
}
