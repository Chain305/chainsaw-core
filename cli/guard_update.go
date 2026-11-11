package cli

// `chainsaw guard update` — the ONLY networked part of the install guard, and
// only when you run it (D1-R: opt-in enrichment). Fetches the full OpenSSF
// malicious-packages dataset and writes a single local cache file that the
// guard merges on top of its built-in offline floor. After this, the guard's
// known-malicious coverage is the full set, still evaluated locally.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// guardUpdateMeta is the sidecar written next to the known-malicious cache so a
// re-run can send a conditional request (If-None-Match) and skip the multi-MB
// download + re-index when the remote dataset is unchanged.
type guardUpdateMeta struct {
	ETag    string `json:"etag"`
	Entries int    `json:"entries"`
	Updated string `json:"updated"`
	// Checked is when the cache was last CONFIRMED current against upstream:
	// a fresh download or a 304 Not Modified. Updated only moves on a
	// download, so reading feed age off Updated alone would call a cache
	// stale forever on a quiet upstream and re-offer a refresh on every
	// install. Absent in metas written before this field existed; readers
	// fall back to Updated, then the file's mtime (guardFeedCheckedAt).
	Checked string `json:"checked,omitempty"`
	// Size is the cache file's byte size when this meta was written. It binds
	// the meta to the file it describes: a cache truncated, replaced, restored
	// from an older backup or deleted after the meta was written no longer
	// matches, and its meta (ETag, entry count, dates) is then ignored. Zero in
	// metas written before this field existed (no binding check possible).
	Size int64 `json:"size,omitempty"`
}

func guardUpdateMetaPath(cache string) string { return cache + ".meta" }

// guardFeedStaleAfter is how old the `guard update` cache may get before the
// guard calls it stale. OpenSSF publishes new malicious-package advisories
// every day; before this existed the cache was trusted forever, so a machine
// that ran `guard update` once kept reporting "full OpenSSF set" for months
// while missing everything published since.
const guardFeedStaleAfter = 7 * 24 * time.Hour

// guardFeedCheckedAt returns when the `guard update` cache at cachePath was
// last confirmed current, or the zero time when no non-empty cache exists.
// Order of evidence: meta Checked, meta Updated (only while the meta still
// matches the file, see readBoundGuardUpdateMeta), then the file's mtime.
func guardFeedCheckedAt(cachePath string) time.Time {
	m, fi := readBoundGuardUpdateMeta(cachePath)
	if fi == nil {
		return time.Time{}
	}
	for _, v := range []string{m.Checked, m.Updated} {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
	}
	return fi.ModTime()
}

// guardFeedAgeLabel renders a feed timestamp for humans: "on 2026-07-14 (120
// days ago)", or "today" / "yesterday" for the obvious cases.
func guardFeedAgeLabel(checked, now time.Time) string {
	days := int(now.Sub(checked).Hours() / 24)
	switch {
	case checked.Sub(now) > 24*time.Hour:
		return fmt.Sprintf("with a date in the future (%s)", checked.UTC().Format("2006-01-02"))
	case days <= 0:
		return "today"
	case days == 1:
		return "yesterday"
	}
	return fmt.Sprintf("on %s (%d days ago)", checked.UTC().Format("2006-01-02"), days)
}

// guardFeedIsStale reports whether a cache last confirmed at checked is past
// guardFeedStaleAfter. An unknown (zero) time is not called stale: there is
// no cache to refresh, and the absent-feed path already nudges.
//
// A time more than a day in the FUTURE is also stale: it comes from clock skew
// or a copied/extracted file, and trusting it would keep the feed "fresh"
// until that date arrives.
func guardFeedIsStale(checked, now time.Time) bool {
	if checked.IsZero() {
		return false
	}
	return now.Sub(checked) > guardFeedStaleAfter || checked.Sub(now) > 24*time.Hour
}

func readGuardUpdateMeta(path string) guardUpdateMeta {
	var m guardUpdateMeta
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func writeGuardUpdateMeta(path string, m guardUpdateMeta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, 0o644)
}

// warnGuardMetaWrite reports a meta sidecar that could not be written. The
// meta now carries the feed's freshness, so a silent failure would leave
// `guard status` reporting STALE right after `guard update` said it was done.
func warnGuardMetaWrite(path string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "chainsaw: WARNING — could not record the refresh time in %s (%v); the feed will keep reporting as stale until this file is writable\n", path, err)
	}
}

// readBoundGuardUpdateMeta returns the meta for cachePath only when it still
// describes that file: the cache exists, is non-empty, and (for metas that
// record it) has the size the meta was written for. Otherwise it returns the
// zero meta, so no stale ETag, entry count or date outlives its file.
func readBoundGuardUpdateMeta(cachePath string) (guardUpdateMeta, os.FileInfo) {
	fi, err := os.Stat(cachePath)
	if err != nil || fi.Size() == 0 {
		return guardUpdateMeta{}, nil
	}
	m := readGuardUpdateMeta(guardUpdateMetaPath(cachePath))
	if m.Size != 0 && m.Size != fi.Size() {
		return guardUpdateMeta{}, fi
	}
	return m, fi
}

// newGuardUpdateProgress builds a malware.ProgressFunc that reports download
// liveness to w. On a terminal it rewrites a single line with a running byte
// total; in non-interactive contexts (CI capturing stderr) it emits a newline
// heartbeat every ~16 MB so the log shows progress without thousands of lines.
func newGuardUpdateProgress(w io.Writer, tty bool) malware.ProgressFunc {
	if tty {
		return func(n int64) {
			fmt.Fprintf(w, "\r  downloaded %-12s", humanBytes(n))
		}
	}
	const heartbeat = 16 << 20 // 16 MB
	var lastMark int64
	return func(n int64) {
		if n-lastMark >= heartbeat {
			lastMark = n
			fmt.Fprintf(w, "chainsaw: downloaded %s…\n", humanBytes(n))
		}
	}
}

// humanBytes renders a byte count in IEC units (KiB-style, base 1024) with a
// single decimal place above 1 KB.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

var guardCmd = &cobra.Command{
	Use:     "guard",
	Short:   "Install-path guard maintenance",
	GroupID: GrpGuard,
}

var guardUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Fetch the full known-malicious set for offline use (opt-in; uses the network)",
	Long: `Download the OpenSSF malicious-packages dataset and write a local cache that
the install guard (chainsaw npm/pip/go) merges on top of its built-in offline
floor. This is the only part of the guard that touches the network, and only
when you run it. After updating, known-malicious coverage is the full set,
evaluated entirely on-box.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runGuardUpdateExplicit,
}

// runGuardUpdateExplicit is the cobra entry point, and exists ONLY to mark
// "a human typed `chainsaw guard update`" as distinct from "the guarded
// install path called the fetch on its own".
//
// L-21: the auto path calls runGuardUpdate DIRECTLY (guard_autofetch.go), so a
// thin wrapper on the cobra side is unambiguous, whereas trying to detect the
// caller inside runGuardUpdate would be a guess. The failure backoff is
// cleared BEFORE the attempt, not after a success: a user who has just fixed
// their proxy and reached for the manual command must never be told to wait,
// and must never be left in backoff because the fix was only partial.
func runGuardUpdateExplicit(cmd *cobra.Command, args []string) error {
	clearFeedFetchBackoff()
	return runGuardUpdate(cmd, args)
}

// guardUpdateOfflineEnv is the offline umbrella. `guard update` is the ONE
// networked guard command, so it must honour it: an operator who declared the
// box offline should get a clear refusal, not an outbound GET and a DNS error.
// Read via envTruthy so `1/true/yes/on` (any case, trimmed) all count — the same
// reading as intelligence.IsOffline and coverage.isTruthy. core/cli does not
// import chainsaw-core/config, so config.IsOffline() is not callable here
// without adding a package edge.
const guardUpdateOfflineEnv = "CHAINSAW_OFFLINE"

func init() {
	guardUpdateCmd.Flags().Bool("force", false, "re-download and re-index even if the dataset is unchanged (skip the ETag check)")
	guardUpdateCmd.Flags().Bool("allow-network", false, "fetch even when "+guardUpdateOfflineEnv+" is set (this command is the guard's only network call)")
	guardCmd.AddCommand(guardUpdateCmd)
	rootCmd.AddCommand(guardCmd)
}

// syncGuardDataset is the one network call guard update makes. A var so the
// BUG-04 regression test can see the context that actually reaches the
// syncer; production never reassigns it.
var syncGuardDataset = (*malware.Syncer).Sync

func runGuardUpdate(cmd *cobra.Command, _ []string) error {
	// Offline umbrella. The escape hatch is not polish: CHAINSAW_OFFLINE is also
	// documented as a telemetry kill switch, so someone who set it for THAT
	// reason must be able to keep refreshing their malware feed — a bare refusal
	// would be a baffling wall. Name both ways forward in the message: the flag
	// for a box that does have egress, and the signed bundle for one that
	// genuinely does not.
	if allowNetwork, _ := cmd.Flags().GetBool("allow-network"); !allowNetwork {
		if envTruthy(os.Getenv(guardUpdateOfflineEnv)) {
			return fmt.Errorf("%s is set, and this is the guard's only networked command; "+
				"re-run with --allow-network to fetch anyway, or deliver the feed offline via a "+
				"signed intelligence bundle (CHAINSAW_INTEL_BUNDLE_PATH) or a pre-populated %s file",
				guardUpdateOfflineEnv, guardDBEnv)
		}
	}

	dst := guardDBPath()
	if dst == "" {
		return fmt.Errorf("cannot determine cache path; set %s to a writable file path", guardDBEnv)
	}
	force, _ := cmd.Flags().GetBool("force")
	metaPath := guardUpdateMetaPath(dst)
	// Only a meta that still describes the cache on disk may short-circuit the
	// download: with the cache deleted, emptied, truncated or swapped, a 304
	// would report "already up to date" over a file the guard cannot use.
	prevMeta, _ := readBoundGuardUpdateMeta(dst)

	// No whole-command deadline. There used to be a 5-minute WithTimeout here,
	// and it was BUG-04 all over again one layer up: it flowed into
	// syncer.Sync and capped the malware package's own 1h refresh ceiling, so
	// a ~46 MB tarball that was downloading and extracting perfectly well on a
	// slow link (or a slow disk — Defender scanning each of ~239k files) died
	// with a bare "context deadline exceeded". The syncer bounds every phase
	// itself: response headers (ResponseHeaderTimeout), body silence
	// (downloadStallWindow, 90s) and the whole refresh (maxRefreshDuration,
	// 1h). Ctrl-C still cancels via cmd.Context().
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	syncDir, err := os.MkdirTemp("", "chainsaw-malware-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(syncDir)

	fmt.Fprintln(os.Stderr, "chainsaw: fetching the OpenSSF malicious-packages dataset…")

	// The pull streams a multi-MB tarball and can take tens of seconds on a
	// slow link. Without progress it reads as a hang — the worst thing for a
	// security update to look like. Show liveness: a carriage-return byte
	// counter on a terminal, a coarse newline heartbeat in non-TTY logs (CI),
	// and nothing at all when the syncer is driven headless elsewhere.
	stderrTTY := term.IsTerminal(int(os.Stderr.Fd()))
	inner := newGuardUpdateProgress(os.Stderr, stderrTTY)

	// The byte counter only fires once data flows. If the server stalls before
	// the first byte (DNS, TLS, a slow upstream), nothing would print until the
	// syncer's response-header timeout and the run would look wedged. A watchdog ticks a
	// heartbeat until the first byte arrives, then goes quiet and lets the
	// counter take over. `gotByte` gates the two so they never interleave.
	var gotByte atomic.Bool
	progress := func(n int64) {
		gotByte.Store(true)
		inner(n)
	}
	watchdogDone := make(chan struct{})
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-watchdogDone:
				return
			case <-t.C:
				if !gotByte.Load() {
					fmt.Fprintln(os.Stderr, "chainsaw: still waiting for the server to respond…")
				}
			}
		}
	}()

	idx := malware.NewIndex(guardLogger)
	opts := []malware.SyncerOption{malware.WithProgress(progress)}
	// Conditional fetch: unless --force, send the ETag from the last update so
	// an unchanged dataset returns 304 and we skip the ~46 MB download + the
	// minute-long re-index entirely.
	if !force && prevMeta.ETag != "" {
		opts = append(opts, malware.WithIfNoneMatch(prevMeta.ETag))
	}
	syncer := malware.NewSyncer(idx, syncDir, guardLogger, opts...)
	err = syncGuardDataset(syncer, ctx)
	close(watchdogDone)
	if errors.Is(err, malware.ErrNotModified) {
		if stderrTTY && gotByte.Load() {
			fmt.Fprintln(os.Stderr) // close the in-place progress line
		}
		// Upstream confirmed our copy is current: that resets the feed's age.
		prevMeta.Checked = time.Now().UTC().Format(time.RFC3339)
		warnGuardMetaWrite(metaPath, writeGuardUpdateMeta(metaPath, prevMeta))
		fmt.Fprintf(os.Stderr, "chainsaw: already up to date — %s known-malicious entries, unchanged since the last update (skipped the re-download). Use --force to refresh anyway.\n", humanCount(prevMeta.Entries))
		return nil
	}
	if err != nil {
		if stderrTTY && gotByte.Load() {
			fmt.Fprintln(os.Stderr) // close the in-place progress line
		}
		return fmt.Errorf("fetch failed: %w", err)
	}
	if stderrTTY && gotByte.Load() {
		fmt.Fprintln(os.Stderr) // close the in-place progress line
	}

	// The download is done; the next phase — walking + parsing ~200k advisory
	// files, then marshaling and writing a ~200 MB cache — used to run silently
	// and looked like a hang. Report a running count so it reads as progress.
	fmt.Fprintln(os.Stderr, "chainsaw: indexing the malicious-package dataset (one-time; this takes a minute or two)…")
	indexProgress := func(n int) {
		if stderrTTY {
			fmt.Fprintf(os.Stderr, "\r  indexed %s advisories…", humanCount(n))
		} else {
			fmt.Fprintf(os.Stderr, "chainsaw: indexed %s advisories…\n", humanCount(n))
		}
	}
	entries := collectOSVEntries(filepath.Join(syncDir, "malicious-packages", "active", "osv", "malicious"), indexProgress)
	finishIndexProgress(os.Stderr, stderrTTY, len(entries))
	if len(entries) == 0 {
		return fmt.Errorf("dataset fetch produced no entries (layout change?)")
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "chainsaw: writing the offline cache (%s advisories)…\n", humanCount(len(entries)))
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	// Atomic: a guarded install (or a second background refresh) reading the
	// cache mid-write would otherwise see a truncated file.
	if err := writeFileAtomic(dst, data, 0o644); err != nil {
		return err
	}
	// Persist the ETag, count, size and refresh time. The ETag lets the next
	// run send If-None-Match; the time is the feed's age (guardFeedCheckedAt),
	// so a failed write is reported rather than swallowed.
	now := time.Now().UTC().Format(time.RFC3339)
	warnGuardMetaWrite(metaPath, writeGuardUpdateMeta(metaPath, guardUpdateMeta{
		ETag:    syncer.ETag(),
		Entries: len(entries),
		Updated: now,
		Checked: now,
		Size:    int64(len(data)),
	}))
	fmt.Fprintf(os.Stderr, "chainsaw: wrote %s known-malicious entries to %s\n", humanCount(len(entries)), dst)
	fmt.Fprintln(os.Stderr, "chainsaw: the guard will now use the full set offline.")
	// The typosquat popular corpus is deliberately NOT refreshed here:
	// corpus membership grants the exact-match exemption, so it only rides
	// trust-reviewed channels — the embedded generated seed (a chainsaw
	// upgrade) or a Sigstore-verified intelligence bundle. An unsigned
	// cache file would let a compromised install self-exempt by editing it.
	fmt.Fprintln(os.Stderr, "chainsaw: typosquat corpus refreshes via chainsaw upgrades or a signed intelligence bundle (CHAINSAW_INTEL_BUNDLE_PATH).")
	return nil
}

// finishIndexProgress closes the in-place indexing progress line.
//
// BUG-F-005: on a TTY the heartbeat redraws "\r  indexed 220,000 advisories…"
// every osvIndexProgressStep, and the close used to be a bare newline — so the
// last thing the user saw on that line was the final HEARTBEAT (220,000), not
// the total (237,079), and the two numbers read as an undercount. The close is
// now a final redraw carrying the total. The trailing space before the newline
// overwrites the heartbeat's "…" (the total is the same width as the last tick
// minus the ellipsis), so the finished line does not read as still-running.
//
// The non-TTY path writes nothing here: its heartbeats are newline-terminated
// log lines and the "writing the offline cache (N advisories)" line that
// follows already carries the total. The hook is deliberately NOT fired inside
// collectOSVEntries, which would change its tick sequence and break the
// `[2 4]` pin in TestCollectOSVEntriesProgress.
func finishIndexProgress(w io.Writer, tty bool, n int) {
	if !tty {
		return
	}
	fmt.Fprintf(w, "\r  indexed %s advisories \n", humanCount(n))
}

// osvIndexProgressStep is how often collectOSVEntries reports its running
// count. The OpenSSF dataset holds ~200k+ advisories; walking and parsing them
// is the multi-minute phase that used to run SILENTLY after the download, so a
// heartbeat every 20k keeps the terminal from looking frozen.
var osvIndexProgressStep = 20000

// humanCount formats an integer with thousands separators (e.g. 228044 ->
// "228,044") for the progress lines.
func humanCount(n int) string {
	s := strconv.Itoa(n)
	if n < 1000 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// collectOSVEntries walks a directory of OSV JSON files (the OpenSSF dataset
// layout) and parses each into an entry. Skips unreadable/unparseable files.
// onCount, when non-nil, is called with the running entry total every
// osvIndexProgressStep entries so the caller can report progress.
func collectOSVEntries(dir string, onCount func(n int)) []*malware.OSVEntry {
	var entries []*malware.OSVEntry
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		if data, rerr := os.ReadFile(path); rerr == nil {
			if e, perr := malware.ParseOSVEntry(data); perr == nil {
				entries = append(entries, e)
				if onCount != nil && len(entries)%osvIndexProgressStep == 0 {
					onCount(len(entries))
				}
			}
		}
		return nil
	})
	return entries
}
