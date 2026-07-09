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
}

func guardUpdateMetaPath(cache string) string { return cache + ".meta" }

func readGuardUpdateMeta(path string) guardUpdateMeta {
	var m guardUpdateMeta
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func writeGuardUpdateMeta(path string, m guardUpdateMeta) {
	if b, err := json.Marshal(m); err == nil {
		_ = os.WriteFile(path, b, 0o644)
	}
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
	RunE:         runGuardUpdate,
}

func init() {
	guardUpdateCmd.Flags().Bool("force", false, "re-download and re-index even if the dataset is unchanged (skip the ETag check)")
	guardCmd.AddCommand(guardUpdateCmd)
	rootCmd.AddCommand(guardCmd)
}

func runGuardUpdate(cmd *cobra.Command, _ []string) error {
	dst := guardDBPath()
	if dst == "" {
		return fmt.Errorf("cannot determine cache path; set %s to a writable file path", guardDBEnv)
	}
	force, _ := cmd.Flags().GetBool("force")
	metaPath := guardUpdateMetaPath(dst)
	prevMeta := readGuardUpdateMeta(metaPath)

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

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
	// the first byte (DNS, TLS, a slow upstream), nothing would print for up to
	// the 5-minute timeout and the run would look wedged. A watchdog ticks a
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
	// an unchanged dataset returns 304 and we skip the ~32 MB download + the
	// minute-long re-index entirely.
	if !force && prevMeta.ETag != "" {
		opts = append(opts, malware.WithIfNoneMatch(prevMeta.ETag))
	}
	syncer := malware.NewSyncer(idx, syncDir, guardLogger, opts...)
	err = syncer.Sync(ctx)
	close(watchdogDone)
	if errors.Is(err, malware.ErrNotModified) {
		if stderrTTY && gotByte.Load() {
			fmt.Fprintln(os.Stderr) // close the in-place progress line
		}
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
	if stderrTTY {
		fmt.Fprintln(os.Stderr) // close the in-place progress line
	}
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
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	// Persist the ETag + count so the next run can send If-None-Match and skip
	// the download when nothing changed. Best-effort: a write failure just means
	// the next update re-downloads (correct, only slower).
	writeGuardUpdateMeta(metaPath, guardUpdateMeta{
		ETag:    syncer.ETag(),
		Entries: len(entries),
		Updated: time.Now().UTC().Format(time.RFC3339),
	})
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
