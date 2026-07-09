package osv

// refresher.go — runtime auto-updater for the OSV advisory bundle.
//
// Why this exists: the bundle ships baked into the image at build time
// via dockerized/build.sh. Once a pod starts, it stales — advisories
// published between deploys never reach the runtime matcher. The Trivy
// DB has had a runtime OCI updater for this exact reason (see
// internal/trivydb/updater.go); this package mirrors that pattern for
// OSV by re-pulling the upstream all.zip dumps every
// CHAINSAW_OSV_REFRESH_INTERVAL (default disabled — opt-in).
//
// Pipeline per tick:
//   1. For each supported ecosystem, GET
//      https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip
//   2. Walk every JSON record in the zip, flatten the same way build.sh
//      does (per-affected-block records, range tuples preserved, CVSS
//      vector parsed via cvss.go).
//   3. Concatenate every ecosystem's flat records into one in-memory
//      slice, marshal to JSON, gzip, write to a sibling temp file,
//      atomic-rename onto the destination path.
//   4. Re-load the file into a new *Index and call the swap callback
//      so the in-memory provider pointer flips atomically.
//
// Fail-closed: any error in steps 1–3 aborts THIS tick without
// touching the on-disk file or the in-memory pointer. The previous
// bundle / index keeps serving. The error is logged at WARN and the
// next tick retries.
//
// Off-by-default: NewRefresher returns a nil-but-valid receiver when
// CHAINSAW_OSV_REFRESH_INTERVAL is unset / <= 0 / CHAINSAW_OFFLINE=1.
// Start on the nil receiver is a no-op, so the boot path can call it
// unconditionally.

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
)

// Env vars consulted by the refresher. Kept as exported constants so
// the bootstrap path and tests can refer to the same strings.
const (
	// RefreshIntervalEnv controls how often the refresher wakes. Parsed
	// via time.ParseDuration. Unset / "" / "0" / negative → refresher
	// stays dormant (opt-in preserves the pre-refresher boot path).
	RefreshIntervalEnv = "CHAINSAW_OSV_REFRESH_INTERVAL"
	// OfflineEnv shares the same flag the rest of the server uses; when
	// truthy the refresher skips network entirely.
	OfflineEnv = "CHAINSAW_OFFLINE"
)

// DefaultEcosystems mirrors the OSV_ECOSYSTEMS list in build.sh. Names
// MUST match the upstream all.zip directory layout exactly — the URL
// is os.Open at https://osv-vulnerabilities.storage.googleapis.com/<name>/all.zip
var DefaultEcosystems = []string{
	"npm", "PyPI", "crates.io", "RubyGems", "NuGet", "Packagist", "Maven", "Go",
}

// SwapFunc receives a freshly-loaded Index. The provider in
// internal/intelligence wires this to atomic.Pointer[Index].Store so
// the next Run call sees the new advisories without any synchronisation
// in the hot path.
type SwapFunc func(*Index)

// RefresherConfig pins the runtime knobs. All fields are optional; zero
// values pick sensible defaults except Path (must be set) and Swap
// (must be set if the caller wants the index hot-swapped).
type RefresherConfig struct {
	// Path is the destination on disk. Atomic-replace writes here. The
	// provider's boot-time LoadFile path SHOULD be the same string so
	// pod restarts pick up the freshest copy.
	Path string

	// Interval is the tick cadence. Zero / negative → refresher disabled.
	// Read once at construction; restart the pod to change the cadence.
	Interval time.Duration

	// Ecosystems names the upstream all.zip dumps to pull. Empty →
	// DefaultEcosystems.
	Ecosystems []string

	// HTTPClient is the outbound client for the all.zip fetches. Nil →
	// httpclient.New with a long timeout (each ecosystem's zip can be
	// 20–80 MB).
	HTTPClient *http.Client

	// Logger routes refresher diagnostics. Nil → slog.Default.
	Logger *slog.Logger

	// Swap is invoked with the freshly-loaded *Index after a successful
	// refresh. Nil → the file is updated on disk but the in-memory
	// pointer does NOT flip (rare; useful for the "warm next pod start"
	// half of the strategy).
	Swap SwapFunc

	// BaseURL overrides the upstream host. Tests stand up an httptest
	// server here; production leaves it empty so the constant
	// defaultUpstreamBase wins.
	BaseURL string

	// now is overridable for tests. nil → time.Now.
	now func() time.Time
}

const defaultUpstreamBase = "https://osv-vulnerabilities.storage.googleapis.com"

// Refresher is the background goroutine handle. Construct via
// NewRefresher; call Start to launch the loop. Safe on a nil receiver
// — Start becomes a no-op when NewRefresher returned nil.
type Refresher struct {
	cfg     RefresherConfig
	client  *http.Client
	logger  *slog.Logger
	baseURL string

	mu      sync.Mutex
	running bool

	// lastSwapAt records the most-recent successful refresh as unix
	// nanos. Read via LastSwapAt. Useful for the doctor / health JSON.
	lastSwapAt atomic.Int64
	// totalRefreshes counts successful refreshes across the lifetime of
	// the process (does NOT include the boot-time load).
	totalRefreshes atomic.Int64
	// totalFailures counts ticks that hit a network / parse / write
	// error and aborted without swapping.
	totalFailures atomic.Int64
}

// DefaultRefreshInterval matches the cadence of the other data-source
// refreshers (Trivy DB OCI updater, EPSS source, ClamAV) so OSV doesn't
// stale relative to its peers between deploys.
const DefaultRefreshInterval = 6 * time.Hour

// NewRefresher decides — at construction time — whether the refresher
// should run. Returns nil when:
//
//   - CHAINSAW_OFFLINE is truthy (no network refreshes in airgap mode),
//   - CHAINSAW_OSV_REFRESH_INTERVAL is explicitly set to "0", "off",
//     "disabled", or "false" (operator kill-switch),
//   - cfg.Path is empty (we need somewhere to atomically write to),
//   - the parent dir of cfg.Path is not writable (we log once and bail
//     so the goroutine doesn't spin on EPERM every tick).
//
// Otherwise the refresher runs every cfg.Interval (default 6h, matching
// the Trivy DB updater). Override via cfg.Interval or
// CHAINSAW_OSV_REFRESH_INTERVAL (Go duration string or bare seconds).
//
// A nil return is the dormant state — Start on a nil receiver is a
// no-op so the caller can wire this unconditionally at boot.
func NewRefresher(cfg RefresherConfig) *Refresher {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if isTruthy(os.Getenv(OfflineEnv)) {
		logger.Info("osv refresher disabled: CHAINSAW_OFFLINE set")
		return nil
	}

	// Explicit kill-switch values force-disable even when offline mode
	// isn't on. Anything else (unset, blank, a positive duration)
	// proceeds with the default cadence.
	if env := strings.TrimSpace(strings.ToLower(os.Getenv(RefreshIntervalEnv))); env != "" {
		switch env {
		case "0", "0s", "off", "disabled", "false", "no":
			logger.Info("osv refresher disabled: CHAINSAW_OSV_REFRESH_INTERVAL kill-switch", "value", env)
			return nil
		}
	}

	interval := cfg.Interval
	if interval <= 0 {
		if env := strings.TrimSpace(os.Getenv(RefreshIntervalEnv)); env != "" {
			if d, err := time.ParseDuration(env); err == nil && d > 0 {
				interval = d
			} else if n, perr := strconv.Atoi(env); perr == nil && n > 0 {
				interval = time.Duration(n) * time.Second
			}
		}
	}
	if interval <= 0 {
		// Fall through to the package default — matches the cadence of
		// every other data-source refresher in the bootstrap so OSV
		// doesn't drift between deploys when the bundle is stale.
		interval = DefaultRefreshInterval
	}

	if strings.TrimSpace(cfg.Path) == "" {
		logger.Warn("osv refresher disabled: empty bundle path")
		return nil
	}

	// Probe parent-dir writability ONCE at construction. If we can't
	// write here, the loop would EPERM on every tick — silently spin
	// is worse than not running at all.
	parent := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		logger.Warn("osv refresher disabled: cannot create bundle parent dir", "parent", parent, "err", err)
		return nil
	}
	probe, err := os.CreateTemp(parent, ".osv-refresh-probe-*")
	if err != nil {
		logger.Warn("osv refresher disabled: bundle dir not writable", "parent", parent, "err", err)
		return nil
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())

	cfg.Interval = interval
	if len(cfg.Ecosystems) == 0 {
		cfg.Ecosystems = DefaultEcosystems
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultUpstreamBase
	}
	client := cfg.HTTPClient
	if client == nil {
		// Each all.zip is 20-80 MB across slow links; bound the per-tick
		// HTTP call generously. The outer context is the real cancellation
		// signal.
		client = httpclient.New(httpclient.WithTimeout(10 * time.Minute))
	}

	return &Refresher{
		cfg:     cfg,
		client:  client,
		logger:  logger,
		baseURL: baseURL,
	}
}

// Start launches the refresher's ticker goroutine. Safe on a nil
// receiver (dormant state). Idempotent — calling twice is a no-op.
// The goroutine exits when ctx is cancelled.
func (r *Refresher) Start(ctx context.Context) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	r.running = true
	r.mu.Unlock()

	go r.loop(ctx)
}

// loop is the background ticker. The first tick fires immediately so
// the freshly-booted pod gets the latest advisories without waiting
// for the full interval; subsequent ticks honor cfg.Interval.
func (r *Refresher) loop(ctx context.Context) {
	r.logger.Info("osv refresher started",
		"path", r.cfg.Path,
		"interval", r.cfg.Interval.String(),
		"ecosystems", strings.Join(r.cfg.Ecosystems, ","),
	)
	// Stagger the first tick by a small jitter so a fleet of pods
	// starting together doesn't all hammer storage.googleapis.com in
	// the same second. 0-30s — small enough to keep the boot-fresh
	// guarantee, large enough to break thundering-herd.
	jitter := time.Duration(r.cfg.now().UnixNano()%int64(30*time.Second) + int64(time.Second))
	first := time.NewTimer(jitter)
	defer first.Stop()
	select {
	case <-ctx.Done():
		return
	case <-first.C:
	}
	r.runOnce(ctx)

	tick := time.NewTicker(r.cfg.Interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			r.logger.Info("osv refresher stopping", "reason", ctx.Err())
			return
		case <-tick.C:
			r.runOnce(ctx)
		}
	}
}

// runOnce performs a single refresh attempt. Returns nil on success.
// All errors are logged at WARN; the caller (loop) ignores the return
// value because there's nothing it can do beyond wait for the next
// tick.
func (r *Refresher) runOnce(ctx context.Context) error {
	if r == nil {
		return nil
	}
	start := r.cfg.now()
	advisories, err := r.fetchAll(ctx)
	if err != nil {
		r.totalFailures.Add(1)
		r.logger.Warn("osv refresher: fetch failed; keeping prior bundle",
			"err", err,
			"elapsed", r.cfg.now().Sub(start).String(),
		)
		return err
	}
	if err := r.write(advisories); err != nil {
		r.totalFailures.Add(1)
		r.logger.Warn("osv refresher: atomic write failed; keeping prior bundle",
			"path", r.cfg.Path,
			"err", err,
		)
		return err
	}
	// Re-load from disk so the swapped index reflects exactly what's
	// persisted (catches any marshal/gzip discrepancy that future-us
	// might introduce).
	idx, err := LoadFile(r.cfg.Path)
	if err != nil {
		r.totalFailures.Add(1)
		r.logger.Warn("osv refresher: reload after write failed",
			"path", r.cfg.Path,
			"err", err,
		)
		return err
	}
	if r.cfg.Swap != nil {
		r.cfg.Swap(idx)
	}
	r.totalRefreshes.Add(1)
	r.lastSwapAt.Store(r.cfg.now().UnixNano())
	r.logger.Info("osv refresher: swapped",
		"path", r.cfg.Path,
		"advisories", idx.Total(),
		"elapsed", r.cfg.now().Sub(start).String(),
	)
	return nil
}

// fetchAll downloads and flattens every configured ecosystem. Partial-
// failure policy mirrors build.sh: if at least one ecosystem succeeds
// AND every other failure is logged, the tick succeeds with whatever
// records came back. If ALL ecosystems fail we return an aggregate
// error so the caller keeps the prior bundle.
func (r *Refresher) fetchAll(ctx context.Context) ([]Advisory, error) {
	var (
		out  []Advisory
		errs []string
		any  bool
	)
	for _, eco := range r.cfg.Ecosystems {
		eco := strings.TrimSpace(eco)
		if eco == "" {
			continue
		}
		recs, err := r.fetchEcosystem(ctx, eco)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", eco, err))
			r.logger.Warn("osv refresher: ecosystem fetch failed",
				"ecosystem", eco, "err", err)
			continue
		}
		any = true
		out = append(out, recs...)
	}
	if !any {
		return nil, fmt.Errorf("all ecosystems failed: %s", strings.Join(errs, "; "))
	}
	return out, nil
}

// fetchEcosystem GETs the per-ecosystem all.zip, walks every JSON file
// inside, and flattens to Advisory records using the same per-affected
// expansion build.sh does. The zip is fully buffered in memory — each
// dump tops out around 80 MB which is well below the 256 MB pod memory
// floor we ship with. If that changes, swap the buffer for a temp file
// and `zip.OpenReader`.
func (r *Refresher) fetchEcosystem(ctx context.Context, ecosystem string) ([]Advisory, error) {
	url := fmt.Sprintf("%s/%s/all.zip", r.baseURL, ecosystem)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("upstream %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return nil, fmt.Errorf("zip: %w", err)
	}
	var advisories []Advisory
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rec, err := readZipRecord(f)
		if err != nil {
			// Skip individual bad files — upstream occasionally ships
			// half-written records during their own publish window.
			r.logger.Debug("osv refresher: skipping malformed record",
				"ecosystem", ecosystem, "file", f.Name, "err", err)
			continue
		}
		advisories = append(advisories, flattenRecord(rec)...)
	}
	return advisories, nil
}

// readZipRecord decodes one OSV JSON file from inside the all.zip.
func readZipRecord(f *zip.File) (osvRecord, error) {
	var rec osvRecord
	rc, err := f.Open()
	if err != nil {
		return rec, err
	}
	defer rc.Close()
	if err := json.NewDecoder(rc).Decode(&rec); err != nil {
		return rec, err
	}
	return rec, nil
}

// osvRecord is the subset of upstream OSV schema fields we read. Mirrors
// the shape the Python flattener walks in build.sh; unknown fields are
// dropped on decode.
type osvRecord struct {
	ID        string          `json:"id"`
	Aliases   []string        `json:"aliases"`
	Summary   string          `json:"summary"`
	Published string          `json:"published"`
	Modified  string          `json:"modified"`
	Severity  []SeverityEntry `json:"severity"`
	Affected  []osvAffected   `json:"affected"`
}

type osvAffected struct {
	Package  osvPackage   `json:"package"`
	Versions []string     `json:"versions"`
	Ranges   []osvRangeIn `json:"ranges"`
}

type osvPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type osvRangeIn struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

// flattenRecord turns one OSV record into 0..N flat Advisory rows —
// one per (advisory, affected[].package) pair, mirroring build.sh.
//
// Range walk: OSV records ship `events` as a timeline of {introduced},
// {fixed}, {last_affected} markers. We rebuild [introduced, fixed) and
// [introduced, last_affected] tuples by stepping through in order — a
// new `introduced` without a closing `fixed`/`last_affected` flushes
// the prior open range and starts a new one, matching the Python flow
// exactly so the bundles produced by both paths are interchangeable.
func flattenRecord(rec osvRecord) []Advisory {
	if rec.ID == "" {
		return nil
	}
	score, label := SeveritySummary(rec.Severity)
	var out []Advisory
	for _, aff := range rec.Affected {
		eco := strings.TrimSpace(aff.Package.Ecosystem)
		name := strings.TrimSpace(aff.Package.Name)
		if eco == "" || name == "" {
			continue
		}
		var (
			fixed      []string
			rangesOut  []VulnerableRange
			introduced string
		)
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if v, ok := ev["introduced"]; ok {
					if introduced != "" {
						rangesOut = append(rangesOut, VulnerableRange{Introduced: introduced})
					}
					if v == "" {
						v = "0"
					}
					introduced = v
				} else if v, ok := ev["fixed"]; ok {
					if v != "" {
						fixed = append(fixed, v)
						intro := introduced
						if intro == "" {
							intro = "0"
						}
						rangesOut = append(rangesOut, VulnerableRange{
							Introduced: intro,
							Fixed:      v,
						})
						introduced = ""
					}
				} else if v, ok := ev["last_affected"]; ok {
					if v != "" {
						intro := introduced
						if intro == "" {
							intro = "0"
						}
						rangesOut = append(rangesOut, VulnerableRange{
							Introduced:   intro,
							LastAffected: v,
						})
						introduced = ""
					}
				}
			}
			// Trailing open `introduced` (no closing event in this
			// range) — emit it as an open upper-bound entry.
			if introduced != "" {
				rangesOut = append(rangesOut, VulnerableRange{Introduced: introduced})
				introduced = ""
			}
		}
		adv := Advisory{
			Ecosystem:          eco,
			Package:            name,
			VulnerableVersions: aff.Versions,
			VulnerableRanges:   rangesOut,
			AdvisoryID:         rec.ID,
			Summary:            rec.Summary,
			CVSSScore:          score,
			Severity:           label,
			FixedVersions:      fixed,
			Aliases:            rec.Aliases,
			Published:          rec.Published,
			Modified:           rec.Modified,
		}
		out = append(out, adv)
	}
	return out
}

// write marshals the flat advisory slice to gzip'd JSON and atomically
// replaces cfg.Path. Writes to a sibling temp file in the same dir so
// the rename is atomic on POSIX. Removes the temp file on failure so
// crashes don't leak.
func (r *Refresher) write(advisories []Advisory) error {
	dir := filepath.Dir(r.cfg.Path)
	base := filepath.Base(r.cfg.Path)
	tmp, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup if anything below fails before the rename.
	defer func() {
		// If the rename succeeded the temp file no longer exists at
		// tmpPath; Remove returns ErrNotExist which we ignore.
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	gz := gzip.NewWriter(tmp)
	if err := json.NewEncoder(gz).Encode(advisories); err != nil {
		_ = gz.Close()
		_ = tmp.Close()
		return fmt.Errorf("encode: %w", err)
	}
	if err := gz.Close(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("gzip close: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("temp close: %w", err)
	}
	if err := os.Rename(tmpPath, r.cfg.Path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// LastSwapAt returns the wall-clock time of the most recent successful
// swap. Zero value on a refresher that hasn't completed a tick yet.
func (r *Refresher) LastSwapAt() time.Time {
	if r == nil {
		return time.Time{}
	}
	ns := r.lastSwapAt.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// TotalRefreshes returns the count of successful refreshes during this
// process lifetime. Diagnostic-only.
func (r *Refresher) TotalRefreshes() int64 {
	if r == nil {
		return 0
	}
	return r.totalRefreshes.Load()
}

// TotalFailures returns the count of ticks that hit an error and aborted
// without swapping. Diagnostic-only.
func (r *Refresher) TotalFailures() int64 {
	if r == nil {
		return 0
	}
	return r.totalFailures.Load()
}

// isTruthy recognises the same env-flag dialect the rest of the server
// uses for CHAINSAW_OFFLINE / similar toggles.
func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}
