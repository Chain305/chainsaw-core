package osv

// refresher_test.go — covers the OSV runtime refresher. Two themes:
//
//  1. CVSS parity: the runtime CVSS-vector parser (cvss.go) must agree
//     with the build-time Python parser bit-for-bit. The cases below
//     are lifted directly from dockerized/test-osv-severity.sh so the
//     two paths stay in lockstep.
//
//  2. End-to-end refresh: stand up an httptest server that serves
//     a synthetic per-ecosystem all.zip, point a Refresher at it,
//     trigger one runOnce, and assert that the destination file is
//     written, decodable, and atomically swapped into the provided
//     swap callback.

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testLogger discards every log line so test output stays clean.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestSeveritySummary_CVSSParity mirrors dockerized/test-osv-severity.sh.
// Any divergence between this and the build.sh embedded parser means a
// freshly-refreshed bundle would carry different scores than the
// image-baked one for the same advisory.
func TestSeveritySummary_CVSSParity(t *testing.T) {
	cases := []struct {
		name      string
		entries   []SeverityEntry
		wantScore float64
		wantLabel string
	}{
		{
			name:      "CVSS:3.1 NetworkLow CIA=H -> 9.8 CRITICAL",
			entries:   []SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			wantScore: 9.8, wantLabel: "CRITICAL",
		},
		{
			name:      "CVSS:3.1 A:H only -> 7.5 HIGH",
			entries:   []SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}},
			wantScore: 7.5, wantLabel: "HIGH",
		},
		{
			name:      "CVSS:3.0 same shape -> 9.8 CRITICAL",
			entries:   []SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			wantScore: 9.8, wantLabel: "CRITICAL",
		},
		{
			name:      "bare float keeps legacy path",
			entries:   []SeverityEntry{{Type: "CVSS_V3", Score: "7.5"}},
			wantScore: 7.5, wantLabel: "HIGH",
		},
		{
			name:      "CVSS:4.0 vector skipped (no inline lookup)",
			entries:   []SeverityEntry{{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}},
			wantScore: 0.0, wantLabel: "",
		},
		{
			name:      "malformed vector returns 0",
			entries:   []SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/garbage"}},
			wantScore: 0.0, wantLabel: "",
		},
		{
			name:      "MEDIUM band AC:H -> 4.8",
			entries:   []SeverityEntry{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"}},
			wantScore: 4.8, wantLabel: "MEDIUM",
		},
	}
	const tol = 0.05
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			score, label := SeveritySummary(tc.entries)
			if abs(score-tc.wantScore) > tol {
				t.Errorf("score=%v want %v", score, tc.wantScore)
			}
			if label != tc.wantLabel {
				t.Errorf("label=%q want %q", label, tc.wantLabel)
			}
		})
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

// buildSyntheticZip emits an in-memory zip containing the supplied OSV
// JSON records, mirroring the all.zip dump layout (one file per record).
func buildSyntheticZip(t *testing.T, records []map[string]any) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, rec := range records {
		f, err := zw.Create(rec["id"].(string) + ".json")
		if err != nil {
			t.Fatalf("zip create %d: %v", i, err)
		}
		if err := json.NewEncoder(f).Encode(rec); err != nil {
			t.Fatalf("encode %d: %v", i, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// TestRefresher_FlattenAndSwap exercises the full pipeline against a
// stubbed upstream: download → unzip → flatten → atomic write → reload
// → swap. Asserts the swapped index sees the synthetic record and the
// destination file is a valid gzip'd bundle.
func TestRefresher_FlattenAndSwap(t *testing.T) {
	// One synthetic record matching the OSV upstream shape — including
	// both a `versions` list and a `ranges` block so flattenRecord
	// exercises the timeline walk.
	rec := map[string]any{
		"id":      "GHSA-fake-0001",
		"summary": "synthetic advisory for refresher test",
		"aliases": []string{"CVE-2099-0001"},
		"severity": []map[string]any{
			{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
		"affected": []map[string]any{
			{
				"package":  map[string]any{"ecosystem": "npm", "name": "synthetic-pkg"},
				"versions": []string{"1.0.0"},
				"ranges": []map[string]any{
					{
						"type": "SEMVER",
						"events": []map[string]string{
							{"introduced": "0"},
							{"fixed": "1.0.1"},
						},
					},
				},
			},
		},
	}
	zipBytes := buildSyntheticZip(t, []map[string]any{rec})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !strings.HasSuffix(req.URL.Path, "/all.zip") {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(zipBytes)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "osv-bundle.json.gz")

	var swapped *Index
	r := &Refresher{
		cfg: RefresherConfig{
			Path:       dest,
			Ecosystems: []string{"npm"},
			Swap:       func(idx *Index) { swapped = idx },
			now:        time.Now,
		},
		client:  srv.Client(),
		logger:  testLogger(t),
		baseURL: srv.URL,
	}
	if err := r.runOnce(context.Background()); err != nil {
		t.Fatalf("runOnce: %v", err)
	}

	// File exists + is a valid gzip'd bundle.
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("dest missing: %v", err)
	}
	idx, err := LoadFile(dest)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if idx.Total() != 1 {
		t.Fatalf("idx.Total()=%d want 1", idx.Total())
	}
	hits := idx.Lookup("npm", "synthetic-pkg", "1.0.0")
	if len(hits) != 1 {
		t.Fatalf("Lookup hits=%d want 1", len(hits))
	}
	if hits[0].AdvisoryID != "GHSA-fake-0001" {
		t.Errorf("AdvisoryID=%q want GHSA-fake-0001", hits[0].AdvisoryID)
	}
	if hits[0].CVSSScore < 9.0 {
		t.Errorf("CVSSScore=%v want >= 9.0", hits[0].CVSSScore)
	}
	if hits[0].Severity != "CRITICAL" {
		t.Errorf("Severity=%q want CRITICAL", hits[0].Severity)
	}

	// Swap callback fired with a non-nil index.
	if swapped == nil {
		t.Fatal("swap callback did not fire")
	}
	if swapped.Total() != 1 {
		t.Errorf("swapped.Total()=%d want 1", swapped.Total())
	}

	if got := r.TotalRefreshes(); got != 1 {
		t.Errorf("TotalRefreshes=%d want 1", got)
	}
	if got := r.TotalFailures(); got != 0 {
		t.Errorf("TotalFailures=%d want 0", got)
	}
}

// TestRefresher_FailClosed_KeepsPriorBundle verifies the fail-closed
// guarantee: when the upstream errors, the destination file is left
// untouched and the swap callback is NOT invoked.
func TestRefresher_FailClosed_KeepsPriorBundle(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "osv-bundle.json.gz")

	// Pre-seed the destination with a known-good bundle.
	priorBytes := mustGzipJSON(t, []Advisory{{
		Ecosystem:          "npm",
		Package:            "prior-pkg",
		VulnerableVersions: []string{"0.0.1"},
		AdvisoryID:         "GHSA-prior-0001",
	}})
	if err := os.WriteFile(dest, priorBytes, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	var swapped *Index
	r := &Refresher{
		cfg: RefresherConfig{
			Path:       dest,
			Ecosystems: []string{"npm"},
			Swap:       func(idx *Index) { swapped = idx },
			now:        time.Now,
		},
		client:  srv.Client(),
		logger:  testLogger(t),
		baseURL: srv.URL,
	}
	if err := r.runOnce(context.Background()); err == nil {
		t.Fatal("runOnce: want error, got nil")
	}

	// File untouched — load and confirm it's the seeded bundle.
	idx, err := LoadFile(dest)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if idx.Total() != 1 || !idx.HasPackage("npm", "prior-pkg") {
		t.Errorf("destination file was modified by failed refresh")
	}
	if swapped != nil {
		t.Errorf("swap fired despite failure")
	}
	if r.TotalFailures() != 1 {
		t.Errorf("TotalFailures=%d want 1", r.TotalFailures())
	}
}

// TestNewRefresher_DefaultsOnWith6hInterval pins the refresher's new
// default: when no env override is set and OFFLINE is not on, the
// refresher runs every 6h matching the Trivy DB / EPSS / typosquat
// refreshers. Operators kill it via CHAINSAW_OSV_REFRESH_INTERVAL=0
// (see TestNewRefresher_DormantWhenKillSwitchSet).
func TestNewRefresher_DefaultsOnWith6hInterval(t *testing.T) {
	t.Setenv("CHAINSAW_OSV_REFRESH_INTERVAL", "")
	t.Setenv("CHAINSAW_OFFLINE", "")
	r := NewRefresher(RefresherConfig{Path: filepath.Join(t.TempDir(), "x.json.gz")})
	if r == nil {
		t.Fatalf("want non-nil refresher under default env, got nil")
	}
	if r.cfg.Interval != DefaultRefreshInterval {
		t.Errorf("Interval=%v want %v (default)", r.cfg.Interval, DefaultRefreshInterval)
	}
}

// TestNewRefresher_DormantWhenKillSwitchSet pins the explicit-disable
// path. Operators that don't want the refresher set the env var to
// 0/off/disabled/false and NewRefresher returns nil.
func TestNewRefresher_DormantWhenKillSwitchSet(t *testing.T) {
	for _, val := range []string{"0", "off", "disabled", "false", "no", "OFF", "Disabled"} {
		t.Run("env="+val, func(t *testing.T) {
			t.Setenv("CHAINSAW_OSV_REFRESH_INTERVAL", val)
			t.Setenv("CHAINSAW_OFFLINE", "")
			r := NewRefresher(RefresherConfig{Path: filepath.Join(t.TempDir(), "x.json.gz")})
			if r != nil {
				t.Fatalf("want nil refresher with kill-switch %q, got %#v", val, r)
			}
			// Start on nil must not panic.
			r.Start(context.Background())
		})
	}
}

// TestNewRefresher_DormantWhenOffline ensures CHAINSAW_OFFLINE=1 trumps
// any positive interval. We never want to dial out in airgap mode.
func TestNewRefresher_DormantWhenOffline(t *testing.T) {
	t.Setenv("CHAINSAW_OSV_REFRESH_INTERVAL", "1h")
	t.Setenv("CHAINSAW_OFFLINE", "1")
	r := NewRefresher(RefresherConfig{Path: filepath.Join(t.TempDir(), "x.json.gz")})
	if r != nil {
		t.Fatalf("want nil refresher with CHAINSAW_OFFLINE=1, got non-nil")
	}
}

// TestNewRefresher_ActiveWhenIntervalSet flips the env on and confirms
// NewRefresher returns a usable handle.
func TestNewRefresher_ActiveWhenIntervalSet(t *testing.T) {
	t.Setenv("CHAINSAW_OSV_REFRESH_INTERVAL", "30m")
	t.Setenv("CHAINSAW_OFFLINE", "")
	dir := t.TempDir()
	r := NewRefresher(RefresherConfig{Path: filepath.Join(dir, "x.json.gz")})
	if r == nil {
		t.Fatalf("want non-nil refresher")
	}
	if r.cfg.Interval != 30*time.Minute {
		t.Errorf("Interval=%v want 30m", r.cfg.Interval)
	}
}

// mustGzipJSON marshals advs to gzip'd JSON exactly the way the
// refresher's write() helper does. Used by the fail-closed test to
// pre-seed the destination file.
func mustGzipJSON(t *testing.T, advs []Advisory) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gz).Encode(advs); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}
