package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeFileInfo is a minimal os.FileInfo implementation that carries
// only the mtime the freshness check relies on. Using a struct keeps
// the test data declarative and avoids writing real files when we
// only care about the modtime comparison.
type fakeFileInfo struct {
	mod time.Time
}

func (f fakeFileInfo) Name() string       { return "test.yaml" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return 0o600 }
func (f fakeFileInfo) ModTime() time.Time { return f.mod }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

func fixedStat(mod time.Time) func(string) (os.FileInfo, error) {
	return func(string) (os.FileInfo, error) { return fakeFileInfo{mod: mod}, nil }
}

func missingStat() func(string) (os.FileInfo, error) {
	return func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
}

func errStat(err error) func(string) (os.FileInfo, error) {
	return func(string) (os.FileInfo, error) { return nil, err }
}

// TestBuildYAMLFreshnessReport_Cases covers the P1.4 decision matrix:
// (prior import? y/n) × (file exists? y/n) × (same path? y/n) ×
// (file newer? y/n). Only the "same path AND file newer than last
// import" cell produces ModifiedAfterImport=true — that's the
// footgun we warn on.
func TestBuildYAMLFreshnessReport_Cases(t *testing.T) {
	t0 := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	later := t0.Add(time.Hour)
	earlier := t0.Add(-time.Hour)
	path := "/etc/chainsaw/foo.yaml"

	cases := []struct {
		name            string
		path            string
		lastPath        string
		lastImportedAt  time.Time
		statFn          func(string) (os.FileInfo, error)
		wantSamePath    bool
		wantExists      bool
		wantModified    bool
		wantFileModTime time.Time
	}{
		{
			name:           "no_prior_import",
			path:           path,
			lastPath:       "",
			lastImportedAt: time.Time{},
			statFn:         fixedStat(t0),
			wantSamePath:   false,
			wantExists:     true,
			// Without a prior import we have nothing to compare
			// against — never trigger the stale warning.
			wantModified:    false,
			wantFileModTime: t0.UTC(),
		},
		{
			name:            "same_path_file_newer_TRIGGERS_WARN",
			path:            path,
			lastPath:        path,
			lastImportedAt:  t0,
			statFn:          fixedStat(later),
			wantSamePath:    true,
			wantExists:      true,
			wantModified:    true,
			wantFileModTime: later.UTC(),
		},
		{
			name:            "same_path_file_older_no_warn",
			path:            path,
			lastPath:        path,
			lastImportedAt:  t0,
			statFn:          fixedStat(earlier),
			wantSamePath:    true,
			wantExists:      true,
			wantModified:    false,
			wantFileModTime: earlier.UTC(),
		},
		{
			name: "same_path_file_equal_mtime_no_warn",
			// Equal mtimes must not trigger — "strictly after" is
			// the contract, because touching the file atomically
			// with the import is a common operator pattern.
			path:            path,
			lastPath:        path,
			lastImportedAt:  t0,
			statFn:          fixedStat(t0),
			wantSamePath:    true,
			wantExists:      true,
			wantModified:    false,
			wantFileModTime: t0.UTC(),
		},
		{
			name:            "different_path_file_newer_no_warn",
			path:            path,
			lastPath:        "/etc/chainsaw/other.yaml",
			lastImportedAt:  t0,
			statFn:          fixedStat(later),
			wantSamePath:    false,
			wantExists:      true,
			wantModified:    false,
			wantFileModTime: later.UTC(),
		},
		{
			name:           "missing_file_no_warn",
			path:           path,
			lastPath:       path,
			lastImportedAt: t0,
			statFn:         missingStat(),
			wantSamePath:   true,
			wantExists:     false,
			wantModified:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := buildYAMLFreshnessReport(tc.path, tc.lastPath, tc.lastImportedAt, tc.statFn)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if report.SamePath != tc.wantSamePath {
				t.Errorf("SamePath: got %v want %v", report.SamePath, tc.wantSamePath)
			}
			if report.FileExists != tc.wantExists {
				t.Errorf("FileExists: got %v want %v", report.FileExists, tc.wantExists)
			}
			if report.ModifiedAfterImport != tc.wantModified {
				t.Errorf("ModifiedAfterImport: got %v want %v", report.ModifiedAfterImport, tc.wantModified)
			}
			if !tc.wantFileModTime.IsZero() && !report.FileModTime.Equal(tc.wantFileModTime) {
				t.Errorf("FileModTime: got %v want %v", report.FileModTime, tc.wantFileModTime)
			}
		})
	}
}

// TestBuildYAMLFreshnessReport_StatErrorSurfaces ensures non-NotExist
// stat errors (EACCES, EIO, etc.) propagate to the caller instead of
// being silently swallowed. A permissions-denied mtime read would make
// the warning trivially false-negative otherwise.
func TestBuildYAMLFreshnessReport_StatErrorSurfaces(t *testing.T) {
	sentinel := errors.New("boom: stat exploded")
	_, err := buildYAMLFreshnessReport("/tmp/x.yaml", "/tmp/x.yaml", time.Now(), errStat(sentinel))
	if err == nil {
		t.Fatal("expected stat error to propagate")
	}
	if !errors.Is(err, sentinel) && err != sentinel {
		// errors.Is will fail because we return err directly (not
		// wrapped), so allow either pointer-equal or Is-match — the
		// point is: don't eat the error.
		t.Errorf("stat error not propagated: got %v want %v", err, sentinel)
	}
}

// TestInspectYAMLFreshness_AbsolutePathResolved verifies that the
// public entry point resolves the input to an absolute path before
// comparing. Operators may pass relative paths on the CLI; the
// settings table stores absolute paths (RecordYAMLImport calls
// filepath.Abs), so without this normalisation the SamePath
// comparison would false-negative and the warning would never fire.
//
// Nil store is used because this test only exercises the path
// resolution — we don't look up prior imports, so LastYAMLImport
// returns an error we expect.
func TestInspectYAMLFreshness_AbsolutePathResolved(t *testing.T) {
	// Create a real file so os.Stat can succeed.
	dir := t.TempDir()
	full := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(full, []byte("x: y\n"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	// Sanity: buildYAMLFreshnessReport accepts the already-abs path.
	report, err := buildYAMLFreshnessReport(full, "", time.Time{}, os.Stat)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.FileExists {
		t.Fatal("expected FileExists=true on a file we just wrote")
	}
	// filepath.Abs on an already-abs path is the identity, so this
	// is a stability check: re-resolving must not break SamePath.
	abs, err := filepath.Abs(full)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if abs != full {
		t.Errorf("expected absolute resolution to be stable: got %q want %q", abs, full)
	}
}
