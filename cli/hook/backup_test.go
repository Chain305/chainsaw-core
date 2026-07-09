package hook

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestBackupNoFileReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing")
	got, err := backup(path)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	if got != "" {
		t.Errorf("backup returned %q, want empty string", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("backup of missing file left %d entries behind", len(entries))
	}
}

func TestBackupContentsMatchOriginal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".npmrc")
	orig := []byte("registry=https://example\nuser-config=keep\n")
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	dst, err := backup(path)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(got) != string(orig) {
		t.Errorf("backup contents differ:\ngot  %q\nwant %q", got, orig)
	}
}

func TestBackupFileModeIsRestrictive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ".npmrc")
	if err := os.WriteFile(path, []byte("x=1\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	dst, err := backup(path)
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("backup mode = %o, want 0600", got)
	}
}

func TestBackupRapidSuccessiveCallsProduceDistinctFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".npmrc")
	if err := os.WriteFile(path, []byte("x=1\n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Pin time to a known second so we know any distinction must come from
	// the nanosecond component. Advance by 1ns per call so formatted stamps
	// differ even when wall-clock resolution is coarse.
	base := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	calls := 0
	oldTimeNow := timeNow
	timeNow = func() time.Time {
		t := base.Add(time.Duration(calls) * time.Nanosecond)
		calls++
		return t
	}
	t.Cleanup(func() { timeNow = oldTimeNow })

	var dsts []string
	for i := 0; i < 3; i++ {
		dst, err := backup(path)
		if err != nil {
			t.Fatalf("backup %d: %v", i, err)
		}
		dsts = append(dsts, dst)
	}
	seen := map[string]bool{}
	for _, d := range dsts {
		if seen[d] {
			t.Errorf("duplicate backup path %q", d)
		}
		seen[d] = true
		if _, err := os.Stat(d); err != nil {
			t.Errorf("backup %q does not exist: %v", d, err)
		}
	}
	matches, err := filepath.Glob(path + ".chainsaw.bak.*")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) != 3 {
		t.Errorf("expected 3 backup files on disk, got %d: %v", len(matches), matches)
	}
}
