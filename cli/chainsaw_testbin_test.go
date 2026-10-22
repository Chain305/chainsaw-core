package cli

// chainsaw_testbin_test.go — the one cmd/chainsaw build that the subprocess
// harnesses (exit codes, output purity, guard bypass) share, and its cleanup.
//
// Each harness used to os.MkdirTemp its own dir for a ~63 MB binary and never
// remove it: three binaries leaked into $TMPDIR per `go test ./core/cli`, and on
// 2026-10-22 545 of them (9.5 GB) filled the release Mac's disk mid-release.
// t.TempDir cannot hold a build shared across tests, so the dir is package-
// scoped instead: TestMain removes it after m.Run, and sweepStaleTestScratch
// removes what a run killed before reaching that line (a test panic, a
// -timeout, Ctrl-C) left behind.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const chainsawTestBinPrefix = "chainsaw-cli-testbin-"

// staleTestScratchPrefixes are the $TMPDIR entries this package's tests
// create. The last three are the per-harness dirs from before the shared
// build; they stay listed so the first run of this code clears the backlog.
var staleTestScratchPrefixes = []string{
	chainsawTestBinPrefix,
	"chainsaw-cli-confighome-",
	"chainsaw-exitbin-",
	"chainsaw-guardbypass-bin",
	"chainsaw-purity-bin",
}

// staleTestScratchAge keeps the sweep off a concurrent run's live dirs (other
// worktrees run this suite at the same time). The Makefile's longest timeout
// for this package is 10m.
const staleTestScratchAge = 2 * time.Hour

var (
	chainsawTestBinOnce sync.Once
	chainsawTestBinDir  string
	chainsawTestBinPath string
	chainsawTestBinErr  error
)

// sharedChainsawBinary compiles ../cmd/chainsaw once per test binary. A
// missing toolchain returns an error wrapping exec.ErrNotFound, so callers can
// skip on that and fail on a real build error.
func sharedChainsawBinary() (string, error) {
	chainsawTestBinOnce.Do(func() {
		goTool, err := exec.LookPath("go")
		if err != nil {
			chainsawTestBinErr = err
			return
		}
		chainsawTestBinDir, err = os.MkdirTemp("", chainsawTestBinPrefix)
		if err != nil {
			chainsawTestBinErr = err
			return
		}
		bin := filepath.Join(chainsawTestBinDir, "chainsaw")
		if runtime.GOOS == "windows" {
			bin += ".exe"
		}
		// The test runs from core/cli; main lives at ../cmd/chainsaw.
		if out, err := exec.Command(goTool, "build", "-o", bin, "../cmd/chainsaw").CombinedOutput(); err != nil {
			chainsawTestBinErr = fmt.Errorf("build chainsaw binary: %w\n%s", err, out)
			return
		}
		chainsawTestBinPath = bin
	})
	return chainsawTestBinPath, chainsawTestBinErr
}

// removeSharedChainsawBinary is TestMain's half of the contract.
func removeSharedChainsawBinary() {
	if chainsawTestBinDir != "" {
		os.RemoveAll(chainsawTestBinDir)
	}
}

// sweepStaleTestScratch removes this package's $TMPDIR entries older than
// staleTestScratchAge. Best effort: an entry it cannot read or remove is left.
func sweepStaleTestScratch() {
	tmp := os.TempDir()
	entries, err := os.ReadDir(tmp)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-staleTestScratchAge)
	for _, e := range entries {
		if !hasAnyPrefix(e.Name(), staleTestScratchPrefixes) {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		os.RemoveAll(filepath.Join(tmp, e.Name()))
	}
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// TestSweepStaleTestScratchRemovesOnlyOldOwnEntries proves the sweep can both
// remove (an old leftover of ours) and refrain (a fresh one, which may be a
// concurrent run's live build, and an old entry that is not ours).
func TestSweepStaleTestScratchRemovesOnlyOldOwnEntries(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	old := time.Now().Add(-staleTestScratchAge - time.Minute)
	mk := func(name string, mtime time.Time) string {
		p := filepath.Join(tmp, name)
		if err := os.MkdirAll(filepath.Join(p, "inner"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
		return p
	}
	oldOwn := mk("chainsaw-exitbin-123", old)
	oldShared := mk(chainsawTestBinPrefix+"456", old)
	freshOwn := mk(chainsawTestBinPrefix+"789", time.Now())
	oldOther := mk("go-build123", old)

	sweepStaleTestScratch()

	for _, p := range []string{oldOwn, oldShared} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived the sweep (stat err %v)", filepath.Base(p), err)
		}
	}
	for _, p := range []string{freshOwn, oldOther} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was removed: %v", filepath.Base(p), err)
		}
	}
}
