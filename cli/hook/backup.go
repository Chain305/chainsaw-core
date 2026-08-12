package hook

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/chain305/chainsaw-core/cli/secureio"
)

// backupsKept is how many <path>.chainsaw.bak.* files survive a Wire/Unwire
// (H13). Each backup can hold a previous plaintext credential pair, so they
// must not pile up next to the config forever — but the NEWEST one is
// load-bearing (it is xmlUnwire's restore source and the only surviving copy
// of a user's original GOFLAGS), so pruning always keeps the most recent few.
const backupsKept = 3

// backup writes a timestamped copy of path if it exists. Returns the backup
// path written, or "" if nothing was backed up (the file didn't exist). The
// backup is written via secureio so perms stay reasonable.
func backup(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read for backup: %w", err)
	}
	// Nanosecond precision so rapid consecutive calls produce distinct
	// backup filenames; a second-resolution stamp would collide.
	stamp := timeNow().UTC().Format("20060102-150405.000000000")
	dst := fmt.Sprintf("%s.chainsaw.bak.%s", path, stamp)
	if err := secureio.WriteFile(dst, data); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}
	pruneBackups(path, backupsKept)
	return dst, nil
}

// pruneBackups deletes all but the `keep` most recent <path>.chainsaw.bak.*
// files. Backup names embed a zero-padded UTC timestamp, so lexical order is
// chronological. Best-effort: a failure to remove an old backup must never
// fail a Wire.
func pruneBackups(path string, keep int) {
	if keep < 1 {
		keep = 1
	}
	matches, err := filepath.Glob(path + ".chainsaw.bak.*")
	if err != nil || len(matches) <= keep {
		return
	}
	sort.Sort(sort.Reverse(sort.StringSlice(matches)))
	for _, old := range matches[keep:] {
		_ = os.Remove(old)
	}
}

// backupAndNotify backs path up and tells the user where the copy went (H13:
// the CLI never mentioned the backups it was leaving behind, each of which
// can contain a previous plaintext credential pair).
func backupAndNotify(path string, opts WireOpts) error {
	dst, err := backup(path)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if dst != "" {
		opts.notify("backed up %s to %s", path, dst)
	}
	return nil
}

// readOrEmpty reads path or returns (nil, nil) if the file does not exist.
func readOrEmpty(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return data, nil
}

// writeAtomic writes data to path via a sibling temp file and renames. When
// path already exists the target's mode is preserved; new files are 0o644.
func writeAtomic(path string, data []byte) error {
	return writeAtomicMode(path, data, 0o644)
}

// writeAtomicMode is writeAtomic with an explicit mode for NEWLY CREATED
// files. An existing file's mode is still preserved — a user who chmod'd
// their ~/.npmrc keeps their choice.
//
// H5: the default stays 0644 on purpose. writeAtomic is also the write path
// for ScopeSystem (/etc/npmrc, /etc/pip.conf, /etc/go/env), and a root-owned
// 0600 /etc/npmrc is unreadable by every non-root user — that would break npm
// machine-wide. Only the secret-bearing, non-system writes pass 0o600; see
// credentialFileMode.
func writeAtomicMode(path string, data []byte, newFileMode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create parent: %w", err)
	}
	mode := newFileMode
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".chainsaw.*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail out below.
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
