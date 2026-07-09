package hook

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chain305/chainsaw-core/cli/secureio"
)

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
	return dst, nil
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
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create parent: %w", err)
	}
	mode := os.FileMode(0o644)
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
