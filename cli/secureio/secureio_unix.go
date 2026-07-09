//go:build !windows

package secureio

import (
	"fmt"
	"os"
	"path/filepath"
)

func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("secureio: create parent: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("secureio: write: %w", err)
	}
	// Explicit chmod in case WriteFile was subject to umask.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("secureio: chmod: %w", err)
	}
	return nil
}
