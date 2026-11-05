//go:build !darwin && !linux

package homebrew

import "io/fs"

// statKey: no Homebrew here; always re-hash.
func statKey(fs.FileInfo) string { return "?" }

func allocatedBytes(fs.FileInfo) (int64, bool) { return 0, false }
