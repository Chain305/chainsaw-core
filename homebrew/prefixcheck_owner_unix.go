//go:build !windows

package homebrew

import (
	"os"
	"syscall"
)

// entryRootOwned: the entry itself (not its target) is owned by root and is
// a symlink or a file with one link. A user can hardlink a root-owned file
// into a directory they own; nlink == 1 rules that out.
var entryRootOwned = func(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0 || st.Nlink == 1
}
