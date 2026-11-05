//go:build !windows

package cli

import (
	"fmt"
	"os"
	"syscall"
)

// rootOwnedNotWritable refuses a file a non-root user could have written:
// /etc/homebrew/brew.env is policy only while root alone controls it.
func rootOwnedNotWritable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read the owner of %s", path)
	}
	if st.Uid != 0 {
		return fmt.Errorf("owned by uid %d, not root", st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("mode %v is group- or world-writable", fi.Mode().Perm())
	}
	return nil
}
