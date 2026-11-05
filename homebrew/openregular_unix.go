//go:build !windows

package homebrew

import "syscall"

// openRegularFlags: never follow a final symlink and never block on a FIFO
// swapped in after Lstat (both no-ops on the regular file we expect).
const openRegularFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
