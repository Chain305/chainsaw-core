//go:build !windows

package cli

import "syscall"

// detachedProcAttr puts the background refresh in its own session, so closing
// the terminal (SIGHUP) or Ctrl-C in the install does not kill it.
func detachedProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setsid: true} }
