//go:build windows

package cli

import "syscall"

// detachedProcAttr runs the background refresh without a console and in its
// own process group, so closing the install's console or Ctrl-C does not kill
// it. 0x00000008 is DETACHED_PROCESS.
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x00000008}
}
