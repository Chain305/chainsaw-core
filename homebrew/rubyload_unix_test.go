//go:build !windows

package homebrew

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Root hashes files the user can swap: a FIFO must not hang it and a
// symlink must not be followed.
func TestFileSHA256RefusesSwaps(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo.rb")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := fileSHA256(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("hashed a FIFO")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked on a FIFO")
	}
	link := filepath.Join(dir, "zero.rb")
	os.Symlink("/dev/zero", link)
	if _, err := fileSHA256(link); err == nil {
		t.Fatal("followed a symlink")
	}
}
