//go:build !windows

package homebrew

import (
	"os"
	"path/filepath"
	"strings"
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

// The window between Lstat and open: a regular file swapped for a symlink
// (O_NOFOLLOW refuses it), a FIFO (O_NONBLOCK opens it, the fstat check
// refuses it), or another regular file (SameFile refuses it).
func TestOpenRegularRefusesSwapAfterLstat(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("root-only secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	swaps := map[string]func(p string) error{
		"symlink": func(p string) error { os.Remove(p); return os.Symlink(target, p) },
		"fifo":    func(p string) error { os.Remove(p); return syscall.Mkfifo(p, 0o644) },
		"other regular file": func(p string) error {
			os.Remove(p)
			return os.WriteFile(p, []byte("x"), 0o644)
		},
	}
	t.Cleanup(func() { afterLstat = func(string) {} })
	for name, swap := range swaps {
		p := filepath.Join(dir, "f-"+strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		afterLstat = func(string) {
			if err := swap(p); err != nil {
				t.Fatal(err)
			}
		}
		done := make(chan error, 1)
		go func() {
			f, _, err := openRegular(p)
			if f != nil {
				f.Close()
			}
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "changed while being opened") {
				t.Errorf("%s swap: err = %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s swap hung the reader", name)
		}
	}
}
