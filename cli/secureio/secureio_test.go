package secureio

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFile_CreatesFileAndParent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "nested", "creds.json")
	payload := []byte(`{"hello":"world"}`)

	if err := WriteFile(target, payload); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, payload)
	}
}

func TestWriteFile_UnixModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-mode check not meaningful on Windows")
	}
	root := t.TempDir()
	target := filepath.Join(root, "newdir", "secret")
	if err := WriteFile(target, []byte("s3cret")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("file perm = %o, want 0600", perm)
	}

	dirInfo, err := os.Stat(filepath.Dir(target))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("dir perm = %o, want 0700", perm)
	}
}

func TestWriteFile_OverwritesExisting(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "creds")
	if err := WriteFile(target, []byte("first")); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFile(target, []byte("second")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("overwrite mismatch: got %q want %q", got, "second")
	}
}
