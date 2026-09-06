package dsl

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A bundle path that does not exist used to be skipped silently: discover
// `continue`d, New returned an empty engine, and Decide short-circuited to
// ActionAllow. That is the whole rubber-stamp defect, and it starts here.
func TestDiscoverRecordsAMissingSource(t *testing.T) {
	eng, err := New(context.Background(), Options{Sources: []string{"/nonexistent/bundle/path"}})
	if err != nil {
		t.Fatalf("a missing source must not be an error — the loader contract is empty-in/empty-out: %v", err)
	}
	if !eng.Empty() {
		t.Fatal("engine is not empty for a nonexistent source")
	}
	skips := eng.Skipped()
	if len(skips) != 1 {
		t.Fatalf("Skipped() = %d entries, want 1 — a silently-dropped source is the defect", len(skips))
	}
	if skips[0].Path != "/nonexistent/bundle/path" {
		t.Errorf("skip does not name the offending path: %+v", skips[0])
	}
}

// The control: a bundle that IS fully read reports no skips. Without this,
// "always report a skip" would satisfy the test above.
func TestDiscoverReportsNoSkipsOnACompleteBundle(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.rego"), []byte("package chainsaw.policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := New(context.Background(), Options{Sources: []string{dir}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := eng.Skipped(); len(got) != 0 {
		t.Errorf("a fully-readable bundle reported skips: %+v", got)
	}
	if eng.Empty() {
		t.Error("engine is empty for a bundle containing a .rego file")
	}
}

// An unreadable subdirectory must be RECORDED and the rest of the bundle
// still read. Returning the walk error discarded every rule over one bad
// directory; returning nil would hide it. Neither is safe for a gate.
func TestDiscoverKeepsReadableRulesWhenOneDirectoryIsUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission denial is not portable to Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: chmod 000 does not deny access")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.rego"), []byte("package chainsaw.policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "hidden.rego"), []byte("package chainsaw.policy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	eng, err := New(context.Background(), Options{Sources: []string{dir}})
	if err != nil {
		t.Fatalf("one unreadable directory discarded the whole bundle: %v", err)
	}
	if eng.Empty() {
		t.Error("readable rules were dropped alongside the unreadable directory")
	}
	if len(eng.Skipped()) == 0 {
		t.Error("the unreadable directory was not recorded — a gate would allow over an incomplete bundle")
	}
}
