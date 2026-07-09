package cli

// intel_scan_test.go covers the pure helpers behind `intel scan`:
// lockfile detection/type inference and the CI exit-code ladder. The
// network path (client.Evaluate, which now prints an "evaluating …"
// progress line to stderr before the call) requires a configured server
// and is exercised manually; these tests pin the deterministic seams.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLockfileTypeFromPath(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"package-lock.json", "npm"},
		{"./client/package-lock.json", "npm"},
		{"pnpm-lock.yaml", "pnpm"},
		{"/abs/pnpm-lock.yaml", "pnpm"},
		{"PACKAGE-LOCK.JSON", "npm"},  // case-insensitive on basename
		{"package-lock.json.bak", ""}, // basename match, not extension
		{"yarn.lock", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := lockfileTypeFromPath(tc.path); got != tc.want {
			t.Errorf("lockfileTypeFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestDetectLockfilePrefersNpm(t *testing.T) {
	dir := t.TempDir()
	// Both present → npm wins (preference order documented in detectLockfile).
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	path, kind, ok := detectLockfile(dir)
	if !ok {
		t.Fatal("expected detection, got ok=false")
	}
	if kind != "npm" {
		t.Errorf("kind = %q, want npm (npm preferred when both exist)", kind)
	}
	if filepath.Base(path) != "package-lock.json" {
		t.Errorf("path = %q, want package-lock.json", path)
	}
}

func TestDetectLockfilePnpmOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, kind, ok := detectLockfile(dir)
	if !ok || kind != "pnpm" {
		t.Errorf("detectLockfile pnpm-only = (%q, %v), want (pnpm, true)", kind, ok)
	}
}

func TestDetectLockfileNone(t *testing.T) {
	if _, _, ok := detectLockfile(t.TempDir()); ok {
		t.Error("expected ok=false for empty dir")
	}
}

func TestTreeExitCode(t *testing.T) {
	mk := func(byVerdict map[string]int) *v1TreeData {
		tr := &v1TreeData{}
		tr.Summary.ByVerdict = byVerdict
		return tr
	}
	cases := []struct {
		name string
		tree *v1TreeData
		want int
	}{
		{"nil tree → 0", nil, ExitOK},
		{"all allow → 0", mk(map[string]int{"allow": 5}), ExitOK},
		{"warn → 1", mk(map[string]int{"allow": 3, "warn": 1}), ExitBlocked},
		{"upgrade_available → 1", mk(map[string]int{"upgrade_available": 2}), ExitBlocked},
		// invariant B: the hard block uses the command-specific ExitIntelBlock(11),
		// NOT ExitOpError(2), so CI can't confuse a malicious package with a
		// server/IO failure.
		{"quarantine → 11", mk(map[string]int{"quarantine": 1}), ExitIntelBlock},
		{"replace → 11", mk(map[string]int{"replace": 1}), ExitIntelBlock},
		{"quarantine outranks warn → 11", mk(map[string]int{"warn": 9, "quarantine": 1}), ExitIntelBlock},
		{"unknown verdict → 0", mk(map[string]int{"future_verdict": 3}), ExitOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := treeExitCode(tc.tree); got != tc.want {
				t.Errorf("treeExitCode = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestIntelScanCmdRegistered(t *testing.T) {
	c, _, err := intelCmd.Find([]string{"scan"})
	if err != nil {
		t.Fatalf("intel scan not registered: %v", err)
	}
	if c.Use != "scan" {
		t.Errorf("found wrong command: %q", c.Use)
	}
	if f := c.Flags().Lookup("lockfile"); f == nil {
		t.Error("intel scan missing --lockfile flag")
	}
}
