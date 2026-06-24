package hook

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupNpm(t *testing.T) (npmManager, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, ".npmrc")
	t.Setenv("NPM_CONFIG_USERCONFIG", path)
	return npmManager{}, path
}

func countSentinels(data []byte) int {
	return bytes.Count(data, []byte(sentinelStart))
}

func listBackups(t *testing.T, path string) []string {
	t.Helper()
	matches, err := filepath.Glob(path + ".chainsaw.bak.*")
	if err != nil {
		t.Fatalf("glob backups: %v", err)
	}
	return matches
}

func TestNpmWireIntoEmpty(t *testing.T) {
	m, path := setupNpm(t)
	if err := m.Wire(WireOpts{}); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !hasSentinel(data) {
		t.Errorf("file missing sentinel: %s", data)
	}
	if !strings.Contains(string(data), "ignore-scripts=true") {
		t.Errorf("body missing ignore-scripts=true: %s", data)
	}
	if bks := listBackups(t, path); len(bks) != 0 {
		t.Errorf("expected no backup on fresh wire, got %v", bks)
	}
}

func TestNpmWireTwiceReplacesAndBacksUp(t *testing.T) {
	m, path := setupNpm(t)
	if err := m.Wire(WireOpts{}); err != nil {
		t.Fatalf("first Wire: %v", err)
	}
	if err := m.Wire(WireOpts{}); err != nil {
		t.Fatalf("second Wire: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n := countSentinels(data); n != 1 {
		t.Errorf("expected exactly one sentinel block, got %d", n)
	}
	if bks := listBackups(t, path); len(bks) != 1 {
		t.Errorf("expected exactly 1 backup after second wire, got %d: %v", len(bks), bks)
	}
}

func TestNpmWirePreservesUserContent(t *testing.T) {
	m, path := setupNpm(t)
	user := "user-config=please-keep\n"
	if err := os.WriteFile(path, []byte(user), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := m.Wire(WireOpts{}); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "user-config=please-keep") {
		t.Errorf("user content dropped: %s", data)
	}
	if !hasSentinel(data) {
		t.Errorf("sentinel missing: %s", data)
	}
	if bks := listBackups(t, path); len(bks) != 1 {
		t.Errorf("expected 1 backup of pre-existing file, got %d", len(bks))
	}
}

func TestNpmUnwireAfterWire(t *testing.T) {
	m, path := setupNpm(t)
	user := "user-config=please-keep\n"
	if err := os.WriteFile(path, []byte(user), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := m.Wire(WireOpts{}); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatalf("Unwire: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if hasSentinel(data) {
		t.Errorf("sentinel still present: %s", data)
	}
	if !strings.Contains(string(data), "user-config=please-keep") {
		t.Errorf("user content lost after unwire: %s", data)
	}
	if got := string(data); got != user {
		t.Errorf("content not restored exactly:\ngot  %q\nwant %q", got, user)
	}
}

func TestNpmUnwireNoSentinelReturnsErrNotWired(t *testing.T) {
	m, _ := setupNpm(t)
	if err := m.Unwire(ScopeUser); !errors.Is(err, ErrNotWired) {
		t.Errorf("empty file Unwire error = %v, want ErrNotWired", err)
	}
}

func TestNpmWireRejectsControlCharURL(t *testing.T) {
	m, path := setupNpm(t)
	err := m.Wire(WireOpts{ServerURL: "https://foo.example/%0Aevil-line"})
	if err == nil {
		t.Fatalf("Wire with control-char URL = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "invalid server URL") {
		t.Errorf("error = %v, want to mention 'invalid server URL'", err)
	}
	// The config file must NOT have been written — a bad URL must never
	// produce a partial/empty .npmrc that could mask the attacker's intent.
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("expected .npmrc to be absent after failed Wire, stat err = %v", statErr)
	}
}

func TestNpmWireAcceptsValidURL(t *testing.T) {
	m, path := setupNpm(t)
	if err := m.Wire(WireOpts{ServerURL: "https://proxy.example.com/"}); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Canonicalised URL should be embedded (no trailing slash before path).
	// BUG-A6: org-scoped path; placeholder when WireOpts.OrgSlug unset.
	if !strings.Contains(string(data), "registry=https://proxy.example.com/chainproxy/repository/@your-org-slug/npmjs/") {
		t.Errorf("expected canonicalised registry line, got: %s", data)
	}
}

func TestNpmStatusBeforeAndAfterWire(t *testing.T) {
	m, _ := setupNpm(t)
	st, err := m.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Wired {
		t.Error("unwired Status.Wired = true")
	}
	if err := m.Wire(WireOpts{}); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	st, err = m.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if !st.Wired {
		t.Error("wired Status.Wired = false")
	}
}
