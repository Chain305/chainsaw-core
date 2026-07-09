package hook

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupPip(t *testing.T) (pipManager, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pip.conf")
	t.Setenv("PIP_CONFIG_FILE", path)
	return pipManager{}, path
}

func TestPipWireIntoEmpty(t *testing.T) {
	m, path := setupPip(t)
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
	if !strings.Contains(string(data), "[global]") {
		t.Errorf("body missing [global] section: %s", data)
	}
	if bks := listBackups(t, path); len(bks) != 0 {
		t.Errorf("expected no backup on fresh wire, got %v", bks)
	}
}

func TestPipWireTwiceReplacesAndBacksUp(t *testing.T) {
	m, path := setupPip(t)
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
		t.Errorf("expected one sentinel, got %d", n)
	}
	if bks := listBackups(t, path); len(bks) != 1 {
		t.Errorf("expected 1 backup, got %d", len(bks))
	}
}

func TestPipWirePreservesUserContent(t *testing.T) {
	m, path := setupPip(t)
	user := "[global]\ntimeout = 60\n"
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
	if !strings.Contains(string(data), "timeout = 60") {
		t.Errorf("user content dropped: %s", data)
	}
	if !hasSentinel(data) {
		t.Errorf("sentinel missing: %s", data)
	}
	if bks := listBackups(t, path); len(bks) != 1 {
		t.Errorf("expected 1 backup, got %d", len(bks))
	}
}

func TestPipUnwireAfterWire(t *testing.T) {
	m, path := setupPip(t)
	user := "[global]\ntimeout = 60\n"
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
	if !strings.Contains(string(data), "timeout = 60") {
		t.Errorf("user content lost: %s", data)
	}
}

func TestPipUnwireNoSentinelReturnsErrNotWired(t *testing.T) {
	m, _ := setupPip(t)
	if err := m.Unwire(ScopeUser); !errors.Is(err, ErrNotWired) {
		t.Errorf("empty file Unwire error = %v, want ErrNotWired", err)
	}
}

func TestPipWireRejectsControlCharURL(t *testing.T) {
	m, path := setupPip(t)
	err := m.Wire(WireOpts{ServerURL: "https://foo.example/%0Aevil"})
	if err == nil {
		t.Fatalf("Wire with control-char URL = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "invalid server URL") {
		t.Errorf("error = %v, want to mention 'invalid server URL'", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("expected pip.conf to be absent after failed Wire, stat err = %v", statErr)
	}
}

func TestPipStatusBeforeAndAfterWire(t *testing.T) {
	m, _ := setupPip(t)
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
