package hook

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupCargo(t *testing.T) (cargoManager, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("CARGO_HOME", dir)
	return cargoManager{}, filepath.Join(dir, "config.toml")
}

func TestCargoWireIntoEmpty(t *testing.T) {
	m, path := setupCargo(t)
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
	if !strings.Contains(string(data), "source.crates-io") {
		t.Errorf("body missing cargo scaffold: %s", data)
	}
	if bks := listBackups(t, path); len(bks) != 0 {
		t.Errorf("expected no backup on fresh wire, got %v", bks)
	}
}

func TestCargoWireTwiceReplacesAndBacksUp(t *testing.T) {
	m, path := setupCargo(t)
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

func TestCargoWirePreservesUserContent(t *testing.T) {
	m, path := setupCargo(t)
	user := "[build]\njobs = 4\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
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
	if !strings.Contains(string(data), "jobs = 4") {
		t.Errorf("user content dropped: %s", data)
	}
	if !hasSentinel(data) {
		t.Errorf("sentinel missing: %s", data)
	}
	if bks := listBackups(t, path); len(bks) != 1 {
		t.Errorf("expected 1 backup, got %d", len(bks))
	}
}

func TestCargoUnwireAfterWire(t *testing.T) {
	m, path := setupCargo(t)
	user := "[build]\njobs = 4\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
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
	if !strings.Contains(string(data), "jobs = 4") {
		t.Errorf("user content lost: %s", data)
	}
}

func TestCargoUnwireNoSentinelReturnsErrNotWired(t *testing.T) {
	m, _ := setupCargo(t)
	if err := m.Unwire(ScopeUser); !errors.Is(err, ErrNotWired) {
		t.Errorf("empty file Unwire error = %v, want ErrNotWired", err)
	}
}

func TestCargoWireRejectsQuoteInURL(t *testing.T) {
	m, path := setupCargo(t)
	err := m.Wire(WireOpts{ServerURL: `https://foo.example/"-evil="true`})
	if err == nil {
		t.Fatalf("Wire with quote-injection URL = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "invalid server URL") {
		t.Errorf("error = %v, want to mention 'invalid server URL'", err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("expected config.toml to be absent after failed Wire, stat err = %v", statErr)
	}
}

func TestCargoWireProducesQuotedTOML(t *testing.T) {
	m, path := setupCargo(t)
	if err := m.Wire(WireOpts{ServerURL: "https://proxy.example.com"}); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// strconv.Quote output surrounds with double quotes and forms a valid
	// TOML basic-string literal.
	// BUG-A6: URL must be org-scoped; missing OrgSlug falls back to the
	// "your-org-slug" placeholder so the snippet fails closed.
	want := `registry = "sparse+https://proxy.example.com/chainproxy/repository/@your-org-slug/crates-io/"`
	if !strings.Contains(string(data), want) {
		t.Errorf("config.toml missing quoted registry line %q; got:\n%s", want, data)
	}
}

func TestCargoStatusBeforeAndAfterWire(t *testing.T) {
	m, _ := setupCargo(t)
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
