package hook

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every test in this package must read a throwaway system brew.env, never
// the machine's real /etc/homebrew/brew.env.
func init() {
	BrewSystemEnvPath = filepath.Join(os.TempDir(), "chainsaw-hook-test-no-such-dir", "brew.env")
}

func TestBrewWirePreservesLinesAndIsIdempotent(t *testing.T) {
	home := sandboxHome(t)
	path := filepath.Join(home, ".homebrew", "brew.env")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("HOMEBREW_NO_ANALYTICS=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := testWireOpts()
	opts.Credentials = testCreds
	m := brewManager{}
	for i := 0; i < 2; i++ {
		if err := m.Wire(opts); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(path)
	body := string(b)
	for _, want := range []string{
		"HOMEBREW_NO_ANALYTICS=1",
		"HOMEBREW_API_DOMAIN=https://chain305.com/repository/@acme-corp/homebrew/api",
		"HOMEBREW_ARTIFACT_DOMAIN=https://chain305.com/repository/@acme-corp/homebrew\n",
		"HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1",
		// Built, not a literal: a hardcoded token-shaped string trips the
		// opencore-export gitleaks gate.
		"HOMEBREW_DOCKER_REGISTRY_BASIC_AUTH_TOKEN=" + base64.StdEncoding.EncodeToString([]byte(testCreds)),
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in\n%s", want, body)
		}
	}
	if strings.Count(body, sentinelStart) != 1 {
		t.Errorf("wire is not idempotent:\n%s", body)
	}
	if st, _ := m.Status(); !st.Wired {
		t.Error("Status not wired after Wire")
	}
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(path)
	if strings.TrimSpace(string(b)) != "HOMEBREW_NO_ANALYTICS=1" {
		t.Errorf("unwire left %q", b)
	}
}

func TestBrewStatusNeedsNoFallback(t *testing.T) {
	home := sandboxHome(t)
	path := filepath.Join(home, ".homebrew", "brew.env")
	for body, want := range map[string]bool{
		"HOMEBREW_ARTIFACT_DOMAIN=https://x/repository/@a/homebrew\nHOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1\n":     true,
		"HOMEBREW_ARTIFACT_DOMAIN=https://x/repository/@a/homebrew\n":                                             false,
		"HOMEBREW_ARTIFACT_DOMAIN=https://x/repository/@a/homebrew\nHOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=false\n": false,
		"HOMEBREW_ARTIFACT_DOMAIN=https://ghcr.io\nHOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1\n":                      false,
		"# HOMEBREW_ARTIFACT_DOMAIN=https://x/repository/h\n# HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1\n":           false,
	} {
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		st, err := brewManager{}.Status()
		if err != nil || st.Wired != want {
			t.Errorf("Status(%q) wired=%v err=%v, want %v", body, st.Wired, err, want)
		}
	}
}

func TestWriteBrewPolicyKeepsOtherBlocks(t *testing.T) {
	home := sandboxHome(t)
	if err := (brewManager{}).Wire(testWireOpts()); err != nil {
		t.Fatal(err)
	}
	path, _ := BrewUserEnvPath()
	for _, body := range []string{"HOMEBREW_FORBIDDEN_FORMULAE=a b\n", "# v2\nHOMEBREW_FORBIDDEN_FORMULAE=c\n"} {
		if err := WriteBrewPolicy(path, body); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(path)
	s := string(b)
	if !strings.Contains(s, "HOMEBREW_ARTIFACT_DOMAIN=") || !strings.Contains(s, "HOMEBREW_FORBIDDEN_FORMULAE=c") ||
		strings.Contains(s, "=a b") || strings.Count(s, BrewPolicyMarkers[0]) != 1 {
		t.Fatalf("policy block not replaced in place:\n%s", s)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
	_ = home
}
