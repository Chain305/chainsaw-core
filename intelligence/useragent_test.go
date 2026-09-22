package intelligence

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestUserAgent_CarriesVersionAndContact(t *testing.T) {
	got := UserAgent("deps")
	if !strings.HasPrefix(got, "chainsaw-intelligence/") {
		t.Errorf("UserAgent = %q, want the chainsaw-intelligence product token", got)
	}
	// PyPI, crates.io and Sonatype each ask for a contact URL by name.
	if !strings.Contains(got, "+https://chain305.com") {
		t.Errorf("UserAgent = %q, missing the contact URL those registry policies require", got)
	}
	if !strings.Contains(got, "deps") {
		t.Errorf("UserAgent = %q, lost the component that lets an operator tell our callers apart", got)
	}
	if strings.Contains(got, "//") && !strings.Contains(got, "https://") {
		t.Errorf("UserAgent = %q looks malformed", got)
	}
}

func TestUserAgent_EmptyComponentStillWellFormed(t *testing.T) {
	got := UserAgent("  ")
	if got != "chainsaw-intelligence/"+UserAgentVersion+" (+https://chain305.com)" {
		t.Errorf("UserAgent(\"\") = %q", got)
	}
}

// TestNoHardcodedIntelligenceUserAgent is the guard, not the test.
//
// The defect was never one bad string — it was six hand-written
// variants that drifted apart, none carrying a version or a contact,
// while two files elsewhere had already settled the right shape. A unit
// test on UserAgent() cannot catch the seventh one somebody adds, so
// this scans the package source instead.
func TestNoHardcodedIntelligenceUserAgent(t *testing.T) {
	// `User-Agent", "` — a Set with a string literal rather than a call.
	literal := regexp.MustCompile(`User-Agent"\s*,\s*"`)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var scanned int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scanned++
		for i, line := range strings.Split(string(src), "\n") {
			if literal.MatchString(line) {
				t.Errorf("%s:%d sets a literal User-Agent; use UserAgent(<component>) so the version and contact URL stay in one place\n  %s",
					name, i+1, strings.TrimSpace(line))
			}
		}
	}
	// A guard that scanned nothing is a guard that passed for the wrong
	// reason.
	if scanned == 0 {
		t.Fatal("scanned 0 files — the guard did not run")
	}
}
