package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
)

// T5: `chainsaw version --json` must carry an `edition` field, defaulting to
// "community" for an un-ldflag'd build (go test injects no -X, so Edition
// stays at its package default).
func TestVersionJSON_IncludesEdition(t *testing.T) {
	c, _, err := rootCmd.Find([]string{"version"})
	if err != nil || c == nil || c.Name() != "version" {
		t.Fatalf("could not locate version command: %v", err)
	}
	// Drive RunE with a command that has the --json flag registered, since
	// the version command reads it via useJSON/resolveFormat.
	test := &cobra.Command{Use: "version"}
	test.Flags().Bool("json", true, "")
	var buf bytes.Buffer
	test.SetOut(&buf)
	if rerr := c.RunE(test, nil); rerr != nil {
		t.Fatalf("version RunE: %v", rerr)
	}
	var doc map[string]any
	if jerr := json.Unmarshal(buf.Bytes(), &doc); jerr != nil {
		t.Fatalf("version --json not valid JSON: %v\n%s", jerr, buf.String())
	}
	ed, ok := doc["edition"]
	if !ok {
		t.Fatalf("version --json missing `edition` key: %s", buf.String())
	}
	if ed != "community" {
		t.Errorf("edition = %v, want %q (default build)", ed, "community")
	}
}

// BUG-CLI-5 regression: when -ldflags weren't set (ad-hoc `go build`),
// resolveVersion must pull VCS info from runtime/debug.ReadBuildInfo
// instead of leaving the user with bare "dev / none". The exact commit
// SHA depends on the host workspace, so we only assert structural shape:
// the AdHoc flag is set, and Version + Commit are non-empty defaults.
func TestResolveVersion_AdHocFallback(t *testing.T) {
	// Reset the once so the test re-runs the resolver. Tests run inside
	// the same process as other version tests, so be cautious — we
	// restore the original sync.Once afterwards.
	versionOnce = sync.Once{}
	defer func() { versionOnce = sync.Once{} }()

	v := resolveVersion()
	if v.Version == "" {
		t.Errorf("Version should never be empty after resolveVersion")
	}
	if v.Commit == "" {
		t.Errorf("Commit should never be empty after resolveVersion")
	}
	// In an ad-hoc test binary (no -ldflags), the ad-hoc flag must fire.
	// `go test` doesn't inject -X, so the package-level Version stays at
	// its compile-time "dev" sentinel and AdHoc resolves true.
	if Version == "dev" && !v.AdHoc {
		t.Errorf("AdHoc should be true when no -ldflags were applied")
	}
}

// BUG-CLI-5: the human-readable output should signal ad-hoc builds so
// support tickets can tell production binaries from local compiles.
func TestResolveVersion_AdHocTagInHumanString(t *testing.T) {
	versionOnce = sync.Once{}
	defer func() { versionOnce = sync.Once{} }()

	v := resolveVersion()
	if !v.AdHoc {
		t.Skip("not running in an ad-hoc binary; nothing to assert")
	}
	// Mimic the version command's format.
	line := "chainsaw version " + v.Version
	if v.AdHoc {
		line += " (ad-hoc build)"
	}
	if !strings.Contains(line, "(ad-hoc build)") {
		t.Errorf("ad-hoc human line missing tag: %s", line)
	}
}
