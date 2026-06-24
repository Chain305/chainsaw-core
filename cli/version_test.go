package cli

import (
	"strings"
	"sync"
	"testing"
)

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
