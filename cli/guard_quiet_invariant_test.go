package cli_test

// guard_quiet_invariant_test.go — Foundation part 2, invariant (5).
//
// --quiet must NEVER suppress a block reason or change an exit code; it only
// silences progress/chatter. The guard block path (runGuardedPassthrough →
// os.Exit(ExitBlocked)) writes its verdict to stderr unconditionally, so the
// only faithful way to prove the invariant end-to-end is to run the real
// binary: assert that a blocked typosquat install under --quiet still prints
// the verdict to stderr AND exits with ExitBlocked(1).
//
// This lives in package cli_test (external) and shells out to the compiled
// binary so the os.Exit in the guard path is exercised for real rather than
// mocked away.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildChainsawBinary compiles cmd/chainsaw into a temp path once per test.
// Returns the binary path; skips (not fails) if the toolchain is unavailable so
// the broader suite stays runnable in constrained environments.
func buildChainsawBinary(t *testing.T) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH; skipping binary-level invariant test")
	}
	bin := filepath.Join(t.TempDir(), "chainsaw")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	// The test runs from core/cli; the binary main lives at ../cmd/chainsaw.
	cmd := exec.Command(goTool, "build", "-o", bin, "../cmd/chainsaw")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build chainsaw binary: %v\n%s", err, out)
	}
	return bin
}

// TestQuiet_BlockedInstallStillEmitsVerdictAndExitsBlocked is the invariant
// guard. `chainsaw --quiet npm install lodahs` (a 1-edit typosquat of lodash
// caught by the offline floor) must:
//   - exit ExitBlocked (process exit code 1),
//   - print the block verdict to STDERR (never silenced by --quiet),
//   - keep STDOUT clean.
func TestQuiet_BlockedInstallStillEmitsVerdictAndExitsBlocked(t *testing.T) {
	bin := buildChainsawBinary(t)

	cmd := exec.Command(bin, "--quiet", "npm", "install", "lodahs")
	// Force-disable color and pin a clean env so the assertion is on the text,
	// not on ANSI. Keep PATH so exec.LookPath inside the guard still resolves.
	cmd.Env = append(os.Environ(),
		"NO_COLOR=1",
		"CHAINSAW_NO_TELEMETRY=1",
	)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	// Exit code must be ExitBlocked(1). exec returns *ExitError for non-zero.
	exitCode := 0
	if err != nil {
		var ee *exec.ExitError
		if !asExitError(err, &ee) {
			t.Fatalf("unexpected non-exit error running guard: %v (stderr=%q)", err, stderr.String())
		}
		exitCode = ee.ExitCode()
	}
	if exitCode != 1 { // ExitBlocked
		t.Fatalf("blocked install under --quiet exit code = %d, want 1 (ExitBlocked)\nstderr=%q",
			exitCode, stderr.String())
	}

	// The block verdict MUST survive --quiet, on stderr.
	if !strings.Contains(stderr.String(), "lodahs") || !strings.Contains(stderr.String(), "blocked") {
		t.Fatalf("--quiet swallowed the block verdict; stderr=%q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "nothing was installed") {
		t.Fatalf("--quiet swallowed the refusal summary; stderr=%q", stderr.String())
	}

	// Results channel (stdout) stays clean — the guard speaks on stderr.
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("guard wrote to stdout under --quiet (should be stderr-only): %q", stdout.String())
	}
}

// asExitError is a tiny errors.As shim kept local so this external test file
// doesn't need to import errors just for one call site.
func asExitError(err error, target **exec.ExitError) bool {
	for err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			*target = ee
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
