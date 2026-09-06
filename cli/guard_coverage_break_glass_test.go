package cli

// On the CLI/guard surface the ONLY record of CHAINSAW_COVERAGE_BREAK_GLASS
// was a line on the stderr of the process doing the bypassing — erasable with
// `2>/dev/null`. These pin the local spool that survives the invocation, and,
// more importantly, pin that the spool can NEVER fail the invocation.
//
// The failure mode is the whole design. Break-glass is an emergency hatch; a
// hatch that fails during an emergency is worse than no hatch.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/cli/platform"
	"github.com/chain305/chainsaw-core/coverage"
)

// withTempConfigHome points configDir() at a scratch directory for one test.
func withTempConfigHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(platform.EnvConfigHome, dir)
	return dir
}

func readSpool(t *testing.T, dir string) []breakGlassRecord {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, breakGlassSpoolFile))
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	var out []breakGlassRecord
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var rec breakGlassRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("spool line is not JSON (%q): %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

// TestGuardPostureBreakGlassWritesDurableSpool is the core claim: after a
// break-glass invocation there is a record that outlives the process, and the
// operator is told where it is.
//
// Deletion proof: remove recordGuardBreakGlass from guardPosture's callback
// and this fails.
func TestGuardPostureBreakGlassWritesDurableSpool(t *testing.T) {
	dir := withTempConfigHome(t)
	t.Setenv(coverage.EnvMode, string(coverage.ModeClosed))
	t.Setenv(coverage.EnvRequired, string(coverage.SourceCVE))
	t.Setenv(coverage.EnvBreakGlass, "1")

	posture, err := guardPosture()
	if err != nil {
		t.Fatalf("guardPosture: %v", err)
	}
	// Break-glass still disables the gate — the record must not change the
	// behaviour of the hatch.
	if posture.Mode != coverage.ModeOff {
		t.Fatalf("posture mode = %q, want off; recording a bypass must not change what the bypass does", posture.Mode)
	}

	recs := readSpool(t, dir)
	if len(recs) != 1 {
		t.Fatalf("spool holds %d records, want 1", len(recs))
	}
	got := recs[0]
	if got.Event != "coverage.break_glass" {
		t.Fatalf("event = %q, want coverage.break_glass (the audit_events action the server persists)", got.Event)
	}
	if got.Mode != string(coverage.ModeClosed) {
		t.Fatalf("coverage_mode = %q, want closed — the record must say WHICH control was disabled", got.Mode)
	}
	if got.PID == 0 || got.At.IsZero() {
		t.Fatalf("record is missing pid/time: %+v", got)
	}
	if got.Delivered {
		t.Fatal("record claims delivered=true, but nothing ships the spool to the server yet — claiming delivery that did not happen is worse than reporting the gap")
	}
	if strings.TrimSpace(got.Undelivered) == "" {
		t.Fatal("record reports delivered=false with no reason; an operator collecting the spool needs to know why it is still local")
	}
}

// TestBreakGlassRecordIsAppendOnly — a second bypass must not overwrite the
// first. A security log that keeps only the most recent entry hides exactly
// the pattern an investigation is looking for.
func TestBreakGlassRecordIsAppendOnly(t *testing.T) {
	dir := withTempConfigHome(t)
	t.Setenv(coverage.EnvMode, string(coverage.ModeClosed))
	t.Setenv(coverage.EnvRequired, string(coverage.SourceCVE))
	t.Setenv(coverage.EnvBreakGlass, "1")

	for i := 0; i < 3; i++ {
		if _, err := guardPosture(); err != nil {
			t.Fatalf("guardPosture #%d: %v", i, err)
		}
	}
	if recs := readSpool(t, dir); len(recs) != 3 {
		t.Fatalf("spool holds %d records after 3 bypasses, want 3", len(recs))
	}
}

// TestNoBreakGlassWritesNothing — the spool must not appear on ordinary runs.
// A file that exists on every invocation tells an investigator nothing.
func TestNoBreakGlassWritesNothing(t *testing.T) {
	dir := withTempConfigHome(t)
	t.Setenv(coverage.EnvMode, string(coverage.ModeClosed))
	t.Setenv(coverage.EnvRequired, string(coverage.SourceCVE))

	if _, err := guardPosture(); err != nil {
		t.Fatalf("guardPosture: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, breakGlassSpoolFile)); !os.IsNotExist(err) {
		t.Fatalf("spool exists without break-glass (stat err = %v)", err)
	}
}

// TestBreakGlassNeverFailsTheInvocation is the one that matters most.
//
// An unwritable config home is the realistic emergency case: a hardened CI
// image, a read-only HOME, a full disk. The hatch must still open, the call
// must still return the OFF posture with no error, and the operator must be
// told plainly that no durable record exists — never a silent success.
//
// Deletion proof: change appendBreakGlassSpool's error branch to panic, or
// make recordGuardBreakGlass propagate, and this fails.
func TestBreakGlassNeverFailsTheInvocation(t *testing.T) {
	parent := t.TempDir()
	// A regular FILE where the config directory should be: MkdirAll and
	// OpenFile both fail, and no test can be tricked into passing by root.
	blocked := filepath.Join(parent, "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	t.Setenv(platform.EnvConfigHome, blocked)
	t.Setenv(coverage.EnvMode, string(coverage.ModeClosed))
	t.Setenv(coverage.EnvRequired, string(coverage.SourceCVE))
	t.Setenv(coverage.EnvBreakGlass, "1")

	if _, err := appendBreakGlassSpool(breakGlassRecord{Event: "coverage.break_glass"}); err == nil {
		t.Fatal("appendBreakGlassSpool succeeded against an unwritable config home; the fixture is not exercising the failure branch")
	}

	posture, err := guardPosture()
	if err != nil {
		t.Fatalf("guardPosture returned an error when the spool could not be written: %v — break-glass must never introduce a new failure mode", err)
	}
	if posture.Mode != coverage.ModeOff {
		t.Fatalf("posture mode = %q, want off — an unwritable spool must not stop the hatch opening", posture.Mode)
	}
}

// TestBreakGlassSpoolRefusesToGrowUnbounded — a CI job looping with
// break-glass set must not fill a developer's disk through a security-logging
// path. And it must REFUSE rather than rotate: rotation deletes un-shipped
// security records, the one outcome this file exists to prevent.
func TestBreakGlassSpoolRefusesToGrowUnbounded(t *testing.T) {
	dir := withTempConfigHome(t)
	path := filepath.Join(dir, breakGlassSpoolFile)
	if err := os.WriteFile(path, make([]byte, breakGlassSpoolCap+1), 0o600); err != nil {
		t.Fatalf("seed oversized spool: %v", err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if _, err := appendBreakGlassSpool(breakGlassRecord{Event: "coverage.break_glass", At: time.Now()}); err == nil {
		t.Fatal("appended past the spool cap; a looping CI job could fill the disk through the logging path")
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after: %v", err)
	}
	if after.Size() < before.Size() {
		t.Fatalf("spool shrank from %d to %d bytes — the cap must refuse, never truncate un-shipped records", before.Size(), after.Size())
	}
}

// TestBreakGlassRecordCarriesNoCredential — the spool sits unencrypted in the
// user's config home. Host, user and pid are the identifiers an investigator
// needs; an auth token is not.
func TestBreakGlassRecordCarriesNoCredential(t *testing.T) {
	dir := withTempConfigHome(t)
	t.Setenv(coverage.EnvMode, string(coverage.ModeClosed))
	t.Setenv(coverage.EnvRequired, string(coverage.SourceCVE))
	t.Setenv(coverage.EnvBreakGlass, "1")
	if _, err := guardPosture(); err != nil {
		t.Fatalf("guardPosture: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, breakGlassSpoolFile))
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	for _, banned := range []string{"token", "secret", "password", "api_key", "authorization"} {
		if strings.Contains(strings.ToLower(string(raw)), banned) {
			t.Fatalf("spool line contains %q; this file is unencrypted in the user's config home", banned)
		}
	}
}
