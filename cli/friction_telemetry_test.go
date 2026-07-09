package cli

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/telemetry"
)

// capturedEvent (declared in guard_nudge_test.go) records one emitted event;
// reused here so the two telemetry seams share a single recorder shape.

// withCapturedEmits swaps the package-level cliEmit seam for an in-memory
// recorder for the duration of a test, returning a pointer to the slice the
// friction-telemetry call sites append to. Restores the real emit on cleanup.
// This is the same seam guardEmit uses, so no network client is stood up.
func withCapturedEmits(t *testing.T) *[]capturedEvent {
	t.Helper()
	var events []capturedEvent
	prev := cliEmit
	cliEmit = func(name string, props map[string]any) {
		events = append(events, capturedEvent{name: name, props: props})
	}
	t.Cleanup(func() { cliEmit = prev })
	return &events
}

// findEvent returns the first captured event with the given name, or nil.
func findEvent(events []capturedEvent, name string) *capturedEvent {
	for i := range events {
		if events[i].name == name {
			return &events[i]
		}
	}
	return nil
}

// TestUninstallHook_EmitsRemovedEvent asserts the churn signal fires with the
// manager name when an actually-wired hook is removed.
func TestUninstallHook_EmitsRemovedEvent(t *testing.T) {
	withHookEnv(t)
	events := withCapturedEmits(t)

	// Wire npm first so there is a block to remove.
	install := newInstallHookCmd()
	install.SetArgs([]string{"npm"})
	var out, errb bytes.Buffer
	install.SetOut(&out)
	install.SetErr(&errb)
	if err := install.Execute(); err != nil {
		t.Fatalf("wire setup: %v\nstderr: %s", err, errb.String())
	}

	uninstall := newUninstallHookCmd()
	uninstall.SetArgs([]string{"npm"})
	out.Reset()
	errb.Reset()
	uninstall.SetOut(&out)
	uninstall.SetErr(&errb)
	if err := uninstall.Execute(); err != nil {
		t.Fatalf("uninstall: %v\nstderr: %s", err, errb.String())
	}

	ev := findEvent(*events, telemetry.EventCLIInstallHookRemoved)
	if ev == nil {
		t.Fatalf("expected %s to be emitted; got events: %v", telemetry.EventCLIInstallHookRemoved, *events)
	}
	if got := ev.props["manager"]; got != "npm" {
		t.Fatalf("removed event manager prop = %v, want \"npm\"", got)
	}
}

// TestUninstallHook_NoBlock_DoesNotEmitRemoved asserts the idempotent no-op
// (ErrNotWired) stays silent — removing nothing is not churn.
func TestUninstallHook_NoBlock_DoesNotEmitRemoved(t *testing.T) {
	withHookEnv(t)
	events := withCapturedEmits(t)

	uninstall := newUninstallHookCmd()
	uninstall.SetArgs([]string{"npm"})
	var out, errb bytes.Buffer
	uninstall.SetOut(&out)
	uninstall.SetErr(&errb)
	if err := uninstall.Execute(); err != nil {
		t.Fatalf("uninstall: %v\nstderr: %s", err, errb.String())
	}

	if ev := findEvent(*events, telemetry.EventCLIInstallHookRemoved); ev != nil {
		t.Fatalf("did not expect %s on an idempotent no-op, got props: %v", telemetry.EventCLIInstallHookRemoved, ev.props)
	}
}

// TestDoctor_EmitsFailedCheckNames asserts cli.doctor.run carries the list of
// which managers are unwired (not just the count), so the funnel can surface
// the most common blocker.
func TestDoctor_EmitsFailedCheckNames(t *testing.T) {
	withHookEnv(t)
	events := withCapturedEmits(t)

	// Wire npm so it passes; every other manager stays unwired and must
	// appear in failed_checks.
	install := newInstallHookCmd()
	install.SetArgs([]string{"npm"})
	var ibuf, ierr bytes.Buffer
	install.SetOut(&ibuf)
	install.SetErr(&ierr)
	if err := install.Execute(); err != nil {
		t.Fatalf("wire npm: %v\nstderr: %s", err, ierr.String())
	}

	cmd := newDoctorCmd()
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("no-color", true, "")
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("doctor: %v\nstderr: %s", err, errb.String())
	}

	ev := findEvent(*events, telemetry.EventCLIDoctorRun)
	if ev == nil {
		t.Fatalf("expected %s to be emitted; got events: %v", telemetry.EventCLIDoctorRun, *events)
	}
	// Counts are still present.
	if _, ok := ev.props["checks_passed"]; !ok {
		t.Fatalf("doctor.run missing checks_passed count; props: %v", ev.props)
	}
	if _, ok := ev.props["checks_failed"]; !ok {
		t.Fatalf("doctor.run missing checks_failed count; props: %v", ev.props)
	}
	// The new names array.
	raw, ok := ev.props["failed_checks"]
	if !ok {
		t.Fatalf("doctor.run missing failed_checks names; props: %v", ev.props)
	}
	names, ok := raw.([]string)
	if !ok {
		t.Fatalf("failed_checks should be []string, got %T (%v)", raw, raw)
	}
	if contains(names, "npm") {
		t.Fatalf("npm was wired; it must not appear in failed_checks: %v", names)
	}
	if !contains(names, "pip") {
		t.Fatalf("pip is unwired and should appear in failed_checks: %v", names)
	}
	// The names array length must match the failed count.
	if cf, ok := ev.props["checks_failed"].(int); ok && len(names) != cf {
		t.Fatalf("failed_checks length %d != checks_failed count %d", len(names), cf)
	}
}

// TestSetup_AbandonedFiresWithStepOnEarlyExit asserts the abandonment funnel
// records WHERE the user dropped: a server that fails the /healthz probe makes
// step 1 return early, and the deferred guard must emit cli.setup.abandoned
// with step="server_url" (not a generic "didn't finish").
func TestSetup_AbandonedFiresWithStepOnEarlyExit(t *testing.T) {
	// Point the wizard at a closed port so /healthz fails immediately.
	// stdinIsTerminal() is false under `go test`, so PromptString returns
	// this default without blocking on input.
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("server_url", "http://127.0.0.1:1")

	// No persisted progress — start clean so step 1 runs.
	t.Setenv("HOME", t.TempDir())

	events := withCapturedEmits(t)

	cmd := &cobra.Command{Use: "setup", RunE: runSetup}
	cmd.Flags().Bool("yes", false, "")
	cmd.Flags().Bool("skip-persona", false, "")
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(nil)

	// Expect a non-nil error (server not reachable) — the wizard bailed.
	if err := cmd.Execute(); err == nil {
		t.Fatalf("expected setup to fail at the connectivity check, got nil error\nstdout: %s", out.String())
	}

	ev := findEvent(*events, telemetry.EventCLISetupAbandoned)
	if ev == nil {
		t.Fatalf("expected %s on early exit; got events: %v", telemetry.EventCLISetupAbandoned, *events)
	}
	if got := ev.props["step"]; got != "server_url" {
		t.Fatalf("abandoned step = %v, want \"server_url\"", got)
	}
	// Abandon XOR completed — the completed event must NOT have fired.
	if c := findEvent(*events, telemetry.EventCLISetupCompleted); c != nil {
		t.Fatalf("completed must not fire on an abandoned run; got props: %v", c.props)
	}
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
