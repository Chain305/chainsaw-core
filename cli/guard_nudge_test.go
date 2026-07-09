package cli

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/telemetry"
)

// captureGuardEmits swaps guardEmit for a recorder and returns the captured
// event names plus a restore func. Tests assert on which funnel events fired.
func captureGuardEmits(t *testing.T) (events *[]capturedEvent, restore func()) {
	t.Helper()
	var got []capturedEvent
	prev := guardEmit
	guardEmit = func(name string, props map[string]any) {
		got = append(got, capturedEvent{name: name, props: props})
	}
	return &got, func() { guardEmit = prev }
}

type capturedEvent struct {
	name  string
	props map[string]any
}

func countEvents(events []capturedEvent, name string) int {
	n := 0
	for _, e := range events {
		if e.name == name {
			n++
		}
	}
	return n
}

// blockVerdict / passVerdict are tiny fixtures for processGuardOutcome.
func blockVerdict() guardVerdict {
	return guardVerdict{Spec: packageSpec{Ecosystem: "npm", Name: "evil"}, Block: true, Severity: "malicious", Reason: "known-malicious package"}
}
func passVerdict() guardVerdict {
	return guardVerdict{Spec: packageSpec{Ecosystem: "npm", Name: "react"}}
}

// hermeticGuard isolates guard_state.json to a temp dir and grants telemetry
// consent so the emit branch is exercised. Returns nothing — state is on disk.
func hermeticGuard(t *testing.T, consent string) {
	t.Helper()
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())
	if consent != "" {
		saveGuardState(&guardState{Consent: consent})
	}
}

// TestProcessGuardOutcome_ActivatedFiresOnce verifies install.guard.activated
// is a once-per-install milestone: it fires on the first block and never again,
// even across a fresh load (persisted via st.Activated).
func TestProcessGuardOutcome_ActivatedFiresOnce(t *testing.T) {
	hermeticGuard(t, consentGranted)
	t.Setenv("CHAINSAW_NO_NUDGE", "1") // keep CTA output off; nudge tests cover that branch
	events, restore := captureGuardEmits(t)
	defer restore()

	// First block → activation fires once.
	processGuardOutcome("npm", []guardVerdict{blockVerdict()}, true)
	if n := countEvents(*events, telemetry.EventInstallGuardActivated); n != 1 {
		t.Fatalf("first block: activated fired %d times, want 1", n)
	}
	if !loadGuardState().Activated {
		t.Fatal("Activated flag must persist after first block")
	}

	// Second block (fresh state load) → must NOT re-fire.
	*events = nil
	processGuardOutcome("npm", []guardVerdict{blockVerdict()}, true)
	if n := countEvents(*events, telemetry.EventInstallGuardActivated); n != 0 {
		t.Fatalf("second block: activated re-fired %d times, want 0", n)
	}
}

// TestProcessGuardOutcome_ActivatedNeedsBlock verifies a clean run never
// activates: no block, no milestone.
func TestProcessGuardOutcome_ActivatedNeedsBlock(t *testing.T) {
	hermeticGuard(t, consentGranted)
	t.Setenv("CHAINSAW_NO_NUDGE", "1")
	events, restore := captureGuardEmits(t)
	defer restore()

	processGuardOutcome("npm", []guardVerdict{passVerdict()}, false)
	if n := countEvents(*events, telemetry.EventInstallGuardActivated); n != 0 {
		t.Fatalf("clean run activated %d times, want 0", n)
	}
	if loadGuardState().Activated {
		t.Fatal("clean run must not set Activated")
	}
}

// TestProcessGuardOutcome_DailyActiveDedupsPerDay verifies install.guard.daily_active
// fires once for the first run of a UTC day and dedups on the next run the same
// day (LastActiveDay persisted).
func TestProcessGuardOutcome_DailyActiveDedupsPerDay(t *testing.T) {
	hermeticGuard(t, consentGranted)
	t.Setenv("CHAINSAW_NO_NUDGE", "1")
	events, restore := captureGuardEmits(t)
	defer restore()

	processGuardOutcome("npm", []guardVerdict{passVerdict()}, false)
	if n := countEvents(*events, telemetry.EventInstallGuardDailyActive); n != 1 {
		t.Fatalf("first run: daily_active fired %d times, want 1", n)
	}

	*events = nil
	processGuardOutcome("npm", []guardVerdict{passVerdict()}, false)
	if n := countEvents(*events, telemetry.EventInstallGuardDailyActive); n != 0 {
		t.Fatalf("same-day second run: daily_active fired %d times, want 0", n)
	}

	// A new UTC day re-arms the heartbeat.
	st := loadGuardState()
	st.LastActiveDay = "2000-01-01"
	saveGuardState(st)
	*events = nil
	processGuardOutcome("npm", []guardVerdict{passVerdict()}, false)
	if n := countEvents(*events, telemetry.EventInstallGuardDailyActive); n != 1 {
		t.Fatalf("new-day run: daily_active fired %d times, want 1", n)
	}
}

// TestProcessGuardOutcome_FirstBlockSilent verifies the first-ever block prints
// no CTA and records neither nudge_shown nor nudge_suppressed — the "aha" block
// is left clean (this is what keeps the demo / Show HN transcript free of
// marketing lines). The block itself is still counted and activation still fires.
func TestProcessGuardOutcome_FirstBlockSilent(t *testing.T) {
	hermeticGuard(t, consentGranted)
	t.Setenv("CHAINSAW_NO_NUDGE", "") // nudges allowed; the silence is the first-block gate, not suppression
	t.Setenv("CI", "")
	events, restore := captureGuardEmits(t)
	defer restore()

	processGuardOutcome("npm", []guardVerdict{blockVerdict()}, true)

	if n := countEvents(*events, telemetry.EventInstallGuardNudgeShown); n != 0 {
		t.Fatalf("first block: nudge_shown fired %d times, want 0", n)
	}
	if n := countEvents(*events, telemetry.EventInstallGuardNudgeSuppressed); n != 0 {
		t.Fatalf("first block: nudge_suppressed fired %d times, want 0", n)
	}
}

// TestProcessGuardOutcome_NudgeShownPostBlock verifies a printed post-block
// nudge emits nudge_shown with kind=post_block (nudges enabled, consent granted).
// The nudge starts on the SECOND block — the first is intentionally silent — so
// this drives two blocks and asserts on the second.
func TestProcessGuardOutcome_NudgeShownPostBlock(t *testing.T) {
	hermeticGuard(t, consentGranted)
	t.Setenv("CHAINSAW_NO_NUDGE", "") // allow nudge
	t.Setenv("CI", "")                // not CI
	events, restore := captureGuardEmits(t)
	defer restore()

	// First block: silent. Second block: the nudge fires.
	processGuardOutcome("npm", []guardVerdict{blockVerdict()}, true)
	*events = nil
	processGuardOutcome("npm", []guardVerdict{blockVerdict()}, true)

	if n := countEvents(*events, telemetry.EventInstallGuardNudgeShown); n != 1 {
		t.Fatalf("second block: nudge_shown fired %d times, want 1", n)
	}
	for _, e := range *events {
		if e.name == telemetry.EventInstallGuardNudgeShown {
			if e.props["nudge_kind"] != "post_block" {
				t.Fatalf("nudge_kind = %v, want post_block", e.props["nudge_kind"])
			}
		}
	}
	if n := countEvents(*events, telemetry.EventInstallGuardNudgeSuppressed); n != 0 {
		t.Fatalf("nudge_suppressed fired %d times on a shown nudge, want 0", n)
	}
}

// TestProcessGuardOutcome_NudgeSuppressedEnv verifies CHAINSAW_NO_NUDGE on a
// block emits nudge_suppressed{reason:env} and never nudge_shown. Suppression is
// only meaningful once a nudge is due, i.e. from the second block, so this drives
// two blocks and asserts on the second.
func TestProcessGuardOutcome_NudgeSuppressedEnv(t *testing.T) {
	hermeticGuard(t, consentGranted)
	t.Setenv("CHAINSAW_NO_NUDGE", "1")
	events, restore := captureGuardEmits(t)
	defer restore()

	processGuardOutcome("npm", []guardVerdict{blockVerdict()}, true)
	*events = nil
	processGuardOutcome("npm", []guardVerdict{blockVerdict()}, true)

	if n := countEvents(*events, telemetry.EventInstallGuardNudgeShown); n != 0 {
		t.Fatalf("nudge_shown fired %d times while suppressed, want 0", n)
	}
	if n := countEvents(*events, telemetry.EventInstallGuardNudgeSuppressed); n != 1 {
		t.Fatalf("nudge_suppressed fired %d times, want 1", n)
	}
	for _, e := range *events {
		if e.name == telemetry.EventInstallGuardNudgeSuppressed && e.props["reason"] != "env" {
			t.Fatalf("suppress reason = %v, want env", e.props["reason"])
		}
	}
}

// TestProcessGuardOutcome_NudgeSuppressedCI verifies CI is reported as
// reason=ci (and env wins over ci when both are set is covered by the ordering
// in nudgeSuppressReason).
func TestProcessGuardOutcome_NudgeSuppressedCI(t *testing.T) {
	hermeticGuard(t, consentGranted)
	t.Setenv("CHAINSAW_NO_NUDGE", "")
	t.Setenv("CI", "true")
	events, restore := captureGuardEmits(t)
	defer restore()

	// First block is silent regardless; the CI suppression is recorded once a
	// nudge is actually due, on the second block.
	processGuardOutcome("npm", []guardVerdict{blockVerdict()}, true)
	*events = nil
	processGuardOutcome("npm", []guardVerdict{blockVerdict()}, true)

	if n := countEvents(*events, telemetry.EventInstallGuardNudgeSuppressed); n != 1 {
		t.Fatalf("nudge_suppressed fired %d times, want 1", n)
	}
	for _, e := range *events {
		if e.name == telemetry.EventInstallGuardNudgeSuppressed && e.props["reason"] != "ci" {
			t.Fatalf("suppress reason = %v, want ci", e.props["reason"])
		}
	}
}

// TestProcessGuardOutcome_NoConsentSendsNothing verifies the whole funnel is
// silent when consent isn't granted, including the new activation/DAU/nudge
// events — the consent gate wraps them all.
func TestProcessGuardOutcome_NoConsentSendsNothing(t *testing.T) {
	hermeticGuard(t, "") // undecided
	t.Setenv("CHAINSAW_NO_NUDGE", "1")
	// Non-TTY so the first-run prompt can't grant; consent stays "".
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = prev }()

	events, restore := captureGuardEmits(t)
	defer restore()

	processGuardOutcome("npm", []guardVerdict{blockVerdict()}, true)
	if len(*events) != 0 {
		t.Fatalf("no-consent run emitted %d events, want 0: %+v", len(*events), *events)
	}
	// State still advances locally (activation flag persists for when they opt in).
	if !loadGuardState().Activated {
		t.Fatal("Activated must still persist locally even without consent")
	}
}

// TestGuardCTA verifies the attribution params are appended/merged, the
// install_id is included ONLY when consent is granted, and never leaks when
// the user declined the consent prompt.
func TestGuardCTA(t *testing.T) {
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())

	got := guardCTA("https://chain305.com/chainsaw/signup", consentGranted)
	if !strings.Contains(got, "ref=guard") {
		t.Fatalf("CTA missing ref=guard: %s", got)
	}
	if !strings.HasPrefix(got, "https://chain305.com/chainsaw/signup?") {
		t.Fatalf("CTA should start a fresh query with ?: %s", got)
	}

	// Existing query string → merge with &, not a second ?.
	merged := guardCTA("https://chain305.com/p?x=1", consentGranted)
	if strings.Count(merged, "?") != 1 || !strings.Contains(merged, "x=1&ref=guard") {
		t.Fatalf("CTA must merge into existing query: %s", merged)
	}

	// Consent declined: ref=guard stays (non-identifying) but the install_id
	// (iid) must NEVER appear — declining means nothing identifying is sent.
	declined := guardCTA("https://chain305.com/chainsaw/signup", consentDeclined)
	if !strings.Contains(declined, "ref=guard") {
		t.Fatalf("declined CTA should still carry ref=guard: %s", declined)
	}
	if strings.Contains(declined, "iid=") {
		t.Fatalf("declined CTA must NOT leak install_id: %s", declined)
	}
}

// TestEnsureGuardConsent_NonTTYNeverGrants is the CI-safety invariant: even
// though the interactive prompt now defaults to Yes, a non-terminal first run
// must stay UNDECIDED and persist nothing. A default "yes" must never silently
// apply in automation.
func TestEnsureGuardConsent_NonTTYNeverGrants(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = prev }()
	t.Setenv("CHAINSAW_TELEMETRY_DISABLED", "")
	t.Setenv("CHAINSAW_OFFLINE", "")

	st := &guardState{}
	if got := ensureGuardConsent(st, true); got != "" {
		t.Fatalf("non-TTY first run must stay undecided, got %q", got)
	}
	if st.Consent != "" {
		t.Fatalf("non-TTY must not persist a consent decision, got %q", st.Consent)
	}
}

// TestEnsureGuardConsent_EnvKillSwitchDeclines verifies an explicit env kill
// switch declines even on a TTY, and does not persist (it's a per-run override).
func TestEnsureGuardConsent_EnvKillSwitchDeclines(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	defer func() { stdinIsTerminal = prev }()
	t.Setenv("CHAINSAW_TELEMETRY_DISABLED", "1")

	st := &guardState{}
	if got := ensureGuardConsent(st, true); got != consentDeclined {
		t.Fatalf("env kill switch must decline, got %q", got)
	}
	if st.Consent != "" {
		t.Fatalf("env kill switch is per-run; must not persist, got %q", st.Consent)
	}
}

// TestEnsureGuardConsent_AlreadyDecidedShortCircuits verifies a stored decision
// is returned without consulting the terminal or prompting.
func TestEnsureGuardConsent_AlreadyDecidedShortCircuits(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { t.Fatal("must not check TTY when already decided"); return false }
	defer func() { stdinIsTerminal = prev }()

	for _, c := range []string{consentGranted, consentDeclined} {
		st := &guardState{Consent: c}
		if got := ensureGuardConsent(st, false); got != c {
			t.Fatalf("already-decided %q changed to %q", c, got)
		}
	}
}

// TestEnsureGuardConsent_InteractiveDefaultsYes verifies the new default: on a
// terminal, a blank Enter opts in, while an explicit "n" declines.
func TestEnsureGuardConsent_InteractiveDefaultsYes(t *testing.T) {
	prev := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	defer func() { stdinIsTerminal = prev }()
	t.Setenv("CHAINSAW_TELEMETRY_DISABLED", "")
	t.Setenv("CHAINSAW_OFFLINE", "")

	answer := func(input string) string {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		oldStdin := os.Stdin
		os.Stdin = r
		defer func() { os.Stdin = oldStdin }()
		go func() {
			_, _ = io.WriteString(w, input)
			_ = w.Close()
		}()
		st := &guardState{}
		return ensureGuardConsent(st, true)
	}

	if got := answer("\n"); got != consentGranted {
		t.Fatalf("blank Enter should default to granted, got %q", got)
	}
	if got := answer("n\n"); got != consentDeclined {
		t.Fatalf("explicit n should decline, got %q", got)
	}
}
