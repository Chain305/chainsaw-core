package telemetry

// install_privacy_test.go — R8, R9, R12.
//
// Every test here writes only into t.TempDir(); nothing touches the real
// ~/.config/chainsaw, and no network client is constructed.

import (
	"os"
	"path/filepath"
	"testing"
)

func installPath(dir string) string { return filepath.Join(dir, installFilename) }

// clearTelemetryEnv neutralizes every variable that steers ResolveMode, so a
// test only exercises the one it sets.
func clearTelemetryEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CHAINSAW_TELEMETRY_DEBUG", "CHAINSAW_TELEMETRY_DISABLED", "CHAINSAW_TELEMETRY_ENABLED",
		"CHAINSAW_OFFLINE", "CHAINSAW_SELF_HOSTED", "DO_NOT_TRACK", envConfigHome,
	} {
		t.Setenv(k, "")
	}
}

// ── R8: no identifier is minted while telemetry is disabled ───────────────────

func TestLoadInstall_OfflineMintsNothing(t *testing.T) {
	clearTelemetryEnv(t)
	dir := t.TempDir()
	t.Setenv("CHAINSAW_OFFLINE", "1")

	got, err := LoadInstall(dir)
	if err != nil {
		t.Fatalf("LoadInstall: %v", err)
	}
	if !got.Disabled || got.ID != "" {
		t.Fatalf("LoadInstall under CHAINSAW_OFFLINE = %+v, want Disabled with no ID", got)
	}
	if _, err := os.Stat(installPath(dir)); !os.IsNotExist(err) {
		data, _ := os.ReadFile(installPath(dir))
		t.Fatalf("CHAINSAW_OFFLINE=1 still wrote an install file (%q); "+
			"`CHAINSAW_OFFLINE=1 chainsaw telemetry status` minted the very id the operator was inspecting", data)
	}
}

func TestLoadInstall_OfflineDoesNotWriteTheStickySentinel(t *testing.T) {
	// CHAINSAW_OFFLINE is a PER-RUN umbrella, not a telemetry decision.
	// Writing the sticky "disabled" sentinel would make one offline
	// invocation permanently opt the box out, and a code revert could not
	// un-write it. Prove the next non-offline run mints normally.
	clearTelemetryEnv(t)
	dir := t.TempDir()

	t.Setenv("CHAINSAW_OFFLINE", "1")
	if _, err := LoadInstall(dir); err != nil {
		t.Fatalf("offline LoadInstall: %v", err)
	}

	t.Setenv("CHAINSAW_OFFLINE", "")
	got, err := LoadInstall(dir)
	if err != nil {
		t.Fatalf("LoadInstall: %v", err)
	}
	if got.Disabled || got.ID == "" {
		t.Fatalf("after an offline run the install is %+v; the umbrella flag must not stick", got)
	}
}

func TestLoadInstall_TelemetryDisabledTruthyValuesWriteTheSentinel(t *testing.T) {
	// The check used to be an exact `== "1"`, so the documented
	// CHAINSAW_TELEMETRY_DISABLED=true opted the user out of SENDING while
	// still persisting a real UUIDv7 — the identifier the opt-out exists to
	// prevent. This is the one signal that IS sticky by design.
	for _, val := range []string{"1", "true", "TRUE", "yes"} {
		t.Run(val, func(t *testing.T) {
			clearTelemetryEnv(t)
			dir := t.TempDir()
			t.Setenv("CHAINSAW_TELEMETRY_DISABLED", val)

			got, err := LoadInstall(dir)
			if err != nil {
				t.Fatalf("LoadInstall: %v", err)
			}
			if !got.Disabled || got.ID != "" {
				t.Fatalf("LoadInstall = %+v, want Disabled with no ID", got)
			}
			data, err := os.ReadFile(installPath(dir))
			if err != nil {
				t.Fatalf("sticky sentinel was not written: %v", err)
			}
			if string(data) != installIDDisabled+"\n" {
				t.Fatalf("install file = %q, want the %q sentinel", data, installIDDisabled)
			}
		})
	}
}

func TestLoadInstall_EnabledStillMints(t *testing.T) {
	// Positive control: the gates above must not have disabled minting
	// outright.
	clearTelemetryEnv(t)
	dir := t.TempDir()

	got, err := LoadInstall(dir)
	if err != nil {
		t.Fatalf("LoadInstall: %v", err)
	}
	if got.Disabled || got.ID == "" {
		t.Fatalf("LoadInstall with telemetry enabled = %+v, want a real ID", got)
	}
	if _, err := os.Stat(installPath(dir)); err != nil {
		t.Fatalf("install file was not persisted: %v", err)
	}
}

func TestLoadInstall_ExistingIDIsReturnedEvenWhileDisabled(t *testing.T) {
	// Never DELETE an existing install_id: that would break the alias for
	// anyone who later opts in. Disabling must be a send-side decision.
	clearTelemetryEnv(t)
	dir := t.TempDir()
	if err := writeInstallFile(dir, installPath(dir), "existing-id"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	t.Setenv("CHAINSAW_OFFLINE", "1")
	got, err := LoadInstall(dir)
	if err != nil {
		t.Fatalf("LoadInstall: %v", err)
	}
	if got.ID != "existing-id" {
		t.Errorf("LoadInstall = %+v, want the existing id preserved", got)
	}
	if data, err := os.ReadFile(installPath(dir)); err != nil || string(data) != "existing-id\n" {
		t.Errorf("install file = %q (err %v); it must be left untouched", data, err)
	}
}

// ── Peek: reading the install state must never create it ──────────────────────

// A user who has never been asked for consent gets a permanent machine
// identifier written to disk merely by RUNNING `chainsaw telemetry status`.
// Peek is the read-only path those status commands use; it must leave the
// directory untouched.
func TestPeekInstall_DoesNotMint(t *testing.T) {
	clearTelemetryEnv(t)
	dir := t.TempDir()

	got, found, err := PeekInstall(dir)
	if err != nil {
		t.Fatalf("PeekInstall: %v", err)
	}
	if found {
		t.Fatalf("PeekInstall reported found on a fresh dir: %+v", got)
	}
	if got.ID != "" || got.Disabled {
		t.Fatalf("PeekInstall = %+v, want the zero value when nothing exists", got)
	}
	if _, err := os.Stat(installPath(dir)); !os.IsNotExist(err) {
		data, _ := os.ReadFile(installPath(dir))
		t.Fatalf("PeekInstall minted an install file (%q); reading a privacy readout "+
			"must not create the identifier it reports on", data)
	}
	// Nothing was minted, so telemetry was NOT disabled here — prove the
	// mint path is still reachable and this is a peek property, not an
	// accidentally-disabled environment.
	if _, err := LoadInstall(dir); err != nil {
		t.Fatalf("LoadInstall after peek: %v", err)
	}
	if _, err := os.Stat(installPath(dir)); err != nil {
		t.Fatalf("control: LoadInstall should still mint here: %v", err)
	}
}

// Once an id exists, peek reports exactly it — reading is not a reset.
func TestPeekInstall_ReadsTheExistingID(t *testing.T) {
	clearTelemetryEnv(t)
	dir := t.TempDir()

	minted, err := LoadInstall(dir)
	if err != nil || minted.ID == "" {
		t.Fatalf("LoadInstall = %+v, %v", minted, err)
	}
	for i := 0; i < 3; i++ {
		got, found, err := PeekInstall(dir)
		if err != nil {
			t.Fatalf("PeekInstall #%d: %v", i, err)
		}
		if !found || got.ID != minted.ID {
			t.Fatalf("PeekInstall #%d = %+v (found=%v), want the minted id %q", i, got, found, minted.ID)
		}
	}
}

// The sticky opt-out sentinel is a real record: peek must report Disabled
// rather than "nothing here", or a status command would offer to mint.
func TestPeekInstall_ReportsTheDisabledSentinel(t *testing.T) {
	clearTelemetryEnv(t)
	dir := t.TempDir()
	if err := writeInstallFile(dir, installPath(dir), installIDDisabled); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, found, err := PeekInstall(dir)
	if err != nil {
		t.Fatalf("PeekInstall: %v", err)
	}
	if !found || !got.Disabled || got.ID != "" {
		t.Fatalf("PeekInstall = %+v (found=%v), want the disabled record", got, found)
	}
}

// An empty file is "first run" to LoadInstall; peek must agree, otherwise a
// truncated file would be reported as an id.
func TestPeekInstall_EmptyFileIsNotFound(t *testing.T) {
	clearTelemetryEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(installPath(dir), []byte("  \n"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, found, err := PeekInstall(dir)
	if err != nil {
		t.Fatalf("PeekInstall: %v", err)
	}
	if found || got.ID != "" {
		t.Fatalf("PeekInstall on an empty file = %+v (found=%v), want not-found", got, found)
	}
}

// STABILITY. Lazy minting must not become per-invocation minting: once an id
// exists it has to survive the process cache being dropped (a new `chainsaw`
// run) and any number of peeks in between.
func TestPeekAndLoadInstall_IDIsStableAcrossCalls(t *testing.T) {
	clearTelemetryEnv(t)
	dir := t.TempDir()
	t.Setenv(envConfigHome, dir)
	ResetProcessInstall()
	t.Cleanup(ResetProcessInstall)

	first, err := ProcessInstall()
	if err != nil || first.ID == "" {
		t.Fatalf("ProcessInstall = %+v, %v", first, err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := PeekProcessInstall(); err != nil {
			t.Fatalf("PeekProcessInstall #%d: %v", i, err)
		}
		// Simulate a fresh process: the on-disk file is the only thing
		// carrying the id across invocations.
		ResetProcessInstall()
		again, err := ProcessInstall()
		if err != nil {
			t.Fatalf("ProcessInstall #%d: %v", i, err)
		}
		if again.ID != first.ID {
			t.Fatalf("install_id changed between invocations: %q then %q; "+
				"lazy minting must not mint per run", first.ID, again.ID)
		}
	}
}

// PeekProcessInstall must not populate the process cache — a status read
// deciding what a later emit() sees would be a nasty ordering coupling.
func TestPeekProcessInstall_DoesNotPoisonTheProcessCache(t *testing.T) {
	clearTelemetryEnv(t)
	dir := t.TempDir()
	t.Setenv(envConfigHome, dir)
	ResetProcessInstall()
	t.Cleanup(ResetProcessInstall)

	if _, found, err := PeekProcessInstall(); err != nil || found {
		t.Fatalf("PeekProcessInstall = found %v, %v; want nothing on a fresh dir", found, err)
	}
	got, err := ProcessInstall()
	if err != nil || got.ID == "" {
		t.Fatalf("ProcessInstall after a peek = %+v, %v; the peek must not have "+
			"cached an empty record", got, err)
	}
}

// ── R12: DO_NOT_TRACK ─────────────────────────────────────────────────────────

func TestResolveMode_HonorsDoNotTrack(t *testing.T) {
	clearTelemetryEnv(t)
	t.Setenv("DO_NOT_TRACK", "1")
	if got := ResolveMode(); got != ModeDisabled {
		t.Fatalf("ResolveMode with DO_NOT_TRACK=1 = %v, want ModeDisabled. "+
			"The variable was claimed in two Go comments and TELEMETRY.md but honored nowhere.", got)
	}
}

func TestResolveMode_IgnoresBareDNT(t *testing.T) {
	// Deliberately NOT honored: "DNT" is an HTTP-header convention and a
	// plausible collision as a shell variable. Only DO_NOT_TRACK is a
	// console opt-out.
	clearTelemetryEnv(t)
	t.Setenv("DNT", "1")
	if got := ResolveMode(); got != ModeEnabled {
		t.Fatalf("ResolveMode with DNT=1 = %v, want ModeEnabled (only DO_NOT_TRACK is honored)", got)
	}
}

func TestLoadInstall_DoNotTrackMintsNothing(t *testing.T) {
	clearTelemetryEnv(t)
	dir := t.TempDir()
	t.Setenv("DO_NOT_TRACK", "1")

	if _, err := LoadInstall(dir); err != nil {
		t.Fatalf("LoadInstall: %v", err)
	}
	if _, err := os.Stat(installPath(dir)); !os.IsNotExist(err) {
		t.Fatal("DO_NOT_TRACK=1 still minted a persistent install_id")
	}
}

// ── R9: CHAINSAW_CONFIG_HOME ──────────────────────────────────────────────────

func TestConfigDir_HonorsChainsawConfigHome(t *testing.T) {
	clearTelemetryEnv(t)
	want := filepath.Join(t.TempDir(), "portable")
	t.Setenv(envConfigHome, want)

	got, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	if got != want {
		t.Fatalf("ConfigDir = %q, want %q. A CI container that scopes CHAINSAW_CONFIG_HOME "+
			"still persisted a stable identifier outside it, and `telemetry reset` targeted "+
			"a directory the operator never configured.", got, want)
	}
	if _, err := os.Stat(got); err != nil {
		t.Errorf("ConfigDir did not create the override directory: %v", err)
	}
	// The override returns the directory ITSELF — no "chainsaw" suffix —
	// matching cli/platform.ConfigHome so install_id lands next to
	// config.yaml and guard_state.json.
	if filepath.Base(got) == "chainsaw" && filepath.Base(want) != "chainsaw" {
		t.Errorf("ConfigDir appended a chainsaw/ suffix to the override; cli/platform does not")
	}
}

func TestConfigDir_FallsBackToXDGWhenOverrideAbsent(t *testing.T) {
	clearTelemetryEnv(t)
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)

	got, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	// On darwin/linux the XDG branch appends chainsaw/; on Windows the
	// APPDATA branch does the same. Either way the suffix is present.
	if want := filepath.Join(base, "chainsaw"); got != want && os.Getenv("APPDATA") == "" {
		t.Logf("ConfigDir = %q (platform-specific; XDG branch expects %q)", got, want)
	}
}

func TestResetProcessInstall_ClearsTheCache(t *testing.T) {
	clearTelemetryEnv(t)
	dir := t.TempDir()
	t.Setenv(envConfigHome, dir)
	ResetProcessInstall()
	t.Cleanup(ResetProcessInstall)

	first, err := ProcessInstall()
	if err != nil || first.ID == "" {
		t.Fatalf("ProcessInstall = %+v, %v", first, err)
	}
	if err := ResetInstall(dir); err != nil {
		t.Fatalf("ResetInstall: %v", err)
	}
	ResetProcessInstall()

	second, err := ProcessInstall()
	if err != nil {
		t.Fatalf("ProcessInstall after reset: %v", err)
	}
	if second.ID == first.ID {
		t.Error("ProcessInstall returned the pre-reset id; `chainsaw telemetry reset` would not take effect within its own invocation")
	}
}
