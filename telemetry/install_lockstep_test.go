package telemetry

// install_lockstep_test.go — the real resolvers, no injection.
//
// These use only the exported API and environment variables, so they run
// against the shipped resolution logic rather than a test double. They are
// the tests that FAIL against the pre-fix code on macOS (and on any GOOS that
// is neither linux nor windows): core/telemetry's private copy of the
// resolver put install_id under ~/.config/chainsaw while cli/platform put
// config.yaml and guard_state.json under ~/.chainsaw.
//
// On Linux the two locations coincide, so there they assert only that they
// still coincide — which is the point: this is the regression guard for a
// divergence that a comment ("must stay in lockstep") failed to prevent.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/chain305/chainsaw-core/cli/platform"
)

// fakeHome points every home-derived lookup at a temp directory so the real
// resolvers can be exercised without touching the developer's actual config.
func fakeHome(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("home redirection is not portable to windows; see the APPDATA cases below")
	}
	home := t.TempDir()
	clearTelemetryEnv(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	ResetProcessInstall()
	t.Cleanup(ResetProcessInstall)
	return home
}

// The defect itself, stated as an assertion.
func TestConfigDir_AgreesWithPlatformConfigHome(t *testing.T) {
	fakeHome(t)

	got, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	want := platform.ConfigHome()
	if got != want {
		t.Fatalf("telemetry.ConfigDir() = %q but cli/platform.ConfigHome() = %q.\n"+
			"Two config directories on one machine: config.yaml and guard_state.json "+
			"land in one, install_id in the other. The two resolvers are documented as "+
			"having to stay in lockstep; they must now be the same code, not two copies.",
			got, want)
	}
}

// The user-visible consequence, stated separately: whatever the OS
// conventions are, the identifier has to land beside the config it belongs to.
func TestProcessInstall_WritesInstallIDBesideTheConfig(t *testing.T) {
	fakeHome(t)

	if _, err := ProcessInstall(); err != nil {
		t.Fatalf("ProcessInstall: %v", err)
	}
	want := filepath.Join(platform.ConfigHome(), installFilename)
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("no install_id at %s (%v); it was written somewhere other than the config home", want, err)
	}
}

// An id left by an older binary in the pre-fix location must still be the id
// this machine reports. This is the test that stops the fix from being a
// silent mass re-identification.
func TestProcessInstall_HonorsAnIDLeftByAnOlderBinary(t *testing.T) {
	home := fakeHome(t)

	// Exactly where the pre-fix resolver put it on every non-Windows OS.
	old := filepath.Join(home, ".config", "chainsaw")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(old, installFilename), []byte(knownID+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := ProcessInstall()
	if err != nil {
		t.Fatalf("ProcessInstall: %v", err)
	}
	if got.ID != knownID {
		t.Fatalf("ProcessInstall = %q, want %q — the id this machine has had all along.\n"+
			"Reading the new location and minting when it is empty silently inflates "+
			"install counts and orphans the install→account alias.", got.ID, knownID)
	}

	// And it is stable: a second process sees the same value, whether it
	// comes from the migrated copy or the original.
	ResetProcessInstall()
	again, err := ProcessInstall()
	if err != nil || again.ID != knownID {
		t.Fatalf("second process = %+v, %v; want %q", again, err, knownID)
	}
}

// The override scopes install_id along with everything else (R9), and must
// not be widened by the legacy search: a CI container that sets
// CHAINSAW_CONFIG_HOME expects a self-contained directory, not a lookup that
// reaches back into $HOME.
func TestConfigHomeOverride_LeavesNoLegacySearch(t *testing.T) {
	home := fakeHome(t)
	stray := filepath.Join(home, ".config", "chainsaw")
	if err := os.MkdirAll(stray, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stray, installFilename), []byte(knownID+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	scoped := t.TempDir()
	t.Setenv(envConfigHome, scoped)
	ResetProcessInstall()

	got, err := ProcessInstall()
	if err != nil {
		t.Fatalf("ProcessInstall: %v", err)
	}
	if got.ID == knownID {
		t.Fatal("a scoped CHAINSAW_CONFIG_HOME still picked up the id from $HOME; the override must isolate")
	}
	if _, err := os.Stat(filepath.Join(scoped, installFilename)); err != nil {
		t.Fatalf("no install_id inside the scoped directory: %v", err)
	}
	if dirs := legacyInstallDirs(); dirs != nil {
		t.Errorf("legacyInstallDirs() = %v under an override, want none", dirs)
	}
}

// Per-GOOS statement of what the two locations actually are, so a future
// change to either resolver has to come and edit this.
func TestInstallDirs_PerPlatformCanonicalAndLegacy(t *testing.T) {
	home := fakeHome(t)

	canonical, legacy, err := installDirs()
	if err != nil {
		t.Fatalf("installDirs: %v", err)
	}
	oldLocation := filepath.Join(home, ".config", "chainsaw")

	switch runtime.GOOS {
	case "linux":
		// The one OS where the copies happened to agree, which is why the
		// divergence went unnoticed for as long as it did.
		if want := oldLocation; canonical != want {
			t.Errorf("linux canonical = %q, want %q", canonical, want)
		}
		if len(legacy) != 0 {
			t.Errorf("linux legacy = %v, want none (canonical and legacy are the same directory)", legacy)
		}
	default: // darwin and other unix
		if want := filepath.Join(home, ".chainsaw"); canonical != want {
			t.Errorf("%s canonical = %q, want %q (where config.yaml lives)", runtime.GOOS, canonical, want)
		}
		if len(legacy) != 1 || legacy[0] != oldLocation {
			t.Errorf("%s legacy = %v, want [%q] (where the pre-fix resolver put install_id)",
				runtime.GOOS, legacy, oldLocation)
		}
	}
	if sameDir(canonical, oldLocation) != (len(legacy) == 0) {
		t.Errorf("legacy list disagrees with sameDir: canonical %q, legacy %v", canonical, legacy)
	}
}

// cli/platform.ConfigHome used to read CHAINSAW_CONFIG_HOME untrimmed while
// core/telemetry trimmed it — the last input on which the two disagreed.
func TestConfigHome_WhitespaceOnlyOverrideIsUnset(t *testing.T) {
	fakeHome(t)
	t.Setenv(envConfigHome, "   ")

	if got := platform.ConfigHome(); got == "   " {
		t.Fatal("a whitespace-only CHAINSAW_CONFIG_HOME was treated as a real directory name")
	}
	got, err := ConfigDir()
	if err != nil {
		t.Fatalf("ConfigDir: %v", err)
	}
	if want := platform.ConfigHome(); got != want {
		t.Fatalf("ConfigDir = %q, ConfigHome = %q; the two must agree on a whitespace override too", got, want)
	}
}
