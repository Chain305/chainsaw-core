package telemetry

import "testing"

// TestResolveModeOfflineWins verifies CHAINSAW_OFFLINE=1 forces
// ModeDisabled regardless of the self-hosted/cloud or the legacy
// CHAINSAW_TELEMETRY_ENABLED knob. The air-gap umbrella flag must
// suppress every phone-home code path.
func TestResolveModeOfflineWins(t *testing.T) {
	t.Setenv("CHAINSAW_OFFLINE", "1")
	t.Setenv("CHAINSAW_TELEMETRY_ENABLED", "1")
	t.Setenv("CHAINSAW_TELEMETRY_DISABLED", "")
	t.Setenv("CHAINSAW_TELEMETRY_DEBUG", "")
	if got := ResolveMode(); got != ModeDisabled {
		t.Fatalf("ResolveMode with CHAINSAW_OFFLINE=1 = %v, want ModeDisabled", got)
	}
}

// TestResolveModeDebugBeatsOffline verifies ModeDebug still wins so
// developers inspecting events locally aren't surprised by an offline
// flag flipping them to fully silent.
func TestResolveModeDebugBeatsOffline(t *testing.T) {
	t.Setenv("CHAINSAW_TELEMETRY_DEBUG", "1")
	t.Setenv("CHAINSAW_OFFLINE", "1")
	if got := ResolveMode(); got != ModeDebug {
		t.Fatalf("ResolveMode with DEBUG=1 OFFLINE=1 = %v, want ModeDebug", got)
	}
}

// RefusalSharingEnabled is fail-closed: OFF unless an explicit truthy
// CHAINSAW_REFUSAL_SHARING is set. (The free guard gates identifying data on
// its own first-run consent instead — see the CLI guard path.)
func TestRefusalSharingEnabledDefaultsOff(t *testing.T) {
	cases := map[string]bool{
		"":       false, // unset / absent
		"0":      false,
		"false":  false,
		"no":     false,
		"maybe":  false, // unrecognised ⇒ fail-closed
		"  ":     false,
		"1":      true,
		"true":   true,
		"TRUE":   true,
		"yes":    true,
		" true ": true, // trimmed
	}
	for val, want := range cases {
		t.Setenv("CHAINSAW_REFUSAL_SHARING", val)
		if got := RefusalSharingEnabled(); got != want {
			t.Fatalf("RefusalSharingEnabled with %q = %v, want %v", val, got, want)
		}
	}
}
