package config

import "testing"

// overlay_precedence_test.go holds the tests for the NEW merge API.
// They live apart from roundtrip_db_test.go on purpose: that file must
// compile unmodified against the pre-fix tree so its failure there is
// real evidence, and these reference symbols that only exist after the
// fix.

// TestSettingsTableStillWinsOverYAML pins the other half of the
// precedence rule. The merge must NOT turn into "YAML always wins" —
// admin-UI-set values live in the settings table and have to survive a
// restart even when the YAML on disk says something else.
func TestSettingsTableStillWinsOverYAML(t *testing.T) {
	store, org := roundTripStore(t)

	// Boot 1: operator's YAML says blocking on, clamav off.
	first := loadYAML(t, "blocking_mode: true\nclamav:\n  enabled: false\n")
	if err := SaveToStoreForOrg(store, first, org, true); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	// An admin then flips both in the dashboard, which writes rows.
	if err := SetBlockingModeForOrg(store, org, false); err != nil {
		t.Fatalf("admin toggle blocking: %v", err)
	}
	if err := setSettingForOrg(store, org, settingClamAVEnabled, boolString(true)); err != nil {
		t.Fatalf("admin toggle clamav: %v", err)
	}

	// Boot 2 without --config: the same in-memory YAML-derived config is
	// the base, but the admin's rows must win.
	got, _, err := OverlayFromStoreForOrg(store, org, first)
	if err != nil {
		t.Fatalf("overlay: %v", err)
	}
	if got.BlockingEnabled() {
		t.Errorf("blocking_mode: the settings table lost to YAML — the admin UI toggle would revert on every restart")
	}
	if !got.ClamAV.EnabledValue() {
		t.Errorf("clamav.enabled: the settings table lost to YAML")
	}
}

// TestOverlayDoesNotMutateBase guards the aliasing hazard: boot passes
// the live config as the base and initRepositories passes it once per
// org, so an in-place overlay would leak one org's rows into the next.
func TestOverlayDoesNotMutateBase(t *testing.T) {
	store, org := roundTripStore(t)

	base := loadYAML(t, "runtime:\n  offline: true\n")
	if err := setSettingForOrg(store, org, settingRuntimeOffline, boolString(false)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, _, err := OverlayFromStoreForOrg(store, org, base)
	if err != nil {
		t.Fatalf("overlay: %v", err)
	}
	if got.Runtime.Offline {
		t.Errorf("settings row (false) should have won over base (true)")
	}
	if !base.Runtime.Offline {
		t.Errorf("OverlayFromStoreForOrg mutated the caller's base config")
	}
}

// TestOverlayLeavesUnknownKeysAlone is the structural assertion behind
// the fix: a settings table that does not carry a key must leave the
// caller's value standing, not reset it to the Go zero value. This is
// what makes a newly added block safe even before someone gets around
// to persisting it.
func TestOverlayLeavesUnknownKeysAlone(t *testing.T) {
	store, org := roundTripStore(t)

	base := loadYAML(t, "provenance:\n  swift_full_verify: true\n")
	// Deliberately seed only ONE unrelated row, so every other key is
	// absent from the table.
	if err := setSettingForOrg(store, org, settingServerListen, ":9999"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, _, err := OverlayFromStoreForOrg(store, org, base)
	if err != nil {
		t.Fatalf("overlay: %v", err)
	}
	if got.Server.Listen != ":9999" {
		t.Errorf("present row did not win: listen=%q", got.Server.Listen)
	}
	if !got.Provenance.SwiftFullVerify {
		t.Errorf("absent row zeroed a base value: provenance.swift_full_verify was reset to false")
	}
}
