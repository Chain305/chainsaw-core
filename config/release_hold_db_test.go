package config

import (
	"slices"
	"testing"
	"time"
)

// The release-age hold's fields survive both write paths: the boot-time
// YAML import and the settings API's per-org setter.
func TestReleaseHoldSurvivesStoreRoundTrip(t *testing.T) {
	store, org := roundTripStore(t)

	cfg := loadYAML(t, `
release_policy:
  min_age_days: 2
  min_age_hours: 36
  warn_hold_multiplier: 3
  exempt_scopes: ["@acme", "internal-*"]
  exemptions: ["left-pad@1.3.1"]
`)
	if err := SaveToStoreForOrg(store, cfg, org, true); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, _, err := LoadFromStoreForOrg(store, org)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rp := got.ReleasePolicy
	if rp.MinAgeDays == nil || *rp.MinAgeDays != 2 || rp.MinAgeHours == nil || *rp.MinAgeHours != 36 || rp.WarnHoldMultiplier != 3 ||
		!slices.Equal(rp.ExemptScopes, []string{"@acme", "internal-*"}) || !slices.Equal(rp.Exemptions, []string{"left-pad@1.3.1"}) {
		t.Fatalf("after YAML import: %+v", rp)
	}
	if got.ReleaseHold() != 36*time.Hour {
		t.Fatalf("hours must override days: %s", got.ReleaseHold())
	}

	// A nil MinAgeHours deletes the hours row, so the stored days apply.
	if err := SetReleaseHoldForOrg(store, org, ReleasePolicyConfig{WarnHoldMultiplier: 1}); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, _, err = LoadFromStoreForOrg(store, org)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	rp = got.ReleasePolicy
	if rp.MinAgeHours != nil || rp.WarnHoldMultiplier != 1 || len(rp.ExemptScopes) != 0 || len(rp.Exemptions) != 0 {
		t.Fatalf("after setter: %+v; cleared fields must stay cleared", rp)
	}
	if got.ReleaseHold() != 48*time.Hour {
		t.Fatalf("with hours cleared the stored 2 days apply: %s", got.ReleaseHold())
	}
}

// The default-on decision lives entirely in "no row means unset". A fresh
// org with no rows gets 48h; a seed of a config that never stated the hold
// writes no row (so it stays on the default); a stored 0 — the shape every
// pre-2026-10-10 deployment has for its default org — stays an explicit off.
func TestReleaseHoldStoreUnsetVersusStoredZero(t *testing.T) {
	store, org := roundTripStore(t)

	fresh, _, err := LoadFromStoreForOrg(store, org)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if fresh.ReleaseHold() != DefaultReleaseHold {
		t.Fatalf("an org with no rows must get the default, got %s", fresh.ReleaseHold())
	}

	if err := SaveToStoreForOrg(store, loadYAML(t, "blocking_mode: true\n"), org, true); err != nil {
		t.Fatalf("seed: %v", err)
	}
	var n int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM settings WHERE org_id=$1 AND key IN ($2,$3)`,
		org, settingReleaseMinAgeDays, settingReleaseMinAgeHours).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("seeding a config that never stated the hold wrote %d hold rows; that pins the org off the default", n)
	}

	if err := SetReleaseMinAgeDaysForOrg(store, org, 0); err != nil {
		t.Fatal(err)
	}
	zero, _, err := LoadFromStoreForOrg(store, org)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if zero.ReleaseHold() != 0 {
		t.Fatalf("a stored release.min_age_days=0 must stay off, got %s", zero.ReleaseHold())
	}
}
