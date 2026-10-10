package config

import (
	"testing"
	"time"
)

func intPtr(v int) *int { return &v }

// The release-age hold is ON by default (owner decision 2026-10-10). Unset
// means 48h; an explicit 0 is the opt-out; an explicit value wins.
func TestReleaseHoldDuration(t *testing.T) {
	cases := []struct {
		name        string
		days, hours *int
		want        time.Duration
	}{
		{"unset resolves to the 48h default", nil, nil, 48 * time.Hour},
		{"explicit days 0 is off", intPtr(0), nil, 0},
		{"explicit hours 0 is off, even with days set", intPtr(7), intPtr(0), 0},
		{"explicit days wins over the default", intPtr(7), nil, 7 * 24 * time.Hour},
		{"explicit hours wins over days", intPtr(7), intPtr(12), 12 * time.Hour},
		{"negative explicit value is off, never the default", intPtr(-3), nil, 0},
	}
	for _, c := range cases {
		if got := ReleaseHoldDuration(c.days, c.hours); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
	if DefaultReleaseHold != 48*time.Hour {
		t.Fatalf("DefaultReleaseHold = %s; the owner decision is 48h", DefaultReleaseHold)
	}
}

// A YAML file that omits release_policy leaves both keys nil, so the
// default applies; one that states `min_age_days: 0` is an explicit opt-out.
func TestReleaseHoldYAMLUnsetVersusZero(t *testing.T) {
	unset := loadYAML(t, "blocking_mode: true\n")
	if unset.ReleasePolicy.MinAgeDays != nil || unset.ReleasePolicy.MinAgeHours != nil || unset.ReleaseHold() != DefaultReleaseHold {
		t.Fatalf("omitted release_policy must resolve to the default: %+v -> %s", unset.ReleasePolicy, unset.ReleaseHold())
	}
	off := loadYAML(t, "release_policy:\n  min_age_hours: 0\n")
	if off.ReleaseHold() != 0 {
		t.Fatalf("explicit min_age_hours: 0 must turn the hold off, got %s", off.ReleaseHold())
	}
}
