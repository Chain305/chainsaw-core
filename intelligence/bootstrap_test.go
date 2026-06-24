package intelligence

import (
	"testing"
)

// Phase D made the intelligence service the always-on primary path.
// The CHAINSAW_INTELLIGENCE_SERVICE env var is now cosmetic — these
// tests pin that behavior so an accidental re-introduction of a
// feature-flag branch is caught before it ships.

func TestBootstrap_AlwaysReturnsDefaultService(t *testing.T) {
	// Flag values that previously produced a NoopService must still
	// yield the full DefaultService post-Phase-D.
	cases := []string{"", "off", "shadow", "on", "not-a-mode"}
	for _, mode := range cases {
		t.Run("mode="+mode, func(t *testing.T) {
			t.Setenv("CHAINSAW_INTELLIGENCE_SERVICE", mode)
			svc := Bootstrap(BootstrapConfig{})
			if _, ok := svc.(*DefaultService); !ok {
				t.Fatalf("Bootstrap(%q) returned %T, want *DefaultService — Phase D made the service always-on", mode, svc)
			}
		})
	}
}

func TestResolveMode_ParsesKnownValues(t *testing.T) {
	// Mode is kept so operator tooling that parses env state still
	// compiles, but Bootstrap ignores its output. We still test parsing
	// so the human-readable output is stable.
	cases := []struct {
		in   string
		want Mode
	}{
		{"on", ModeOn},
		{"shadow", ModeShadow},
		{"off", ModeOff},
		{"", ModeOff},
		{"garbage", ModeOff},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Setenv("CHAINSAW_INTELLIGENCE_SERVICE", "")
			if got := ResolveMode(tc.in); got != tc.want {
				t.Fatalf("ResolveMode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
