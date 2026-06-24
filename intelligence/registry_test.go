package intelligence

import (
	"testing"
)

// TestProviderRegistry_CoreOrderAndTiers pins the registration order and the
// CORE classification for the FREE build's provider set.
//
// After the open-core split, the core intelligence package registers ONLY
// the TierCore providers; the TierPremium providers register themselves from
// internal/intelligence/premium (blank-imported by the enterprise build).
// This test therefore asserts the CORE subset only — it holds identically in
// BOTH build modes because the core package's own registrations never change.
//
// Two invariants it protects for the free build:
//
//  1. Order. Each registration carries an explicit Order;
//     buildRegisteredProviders sorts by it. The CORE Order values (the
//     pre-split slots 0,1,2,3,6,7,8,9,10,11,12,13,14,34,36,38) must be
//     preserved exactly — any accidental reorder, drop, or add fails here.
//  2. Classification. Every core entry's tier is asserted TierCore, so a
//     provider accidentally left registered as premium (or vice-versa) in
//     the core file is caught.
//
// The FULL 41-entry ordered set (core + premium interleaved) is asserted
// separately in internal/intelligence/premium (TestFullProviderRegistry_…),
// which can observe both packages' registrations without an import cycle.
func TestProviderRegistry_CoreOrderAndTiers(t *testing.T) {
	type want struct {
		order int
		name  string
		tier  ProviderTier
	}
	// The CORE registrations, in their canonical Order. Premium Orders
	// (4, 5, 15-33, 35, 37, 39, 40) are intentionally absent in the free
	// build.
	expected := []want{
		{0, "malware", TierCore},
		{1, "typosquat", TierCore},
		{2, "provenance", TierCore},
		{3, "cve", TierCore},
		{6, "reservedns", TierCore},
		{7, "osv", TierCore},
		{8, "registrymetadata", TierCore},
		{9, "installscripts", TierCore},
		{10, "hiddenunicode", TierCore},
		{11, "checksum", TierCore},
		{12, "shrinkwrap", TierCore},
		{13, "manifestconfusion", TierCore},
		{14, "manifestconfusion", TierCore},
		{34, "kev", TierCore},
		{36, "repolink", TierCore},
		{38, "signature_verify", TierCore},
	}

	got := RegisteredProviders()

	// Keep only the CORE registrations from whatever is registered. In the
	// free build that is everything; in the enterprise build (premium
	// imported) this filters the premium entries out so the core assertion
	// is build-mode-independent.
	var core []ProviderRegistration
	for _, r := range got {
		if r.Tier == TierCore {
			core = append(core, r)
		}
	}

	if len(core) != len(expected) {
		t.Fatalf("core registry has %d entries, want %d", len(core), len(expected))
	}
	for i, exp := range expected {
		if core[i].Name != exp.name {
			t.Errorf("core[%d].Name = %q, want %q", i, core[i].Name, exp.name)
		}
		if core[i].Tier != exp.tier {
			t.Errorf("core[%d] (%s).Tier = %s, want %s", i, exp.name, core[i].Tier, exp.tier)
		}
		if core[i].Order != exp.order {
			t.Errorf("core[%d] (%s).Order = %d, want %d", i, exp.name, core[i].Order, exp.order)
		}
		if core[i].Factory == nil {
			t.Errorf("core[%d] (%s) has nil Factory", i, exp.name)
		}
	}
}

// TestBuildRegisteredProviders_CoreNilConfig pins the nil-dependency gating
// for the FREE build: with an empty BootstrapConfig, every CORE factory that
// guards on a wired dependency returns nil and is skipped, while the
// unconditional CORE providers still materialise. This is the behaviour the
// old `if cfg.X != nil` blocks produced.
func TestBuildRegisteredProviders_CoreNilConfig(t *testing.T) {
	providers := buildRegisteredProviders(BootstrapConfig{})

	// CORE providers that REQUIRE a wired dependency must be absent under an
	// empty config. Their runtime Name() values:
	gatedOut := map[string]bool{
		"malware":    true,
		"typosquat":  true,
		"provenance": true,
		"cve":        true,
		"kev":        true,
	}
	for _, p := range providers {
		if gatedOut[p.Name()] {
			t.Errorf("provider %q materialised under empty config but is dependency-gated", p.Name())
		}
	}

	// A few unconditional CORE providers MUST be present regardless of
	// config. (maintenance was unconditional pre-split but is now premium,
	// so it is intentionally NOT asserted here — see the premium package's
	// own gating test.)
	required := map[string]bool{
		"reservednamespaces": false,
		"registrymetadata":   false,
		"checksum":           false,
		"repolink":           false,
	}
	for _, p := range providers {
		if _, ok := required[p.Name()]; ok {
			required[p.Name()] = true
		}
	}
	for name, present := range required {
		if !present {
			t.Errorf("unconditional core provider %q missing under empty config", name)
		}
	}
}
