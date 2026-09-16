package risk

// Compound-rule fire tests. Validates that CompoundSCEnvNetInstall
// only fires when ALL THREE axes (env-var, network, install-script)
// are present, and that one or two axes alone leave it dormant.

import "testing"

func TestCompoundSCEnvNetInstall_FiresWhenAllThree(t *testing.T) {
	in := Input{
		Ecosystem:                  "npm",
		Package:                    "evil-pkg",
		Version:                    "1.0.0",
		EnvVarAccess:               true,
		NetworkAccess:              true,
		HasInstallScript:           true,
		InstallScriptFetchesRemote: true,
	}
	ev := EvaluatePackage(in, Options{})
	found := false
	for _, cs := range ev.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			if f.ID == CompoundSCEnvNetInstall {
				found = true
				if f.Weight >= 0 {
					t.Errorf("compound weight should be negative, got %v", f.Weight)
				}
				if !f.Compound {
					t.Errorf("expected Compound=true on fired record")
				}
			}
		}
	}
	if !found {
		t.Errorf("expected CompoundSCEnvNetInstall to fire when all three axes present")
	}
}

func TestCompoundSCEnvNetInstall_DoesNotFireWithOnlyEnvVar(t *testing.T) {
	in := Input{
		Ecosystem:    "npm",
		Package:      "neutral-pkg",
		Version:      "1.0.0",
		EnvVarAccess: true,
		// NetworkAccess and HasInstallScript intentionally absent.
	}
	ev := EvaluatePackage(in, Options{})
	for _, cs := range ev.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			if f.ID == CompoundSCEnvNetInstall {
				t.Errorf("compound must not fire on env-var alone; fired=%v", f)
			}
		}
	}
}

func TestCompoundSCEnvNetInstall_DoesNotFireWithoutInstallScript(t *testing.T) {
	in := Input{
		Ecosystem:     "npm",
		Package:       "lib",
		Version:       "1.0.0",
		EnvVarAccess:  true,
		NetworkAccess: true,
		// HasInstallScript intentionally absent — many legit packages
		// access env vars and do network calls at runtime; only the
		// install-time combination is the block-worthy fingerprint.
	}
	ev := EvaluatePackage(in, Options{})
	for _, cs := range ev.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			if f.ID == CompoundSCEnvNetInstall {
				t.Errorf("compound must not fire without an install script; fired=%v", f)
			}
		}
	}
}

func TestCompoundSCEnvNetInstall_DoesNotFireWithoutNetworkAccess(t *testing.T) {
	in := Input{
		Ecosystem:        "npm",
		Package:          "lib",
		Version:          "1.0.0",
		EnvVarAccess:     true,
		HasInstallScript: true,
		// NetworkAccess intentionally absent.
	}
	ev := EvaluatePackage(in, Options{})
	for _, cs := range ev.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			if f.ID == CompoundSCEnvNetInstall {
				t.Errorf("compound must not fire without network access; fired=%v", f)
			}
		}
	}
}

func TestSignalWeightOverrides_AppliedToFiredSignal(t *testing.T) {
	// Verify that an override map provided via Options reaches the
	// fired signal record. Default weight on sc.typosquat_high is -40;
	// when overridden to -10, the FiredSignal must carry -10 (not -40).
	in := Input{
		Ecosystem:            "npm",
		Package:              "lib",
		Version:              "1.0.0",
		IsSuspectedTyposquat: true,
		TyposquatConfidence:  "high",
	}
	overrides := map[string]int{SignalSCTyposquatHigh: -10}
	ev := EvaluatePackage(in, Options{SignalWeightOverrides: overrides})
	var w float64
	found := false
	for _, cs := range ev.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			if f.ID == SignalSCTyposquatHigh {
				found = true
				w = f.Weight
			}
		}
	}
	if !found {
		t.Fatalf("SignalSCTyposquatHigh did not fire on a typosquat input")
	}
	if w != -10 {
		t.Errorf("override not applied: weight=%v want -10", w)
	}

	// And without the override, the const default holds.
	ev = EvaluatePackage(in, Options{})
	for _, cs := range ev.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			if f.ID == SignalSCTyposquatHigh && f.Weight != -40 {
				t.Errorf("default weight changed: got %v want -40", f.Weight)
			}
		}
	}
}

// TestNPMInstallNetShellIsEcosystemGated pins the gate, which is the entire
// reason this rule exists in the form it does.
//
// The same conjunction measured 0 of 219 held-out benign false positives on
// npm and 26 of 220 (11.8%) on PyPI, because 65.3% of benign PyPI packages
// ship a setup.py and building a C extension legitimately shells out.
// Removing the ecosystem check does not break a test unless this one exists.
func TestNPMInstallNetShellIsEcosystemGated(t *testing.T) {
	var rule *CompoundRule
	for i := range CompoundRules {
		if CompoundRules[i].ID == CompoundSCNetShellInstallNPM {
			rule = &CompoundRules[i]
		}
	}
	if rule == nil {
		t.Fatal("sc.npm_install_net_shell is not registered")
	}
	trip := func(eco string) bool {
		in := Input{
			Ecosystem:        eco,
			HasInstallScript: true,
			NetworkAccess:    true,
			CapShell:         true,
		}
		fired, _, _ := rule.Fires(in, map[string]FiredSignal{})
		return fired
	}
	for _, eco := range []string{"npm", "yarn", "bun", "NPM"} {
		if !trip(eco) {
			t.Errorf("rule did not fire for ecosystem %q; the npm family must all trip it", eco)
		}
	}
	for _, eco := range []string{"pypi", "pip", "cargo", "rubygems", "maven", "go", ""} {
		if trip(eco) {
			t.Errorf("rule fired for ecosystem %q.\n"+
				"It is npm-gated on measurement: the same conjunction produced 26 false "+
				"positives in 220 held-out popular PyPI packages (11.8%%) against 0 in 219 "+
				"on npm. Ungated, this flags one PyPI package in eight.", eco)
		}
	}
	// All three terms are required — any two must not fire.
	for _, in := range []Input{
		{Ecosystem: "npm", HasInstallScript: true, NetworkAccess: true},
		{Ecosystem: "npm", HasInstallScript: true, CapShell: true},
		{Ecosystem: "npm", NetworkAccess: true, CapShell: true},
	} {
		if fired, _, _ := rule.Fires(in, map[string]FiredSignal{}); fired {
			t.Error("rule fired on only two of its three terms")
		}
	}
}
