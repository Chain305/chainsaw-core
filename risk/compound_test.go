package risk

// Compound-rule fire tests. Validates that CompoundSCEnvNetInstall
// only fires when ALL THREE axes (env-var, network, install-script)
// are present, and that one or two axes alone leave it dormant.

import (
	"testing"
	"time"
)

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

// TestEnvNetInstallIsNPMGated pins a production false-positive fix.
//
// CompoundSCEnvNetInstall shipped ecosystem-blind at -45, the heaviest
// supply-chain compound weight, and measurement showed it INVERTED on PyPI:
// 2.4% of malware against 16.4% of held-out popular packages (36 of 220,
// including tqdm, websockets and jupyterlab-server). It fired on more benign
// packages than malicious ones.
func TestEnvNetInstallIsNPMGated(t *testing.T) {
	var rule *CompoundRule
	for i := range CompoundRules {
		if CompoundRules[i].ID == CompoundSCEnvNetInstall {
			rule = &CompoundRules[i]
		}
	}
	if rule == nil {
		t.Fatal("sc.env_net_install is not registered")
	}
	in := func(eco string) Input {
		return Input{Ecosystem: eco, EnvVarAccess: true, NetworkAccess: true, HasInstallScript: true}
	}
	fired := map[string]FiredSignal{SignalSCInstallScriptOnly: {}}
	if ok, _, _ := rule.Fires(in("npm"), fired); !ok {
		t.Error("rule must still fire on npm, where it measures 9.6% malware / 0.0% benign")
	}
	for _, eco := range []string{"pypi", "pip", "rubygems", "cargo", "composer", "nuget"} {
		if ok, _, _ := rule.Fires(in(eco), fired); ok {
			t.Errorf("rule fired for %q at weight -45.\n"+
				"On PyPI it fires on 16.4%% of popular packages and 2.4%% of malware — "+
				"more benign than malicious. pypi is in supportedInstallScriptEcosystems "+
				"and sc.install_script_only is ungated, so this was reachable in production.", eco)
		}
	}
}

// warnCompoundBase is an otherwise clean package: nothing else it carries can
// move the verdict, so a warn below comes from the compound's ceiling.
func warnCompoundBase(eco string) Input {
	return Input{Ecosystem: eco, Package: "fixture", Version: "1.0.0",
		LicenseSPDX: "MIT", LicenseTags: Classify("MIT"), MaintainerCount: 3}
}

// TestWarnCeilingCompounds pins the 2026-10-10 set: each rule alone holds an
// unpopular package at warn, never quarantine, and drops a term to go dormant.
func TestWarnCeilingCompounds(t *testing.T) {
	for _, tc := range []struct {
		id         string
		set, unset func(*Input)
		eco        string
	}{
		{CompoundSCNPMInstallHookShell, func(in *Input) { in.HasInstallScript, in.CapShell = true, true },
			func(in *Input) { in.CapShell = false }, "npm"},
		{CompoundSCEnvNetInstall, func(in *Input) { in.HasInstallScript, in.EnvVarAccess, in.NetworkAccess = true, true, true },
			func(in *Input) { in.EnvVarAccess = false }, "npm"},
		{CompoundSCExfilSinkNamed, func(in *Input) { in.MaliciousIOCKind = "exfil_host" },
			func(in *Input) { in.MaliciousIOCCoupled = true }, "pypi"},
		{CompoundSCImportTimeBeacon, func(in *Input) { in.ImportTimeKind = "import_time_beacon" },
			func(in *Input) { in.ImportTimeKind = "import_time_exfil" }, "pypi"},
		{CompoundSCObfuscatedExecEval, func(in *Input) { in.ImportTimeKind, in.CapDynamicEval = "obfuscated_exec_bare", true },
			func(in *Input) { in.CapDynamicEval = false }, "pypi"},
		{CompoundSCTrivialDynamicCode, func(in *Input) { in.TrivialPackage, in.CapDynamicRequire = true, true },
			func(in *Input) { in.TrivialPackage = false }, "npm"},
		{CompoundSCTrivialDynamicCode, func(in *Input) { in.TrivialPackage, in.CapDynamicEvalObserved = true, true },
			func(in *Input) { in.CapDynamicEvalObserved = false }, "pypi"},
	} {
		in := warnCompoundBase(tc.eco)
		tc.set(&in)
		ev := EvaluatePackage(in, Options{})
		if _, ok := findFired(ev, tc.id); !ok {
			t.Errorf("%s did not fire", tc.id)
			continue
		}
		if ev.Verdict != VerdictWarn {
			t.Errorf("%s: verdict %q (overall %d, ceiling %q), want warn",
				tc.id, ev.Verdict, ev.DirectScore.Overall, ev.DirectScore.CeilingSignal)
		}
		tc.unset(&in)
		if _, ok := findFired(EvaluatePackage(in, Options{}), tc.id); ok {
			t.Errorf("%s fired with one of its terms removed", tc.id)
		}
	}
}

// TestWarnCeilingPopularityExemption: the binary-installer shape (esbuild,
// node-sass) warns on an unpopular package and stays allow past a download
// line; release history alone does not exempt it (pxnpm, 168 versions since
// 2019 at 1,640 a week, shipped install-hook malware in October 2026); and the
// rules that are not DampEstablished warn on popular packages too.
func TestWarnCeilingPopularityExemption(t *testing.T) {
	opts := Options{Now: func() time.Time { return dampNow }}
	installer := func() Input {
		in := warnCompoundBase("npm")
		in.HasInstallScript, in.NetworkAccess, in.CapShell, in.EnvVarAccess = true, true, true, true
		return in
	}

	in := installer()
	if v := EvaluatePackage(in, opts).Verdict; v != VerdictWarn {
		t.Errorf("unpopular installer: verdict %q, want warn", v)
	}

	in.WeeklyDownloads = intp(5_000_000)
	ev := EvaluatePackage(in, opts)
	if ev.Verdict != VerdictAllow {
		t.Errorf("popular installer: verdict %q (overall %d, ceiling %q), want allow",
			ev.Verdict, ev.DirectScore.Overall, ev.DirectScore.CeilingSignal)
	}
	for _, id := range []string{CompoundSCNPMInstallHookShell, CompoundSCNetShellInstallNPM, CompoundSCEnvNetInstall} {
		f, ok := findFired(ev, id)
		if !ok || f.Evidence["damped"] != true {
			t.Errorf("%s: fired=%v, want fired and marked damped: %+v", id, ok, f.Evidence)
		}
	}

	pxnpm := installer()
	first := time.Date(2019, 4, 4, 0, 0, 0, 0, time.UTC)
	pxnpm.WeeklyDownloads, pxnpm.VersionCount, pxnpm.FirstPublishedAt = intp(1_640), 168, &first
	if v := EvaluatePackage(pxnpm, opts).Verdict; v != VerdictWarn {
		t.Errorf("history-only established installer (pxnpm): verdict %q, want warn", v)
	}

	popular := warnCompoundBase("pypi")
	popular.WeeklyDownloads = intp(5_000_000)
	popular.ImportTimeKind, popular.CapDynamicEval = "obfuscated_exec_bare", true
	if v := EvaluatePackage(popular, opts).Verdict; v != VerdictWarn {
		t.Errorf("popular package with obfuscated exec: verdict %q, want warn (not exempt)", v)
	}
}

// TestDampableCompoundDoesNotSuspendDamper: a DampEstablished compound is not
// compromise-shaped, so on a popular package it must leave the hygiene damper
// running; a takeover indicator still suspends everything.
func TestDampableCompoundDoesNotSuspendDamper(t *testing.T) {
	opts := Options{Now: func() time.Time { return dampNow }}
	in := archivedInput(2_000_000)
	in.ImportTimeKind = "import_time_beacon"
	ev := EvaluatePackage(in, opts)
	if f, _ := findFired(ev, SignalSCRepoArchived); f.Evidence["damped"] != true {
		t.Errorf("sc.repo_archived not damped next to a dampable compound: %+v", f)
	}
	if ev.Verdict != VerdictAllow {
		t.Errorf("popular package, beacon + archived repo: verdict %q, want allow", ev.Verdict)
	}
	in.MaliciousIOCKind, in.MaliciousIOCCoupled = "exfil_host", true // sc.exfil_sink_used, a takeover indicator
	ev = EvaluatePackage(in, opts)
	if f, _ := findFired(ev, CompoundSCImportTimeBeacon); f.Evidence["damped"] == true {
		t.Error("beacon ceiling lifted despite a takeover indicator")
	}
}

// TestQuarantineCompoundIgnoresPopularExemption: the popular exemption is for
// warn-ceiling rules only. sc.exfil_sink_at_install must still quarantine an
// established, popular package, including when exempt rules fire beside it.
// The direct call drops the takeover indicator that co-fires in practice
// (sc.exfil_sink_used), so the guarantee does not lean on it.
func TestQuarantineCompoundIgnoresPopularExemption(t *testing.T) {
	for _, rule := range CompoundRules {
		if rule.MaxImpact > 0 && rule.MaxImpact < thresholdQuarantine && rule.DampEstablished {
			t.Errorf("%s carries a quarantine ceiling and is DampEstablished", rule.ID)
		}
	}

	opts := Options{Now: func() time.Time { return dampNow }}
	first := time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)
	in := warnCompoundBase("npm")
	in.WeeklyDownloads, in.VersionCount, in.FirstPublishedAt = intp(50_000_000), 500, &first
	in.HasInstallScript, in.InstallScriptFetchesRemote = true, true
	in.EnvVarAccess, in.NetworkAccess, in.CapShell = true, true, true
	in.MaliciousIOCKind, in.MaliciousIOCCoupled, in.MaliciousIOCAtEntry = "exfil_host", true, true
	ev := EvaluatePackage(in, opts)
	if ev.Verdict != VerdictQuarantine || ev.DirectScore.CeilingSignal != CompoundSCExfilAtInstall {
		t.Errorf("popular package with an exfil sink at install: verdict %q ceiling %q, want quarantine by %s",
			ev.Verdict, ev.DirectScore.CeilingSignal, CompoundSCExfilAtInstall)
	}

	comp := map[string]FiredSignal{
		CompoundSCExfilAtInstall:   {ID: CompoundSCExfilAtInstall, Compound: true},
		CompoundSCImportTimeBeacon: {ID: CompoundSCImportTimeBeacon, Compound: true},
	}
	damped := dampEstablished(in, map[string]FiredSignal{}, comp, dampNow)
	if damped[CompoundSCExfilAtInstall] {
		t.Error("sc.exfil_sink_at_install was damped")
	}
	if got, by := applyMaxImpactCeiling(100, nil, comp, damped); got != thresholdQuarantine-1 || by != CompoundSCExfilAtInstall {
		t.Errorf("ceiling %d by %q, want %d by %s", got, by, thresholdQuarantine-1, CompoundSCExfilAtInstall)
	}
}
