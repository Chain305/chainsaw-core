package risk

import (
	"strings"
	"testing"
)

func TestSCURLDepSignalsRegistered(t *testing.T) {
	cases := []struct {
		id           string
		wantCategory Category
		wantSeverity Severity
		wantWeight   float64
	}{
		{SignalSCGitURLDependency, CategorySupplyChain, SevLow, -8},
		{SignalSCHTTPURLDependency, CategorySupplyChain, SevLow, -8},
	}

	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			sig, ok := Registry[c.id]
			if !ok {
				t.Fatalf("signal %q missing from Registry", c.id)
			}
			if sig.ID != c.id {
				t.Errorf("ID got %q want %q", sig.ID, c.id)
			}
			if sig.Category != c.wantCategory {
				t.Errorf("category got %q want %q", sig.Category, c.wantCategory)
			}
			if sig.Severity != c.wantSeverity {
				t.Errorf("severity got %q want %q", sig.Severity, c.wantSeverity)
			}
			if sig.Weight != c.wantWeight {
				t.Errorf("weight got %v want %v", sig.Weight, c.wantWeight)
			}
			if sig.Title == "" {
				t.Errorf("signal %q has empty Title", c.id)
			}
			if sig.Fires == nil {
				t.Errorf("signal %q has nil Fires", c.id)
			}
		})
	}
}

func TestSCGitURLDependencyFires(t *testing.T) {
	sig := Registry[SignalSCGitURLDependency]

	cases := []struct {
		name         string
		in           Input
		wantFired    bool
		wantEvidence []string // expected dep names in evidence["deps"], nil means skip check
	}{
		{
			name:      "zero input — silent",
			in:        Input{},
			wantFired: false,
		},
		{
			name:         "HasGitURLDep true — fires with evidence",
			in:           Input{HasGitURLDep: true, GitURLDeps: []string{"evil-lib"}},
			wantFired:    true,
			wantEvidence: []string{"evil-lib"},
		},
		{
			name:         "multiple git URL deps — fires listing all",
			in:           Input{HasGitURLDep: true, GitURLDeps: []string{"pkg-a", "pkg-b"}},
			wantFired:    true,
			wantEvidence: []string{"pkg-a", "pkg-b"},
		},
		{
			name:      "HasHTTPURLDep only — git signal silent",
			in:        Input{HasHTTPURLDep: true, HTTPURLDeps: []string{"some-tarball"}},
			wantFired: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fired, msg, evidence := sig.Fires(c.in)
			if fired != c.wantFired {
				t.Fatalf("fired got %v want %v", fired, c.wantFired)
			}
			if !c.wantFired {
				return
			}
			if msg == "" {
				t.Errorf("expected non-empty detail message when fired")
			}
			if c.wantEvidence != nil {
				deps, ok := evidence["deps"].([]string)
				if !ok {
					t.Fatalf("evidence[\"deps\"] is not []string: %T %v", evidence["deps"], evidence["deps"])
				}
				if len(deps) != len(c.wantEvidence) {
					t.Errorf("evidence deps got %v want %v", deps, c.wantEvidence)
				}
				for i, d := range c.wantEvidence {
					if i < len(deps) && deps[i] != d {
						t.Errorf("evidence deps[%d] got %q want %q", i, deps[i], d)
					}
				}
			}
		})
	}
}

func TestSCHTTPURLDependencyFires(t *testing.T) {
	sig := Registry[SignalSCHTTPURLDependency]

	cases := []struct {
		name         string
		in           Input
		wantFired    bool
		wantEvidence []string
	}{
		{
			name:      "zero input — silent",
			in:        Input{},
			wantFired: false,
		},
		{
			name:         "HasHTTPURLDep true — fires with evidence",
			in:           Input{HasHTTPURLDep: true, HTTPURLDeps: []string{"custom-tarball"}},
			wantFired:    true,
			wantEvidence: []string{"custom-tarball"},
		},
		{
			name:         "multiple HTTP URL deps — fires listing all",
			in:           Input{HasHTTPURLDep: true, HTTPURLDeps: []string{"dep-x", "dep-y"}},
			wantFired:    true,
			wantEvidence: []string{"dep-x", "dep-y"},
		},
		{
			name:      "HasGitURLDep only — HTTP signal silent",
			in:        Input{HasGitURLDep: true, GitURLDeps: []string{"git-dep"}},
			wantFired: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fired, msg, evidence := sig.Fires(c.in)
			if fired != c.wantFired {
				t.Fatalf("fired got %v want %v", fired, c.wantFired)
			}
			if !c.wantFired {
				return
			}
			if msg == "" {
				t.Errorf("expected non-empty detail message when fired")
			}
			if c.wantEvidence != nil {
				deps, ok := evidence["deps"].([]string)
				if !ok {
					t.Fatalf("evidence[\"deps\"] is not []string: %T %v", evidence["deps"], evidence["deps"])
				}
				if len(deps) != len(c.wantEvidence) {
					t.Errorf("evidence deps got %v want %v", deps, c.wantEvidence)
				}
				for i, d := range c.wantEvidence {
					if i < len(deps) && deps[i] != d {
						t.Errorf("evidence deps[%d] got %q want %q", i, deps[i], d)
					}
				}
			}
		})
	}
}

// TestSCTransitiveSignalsRegistered pins the contract for the three
// transitive-closure signals: registration metadata (category, severity,
// weight, MaxImpact) plus the NotTunable bit on the malware signal.
func TestSCTransitiveSignalsRegistered(t *testing.T) {
	cases := []struct {
		id             string
		wantCategory   Category
		wantSeverity   Severity
		wantWeight     float64
		wantMaxImpact  int
		wantNotTunable bool
	}{
		{SignalSCTransitiveCriticalVuln, CategorySupplyChain, SevCritical, -40, 30, false},
		{SignalSCTransitiveHighVuln, CategorySupplyChain, SevHigh, -20, 50, false},
		{SignalSCTransitiveMalware, CategorySupplyChain, SevCritical, -1000, 0, true},
	}

	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			sig, ok := Registry[c.id]
			if !ok {
				t.Fatalf("signal %q missing from Registry", c.id)
			}
			if sig.Category != c.wantCategory {
				t.Errorf("category got %q want %q", sig.Category, c.wantCategory)
			}
			if sig.Severity != c.wantSeverity {
				t.Errorf("severity got %q want %q", sig.Severity, c.wantSeverity)
			}
			if sig.Weight != c.wantWeight {
				t.Errorf("weight got %v want %v", sig.Weight, c.wantWeight)
			}
			if sig.MaxImpact != c.wantMaxImpact {
				t.Errorf("MaxImpact got %d want %d", sig.MaxImpact, c.wantMaxImpact)
			}
			if sig.NotTunable != c.wantNotTunable {
				t.Errorf("NotTunable got %v want %v", sig.NotTunable, c.wantNotTunable)
			}
			if sig.Title == "" {
				t.Errorf("empty Title")
			}
			if sig.Fires == nil {
				t.Errorf("nil Fires")
			}
		})
	}
}

// TestSCTransitiveCriticalVulnFires covers the per-count gating: zero
// fires nothing, positive fires with a count rendered in the detail
// message.
func TestSCTransitiveCriticalVulnFires(t *testing.T) {
	sig := Registry[SignalSCTransitiveCriticalVuln]
	cases := []struct {
		name      string
		in        Input
		wantFired bool
	}{
		{"zero count silent", Input{}, false},
		{"one critical fires", Input{TransitiveCriticalCount: 1}, true},
		{"high without critical silent", Input{TransitiveHighCount: 3}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fired, detail, evidence := sig.Fires(c.in)
			if fired != c.wantFired {
				t.Fatalf("fired got %v want %v", fired, c.wantFired)
			}
			if !c.wantFired {
				return
			}
			if detail == "" {
				t.Errorf("expected non-empty detail")
			}
			if got, ok := evidence["count"].(int); !ok || got != c.in.TransitiveCriticalCount {
				t.Errorf("evidence[count] got %v want %d", evidence["count"], c.in.TransitiveCriticalCount)
			}
		})
	}
}

// TestSCTransitiveHighVulnFires mirrors the critical test for the high
// tier — high fires independently of critical.
func TestSCTransitiveHighVulnFires(t *testing.T) {
	sig := Registry[SignalSCTransitiveHighVuln]
	if fired, _, _ := sig.Fires(Input{}); fired {
		t.Fatal("expected dormant on zero counts")
	}
	if fired, _, evidence := sig.Fires(Input{TransitiveHighCount: 2}); !fired {
		t.Fatal("expected fired on TransitiveHighCount=2")
	} else if got, _ := evidence["count"].(int); got != 2 {
		t.Errorf("evidence[count] got %v want 2", got)
	}
	if fired, _, _ := sig.Fires(Input{TransitiveCriticalCount: 5}); fired {
		t.Fatal("high signal must not fire on critical-only counts")
	}
}

// TestSCTransitiveMalwareFires asserts the malware signal's -1000
// instant-block sentinel + NotTunable. The actual short-circuit is
// exercised at the evaluator level (TestEvaluatePackage_*) — here we
// only pin the registration + fire predicate.
func TestSCTransitiveMalwareFires(t *testing.T) {
	sig := Registry[SignalSCTransitiveMalware]
	if !sig.NotTunable {
		t.Fatal("SignalSCTransitiveMalware must be NotTunable")
	}
	if sig.Weight != -1000 {
		t.Errorf("weight got %v want -1000 (instant-block sentinel)", sig.Weight)
	}
	if fired, _, _ := sig.Fires(Input{}); fired {
		t.Fatal("expected dormant when TransitiveMalwareCount=0")
	}
	fired, detail, evidence := sig.Fires(Input{TransitiveMalwareCount: 1})
	if !fired {
		t.Fatal("expected fired on TransitiveMalwareCount=1")
	}
	if detail == "" {
		t.Error("expected non-empty detail")
	}
	if got, _ := evidence["count"].(int); got != 1 {
		t.Errorf("evidence[count] got %v want 1", got)
	}
}

func TestSCBothURLDepSignalsFire(t *testing.T) {
	gitSig := Registry[SignalSCGitURLDependency]
	httpSig := Registry[SignalSCHTTPURLDependency]

	in := Input{
		HasGitURLDep:  true,
		GitURLDeps:    []string{"git-dep"},
		HasHTTPURLDep: true,
		HTTPURLDeps:   []string{"http-dep"},
	}

	gitFired, _, gitEvidence := gitSig.Fires(in)
	if !gitFired {
		t.Errorf("expected git URL signal to fire when both flags set")
	}
	if deps, ok := gitEvidence["deps"].([]string); !ok || len(deps) != 1 || deps[0] != "git-dep" {
		t.Errorf("git URL evidence unexpected: %v", gitEvidence)
	}

	httpFired, _, httpEvidence := httpSig.Fires(in)
	if !httpFired {
		t.Errorf("expected HTTP URL signal to fire when both flags set")
	}
	if deps, ok := httpEvidence["deps"].([]string); !ok || len(deps) != 1 || deps[0] != "http-dep" {
		t.Errorf("HTTP URL evidence unexpected: %v", httpEvidence)
	}
}

// TestSCHighSeverityCeilingsArePresentAndUniform is the guard for the
// omission class that produced this fix.
//
// A Signal with no MaxImpact contributes NO cap — the ceiling is the minimum
// across fired primitives, and an absent value is simply skipped. So omitting
// one on a High-severity supply-chain signal does not make it "uncapped in a
// neutral way"; it makes that signal score MORE LENIENTLY than its identical
// peers, silently. sc.reserved_namespace_violation (since deleted, see
// TestDeletedSignalsStayDeleted) carried Weight -25 and
// SevHigh with no ceiling while five same-category, same-or-lighter peers all
// declared 40, so a lone dependency-confusion hit landed around 91 (Allow)
// where a lone publisher-change landed at 40 (Warn).
//
// This is the same shape as the vuln.cvss_critical inversion pinned by
// TestVulnSeverityLadderIsMonotonic; the supply-chain family had no
// equivalent guard, which is why the gap survived.
//
// The list is the "high-confidence harmful" tier from the MaxImpact policy
// table in docs/ARCHITECTURE.md#architecture-package-intelligence. sc.typosquat_high is
// excluded deliberately: it is the same severity but a heavier -40, and its
// tighter 30 ceiling is a deliberate calibration, not drift.
func TestSCHighSeverityCeilingsArePresentAndUniform(t *testing.T) {
	const wantCeiling = 40

	tier := []string{
		SignalSCPublisherChanged,
		SignalSCInstallScriptNetwork,
		SignalSCRepoOwnershipMismatch,
		SignalSCMaintainerAccountVeryYoung,
		SignalSCNonExistentAuthor,
	}

	for _, id := range tier {
		sig, ok := Registry[id]
		if !ok {
			t.Errorf("signal %q missing from Registry", id)
			continue
		}
		if sig.Severity != SevHigh {
			t.Errorf("%s: severity %q — this list is the High tier; move the row or re-tier the signal", id, sig.Severity)
		}
		if sig.MaxImpact != wantCeiling {
			t.Errorf("%s: MaxImpact = %d, want %d. A missing or divergent ceiling here is not neutral — "+
				"an absent MaxImpact contributes no cap at all, so the signal scores more leniently than its peers",
				id, sig.MaxImpact, wantCeiling)
		}
	}
}

// TestSCHiddenUnicodeKindSplit pins the kind split from
// docs/REPORTS.md#artifact-lane-observability-2026-09-15. Before it, the signal fired
// on a hit COUNT alone, so npm/webpack@5.110.3's 9 benign zero-width hits in a
// minified bundle scored the same as 9 bidi overrides in a credential helper
// and moved a real verdict to warn.
func TestSCHiddenUnicodeKindSplit(t *testing.T) {
	sig := Registry[SignalSCHiddenUnicode]
	if sig.ID == "" {
		t.Fatalf("%s not registered", SignalSCHiddenUnicode)
	}
	// The split must not quietly turn the whole signal informational: a bidi
	// override still has to carry its original weight.
	if sig.Weight != -20 {
		t.Errorf("weight = %v, want -20 — the kind split must not neuter the signal", sig.Weight)
	}

	cases := []struct {
		name string
		in   Input
		want bool
	}{
		{
			name: "webpack shape: 9 zero-width hits in a minified bundle",
			in:   Input{HasHiddenUnicode: true, HiddenUnicodeHits: 9, HiddenUnicodeKinds: []string{"zero_width"}},
			want: false,
		},
		{
			name: "one bidi override — Trojan Source",
			in:   Input{HasHiddenUnicode: true, HiddenUnicodeHits: 1, HiddenUnicodeKinds: []string{"bidi_override"}},
			want: true,
		},
		{
			name: "one tag character",
			in:   Input{HasHiddenUnicode: true, HiddenUnicodeHits: 1, HiddenUnicodeKinds: []string{"tag"}},
			want: true,
		},
		{
			name: "bidi hidden among benign zero-width is not diluted",
			in:   Input{HasHiddenUnicode: true, HiddenUnicodeHits: 10, HiddenUnicodeKinds: []string{"bidi_override", "zero_width"}},
			want: true,
		},
		{
			name: "zero-width at payload volume still fires",
			in:   Input{HasHiddenUnicode: true, HiddenUnicodeHits: 64, HiddenUnicodeKinds: []string{"zero_width"}},
			want: true,
		},
		{
			name: "kinds never observed stays armed, not silently clean",
			in:   Input{HasHiddenUnicode: true, HiddenUnicodeHits: 1},
			want: true,
		},
		{
			name: "nothing found",
			in:   Input{},
			want: false,
		},
	}
	for _, tc := range cases {
		fired, reason, _ := sig.Fires(tc.in)
		if fired != tc.want {
			t.Errorf("%s: fired = %v, want %v", tc.name, fired, tc.want)
		}
		if fired && reason == "" {
			t.Errorf("%s: fired with an empty reason", tc.name)
		}
	}

	// The reason must name Trojan Source when a bidi override is what fired —
	// otherwise the operator cannot tell the two findings apart in the UI.
	_, bidiReason, details := sig.Fires(Input{
		HasHiddenUnicode: true, HiddenUnicodeHits: 1, HiddenUnicodeKinds: []string{"bidi_override"},
	})
	if !strings.Contains(bidiReason, "bidirectional-override") {
		t.Errorf("bidi reason = %q, want it to name the bidirectional override", bidiReason)
	}
	if details == nil || details["hiddenUnicodeKinds"] == nil {
		t.Errorf("bidi details = %v, want the observed kinds attached", details)
	}
}

// TestInstallScriptEvalEncodedIsWiredEndToEnd guards a signal that spent its
// whole life computed and discarded.
//
// core/installscripts set Kind = KindEvalEncoded from the day it was written;
// no projection read it, risk.Input had no field for it, and no signal fired
// on it. It was found by measuring retained malware artifacts, not by reading
// the code — 20.4% of PyPI malware carries it and 0 of 337 benign packages do.
//
// The failure mode this guards is silent: delete the projection line and
// everything still compiles, every other test still passes, and the signal
// simply never fires again.
func TestInstallScriptEvalEncodedIsWiredEndToEnd(t *testing.T) {
	sig, ok := Registry[SignalSCInstallScriptEvalEnc]
	if !ok {
		t.Fatal("sc.install_script_eval_encoded is not registered")
	}
	if sig.Weight >= 0 {
		t.Errorf("Weight = %v; a behaviour with 0/337 benign fires should carry weight", sig.Weight)
	}
	if sig.Severity != SevHigh {
		t.Errorf("Severity = %v, want SevHigh", sig.Severity)
	}
	if fired, _, _ := sig.Fires(Input{InstallScriptEvalEncoded: true}); !fired {
		t.Error("signal did not fire on its own input")
	}
	// It must NOT ride the other install-script inputs: those are separate
	// observations with separate weights, and collapsing them would
	// double-count a package that trips both.
	if fired, _, _ := sig.Fires(Input{HasInstallScript: true}); fired {
		t.Error("fired on HasInstallScript alone — it must read only InstallScriptEvalEncoded")
	}
	if fired, _, _ := sig.Fires(Input{InstallScriptFetchesRemote: true}); fired {
		t.Error("fired on InstallScriptFetchesRemote — that is a different signal")
	}
}

// TestInstallScriptOnlySplit pins both halves and, more importantly, the
// reason the base signal must keep firing everywhere.
//
// sc.install_script_only was -5 and ungated. Measured, it is ANTI-correlated
// on PyPI: 77.3% of held-out popular packages against 47.6% of malware. The
// obvious fix — npm-gate it — is unsafe, because compound.go looks the signal
// up by ID in CompoundSCTakeoverSignature (SevCritical) and
// CompoundSCEnvNetInstall. Starving the primitive would silently narrow those
// rules for every non-npm ecosystem.
//
// So: base signal fires everywhere at weight 0, weight moves to an npm-scoped
// sibling. This test fails if either half is collapsed back.
func TestInstallScriptOnlySplit(t *testing.T) {
	base, ok := Registry[SignalSCInstallScriptOnly]
	if !ok {
		t.Fatal("sc.install_script_only must stay registered — compound.go looks it up by ID")
	}
	npm, ok := Registry[SignalSCInstallScriptOnlyNPM]
	if !ok {
		t.Fatal("sc.install_script_only_npm is not registered")
	}
	if base.Weight != 0 {
		t.Errorf("base signal Weight = %v, want 0.\n"+
			"It fires on 77.3%% of popular PyPI packages; weight there is a uniform "+
			"bias against the ecosystem, not a signal.", base.Weight)
	}
	if npm.Weight >= 0 {
		t.Errorf("npm sibling Weight = %v; it must carry the weight (3.22x on npm)", npm.Weight)
	}

	in := func(eco string) Input {
		return Input{Ecosystem: eco, HasInstallScript: true}
	}
	// The base observation must survive on EVERY ecosystem — this is the
	// property that keeps the compounds wired.
	for _, eco := range []string{"npm", "pypi", "rubygems", "cargo", "composer", "nuget", ""} {
		if fired, _, _ := base.Fires(in(eco)); !fired {
			t.Errorf("base signal did not fire for %q.\n"+
				"compound.go resolves fired[SignalSCInstallScriptOnly] for ALL ecosystems; "+
				"silencing it here silently narrows a SevCritical compound.", eco)
		}
	}
	// The weighted sibling must be npm-only.
	for _, eco := range []string{"npm", "yarn", "bun"} {
		if fired, _, _ := npm.Fires(in(eco)); !fired {
			t.Errorf("npm sibling did not fire for %q", eco)
		}
	}
	for _, eco := range []string{"pypi", "rubygems", "cargo", "composer", "nuget", ""} {
		if fired, _, _ := npm.Fires(in(eco)); fired {
			t.Errorf("npm sibling fired for %q at weight -5; that is the PyPI bias this split removes", eco)
		}
	}
	// Neither half fires when the script fetches remote — that is a
	// different, heavier signal and double-counting it would inflate both.
	remote := Input{Ecosystem: "npm", HasInstallScript: true, InstallScriptFetchesRemote: true}
	if fired, _, _ := base.Fires(remote); fired {
		t.Error("base fired on a remote-fetching install script; sc.install_script_fetches_remote owns that")
	}
	if fired, _, _ := npm.Fires(remote); fired {
		t.Error("npm sibling fired on a remote-fetching install script")
	}
}

// TestVersionDiffSignalsRequireAPriorScan is the guard that keeps these
// signals honest.
//
// They measure 13-58x because an axis APPEARING between versions is rare in
// benign bumps. That only holds if the prior version was actually scanned. If
// the previous row was a Tier-1-only refresh its Scan section is empty, every
// axis looks introduced, and a 57x signal fires on a refresh.
//
// This is the absence-is-not-evidence failure this codebase hit four times on
// 2026-09-16. Here it would not merely hide a capability — it would
// manufacture one.
func TestVersionDiffSignalsRequireAPriorScan(t *testing.T) {
	cases := []struct {
		id  string
		set func(*Input)
	}{
		{SignalSCShellAppeared, func(in *Input) { in.ShellAccessAppeared = true }},
		{SignalSCFilesystemAppeared, func(in *Input) { in.FilesystemAccessAppeared = true }},
		{SignalSCEnvVarAppeared, func(in *Input) { in.EnvVarAccessAppeared = true }},
	}
	for _, c := range cases {
		sig, ok := Registry[c.id]
		if !ok {
			t.Fatalf("%s is not registered", c.id)
		}
		// Without a prior scan: must NOT fire, even with the flag set.
		var noPrior Input
		c.set(&noPrior)
		if fired, _, _ := sig.Fires(noPrior); fired {
			t.Errorf("%s fired with PriorScanAvailable=false.\n"+
				"An unscanned prior version means nobody looked; scoring that as "+
				"'the capability was introduced' turns a Tier-1 refresh into a 57x signal.", c.id)
		}
		// With a prior scan: must fire, and must carry the prior version.
		withPrior := Input{PriorScanAvailable: true, PriorVersion: "1.2.2"}
		c.set(&withPrior)
		fired, _, ev := sig.Fires(withPrior)
		if !fired {
			t.Errorf("%s did not fire with a prior scan available", c.id)
			continue
		}
		if ev == nil || ev["priorVersion"] != "1.2.2" {
			t.Errorf("%s must report which version it compared against, got %v", c.id, ev)
		}
		// And must not fire on an unrelated axis.
		other := Input{PriorScanAvailable: true, PriorVersion: "1.2.2"}
		if fired, _, _ := sig.Fires(other); fired {
			t.Errorf("%s fired with no axis actually appearing", c.id)
		}
	}
}

// TestBuilderRefVersionMismatch pins the S-3 rule: fire only when the
// builder ref is a git TAG that does not contain the version's numeric
// core. Every silent row is a legitimate shape measured in prod.
func TestBuilderRefVersionMismatch(t *testing.T) {
	const wf = "https://github.com/acme/app/.github/workflows/release.yml"
	cases := []struct {
		name, builder, version string
		want                   bool
	}{
		{"campaign tag vs 2.5.1", wf + "@refs/tags/setup-files-v1", "2.5.1", true},
		{"campaign tag vs 11.1.6", wf + "@refs/tags/setup-files-v1", "11.1.6", true},
		{"branch build", wf + "@refs/heads/main", "2.5.1", false},
		{"v-prefixed tag", wf + "@refs/tags/v2.5.1", "2.5.1", false},
		{"scoped npm tag", wf + "@refs/tags/@scope/x@2.5.1", "2.5.1", false},
		{"go submodule tag", wf + "@refs/tags/sub/v1.2.3", "v1.2.3", false},
		{"go checksum db", "sum.golang.org", "v1.2.3", false},
		{"empty builder", "", "2.5.1", false},
		{"non-numeric version", wf + "@refs/tags/setup-files-v1", "latest", false},
	}
	sig := Registry[SignalSCBuilderRefVersionMismatch]
	if sig.Fires == nil {
		t.Fatalf("%s not registered", SignalSCBuilderRefVersionMismatch)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, ev := sig.Fires(Input{BuilderID: tc.builder, Version: tc.version})
			if got != tc.want {
				t.Fatalf("fires = %v, want %v (builder %q, version %q)", got, tc.want, tc.builder, tc.version)
			}
			if got && (ev["tag"] != "setup-files-v1" || ev["versionCore"] != tc.version) {
				t.Errorf("evidence = %v, want tag=setup-files-v1 versionCore=%s", ev, tc.version)
			}
		})
	}
}

// TestBuilderRefMismatchIsNeverScored: recall is unmeasured (no malicious
// corpus row carries a builderId), so the signal is an observation only.
// Giving it a weight, a ceiling or a severity is a decision that needs
// that measurement first.
func TestBuilderRefMismatchIsNeverScored(t *testing.T) {
	sig := Registry[SignalSCBuilderRefVersionMismatch]
	if sig.Weight != 0 || sig.MaxImpact != 0 || sig.Severity != SevInfo {
		t.Errorf("%s: Weight=%v MaxImpact=%d Severity=%q, want 0/0/info",
			sig.ID, sig.Weight, sig.MaxImpact, sig.Severity)
	}
}

// TestDeletedSignalsStayDeleted: each of these was registered, advertised
// by GET /api/v1/intel/signals with a weight, and could never fire in
// production (docs/PLANS_INTELLIGENCE.md#plan-signal-repair, Wave 2).
// Re-registering one needs a writer for its input first.
func TestDeletedSignalsStayDeleted(t *testing.T) {
	deleted := map[string]string{
		"sc.reserved_namespace_violation": "no provider ever wrote SupplyChain.ReservedNamespaceViolation " +
			"(provider_reservedns is a documented no-op); reserved namespaces are enforced by the " +
			"policy condition ReservedNamespaces, which matches the operator's own patterns",
		"sc.first_time_collaborator": "its provider is gated off by wave4Enabled everywhere; the fact " +
			"stays on Report.Scan for the policy condition FirstTimeCollaborator",
		"sc.suspicious_repo_stars": "same wave4Enabled gate; the fact stays on Report.Scan for the " +
			"policy condition SuspiciousRepoStars",
	}
	for id, why := range deleted {
		if _, ok := Registry[id]; ok {
			t.Errorf("%s is registered again. It was deleted because %s.", id, why)
		}
	}
}
