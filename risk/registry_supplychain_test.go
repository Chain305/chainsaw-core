package risk

import "testing"

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
