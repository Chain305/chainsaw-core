package risk

import (
	"testing"
	"time"
)

func TestMaintRelocatedFiresWithEvidenceAndNeverMovesVerdict(t *testing.T) {
	var sig Signal
	for _, s := range AllSignals() {
		if s.ID == SignalMaintRelocated {
			sig = s
		}
	}
	if sig.Fires == nil {
		t.Fatal("maint.relocated not registered")
	}
	if fired, _, _ := sig.Fires(Input{}); fired {
		t.Fatal("fired with no relocation")
	}
	fired, msg, ev := sig.Fires(Input{RelocatedTo: "com.mysql:mysql-connector-j:8.0.33"})
	if !fired || msg != "Relocated to com.mysql:mysql-connector-j:8.0.33." || ev["relocatedTo"] != "com.mysql:mysql-connector-j:8.0.33" {
		t.Fatalf("fired=%v msg=%q ev=%v", fired, msg, ev)
	}
	// A relocation names its replacement and Maven follows it: it must stay
	// informational. A weight or a ceiling here would warn every build still
	// on an old coordinate.
	if sig.Weight != 0 || sig.MaxImpact != 0 {
		t.Fatalf("maint.relocated must be weight 0 with no MaxImpact, got weight=%v max=%v", sig.Weight, sig.MaxImpact)
	}
}

func TestMaintOutdatedVersion(t *testing.T) {
	var sig Signal
	for _, s := range AllSignals() {
		if s.ID == SignalMaintOutdatedVersion {
			sig = s
		}
	}
	if sig.Fires == nil || sig.Weight != 0 || sig.MaxImpact != 0 {
		t.Fatalf("maint.outdated_version must be registered at weight 0 with no MaxImpact: %+v", sig)
	}
	old := time.Now().AddDate(-3, 0, 0)
	young := time.Now().AddDate(-1, 0, 0)
	newer := time.Now().AddDate(0, -2, 0)
	if fired, _, _ := sig.Fires(Input{VersionPublishedAt: &young, NewerVersion: "2.0", NewerVersionAt: &newer}); fired {
		t.Error("fired on a version under two years old")
	}
	if fired, _, _ := sig.Fires(Input{VersionPublishedAt: &old}); fired {
		t.Error("fired with no newer version")
	}
	fired, _, ev := sig.Fires(Input{VersionPublishedAt: &old, NewerVersion: "2.0", NewerVersionAt: &newer})
	if !fired || ev["newerVersion"] != "2.0" || ev["versionPublishedAt"] == nil || ev["newerVersionAt"] == nil {
		t.Fatalf("fired=%v ev=%v", fired, ev)
	}
}
