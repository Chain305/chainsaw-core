package policy

import (
	"testing"
	"time"
)

// Cooldown gates on the VERSION's publish age, so it must catch a poisoned NEW
// version of an OLD package (the Axios/Chalk/Mastra account-takeover class) that
// package-age would miss.
func TestMatchesConditions_Cooldown(t *testing.T) {
	now := time.Now()
	young := now.Add(-2 * 24 * time.Hour)     // version 2 days old
	old := now.Add(-60 * 24 * time.Hour)      // version 60 days old
	oldPkg := now.Add(-3650 * 24 * time.Hour) // package 10 years old
	days7 := 7
	cond := Conditions{CooldownDays: &days7}

	if !matchesConditions(EvaluationContext{VersionReleaseDate: &young}, cond) {
		t.Error("2-day-old version should MATCH cooldown=7 (quarantine)")
	}
	if matchesConditions(EvaluationContext{VersionReleaseDate: &old}, cond) {
		t.Error("60-day-old version should NOT match cooldown=7")
	}
	if matchesConditions(EvaluationContext{VersionReleaseDate: nil}, cond) {
		t.Error("nil version date must NOT match (fail-open, don't quarantine on absent metadata)")
	}
	// THE key case: account-takeover poisons a young version of an old package.
	if !matchesConditions(EvaluationContext{PackageReleaseDate: &oldPkg, VersionReleaseDate: &young}, cond) {
		t.Error("poisoned young version of an OLD package (Axios-class) MUST match cooldown")
	}
}
