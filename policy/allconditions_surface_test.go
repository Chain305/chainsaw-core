package policy

import (
	"reflect"
	"testing"
)

// excludedFromAllConditions lists ConditionTypes that ConditionsUsedBy can
// emit but AllConditions() deliberately omits. Each entry MUST carry a
// non-empty reason — an empty string fails the test, so "add it to the map"
// is never a silent way to make this guard shut up.
//
// P8-14 is the bug this map exists to prevent recurring: six AI-artifact
// ConditionTypes were declared, carried a cell in every SupportMatrix row,
// and were emitted by ConditionsUsedBy — but were missing from
// AllConditions(). Everything that enumerates the matrix through
// AllConditions (GET /api/policies/support-matrix, and through it the UI's
// unsupported-condition warning, plus `chainsaw policy preflight`) was
// therefore blind to them, and preflight exited 0 declaring "every condition
// supported" for a policy that used one.
var excludedFromAllConditions = map[ConditionType]string{
	// DELIBERATELY EMPTY. AllConditions() now publishes every column
	// SupportMatrix carries.
	//
	// The single entry that used to live here was
	// ConditionMaintainerAccountAge, held out only because the Phase-8
	// remediation plan scoped the AllConditions() fix to the six AI-artifact
	// conditions. The exclusion was closed as the Phase-9-fresh §5 follow-up:
	// the column has a cell in all 16 SupportMatrix rows, ConditionsUsedBy
	// emits it, and withholding it made `chainsaw policy preflight` report a
	// maintainerAccountAgeDaysMax rule as absent from the proxy's matrix and
	// exit 12 ("this CLI is newer than the proxy"). See
	// TestAllConditionsPublishesExactlyTheMatrixColumns in proxy_matrix_test.go
	// for the full evidence.
	//
	// Adding an entry here is how a column stops being published. Do it only
	// with a reason that survives that test's set-equality assertion being
	// relaxed — an inert-in-production signal is NOT such a reason, because
	// twenty already-published conditions are in that same state.
}

// TestEveryEmittedConditionIsInAllConditions is the P8-39 rail for P8-14.
//
// It walks every exported field of Conditions by reflection, builds a
// Conditions value with ONLY that field set, asks ConditionsUsedBy what
// column it maps to, and asserts that column is published by AllConditions().
// Driving it from the struct (rather than from a hand-written list of
// ConditionTypes) means a NEW policy field wired into ConditionsUsedBy but
// forgotten in AllConditions fails here immediately — which is exactly how
// the six AI conditions slipped through.
//
// Shape borrowed from TestHasPolicyCondition_Exhaustive in
// cooldown_surface_test.go, which closed the identical class for
// hasPolicyCondition.
func TestEveryEmittedConditionIsInAllConditions(t *testing.T) {
	published := make(map[ConditionType]struct{}, len(AllConditions()))
	for _, c := range AllConditions() {
		published[c] = struct{}{}
	}

	typ := reflect.TypeOf(Conditions{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue // unexported
		}

		c := Conditions{}
		setFieldNonZero(t, reflect.ValueOf(&c).Elem().Field(i), field)

		for _, cond := range ConditionsUsedBy(c) {
			if _, ok := published[cond]; ok {
				continue
			}
			if reason, excluded := excludedFromAllConditions[cond]; excluded {
				if reason == "" {
					t.Errorf("condition %s is excluded from AllConditions() but carries no reason", cond)
				}
				continue
			}
			t.Errorf("Conditions.%s maps to condition %s, which ConditionsUsedBy emits "+
				"but AllConditions() does not publish. Every consumer that enumerates the "+
				"matrix (GET /api/policies/support-matrix, the UI warning, `chainsaw policy "+
				"preflight`) is blind to it. Either add %s to AllConditions() or document it "+
				"in excludedFromAllConditions with a reason.",
				field.Name, cond, cond)
		}
	}
}

// TestExcludedFromAllConditionsIsHonest keeps the exclusion map from rotting
// into a dumping ground: an entry must name a real ConditionType that
// ConditionsUsedBy can actually emit, and must not name one that
// AllConditions() already publishes (that would be a stale exclusion silently
// weakening the guard above).
func TestExcludedFromAllConditionsIsHonest(t *testing.T) {
	published := make(map[ConditionType]struct{}, len(AllConditions()))
	for _, c := range AllConditions() {
		published[c] = struct{}{}
	}
	emittable := emittableConditions(t)

	for cond, reason := range excludedFromAllConditions {
		if reason == "" {
			t.Errorf("exclusion %s carries no reason", cond)
		}
		if _, ok := published[cond]; ok {
			t.Errorf("exclusion %s is stale: AllConditions() already publishes it; remove the entry", cond)
		}
		if _, ok := emittable[cond]; !ok {
			t.Errorf("exclusion %s is not emitted by ConditionsUsedBy for any Conditions field; "+
				"the entry protects nothing", cond)
		}
	}
}

// TestEveryMatrixColumnIsPublished asserts the other direction: every column
// that SupportMatrix actually carries a cell for is published by
// AllConditions(), modulo the same documented exclusions. Without this, a
// condition can have 16 live cells that the support-matrix API never exposes
// — which is precisely the state the six AI conditions were in.
func TestEveryMatrixColumnIsPublished(t *testing.T) {
	published := make(map[ConditionType]struct{}, len(AllConditions()))
	for _, c := range AllConditions() {
		published[c] = struct{}{}
	}
	seen := make(map[ConditionType]struct{})
	for _, row := range SupportMatrix {
		for cond := range row {
			seen[cond] = struct{}{}
		}
	}
	for cond := range seen {
		if _, ok := published[cond]; ok {
			continue
		}
		if reason, excluded := excludedFromAllConditions[cond]; excluded {
			if reason == "" {
				t.Errorf("condition %s is excluded from AllConditions() but carries no reason", cond)
			}
			continue
		}
		t.Errorf("condition %s has cells in SupportMatrix but is not published by AllConditions()", cond)
	}
}

// emittableConditions returns every ConditionType ConditionsUsedBy can emit,
// derived by setting each exported Conditions field in turn.
func emittableConditions(t *testing.T) map[ConditionType]struct{} {
	t.Helper()
	out := make(map[ConditionType]struct{})
	typ := reflect.TypeOf(Conditions{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		c := Conditions{}
		setFieldNonZero(t, reflect.ValueOf(&c).Elem().Field(i), field)
		for _, cond := range ConditionsUsedBy(c) {
			out[cond] = struct{}{}
		}
	}
	return out
}
