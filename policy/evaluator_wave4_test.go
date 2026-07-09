package policy

import "testing"

// ptrFalse returns a *bool pointing at false. Test-local so the
// FirstTimeCollaborator three-state cases can express "confirmed not
// first-time" without a fresh stack variable per case.
func ptrFalse() *bool { f := false; return &f }

// TestWave4ConditionsFire asserts the five Wave-4 bool conditions
// evaluate true when the corresponding EvaluationContext field is set.
// Guards against drift between the matcher switch and the context
// shape.
func TestWave4ConditionsFire(t *testing.T) {
	tr := true
	cases := []struct {
		name string
		cond Conditions
		ctx  EvaluationContext
		want bool
	}{
		{"trivial fires", Conditions{TrivialPackage: &tr}, EvaluationContext{TrivialPackage: true}, true},
		{"trivial quiet", Conditions{TrivialPackage: &tr}, EvaluationContext{}, false},
		{"toomany fires", Conditions{TooManyFiles: &tr}, EvaluationContext{TooManyFiles: true}, true},
		{"nonexistent fires", Conditions{NonExistentAuthor: &tr}, EvaluationContext{NonExistentAuthor: true}, true},
		{"firsttime fires", Conditions{FirstTimeCollaborator: &tr}, EvaluationContext{FirstTimeCollaborator: &tr}, true},
		{"firsttime quiet on unknown", Conditions{FirstTimeCollaborator: &tr}, EvaluationContext{FirstTimeCollaborator: nil}, false},
		{"firsttime quiet on confirmed-not", Conditions{FirstTimeCollaborator: &tr}, EvaluationContext{FirstTimeCollaborator: ptrFalse()}, false},
		{"repostars fires", Conditions{SuspiciousRepoStars: &tr}, EvaluationContext{SuspiciousRepoStars: true}, true},
	}
	for _, tc := range cases {
		if got := matchesConditions(tc.ctx, tc.cond); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// TestWave4ConditionsUsedByMapping ensures ConditionsUsedBy returns
// the matrix column for each Wave-4 bool.
func TestWave4ConditionsUsedByMapping(t *testing.T) {
	tr := true
	pairs := []struct {
		field *bool
		apply func(*Conditions)
		want  ConditionType
	}{
		{&tr, func(c *Conditions) { c.TrivialPackage = &tr }, ConditionTrivialPackage},
		{&tr, func(c *Conditions) { c.TooManyFiles = &tr }, ConditionTooManyFiles},
		{&tr, func(c *Conditions) { c.NonExistentAuthor = &tr }, ConditionNonExistentAuthor},
		{&tr, func(c *Conditions) { c.FirstTimeCollaborator = &tr }, ConditionFirstTimeCollaborator},
		{&tr, func(c *Conditions) { c.SuspiciousRepoStars = &tr }, ConditionSuspiciousRepoStars},
	}
	for _, p := range pairs {
		var c Conditions
		p.apply(&c)
		used := ConditionsUsedBy(c)
		if len(used) != 1 || used[0] != p.want {
			t.Errorf("want [%s], got %v", p.want, used)
		}
	}
}
