package policy

import (
	"database/sql"
	"strings"
	"testing"
)

func TestSystemPoliciesPrefix(t *testing.T) {
	for _, p := range SystemPolicies() {
		if !IsSystemPolicy(p.ID) {
			t.Errorf("policy %q missing %q prefix", p.ID, SystemPolicyIDPrefix)
		}
		if !strings.HasPrefix(p.ID, SystemPolicyIDPrefix) {
			t.Errorf("policy %q ID does not start with %q", p.ID, SystemPolicyIDPrefix)
		}
	}
}

func TestSLSABaselineTier1Shape(t *testing.T) {
	pol := slsaBaselineTier1Policy()

	if pol.ID != SystemSLSABaselineTier1ID {
		t.Errorf("ID = %q, want %q", pol.ID, SystemSLSABaselineTier1ID)
	}
	if pol.Mode != ModeBlock {
		t.Errorf("Mode = %q, want block", pol.Mode)
	}
	if pol.Status != StatusEnabled {
		t.Errorf("Status = %q, want enabled (block-by-default)", pol.Status)
	}
	if pol.Conditions.RequireAttestation == nil || *pol.Conditions.RequireAttestation != true {
		t.Errorf("RequireAttestation = %v, want &true", pol.Conditions.RequireAttestation)
	}
}

func TestIsSystemPolicy(t *testing.T) {
	cases := []struct {
		id   string
		want bool
	}{
		{"system:slsa-baseline-tier1", true},
		{"system:anything", true},
		{"pol-12345-abc", false},
		{"", false},
		{"systemly", false}, // missing colon
	}
	for _, tc := range cases {
		if got := IsSystemPolicy(tc.id); got != tc.want {
			t.Errorf("IsSystemPolicy(%q) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

func TestSeedSystemPoliciesRejectsNonSystemPrefix(t *testing.T) {
	// Drift guard: every entry in SystemPolicies() must use the
	// system: prefix. Constructing a bogus list directly bypasses
	// SystemPolicies() to exercise the guard inside seedSystemPolicies.
	bad := []Policy{{
		ID:         "pol-fake-no-prefix",
		Name:       "fake",
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		Conditions: Conditions{},
	}}
	_, _, err := seedSystemPolicies(stubExecer{}, "org-x", bad)
	if err == nil {
		t.Fatal("expected error for non-system-prefix ID, got nil")
	}
	if !strings.Contains(err.Error(), SystemPolicyIDPrefix) {
		t.Errorf("error should mention prefix; got %q", err.Error())
	}
}

// stubExecer is a no-op policyExecutor that the prefix-guard test uses
// so we don't need a real DB to assert the validation step. The guard
// fires before any Exec is reached, so returning nil for both is fine.
type stubExecer struct{}

func (stubExecer) Exec(query string, args ...any) (sql.Result, error) {
	return nil, nil
}
func (stubExecer) Query(query string, args ...any) (*sql.Rows, error) {
	return nil, nil
}

// regression-check: F-seed-precedence — a seed-precedence collision
// must not leave the policy unseeded. The recovery path catches a
// 23505 on idx_policies_org_precedence_unique and retries with
// MAX(precedence)+10. Pre-fix observed on staging:
//
//	"seed system policy \"system:slsa-baseline-tier1\": ERROR:
//	 duplicate key value violates unique constraint
//	 \"idx_policies_org_precedence_unique\""
//
// — the warning meant slsa-baseline-tier1 was NEVER applied to
// org-default, silently leaving the supply-chain baseline disabled.
func TestSeedSystemPolicies_RecoversFromPrecedenceCollision(t *testing.T) {
	// The classifier must accept a Postgres-shaped error string
	// even when the executor wraps PgError differently.
	wrappedErr := fakeError("ERROR: duplicate key value violates unique constraint \"idx_policies_org_precedence_unique\" (SQLSTATE 23505)")
	if !isPrecedenceUniqueViolation(wrappedErr) {
		t.Fatal("isPrecedenceUniqueViolation must match the on-the-wire Postgres message; recovery is unreachable otherwise")
	}

	// Negative cases: must not match unrelated unique-violation errors.
	other := fakeError("ERROR: duplicate key value violates unique constraint \"some_other_index\" (SQLSTATE 23505)")
	if isPrecedenceUniqueViolation(other) {
		t.Errorf("isPrecedenceUniqueViolation must not match unrelated constraints; would over-trigger recovery")
	}
	if isPrecedenceUniqueViolation(nil) {
		t.Errorf("isPrecedenceUniqueViolation(nil) = true, want false")
	}
}

type fakeError string

func (f fakeError) Error() string { return string(f) }
