package policy

import (
	"strings"
	"testing"
)

// validPolicyWithID builds a policy that passes every OTHER validation
// rule, so a failure can only come from the reserved-prefix guard.
func validPolicyWithID(id string) Policy {
	vulnerable := true
	return Policy{
		ID: id, Name: "n", Mode: ModeBlock, Status: StatusEnabled,
		Conditions: Conditions{IsVulnerable: &vulnerable},
	}
}

// TestReservedFindingPolicyIDPrefixRefused pins that no writer can mint a
// policy inside the namespace verdict-recall findings occupy.
//
// The hazard is not a name clash, it is a WRONG ROW. findings dedups open
// rows on (org_id, policy_id, package_name, package_version) and keeps the
// first one, so a colliding id makes a Critical malware recall render with
// some other finding's title and severity — the customer sees the wrong
// severity for the wrong reason and never learns the package is malware.
//
// Validated in validatePolicy rather than the REST handler on purpose:
// Create, Update, seed.go and system_policies.go all route through it, so
// the CLI, the MCP propose_policy tool and the seed loader are covered by
// the same guard.
func TestReservedFindingPolicyIDPrefixRefused(t *testing.T) {
	refused := []string{
		"recall:malware", "recall:cve", "RECALL:MALWARE", "  recall:typosquat", "recall:",
	}
	for _, id := range refused {
		if err := assertNotReservedID(id); err == nil {
			t.Errorf("assertNotReservedID(%q) = nil, want a rejection", id)
		}
	}
	allowed := []string{
		"recall-malware",    // hyphen, not the reserved separator
		"my-recall:thing",   // prefix must be at the start
		"recalled:x",        // longer word sharing the stem
		"pol-1700000000-ab", // the real generated shape
		"", "normal-policy",
	}
	for _, id := range allowed {
		if err := assertNotReservedID(id); err != nil {
			t.Errorf("assertNotReservedID(%q) = %v, want nil — the guard is over-broad", id, err)
		}
	}
}

// TestGeneratedPolicyIDsNeverEnterTheRecallNamespace is the reason the
// guard above cannot fire today, asserted rather than assumed.
//
// Create overwrites whatever id the request body carried with newID(),
// so a customer cannot choose one. The first version of this guard sat
// inside validatePolicy, which runs against the BODY before that
// reassignment — it checked a value that was then thrown away, and would
// have stayed green no matter what. If this test ever fails, the
// generated-id format changed and the guard above becomes load-bearing.
func TestGeneratedPolicyIDsNeverEnterTheRecallNamespace(t *testing.T) {
	for i := 0; i < 200; i++ {
		id, err := newID()
		if err != nil {
			t.Fatalf("newID: %v", err)
		}
		if !strings.HasPrefix(id, "pol-") {
			t.Fatalf("generated id %q no longer starts with pol- — re-check whether callers can influence it", id)
		}
		if err := assertNotReservedID(id); err != nil {
			t.Fatalf("generated id %q collides with the reserved namespace: %v", id, err)
		}
	}
}

// TestSystemPoliciesDoNotUseReservedPrefix guards the other direction: the
// prefix check runs on the seed path too, so a future seeded policy named
// inside the namespace would fail the server at boot rather than at review.
func TestSystemPoliciesDoNotUseReservedPrefix(t *testing.T) {
	for _, p := range SystemPolicies() {
		if err := validatePolicy(p); err != nil {
			t.Errorf("system policy %q fails validation: %v", p.ID, err)
		}
	}
}
