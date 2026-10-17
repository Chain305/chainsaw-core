package policy

import "testing"

// A rule added to the seed lands on orgs seeded before it, where an
// operator's own rule may hold its precedence. The seed must move to a free
// slot, not fail: at boot a failed seed INSERT on
// idx_policies_org_precedence_unique stopped the proxy (2026-09-18).
func TestSeedNewRuleOnTakenPrecedence(t *testing.T) {
	db, orgID := seedUpgradeTestOrg(t)
	yes := true
	own := Policy{Name: "Operator rule at 125", Precedence: 125, Mode: ModeMonitor, Status: StatusEnabled,
		Conditions: Conditions{HasInstallScript: &yes}}
	if n, err := seedInto(t, db, orgID, []Policy{own}); err != nil || n != 1 {
		t.Fatalf("seed operator rule: created=%d err=%v", n, err)
	}
	seeded := Policy{Name: "Block import-time execution of fetched or decoded code", Precedence: 125,
		Mode: ModeBlock, Status: StatusEnabled, Conditions: Conditions{ImportTimeExecution: &yes}}
	n, err := seedInto(t, db, orgID, []Policy{own, seeded})
	if err != nil || n != 1 {
		t.Fatalf("seed new rule onto a taken precedence: created=%d err=%v", n, err)
	}
	pols, err := (&Store{sql: db, orgID: orgID}).List()
	if err != nil || len(pols) != 2 {
		t.Fatalf("list: %d rows, err=%v", len(pols), err)
	}
	byName := map[string]int{}
	for _, p := range pols {
		byName[p.Name] = p.Precedence
	}
	if byName[own.Name] != 125 {
		t.Fatalf("operator rule moved to %d", byName[own.Name])
	}
	if got := byName[seeded.Name]; got == 125 || got == 0 {
		t.Fatalf("seeded rule precedence = %d, want a free slot other than 125", got)
	}
	// Idempotent: a second boot creates nothing.
	if n, err := seedInto(t, db, orgID, []Policy{own, seeded}); err != nil || n != 0 {
		t.Fatalf("second seed: created=%d err=%v", n, err)
	}
}
