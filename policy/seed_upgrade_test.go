package policy

// The guard for the failure that crashlooped production on 2026-09-18.
//
// configs/seed.yaml renamed three rules ("Block brand-new versions ..." ->
// "Flag brand-new versions ...") while changing their mode to monitor. Every
// unit test passed, the image verified, and the new pod entered
// CrashLoopBackOff on the first org that already had the old rows:
//
//   Failed to seed policies: duplicate key value violates unique constraint
//   "idx_policies_org_precedence_unique" (SQLSTATE 23505)
//
// SeedPoliciesIfNeededTx dedups by NAME and INSERTs at the precedence the
// config names. A renamed rule is therefore a NEW rule competing for a
// precedence the orphaned old row still occupies.
//
// Nothing caught it because every existing test seeds into an EMPTY org. The
// upgrade path — an org carrying the previous release's rows — was untested,
// and that is the only path where this fires. This test seeds twice: once with
// the old config, then with the new one.

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

func seedUpgradeTestOrg(t *testing.T) (*pgstore.Store, string) {
	t.Helper()
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// NewStore runs ensurePolicyIntegrity, which is what CREATEs
	// idx_policies_org_precedence_unique. Opening the pool alone does NOT:
	// a bare migrate leaves only the non-unique idx_policies_org_precedence.
	// The first version of this file skipped that step, so the rename case
	// "passed" against a database with no constraint to violate — the exact
	// did-not-run-reads-as-a-pass shape this whole test is about.
	if _, err := NewStore(db); err != nil {
		t.Fatalf("new policy store: %v", err)
	}
	assertPrecedenceUniqueIndexExists(t, db)

	orgID := "test-seedupgrade-" +
		strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	t.Cleanup(func() {
		if _, err := db.DB().Exec(`DELETE FROM policies WHERE org_id=?`, orgID); err != nil {
			t.Errorf("cleanup policies for %s: %v", orgID, err)
		}
	})
	return db, orgID
}

// assertPrecedenceUniqueIndexExists refuses to let these tests run against a
// database where the constraint is absent. Without it a green run means
// nothing.
func assertPrecedenceUniqueIndexExists(t *testing.T, db *pgstore.Store) {
	t.Helper()
	var n int
	if err := db.DB().QueryRow(
		`SELECT count(*) FROM pg_indexes WHERE tablename='policies' AND indexname='idx_policies_org_precedence_unique'`,
	).Scan(&n); err != nil {
		t.Fatalf("look up precedence unique index: %v", err)
	}
	if n != 1 {
		t.Fatalf("idx_policies_org_precedence_unique is ABSENT — these tests cannot " +
			"exercise what they exist to guard. This is a DID NOT RUN, not a pass.")
	}
}

func seedInto(t *testing.T, db *pgstore.Store, orgID string, policies []Policy) (int, error) {
	t.Helper()
	tx, err := db.DB().Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	n, seedErr := SeedPoliciesIfNeededTx(tx, orgID, policies)
	if seedErr != nil {
		_ = tx.Rollback()
		return n, seedErr
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return n, nil
}

// releaseNMinus1 is the shape configs/seed.yaml shipped before this change:
// the same three rules, at the same precedences, in block mode.
func releaseNMinus1() []Policy {
	yes := true
	ten := 10
	return []Policy{
		{Name: "Block vulnerable packages", Precedence: 100, Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{IsVulnerable: &yes}},
		{Name: "Block publisher-changed versions", Precedence: 130, Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{PublisherChanged: &yes}},
		{Name: "Block brand-new versions (account-takeover / zero-hour)", Precedence: 140,
			Mode: ModeBlock, Status: StatusEnabled, Conditions: Conditions{CooldownDays: &ten}},
	}
}

// TestSeedIsIdempotentAcrossAReleaseThatChangesMode is the shipping path: the
// mode changed, the names did not. Re-seeding an org that already has the old
// rows must be a no-op, not a constraint violation.
func TestSeedIsIdempotentAcrossAReleaseThatChangesMode(t *testing.T) {
	db, orgID := seedUpgradeTestOrg(t)

	if n, err := seedInto(t, db, orgID, releaseNMinus1()); err != nil || n != 3 {
		t.Fatalf("first seed: created=%d err=%v; want 3, nil", n, err)
	}

	// Same names, same precedences, monitor instead of block — what this
	// release actually ships.
	yes := true
	ten := 10
	next := []Policy{
		{Name: "Block vulnerable packages", Precedence: 100, Mode: ModeMonitor, Status: StatusEnabled,
			Conditions: Conditions{IsVulnerable: &yes}},
		{Name: "Block publisher-changed versions", Precedence: 130, Mode: ModeMonitor, Status: StatusEnabled,
			Conditions: Conditions{PublisherChanged: &yes}},
		{Name: "Block brand-new versions (account-takeover / zero-hour)", Precedence: 140,
			Mode: ModeMonitor, Status: StatusEnabled, Conditions: Conditions{CooldownDays: &ten}},
	}
	n, err := seedInto(t, db, orgID, next)
	if err != nil {
		t.Fatalf("re-seeding an existing org failed: %v\n"+
			"This is the startup path for EVERY org that already has these rules. "+
			"A failure here crashloops the proxy.", err)
	}
	if n != 0 {
		t.Errorf("re-seed created %d rows, want 0 — dedup by name should make this a no-op", n)
	}
}

// TestSeedRefusesToRenameAnExistingRule is the red half: it reproduces the
// 2026-09-18 crash. A renamed rule at an occupied precedence must be treated as
// a defect, and this test documents it as one rather than leaving the next
// author to discover it in a CrashLoopBackOff.
func TestSeedRefusesToRenameAnExistingRule(t *testing.T) {
	db, orgID := seedUpgradeTestOrg(t)

	if _, err := seedInto(t, db, orgID, releaseNMinus1()); err != nil {
		t.Fatalf("first seed: %v", err)
	}

	ten := 10
	renamed := []Policy{
		{Name: "Flag brand-new versions (account-takeover / zero-hour)", Precedence: 140,
			Mode: ModeMonitor, Status: StatusEnabled, Conditions: Conditions{CooldownDays: &ten}},
	}
	_, err := seedInto(t, db, orgID, renamed)
	if err == nil {
		t.Fatal("renaming a seeded rule did NOT collide.\n" +
			"Either the seeder gained precedence reallocation — in which case the " +
			"DO-NOT-RENAME banner in configs/seed.yaml can be relaxed and this test " +
			"rewritten — or the constraint is missing and this suite is not testing " +
			"what it claims. Check seed.go and ensurePolicyIntegrity before assuming " +
			"the former.")
	}
	if !strings.Contains(err.Error(), "idx_policies_org_precedence_unique") &&
		!strings.Contains(err.Error(), "23505") {
		t.Fatalf("rename failed for an unexpected reason: %v\n"+
			"Expected the (org_id, precedence) unique violation.", err)
	}
	t.Logf("confirmed: renaming a seeded rule violates the precedence constraint (%v) — "+
		"this is why configs/seed.yaml carries a DO-NOT-RENAME banner", err)
}
