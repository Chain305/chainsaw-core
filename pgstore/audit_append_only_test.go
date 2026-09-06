package pgstore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Tests for append-only-except-erasure on audit_events.
//
// Every test here is DB-backed and runs against a PRIVATE scratch database
// (provisionScratchDatabase), because it installs and removes triggers and
// deletes audit rows — it must not share a database with a parallel package.
//
// Set CHAINSAW_TEST_REQUIRE_DB=1 so an unreachable Postgres FAILS instead of
// skipping. A skipped test still prints "ok" for the package, which is
// exactly how a guard quietly stops being tested.
//
// The tests below are written to be able to FAIL: each guard is proved by
// exercising the thing it forbids, and TestAuditAppendOnly_GuardCanFail
// removes the trigger and re-checks, so "0 failures" is a result rather than
// a statement that never ran.

const (
	auditOrgA = "org-audit-chain-a"
	auditOrgB = "org-audit-chain-b"
)

func newAuditTestStore(t *testing.T) *Store {
	t.Helper()

	baseDSN := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if baseDSN == "" {
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != "" {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but CHAINSAW_DATABASE_URL is empty")
		}
		t.Skip("CHAINSAW_DATABASE_URL not set")
	}
	scratchDSN, drop := provisionScratchDatabase(t, baseDSN)
	store, err := Open(scratchDSN)
	if err != nil {
		drop()
		t.Fatalf("open scratch store: %v", err)
	}
	t.Cleanup(func() {
		store.Close()
		drop()
	})
	return store
}

// insertAudit writes one audit row the way production does — without
// supplying any chain column, so the trigger is what fills them in.
func insertAudit(t *testing.T, db *sql.DB, id, orgID, action string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO audit_events (id, org_id, actor_user_id, actor_role, action, target_type, target_id, metadata, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		id, orgID, "user-1", "admin", action, "org", orgID, `{"k":"v"}`, time.Now().UTC())
	if err != nil {
		t.Fatalf("insert audit row %s: %v", id, err)
	}
}

func chainOf(t *testing.T, db *sql.DB, orgID string) []AuditChainStatus {
	t.Helper()
	got, err := VerifyAuditChain(context.Background(), db, orgID)
	if err != nil {
		t.Fatalf("verify audit chain for %s: %v", orgID, err)
	}
	return got
}

func mustOK(t *testing.T, rows []AuditChainStatus, orgID string, wantChained int64) {
	t.Helper()
	for _, r := range rows {
		if r.OrgID != orgID {
			continue
		}
		if !r.OK {
			t.Fatalf("chain for %s reports tampering at seq=%v id=%v: %v",
				orgID, r.FirstBadSeq.Int64, r.FirstBadID.String, r.Reason.String)
		}
		if r.ChainedRows != wantChained {
			t.Fatalf("chain for %s: chained_rows=%d, want %d", orgID, r.ChainedRows, wantChained)
		}
		return
	}
	t.Fatalf("no chain status row for org %s (got %+v)", orgID, rows)
}

func mustBroken(t *testing.T, rows []AuditChainStatus, orgID, wantReasonSubstr string) {
	t.Helper()
	for _, r := range rows {
		if r.OrgID != orgID {
			continue
		}
		if r.OK {
			t.Fatalf("chain for %s verified OK, but it was tampered with — the chain is not detecting %q", orgID, wantReasonSubstr)
		}
		if !strings.Contains(r.Reason.String, wantReasonSubstr) {
			t.Fatalf("chain for %s broke with reason %q, want something containing %q",
				orgID, r.Reason.String, wantReasonSubstr)
		}
		return
	}
	t.Fatalf("no chain status row for org %s (got %+v)", orgID, rows)
}

// --- the trigger -----------------------------------------------------------

// TestAuditAppendOnly_UpdateRefused is the unconditional half. There is no
// production UPDATE path (verified by the source scan in
// internal/server/adminorgsapi) and there must be no escape hatch for one.
func TestAuditAppendOnly_UpdateRefused(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	insertAudit(t, db, "ae-upd-1", auditOrgA, "policy.updated")

	_, err := db.Exec(`UPDATE audit_events SET action='tampered' WHERE id=?`, "ae-upd-1")
	if err == nil {
		t.Fatal("UPDATE on audit_events succeeded; the append-only trigger is not enforcing")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("UPDATE failed for the wrong reason: %v", err)
	}

	// And the row is untouched.
	var action string
	if err := db.QueryRow(`SELECT action FROM audit_events WHERE id=?`, "ae-upd-1").Scan(&action); err != nil {
		t.Fatalf("re-read row: %v", err)
	}
	if action != "policy.updated" {
		t.Fatalf("row was mutated despite the refusal: action=%q", action)
	}
}

// TestAuditAppendOnly_UpdateRefusedEvenInsidePurgeScope — the erasure escape
// hatch is DELETE-only. If it also unlocked UPDATE, the purge transaction
// would become a general-purpose rewrite window.
func TestAuditAppendOnly_UpdateRefusedEvenInsidePurgeScope(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	ctx := context.Background()
	insertAudit(t, db, "ae-upd-2", auditOrgA, "policy.updated")

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck // best-effort cleanup
	if err := EnableAuditPurge(ctx, tx); err != nil {
		t.Fatalf("enable audit purge: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE audit_events SET action='tampered' WHERE id=?`, "ae-upd-2"); err == nil {
		t.Fatal("UPDATE succeeded inside the erasure scope; the escape hatch is wider than DELETE")
	}
}

// TestAuditAppendOnly_DeleteRefusedWithoutScope covers the default posture on
// every connection that has not opted in — including a connection that once
// carried the GUC in an earlier, now-finished transaction.
func TestAuditAppendOnly_DeleteRefusedWithoutScope(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	insertAudit(t, db, "ae-del-1", auditOrgA, "policy.created")

	_, err := db.Exec(`DELETE FROM audit_events WHERE id=?`, "ae-del-1")
	if err == nil {
		t.Fatal("DELETE on audit_events succeeded outside an erasure transaction")
	}
	if !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("DELETE failed for the wrong reason: %v", err)
	}

	var n int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE id=?`, "ae-del-1").Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("row disappeared despite the refusal: count=%d", n)
	}
}

// TestAuditAppendOnly_DeleteAllowedInsideScope is the half that keeps org
// deletion working. Without it this whole change would be a right-to-erasure
// outage.
func TestAuditAppendOnly_DeleteAllowedInsideScope(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	ctx := context.Background()
	insertAudit(t, db, "ae-del-2", auditOrgA, "policy.created")

	err := store.WithTx(ctx, func(tx *sql.Tx) error {
		if err := EnableAuditPurge(ctx, tx); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE org_id=?`, auditOrgA)
		return err
	})
	if err != nil {
		t.Fatalf("erasure delete inside scope failed — org purge is broken: %v", err)
	}

	var n int
	if err := db.QueryRow(`SELECT count(*) FROM audit_events WHERE org_id=?`, auditOrgA).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("erasure left %d rows behind", n)
	}
}

// TestAuditAppendOnly_ScopeIsTransactionLocal is the test that would catch a
// regression from SET LOCAL to SET. It pins ONE connection so the second
// DELETE provably runs on the same session that carried the GUC.
func TestAuditAppendOnly_ScopeIsTransactionLocal(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	ctx := context.Background()
	insertAudit(t, db, "ae-scope-1", auditOrgA, "a")
	insertAudit(t, db, "ae-scope-2", auditOrgA, "b")

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("pin connection: %v", err)
	}
	defer conn.Close()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := EnableAuditPurge(ctx, tx); err != nil {
		t.Fatalf("enable audit purge: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE id=?`, "ae-scope-1"); err != nil {
		t.Fatalf("scoped delete: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Same connection, transaction over. The GUC must be gone.
	var guc sql.NullString
	if err := conn.QueryRowContext(ctx,
		`SELECT current_setting($1, true)`, AuditPurgeGUC).Scan(&guc); err != nil {
		t.Fatalf("read guc: %v", err)
	}
	if guc.Valid && guc.String == "on" {
		t.Fatalf("%s survived the transaction on a pooled connection — this is a permanent erasure hole", AuditPurgeGUC)
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM audit_events WHERE id=?`, "ae-scope-2"); err == nil {
		t.Fatal("DELETE succeeded on the same connection after the erasure transaction committed")
	}
}

// TestAuditAppendOnly_WrongScopeValueRefused — the check is equality against
// one value, so an unrelated GUC left set to anything else is still a refusal.
func TestAuditAppendOnly_WrongScopeValueRefused(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	ctx := context.Background()
	insertAudit(t, db, "ae-wrong-1", auditOrgA, "a")

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck // best-effort cleanup
	if _, err := tx.ExecContext(ctx, `SELECT set_config($1, 'off', true)`, AuditPurgeGUC); err != nil {
		t.Fatalf("set guc: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE id=?`, "ae-wrong-1"); err == nil {
		t.Fatalf("DELETE succeeded with %s='off'", AuditPurgeGUC)
	}
}

// TestAuditAppendOnly_TruncateRefused — TRUNCATE does not fire row-level
// triggers, so without the statement-level trigger the delete guard would be
// one keyword away from irrelevant.
func TestAuditAppendOnly_TruncateRefused(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	insertAudit(t, db, "ae-trunc-1", auditOrgA, "a")

	if _, err := db.Exec(`TRUNCATE audit_events`); err == nil {
		t.Fatal("TRUNCATE succeeded — the row-level delete guard is bypassable")
	}
	// Even inside the erasure scope: the cascade deletes by org_id and has
	// no use for TRUNCATE, so there is deliberately no escape.
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback() //nolint:errcheck // best-effort cleanup
	if err := EnableAuditPurge(ctx, tx); err != nil {
		t.Fatalf("enable audit purge: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `TRUNCATE audit_events`); err == nil {
		t.Fatal("TRUNCATE succeeded inside the erasure scope")
	}
}

// --- the chain -------------------------------------------------------------

// TestAuditChain_LinksRowsPerOrg pins the structural properties: sequences
// start at 1 per org, each row's prev_hash is its predecessor's row_hash, the
// first row points at genesis, and the two orgs' chains are independent.
func TestAuditChain_LinksRowsPerOrg(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()

	for i := 1; i <= 3; i++ {
		insertAudit(t, db, fmt.Sprintf("ae-a-%d", i), auditOrgA, "a")
		insertAudit(t, db, fmt.Sprintf("ae-b-%d", i), auditOrgB, "b")
	}

	type row struct {
		id       string
		seq      int64
		prevHash string
		rowHash  string
	}
	read := func(orgID string) []row {
		rows, err := db.Query(
			`SELECT id, chain_seq, prev_hash, row_hash FROM audit_events WHERE org_id=? ORDER BY chain_seq`, orgID)
		if err != nil {
			t.Fatalf("read chain: %v", err)
		}
		defer rows.Close()
		var out []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.seq, &r.prevHash, &r.rowHash); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out = append(out, r)
		}
		return out
	}

	for _, orgID := range []string{auditOrgA, auditOrgB} {
		got := read(orgID)
		if len(got) != 3 {
			t.Fatalf("%s: got %d chained rows, want 3", orgID, len(got))
		}
		for i, r := range got {
			if r.seq != int64(i+1) {
				t.Fatalf("%s row %d: chain_seq=%d, want %d — chains are per org and start at 1", orgID, i, r.seq, i+1)
			}
			if r.rowHash == "" {
				t.Fatalf("%s row %d: empty row_hash — the chain-link trigger did not fire", orgID, i)
			}
			want := auditChainGenesisHash
			if i > 0 {
				want = got[i-1].rowHash
			}
			if r.prevHash != want {
				t.Fatalf("%s row %d: prev_hash=%s, want %s", orgID, i, r.prevHash, want)
			}
		}
	}

	mustOK(t, chainOf(t, db, auditOrgA), auditOrgA, 3)
	mustOK(t, chainOf(t, db, auditOrgB), auditOrgB, 3)

	// The all-orgs form (empty orgID) takes a different code path in
	// VerifyAuditChain — the zero-argument call — and must report both.
	all := chainOf(t, db, "")
	mustOK(t, all, auditOrgA, 3)
	mustOK(t, all, auditOrgB, 3)
}

// TestAuditChain_CallerCannotForgeItsPosition — the trigger overwrites any
// caller-supplied chain columns, so a writer (including a compromised one
// that still goes through the table's triggers) cannot choose its own place
// in the chain or precompute a hash for a row it has not written.
func TestAuditChain_CallerCannotForgeItsPosition(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	insertAudit(t, db, "ae-forge-0", auditOrgA, "real")

	_, err := db.Exec(`
		INSERT INTO audit_events (id, org_id, action, metadata, created_at, chain_seq, prev_hash, row_hash)
		VALUES (?,?,?,?,?,?,?,?)`,
		"ae-forge-1", auditOrgA, "forged", "{}", time.Now().UTC(),
		int64(9999), strings.Repeat("f", 64), strings.Repeat("f", 64))
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	var seq int64
	var prev string
	if err := db.QueryRow(`SELECT chain_seq, prev_hash FROM audit_events WHERE id=?`, "ae-forge-1").Scan(&seq, &prev); err != nil {
		t.Fatalf("read forged row: %v", err)
	}
	if seq != 2 {
		t.Fatalf("caller-supplied chain_seq survived: got %d, want 2", seq)
	}
	if prev == strings.Repeat("f", 64) {
		t.Fatal("caller-supplied prev_hash survived — a writer can forge its position in the chain")
	}
	mustOK(t, chainOf(t, db, auditOrgA), auditOrgA, 2)
}

// TestAuditChain_DetectsTamperedRow is the point of the whole chain: it is
// the control that still works after someone with the application role has
// removed the triggers. So the test removes them, exactly as such an attacker
// would, edits a row, puts them back, and checks that the tampering is
// visible anyway.
func TestAuditChain_DetectsTamperedRow(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()

	for i := 1; i <= 3; i++ {
		insertAudit(t, db, fmt.Sprintf("ae-tamper-%d", i), auditOrgA, "policy.created")
	}
	mustOK(t, chainOf(t, db, auditOrgA), auditOrgA, 3)

	// The residual risk, executed: the application role owns the table, so
	// it can turn the guard off.
	if _, err := db.Exec(`ALTER TABLE audit_events DISABLE TRIGGER ` + auditAppendOnlyTrigger); err != nil {
		t.Fatalf("disable trigger: %v", err)
	}
	if _, err := db.Exec(`UPDATE audit_events SET action='policy.approved' WHERE id=?`, "ae-tamper-2"); err != nil {
		t.Fatalf("tampering UPDATE (with the guard off) failed: %v", err)
	}
	if _, err := db.Exec(`ALTER TABLE audit_events ENABLE TRIGGER ` + auditAppendOnlyTrigger); err != nil {
		t.Fatalf("re-enable trigger: %v", err)
	}

	mustBroken(t, chainOf(t, db, auditOrgA), auditOrgA, "row_hash mismatch")
}

// TestAuditChain_DetectsDeletedRow — a partial delete (which only the
// erasure scope can perform, and which the erasure cascade never does: it
// deletes a whole org) leaves a hole the verifier reports.
func TestAuditChain_DetectsDeletedRow(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	ctx := context.Background()

	for i := 1; i <= 4; i++ {
		insertAudit(t, db, fmt.Sprintf("ae-hole-%d", i), auditOrgA, "policy.created")
	}
	mustOK(t, chainOf(t, db, auditOrgA), auditOrgA, 4)

	if err := store.WithTx(ctx, func(tx *sql.Tx) error {
		if err := EnableAuditPurge(ctx, tx); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE id=?`, "ae-hole-2")
		return err
	}); err != nil {
		t.Fatalf("scoped delete: %v", err)
	}

	mustBroken(t, chainOf(t, db, auditOrgA), auditOrgA, "sequence gap")
}

// TestAuditChain_DetectsDeletedHead — removing the FIRST rows of a chain is
// the attack a naive "each row points at the previous one" design misses,
// because what is left still links consistently. The fixed genesis sentinel
// is what makes it visible.
func TestAuditChain_DetectsDeletedHead(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		insertAudit(t, db, fmt.Sprintf("ae-head-%d", i), auditOrgA, "policy.created")
	}
	if err := store.WithTx(ctx, func(tx *sql.Tx) error {
		if err := EnableAuditPurge(ctx, tx); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE id=?`, "ae-head-1")
		return err
	}); err != nil {
		t.Fatalf("scoped delete: %v", err)
	}

	mustBroken(t, chainOf(t, db, auditOrgA), auditOrgA, "does not start at genesis")
}

// TestAuditChain_ErasureLeavesOtherOrgsVerifiable is the reason the chain is
// per org. A full org erasure must not turn every other tenant's audit trail
// into "cannot verify".
func TestAuditChain_ErasureLeavesOtherOrgsVerifiable(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		insertAudit(t, db, fmt.Sprintf("ae-era-a-%d", i), auditOrgA, "a")
		insertAudit(t, db, fmt.Sprintf("ae-era-b-%d", i), auditOrgB, "b")
	}

	if err := store.WithTx(ctx, func(tx *sql.Tx) error {
		if err := EnableAuditPurge(ctx, tx); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE org_id=?`, auditOrgA)
		return err
	}); err != nil {
		t.Fatalf("erasure: %v", err)
	}

	mustOK(t, chainOf(t, db, auditOrgB), auditOrgB, 3)

	// And the erased org restarts cleanly from genesis — this is what the
	// purge's own "org.purge_completed" row does.
	insertAudit(t, db, "ae-era-a-after", auditOrgA, "org.purge_completed")
	mustOK(t, chainOf(t, db, auditOrgA), auditOrgA, 1)
	var seq int64
	if err := db.QueryRow(`SELECT chain_seq FROM audit_events WHERE id=?`, "ae-era-a-after").Scan(&seq); err != nil {
		t.Fatalf("read restarted chain: %v", err)
	}
	if seq != 1 {
		t.Fatalf("erased org's chain restarted at seq %d, want 1", seq)
	}
}

// TestAuditChain_ConcurrentInsertsDoNotCollide — the advisory lock in the
// chain-link trigger is the only thing stopping two concurrent appends for
// the same org from reading the same head and claiming the same predecessor.
func TestAuditChain_ConcurrentInsertsDoNotCollide(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()

	const n = 24
	errs := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			<-start
			_, err := db.Exec(`
				INSERT INTO audit_events (id, org_id, action, metadata, created_at)
				VALUES (?,?,?,?,?)`,
				fmt.Sprintf("ae-conc-%d", i), auditOrgA, "concurrent", "{}", time.Now().UTC())
			errs <- err
		}(i)
	}
	close(start)
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent insert: %v", err)
		}
	}

	var distinct, total int
	if err := db.QueryRow(
		`SELECT count(DISTINCT chain_seq), count(*) FROM audit_events WHERE org_id=?`, auditOrgA,
	).Scan(&distinct, &total); err != nil {
		t.Fatalf("count: %v", err)
	}
	if distinct != total || total != n {
		t.Fatalf("concurrent appends collided: %d rows, %d distinct chain_seq (want %d/%d)", total, distinct, n, n)
	}
	mustOK(t, chainOf(t, db, auditOrgA), auditOrgA, n)
}

// --- the guard's own observability ----------------------------------------

// TestAuditAppendOnly_GuardCanFail is the "prove it by deletion" test. A
// guard nobody has seen fail is a guard nobody knows works, and
// VerifyAuditAppendOnly exists precisely so that a lifted control is loud.
func TestAuditAppendOnly_GuardCanFail(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	ctx := context.Background()

	st, err := VerifyAuditAppendOnly(ctx, db)
	if err != nil {
		t.Fatalf("verify guard: %v", err)
	}
	if !st.Enforced() {
		t.Fatalf("freshly migrated database does not report the guard as enforced: %+v", st)
	}
	// The residual is reported honestly rather than hidden: in the standard
	// single-role deployment the app owns the table and can lift this.
	if !st.Liftable() {
		t.Logf("note: audit_events owner %q differs from the connected role %q — the control is NOT liftable by the app role here",
			st.TableOwner, st.CurrentRole)
	}

	// Disable, and watch it go red.
	if _, err := db.Exec(`ALTER TABLE audit_events DISABLE TRIGGER ` + auditAppendOnlyTrigger); err != nil {
		t.Fatalf("disable trigger: %v", err)
	}
	st, err = VerifyAuditAppendOnly(ctx, db)
	if err != nil {
		t.Fatalf("verify guard (disabled): %v", err)
	}
	if st.Enforced() {
		t.Fatal("VerifyAuditAppendOnly still reports enforced after ALTER TABLE ... DISABLE TRIGGER — the check cannot fail, so it is not a check")
	}

	// Drop it entirely — the other route to the same silent state.
	if _, err := db.Exec(`DROP TRIGGER ` + auditAppendOnlyTrigger + ` ON audit_events`); err != nil {
		t.Fatalf("drop trigger: %v", err)
	}
	st, err = VerifyAuditAppendOnly(ctx, db)
	if err != nil {
		t.Fatalf("verify guard (dropped): %v", err)
	}
	if st.AppendOnlyTrigger {
		t.Fatal("VerifyAuditAppendOnly reports a dropped trigger as present")
	}

	// Re-running the migration restores it: the control is self-healing on
	// the next boot, which is the one thing the app-owns-the-table residual
	// does buy us.
	for _, stmt := range auditAppendOnlyStatements() {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("re-apply migration: %v", err)
		}
	}
	st, err = VerifyAuditAppendOnly(ctx, db)
	if err != nil {
		t.Fatalf("verify guard (re-applied): %v", err)
	}
	if !st.Enforced() {
		t.Fatalf("re-running the migration did not restore the guard: %+v", st)
	}
}

// TestAuditAppendOnly_MigrationIsIdempotent — the migration runs on every
// boot, and the DROP+CREATE trigger pair must never leave a window in which
// the table is unguarded or the chain double-linked.
func TestAuditAppendOnly_MigrationIsIdempotent(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()
	insertAudit(t, db, "ae-idem-1", auditOrgA, "a")

	for pass := 0; pass < 3; pass++ {
		for _, stmt := range auditAppendOnlyStatements() {
			if _, err := db.Exec(stmt); err != nil {
				t.Fatalf("pass %d: %v", pass, err)
			}
		}
	}
	insertAudit(t, db, "ae-idem-2", auditOrgA, "b")
	mustOK(t, chainOf(t, db, auditOrgA), auditOrgA, 2)

	// Exactly one of each trigger — a second copy of the chain-link trigger
	// would re-link the row and quietly break every chain.
	var n int
	if err := db.QueryRow(`
		SELECT count(*) FROM pg_trigger t
		JOIN pg_class c ON c.oid = t.tgrelid
		WHERE c.relname='audit_events' AND NOT t.tgisinternal`).Scan(&n); err != nil {
		t.Fatalf("count triggers: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected exactly 3 triggers on audit_events after 4 migration passes, got %d", n)
	}
}

// TestAuditChain_ReportsUnchainedPrefix — rows that predate the migration
// carry no hashes. They must be reported as "nothing to verify", never as
// damage, or every existing install would boot into a false tamper alert.
func TestAuditChain_ReportsUnchainedPrefix(t *testing.T) {
	store := newAuditTestStore(t)
	db := store.DB()

	// Stand in for a pre-migration row by inserting with the chain-link
	// trigger off, which is exactly the state such a row was written in.
	if _, err := db.Exec(`ALTER TABLE audit_events DISABLE TRIGGER ` + auditChainLinkTrigger); err != nil {
		t.Fatalf("disable chain trigger: %v", err)
	}
	insertAudit(t, db, "ae-legacy-1", auditOrgA, "legacy")
	if _, err := db.Exec(`ALTER TABLE audit_events ENABLE TRIGGER ` + auditChainLinkTrigger); err != nil {
		t.Fatalf("re-enable chain trigger: %v", err)
	}
	insertAudit(t, db, "ae-legacy-2", auditOrgA, "modern")

	rows := chainOf(t, db, auditOrgA)
	mustOK(t, rows, auditOrgA, 1)
	for _, r := range rows {
		if r.OrgID != auditOrgA {
			continue
		}
		if r.UnchainedRows != 1 {
			t.Fatalf("unchained_rows=%d, want 1 — the pre-migration prefix must be counted, not verified", r.UnchainedRows)
		}
	}
}
