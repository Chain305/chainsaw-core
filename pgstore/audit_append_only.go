package pgstore

import (
	"context"
	"database/sql"
	"fmt"
)

// Append-only-except-erasure for `audit_events`.
//
// WHAT THIS IS NOT. It is not immutability, and nothing in the product may
// say that it is. Right-to-erasure requires that an org's audit rows can be
// destroyed on request, so there is a deliberate, narrow escape hatch: a
// transaction-scoped GUC that the org-purge cascade sets. "Append-only
// except erasure" is the honest name and the one used in the docs.
//
// WHY NOT `REVOKE UPDATE, DELETE`. That was the obvious fix and it would
// have caused a data-integrity incident:
//
//   - `internal/simulate.PurgeTables` lists audit_events THIRD, and
//     adminorgsapi.PurgeOrg deletes all 25 tables inside ONE transaction.
//     A revoke aborts that transaction on the third statement and rolls
//     back all 25 — but by then PurgeOrg has already soft-deleted the org,
//     irreversibly purged its blobs, and chunk-deleted its `events` rows,
//     all OUTSIDE the transaction. Every purge would strand an org in a
//     permanently unrecoverable half-state, and every retry would fail at
//     the same statement. A right-to-erasure failure caused by the control
//     that exists to serve compliance.
//   - It would also be theatre. Migrations run as the application role
//     (see rls.go: migrate() runs from Open() on the app's own DSN), so
//     that role OWNS audit_events and can `GRANT` the privilege straight
//     back in one statement — and the next migration boot runs as it.
//
// WHAT THIS ACTUALLY BUYS, honestly stated:
//
//	Layer 1 — the triggers (below) refuse UPDATE unconditionally, refuse
//	  TRUNCATE unconditionally, and refuse DELETE unless the caller is
//	  inside a transaction that has set AuditPurgeGUC. This stops the
//	  realistic failure modes: a buggy handler, a hand-run `DELETE FROM
//	  audit_events WHERE ...` in psql, a test helper reaching prod, an
//	  injected statement. It does NOT stop a fully compromised application
//	  role, because that role owns the table and can DROP TRIGGER. See
//	  VerifyAuditAppendOnly for why that is at least LOUD.
//
//	Layer 2 — the hash chain (chain_seq / prev_hash / row_hash) is what
//	  survives a compromised app role. Dropping the triggers and editing a
//	  row still leaves the row's own hash wrong, and deleting a row still
//	  leaves its successor's prev_hash dangling and a gap in chain_seq.
//	  Detection, not prevention: it makes tampering EVIDENT, which is why
//	  "tamper-evident" is a claim we can make and "tamper-proof" is not.
//
// RESIDUAL RISK — the trigger is liftable, and this is not fixable here.
// A non-liftable trigger needs audit_events to be owned by a role the
// application is not a member of. The application cannot arrange that from
// its own migration: `ALTER TABLE ... OWNER TO r` requires membership in r,
// and membership in r is exactly what would let the app take ownership back.
// An EVENT TRIGGER that blocks `DROP TRIGGER` needs superuser, which the app
// role deliberately is not (P9-22/P9-23: the app connects as chainsaw_app,
// not superuser, not BYPASSRLS). So the ownership half of this control has
// to be an operator action outside the application's own bootstrap, and
// until an operator takes it, Layer 1 is a control against mistakes and
// Layer 2 is the control against malice. That is the state of the art here
// and the docs say so rather than implying otherwise.

// AuditPurgeGUC is the transaction-scoped session variable that unlocks
// DELETE on audit_events. It follows the `chainsaw.` prefix convention
// Postgres requires for custom GUCs, exactly like OrgScopeGUC.
//
// It MUST be set with SET LOCAL semantics (`set_config(name, value, true)`,
// or EnableAuditPurge below), never session-scoped. A session-scoped set
// survives the connection's return to the pool, and the next unrelated
// request on that connection would then be allowed to delete audit rows —
// a permanent hole opened by the fix. This is the same trap documented on
// QueryOrgScoped in rls.go, and the same mitigation.
const AuditPurgeGUC = "chainsaw.audit_purge"

// auditPurgeGUCValue is the single accepted value. Anything else — unset,
// empty, 'off', a stale value from another feature — leaves DELETE refused,
// so the check is fail-closed by construction.
const auditPurgeGUCValue = "on"

// auditChainGenesisHash is the prev_hash of the first chained row in an
// org's chain. A fixed sentinel rather than NULL so "this is the head of
// the chain" is an assertion the verifier can check: if the rows at the
// front of a chain are deleted, the surviving first row still carries the
// hash of its now-missing predecessor, which is not the genesis value, and
// the verifier reports it. NULL would have been indistinguishable from a
// legitimate head.
const auditChainGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// auditRowHashFn / auditChainLinkFn / auditAppendOnlyFn / auditNoTruncateFn /
// auditVerifyFn are the database-side names. Named as constants because the
// migration, the verifier and the tests all have to agree on them.
const (
	auditRowHashFn    = "chainsaw_audit_row_hash"
	auditChainLinkFn  = "chainsaw_audit_chain_link"
	auditAppendOnlyFn = "chainsaw_audit_append_only"
	auditNoTruncateFn = "chainsaw_audit_no_truncate"

	// AuditChainVerifyFn is the SQL entry point an operator (or the Go
	// wrapper below) calls to check the chain:
	//
	//	SELECT * FROM chainsaw_verify_audit_chain();          -- every org
	//	SELECT * FROM chainsaw_verify_audit_chain('org-123'); -- one org
	AuditChainVerifyFn = "chainsaw_verify_audit_chain"

	auditChainLinkTrigger  = "chainsaw_audit_chain_link"
	auditAppendOnlyTrigger = "chainsaw_audit_append_only"
	auditNoTruncateTrigger = "chainsaw_audit_no_truncate"
)

// auditChainedColumns is the ordered argument list passed to the row-hash
// function, as a `prefix.column` template. The trigger and the verifier
// build their call from THIS list, so the two can never disagree about what
// is covered — a hash the verifier computes over a different field set than
// the trigger did would report every row as tampered.
//
// created_at is rendered as integer microseconds since the epoch inside the
// hash function (not via to_char) so the digest does not depend on DateStyle,
// lc_time or TimeZone.
var auditChainedColumns = []string{
	"id",
	"org_id",
	"actor_user_id",
	"actor_role",
	"action",
	"target_type",
	"target_id",
	"metadata",
	"created_at",
	"correlation_id",
	"prev_value",
	"new_value",
	"source",
	"requesting_ip",
	"chain_seq",
	"prev_hash",
}

// auditRowHashCall renders `chainsaw_audit_row_hash(p.id, p.org_id, ...)`
// for a row alias (`NEW` in the trigger, a table alias in the verifier).
func auditRowHashCall(prefix string) string {
	out := auditRowHashFn + "("
	for i, col := range auditChainedColumns {
		if i > 0 {
			out += ", "
		}
		out += prefix + "." + col
	}
	return out + ")"
}

// auditAppendOnlyStatements returns the idempotent DDL that installs the
// append-only triggers and the hash chain on audit_events.
//
// Deliberately NOT backfilled. Rows written before this migration keep NULL
// chain columns and the verifier reports them as an "unchained prefix"
// rather than as damage. Two reasons, and the second is the real one:
//
//  1. A backfill is an UPDATE on audit_events, and the trigger this
//     migration installs refuses UPDATE unconditionally (per spec — there
//     is no production UPDATE path and there must not be an escape hatch
//     for one). A backfill that half-completed on one boot could not be
//     resumed on the next without weakening the trigger.
//  2. Hashing rows retroactively proves nothing. Anyone who could have
//     altered a row before the chain existed could equally have altered it
//     the moment before the backfill computed its hash. A backfilled digest
//     would look like evidence while carrying none. Starting the chain at
//     the migration is the claim we can actually defend.
//
// Every statement is safe to re-run: ADD COLUMN IF NOT EXISTS, CREATE INDEX
// IF NOT EXISTS, CREATE OR REPLACE FUNCTION, and a DO block whose DROP
// TRIGGER IF EXISTS + CREATE TRIGGER pair share one implicit transaction so
// there is never a window in which the table is unguarded.
func auditAppendOnlyStatements() []string {
	genesis := "'" + auditChainGenesisHash + "'"

	return []string{
		// --- chain columns -------------------------------------------------
		`ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS chain_seq BIGINT`,
		`ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS prev_hash TEXT`,
		`ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS row_hash TEXT`,
		// The chain-link trigger reads the current head of each org's chain
		// on every insert; without this index that is a seq scan of the whole
		// table per audit write.
		`CREATE INDEX IF NOT EXISTS idx_audit_events_org_chain_seq ON audit_events(org_id, chain_seq DESC)`,

		// --- the one definition of "the hash of this row" -------------------
		//
		// IMMUTABLE, and genuinely so: every input is rendered through
		// quote_nullable(text), which is injective (NULL renders as the bare
		// token NULL, every other value as a quoted, escaped literal) and
		// locale-independent, and the timestamp is reduced to integer
		// microseconds. `||` rather than concat_ws because concat_ws SKIPS
		// null arguments, which would make two different rows hash alike;
		// quote_nullable guarantees no operand is ever NULL, so `||` is safe
		// and exact.
		`CREATE OR REPLACE FUNCTION ` + auditRowHashFn + `(
	p_id             text,
	p_org_id         text,
	p_actor_user_id  text,
	p_actor_role     text,
	p_action         text,
	p_target_type    text,
	p_target_id      text,
	p_metadata       text,
	p_created_at     timestamptz,
	p_correlation_id text,
	p_prev_value     text,
	p_new_value      text,
	p_source         text,
	p_requesting_ip  text,
	p_chain_seq      bigint,
	p_prev_hash      text
) RETURNS text
LANGUAGE sql IMMUTABLE
AS $chainsaw_audit_row_hash$
	SELECT encode(sha256(convert_to(
		'chainsaw.audit.v1'
		|| chr(30) || quote_nullable(p_id)
		|| chr(30) || quote_nullable(p_org_id)
		|| chr(30) || quote_nullable(p_actor_user_id)
		|| chr(30) || quote_nullable(p_actor_role)
		|| chr(30) || quote_nullable(p_action)
		|| chr(30) || quote_nullable(p_target_type)
		|| chr(30) || quote_nullable(p_target_id)
		|| chr(30) || quote_nullable(p_metadata)
		|| chr(30) || quote_nullable((trunc(extract(epoch FROM p_created_at) * 1000000)::bigint)::text)
		|| chr(30) || quote_nullable(p_correlation_id)
		|| chr(30) || quote_nullable(p_prev_value)
		|| chr(30) || quote_nullable(p_new_value)
		|| chr(30) || quote_nullable(p_source)
		|| chr(30) || quote_nullable(p_requesting_ip)
		|| chr(30) || quote_nullable(p_chain_seq::text)
		|| chr(30) || quote_nullable(p_prev_hash)
	, 'UTF8')), 'hex')
$chainsaw_audit_row_hash$`,

		// --- BEFORE INSERT: link the row into its org's chain ---------------
		//
		// The chain is PER ORG, not global. That is forced by erasure: a
		// global chain would be permanently broken by every right-to-erasure
		// purge, so the first legitimate deletion would make the whole
		// structure unverifiable and it would be quietly abandoned. Per-org,
		// purging org A destroys A's chain (which is the point) and leaves
		// every other org's chain intact and verifiable.
		//
		// Concurrency: two transactions appending for the SAME org must not
		// both read the same head and claim the same predecessor. The
		// advisory lock is transaction-scoped and keyed on the org, so
		// appends serialise per org and not at all across orgs. It is taken
		// before the head is read and released at commit, which closes the
		// read-then-write window. (A single transaction that appends rows for
		// two different orgs takes two of these locks; ordering between such
		// transactions could in principle deadlock, and Postgres would abort
		// one. No writer does that today — every audit write is single-org.)
		//
		// The trigger OVERWRITES whatever the caller supplied for chain_seq /
		// prev_hash / row_hash. A writer cannot forge its own position in the
		// chain, including the writers in this repository.
		//
		// One known, accepted race: an audit INSERT for org X that commits
		// while X's erasure transaction is in flight chains onto a row that
		// erasure then removes, so X's surviving chain reports "does not
		// start at genesis". It is narrow (PurgeOrg soft-deletes the org
		// first, so API traffic for it has already stopped) and it errs the
		// safe way — a verifier that says "rows are missing here" about an
		// org that was just erased is telling the truth.
		`CREATE OR REPLACE FUNCTION ` + auditChainLinkFn + `() RETURNS trigger
LANGUAGE plpgsql
AS $chainsaw_audit_chain_link$
DECLARE
	last_hash text;
	last_seq  bigint;
BEGIN
	PERFORM pg_advisory_xact_lock(hashtext('chainsaw.audit_chain'), hashtext(coalesce(NEW.org_id, '')));

	SELECT a.row_hash, a.chain_seq
	  INTO last_hash, last_seq
	  FROM audit_events a
	 WHERE a.org_id = NEW.org_id
	   AND a.row_hash IS NOT NULL
	 ORDER BY a.chain_seq DESC
	 LIMIT 1;

	NEW.chain_seq := coalesce(last_seq, 0) + 1;
	NEW.prev_hash := coalesce(last_hash, ` + genesis + `);
	NEW.row_hash  := ` + auditRowHashCall("NEW") + `;
	RETURN NEW;
END
$chainsaw_audit_chain_link$`,

		// --- BEFORE UPDATE OR DELETE: refuse, with one narrow escape --------
		//
		// UPDATE is refused unconditionally and has no escape hatch. This was
		// verified before it was written: the tree contains no UPDATE
		// statement targeting this table, in production or in tests, and
		// TestNoProductionUpdateOfAuditEvents (internal/server/adminorgsapi)
		// keeps it that way by scanning for one. A correction to the audit
		// trail is an appended row, never an edit.
		//
		// DELETE is refused unless the transaction has set AuditPurgeGUC. The
		// missing_ok form of current_setting returns NULL when the GUC was
		// never set on the connection, and IS DISTINCT FROM treats that as a
		// refusal — so the default, on every connection that has not opted
		// in, is "no". Same fail-closed shape as the RLS policy in rls.go.
		`CREATE OR REPLACE FUNCTION ` + auditAppendOnlyFn + `() RETURNS trigger
LANGUAGE plpgsql
AS $chainsaw_audit_append_only$
BEGIN
	IF TG_OP = 'UPDATE' THEN
		RAISE EXCEPTION 'audit_events is append-only: UPDATE refused (id=%)', OLD.id
			USING HINT = 'There is no UPDATE path for the audit trail. Correct a record by appending a new audit row.';
	END IF;

	IF current_setting('` + AuditPurgeGUC + `', true) IS DISTINCT FROM '` + auditPurgeGUCValue + `' THEN
		RAISE EXCEPTION 'audit_events is append-only: DELETE refused outside an org-erasure transaction (id=%)', OLD.id
			USING HINT = 'Right-to-erasure deletes must run inside a transaction that has executed set_config(''` + AuditPurgeGUC + `'', ''` + auditPurgeGUCValue + `'', true).';
	END IF;

	RETURN OLD;
END
$chainsaw_audit_append_only$`,

		// --- BEFORE TRUNCATE: refuse ---------------------------------------
		//
		// TRUNCATE does not fire row-level triggers, so without this the
		// delete guard above would be one keyword away from irrelevant.
		// No escape hatch: the erasure cascade deletes by org_id and has no
		// use for TRUNCATE. There is no TRUNCATE of audit_events anywhere in
		// the tree today, and this keeps it that way.
		`CREATE OR REPLACE FUNCTION ` + auditNoTruncateFn + `() RETURNS trigger
LANGUAGE plpgsql
AS $chainsaw_audit_no_truncate$
BEGIN
	RAISE EXCEPTION 'audit_events is append-only: TRUNCATE refused'
		USING HINT = 'Erase one org with the org-purge cascade, which deletes by org_id inside a transaction that sets ` + AuditPurgeGUC + `.';
END
$chainsaw_audit_no_truncate$`,

		// --- attach the triggers -------------------------------------------
		//
		// DROP + CREATE inside one DO block so the drop and the re-create
		// share an implicit transaction: re-running the migration never
		// leaves a window in which audit_events is unguarded.
		`DO $chainsaw_audit_triggers$
BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = 'audit_events') THEN
		RETURN;
	END IF;

	DROP TRIGGER IF EXISTS ` + auditChainLinkTrigger + ` ON public.audit_events;
	CREATE TRIGGER ` + auditChainLinkTrigger + `
		BEFORE INSERT ON public.audit_events
		FOR EACH ROW EXECUTE FUNCTION ` + auditChainLinkFn + `();

	DROP TRIGGER IF EXISTS ` + auditAppendOnlyTrigger + ` ON public.audit_events;
	CREATE TRIGGER ` + auditAppendOnlyTrigger + `
		BEFORE UPDATE OR DELETE ON public.audit_events
		FOR EACH ROW EXECUTE FUNCTION ` + auditAppendOnlyFn + `();

	DROP TRIGGER IF EXISTS ` + auditNoTruncateTrigger + ` ON public.audit_events;
	CREATE TRIGGER ` + auditNoTruncateTrigger + `
		BEFORE TRUNCATE ON public.audit_events
		FOR EACH STATEMENT EXECUTE FUNCTION ` + auditNoTruncateFn + `();
END
$chainsaw_audit_triggers$`,

		// --- the verification path -----------------------------------------
		//
		// A function, not a hand-written query, so "check the audit trail" is
		// one call an auditor or an operator can run in psql without knowing
		// the hash construction:
		//
		//	SELECT * FROM chainsaw_verify_audit_chain();
		//
		// It recomputes every chained row's hash with the SAME function the
		// insert trigger used, then checks four independent properties. The
		// four are listed separately (rather than collapsed into one boolean)
		// because they distinguish WHAT happened: an edited row, a deleted
		// head, a deleted middle row, a reordered row.
		//
		// Output columns are named with a chain_ prefix where they would
		// otherwise collide with a column of audit_events — an output
		// parameter named org_id would make every bare `org_id` inside the
		// body ambiguous.
		`CREATE OR REPLACE FUNCTION ` + AuditChainVerifyFn + `(p_org_id text DEFAULT NULL)
RETURNS TABLE (
	chain_org_id   text,
	chained_rows   bigint,
	unchained_rows bigint,
	ok             boolean,
	first_bad_seq  bigint,
	first_bad_id   text,
	reason         text
)
LANGUAGE sql STABLE
AS $chainsaw_verify_audit_chain$
	WITH scoped AS (
		SELECT a.* FROM audit_events a
		WHERE p_org_id IS NULL OR a.org_id = p_org_id
	),
	linked AS (
		SELECT s.*,
		       lag(s.row_hash)  OVER w AS expect_prev_hash,
		       lag(s.chain_seq) OVER w AS expect_prev_seq
		FROM scoped s
		WHERE s.row_hash IS NOT NULL
		WINDOW w AS (PARTITION BY s.org_id ORDER BY s.chain_seq)
	),
	judged AS (
		SELECT c.org_id AS j_org_id, c.chain_seq AS j_seq, c.id AS j_id,
		CASE
			WHEN c.row_hash IS DISTINCT FROM ` + auditRowHashCall("c") + `
				THEN 'row_hash mismatch: this row''s contents were altered after it was written'
			WHEN c.expect_prev_seq IS NULL AND c.prev_hash IS DISTINCT FROM ` + genesis + `
				THEN 'chain does not start at genesis: rows were removed from the head of this org''s chain'
			WHEN c.expect_prev_seq IS NOT NULL AND c.chain_seq <> c.expect_prev_seq + 1
				THEN 'sequence gap: a row was removed from the middle of this org''s chain'
			WHEN c.expect_prev_seq IS NOT NULL AND c.prev_hash IS DISTINCT FROM c.expect_prev_hash
				THEN 'prev_hash mismatch: the preceding row was altered, removed or reordered'
			ELSE NULL
		END AS j_reason
		FROM linked c
	),
	counts AS (
		SELECT s.org_id AS c_org_id,
		       count(*) FILTER (WHERE s.row_hash IS NOT NULL) AS c_chained,
		       count(*) FILTER (WHERE s.row_hash IS NULL)     AS c_unchained
		FROM scoped s
		GROUP BY s.org_id
	),
	firstbad AS (
		SELECT DISTINCT ON (j.j_org_id) j.j_org_id, j.j_seq, j.j_id, j.j_reason
		FROM judged j
		WHERE j.j_reason IS NOT NULL
		ORDER BY j.j_org_id, j.j_seq
	)
	SELECT n.c_org_id, n.c_chained, n.c_unchained,
	       (f.j_org_id IS NULL) AS ok,
	       f.j_seq, f.j_id, f.j_reason
	FROM counts n
	LEFT JOIN firstbad f ON f.j_org_id = n.c_org_id
	ORDER BY n.c_org_id
$chainsaw_verify_audit_chain$`,
	}
}

// EnableAuditPurge opens the erasure escape hatch for the CURRENT
// transaction and nothing beyond it.
//
// Callers pass a live *sql.Tx on purpose. `set_config(..., is_local => true)`
// is the SET LOCAL equivalent that accepts a bind parameter, and SET LOCAL
// outside a transaction block is a silent no-op — taking a *sql.Tx makes it
// impossible to reach the session-scoped variant by accident, which is the
// one that would leave the hole open on a pooled connection for every
// request that follows.
//
// There is exactly one production caller: the org-purge cascade in
// internal/server/adminorgsapi/purge.go. If a second one ever appears, it is
// asserting a right-to-erasure operation, and it should have to say so here.
func EnableAuditPurge(ctx context.Context, tx *sql.Tx) error {
	if tx == nil {
		return fmt.Errorf("audit purge scope requires an open transaction")
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config($1, $2, true)`, AuditPurgeGUC, auditPurgeGUCValue); err != nil {
		return fmt.Errorf("set %s: %w", AuditPurgeGUC, err)
	}
	return nil
}

// AuditGuardStatus is the observable state of the append-only control.
//
// This type exists because of the rule in CLAUDE.md that a guard which
// cannot run is not a guard. The triggers are droppable by the table owner —
// see the residual-risk note at the top of this file — so the one thing that
// can still be guaranteed is that their ABSENCE is loud rather than silent.
type AuditGuardStatus struct {
	// TablePresent is false on a database that has not been migrated yet.
	// Distinguishing it from "trigger missing" is the difference between
	// "did not run" and "failed".
	TablePresent bool

	// AppendOnlyTrigger / ChainLinkTrigger / NoTruncateTrigger report
	// whether each trigger exists AND is enabled. `ALTER TABLE ... DISABLE
	// TRIGGER` leaves the row in pg_trigger with tgenabled='D', which a
	// bare existence check would report as healthy — the same shape of
	// silent-pass that the DISABLE ROW LEVEL SECURITY case has in rls.go.
	AppendOnlyTrigger bool
	ChainLinkTrigger  bool
	NoTruncateTrigger bool

	// TableOwner and CurrentRole are reported so an operator can see the
	// residual directly: while these are equal (or the current role is a
	// member of the owner), the connected role can drop the triggers.
	TableOwner  string
	CurrentRole string
}

// Enforced reports whether all three triggers are present and enabled.
func (s AuditGuardStatus) Enforced() bool {
	return s.TablePresent && s.AppendOnlyTrigger && s.ChainLinkTrigger && s.NoTruncateTrigger
}

// Liftable reports whether the connected role can remove the control it is
// subject to — true whenever it owns audit_events, which in the standard
// single-role deployment it does. Surfaced rather than hidden: an operator
// who wants a non-liftable audit trail has to move table ownership to a role
// the application is not a member of, and this is how they see that they
// have not done so.
func (s AuditGuardStatus) Liftable() bool {
	return s.TableOwner != "" && s.TableOwner == s.CurrentRole
}

// VerifyAuditAppendOnly reads the live state of the append-only control.
//
// It returns an error only when the state could not be READ. A missing or
// disabled trigger is reported in the returned struct, not as an error, so
// a caller can tell "the control is off" apart from "I could not find out",
// which is the distinction CLAUDE.md §3 exists to preserve.
func VerifyAuditAppendOnly(ctx context.Context, db *sql.DB) (AuditGuardStatus, error) {
	var st AuditGuardStatus
	if db == nil {
		return st, fmt.Errorf("nil database handle")
	}

	var owner sql.NullString
	err := db.QueryRowContext(ctx,
		`SELECT tableowner FROM pg_tables WHERE schemaname='public' AND tablename='audit_events'`,
	).Scan(&owner)
	if err != nil {
		if err == sql.ErrNoRows {
			return st, nil // not migrated yet: TablePresent stays false
		}
		return st, fmt.Errorf("read audit_events owner: %w", err)
	}
	st.TablePresent = true
	st.TableOwner = owner.String

	role, err := CurrentRole(ctx, db)
	if err != nil {
		return st, err
	}
	st.CurrentRole = role

	rows, err := db.QueryContext(ctx, `
		SELECT t.tgname, t.tgenabled
		FROM pg_trigger t
		JOIN pg_class c ON c.oid = t.tgrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relname = 'audit_events' AND NOT t.tgisinternal`)
	if err != nil {
		return st, fmt.Errorf("read audit_events triggers: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name, enabled string
		if err := rows.Scan(&name, &enabled); err != nil {
			return st, fmt.Errorf("scan audit_events trigger: %w", err)
		}
		// 'O' = fires in origin/local mode, i.e. normal application writes.
		// 'D' (disabled), 'R' (replica-only) and 'A' (always) are all states
		// in which this control is not doing what the docs claim, so only
		// 'O' counts as enforced.
		live := enabled == "O"
		switch name {
		case auditAppendOnlyTrigger:
			st.AppendOnlyTrigger = live
		case auditChainLinkTrigger:
			st.ChainLinkTrigger = live
		case auditNoTruncateTrigger:
			st.NoTruncateTrigger = live
		}
	}
	return st, rows.Err()
}

// AuditChainStatus is one org's row from AuditChainVerifyFn.
type AuditChainStatus struct {
	OrgID string

	// ChainedRows counts rows written after the chain migration;
	// UnchainedRows counts the pre-migration prefix, which carries no
	// hashes and is therefore not evidence of anything. Reporting them
	// separately keeps "there is nothing to verify here" distinct from
	// "everything verified".
	ChainedRows   int64
	UnchainedRows int64

	OK bool

	// Set only when OK is false: the earliest position at which the chain
	// stops verifying, and a human-readable reason naming which of the four
	// properties failed.
	FirstBadSeq sql.NullInt64
	FirstBadID  sql.NullString
	Reason      sql.NullString
}

// VerifyAuditChain recomputes and checks the hash chain. Pass an empty
// orgID to check every org.
//
// This is the half of the control that survives a compromised application
// role, so it is deliberately reachable from Go (health checks, tests, an
// admin endpoint) and from psql (the SQL function directly) — an auditor who
// does not trust the application should be able to run it without it.
func VerifyAuditChain(ctx context.Context, db *sql.DB, orgID string) ([]AuditChainStatus, error) {
	if db == nil {
		return nil, fmt.Errorf("nil database handle")
	}
	// Two query shapes rather than one with a NULL argument. Passing an
	// untyped NULL for the function's `text DEFAULT NULL` parameter leaves
	// the driver to infer a type it has no information about; calling the
	// zero-argument form when there is no org to filter by sidesteps that
	// entirely and reads the same at the call site.
	const cols = `SELECT chain_org_id, chained_rows, unchained_rows, ok, first_bad_seq, first_bad_id, reason FROM `
	var (
		rows *sql.Rows
		err  error
	)
	if orgID == "" {
		rows, err = db.QueryContext(ctx, cols+AuditChainVerifyFn+`()`)
	} else {
		rows, err = db.QueryContext(ctx, cols+AuditChainVerifyFn+`($1)`, orgID)
	}
	if err != nil {
		return nil, fmt.Errorf("verify audit chain: %w", err)
	}
	defer rows.Close()

	var out []AuditChainStatus
	for rows.Next() {
		var s AuditChainStatus
		if err := rows.Scan(&s.OrgID, &s.ChainedRows, &s.UnchainedRows, &s.OK,
			&s.FirstBadSeq, &s.FirstBadID, &s.Reason); err != nil {
			return nil, fmt.Errorf("scan audit chain status: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
