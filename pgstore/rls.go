package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// P0-A / A1 — row-level security as the real Billy tenant boundary.
//
// Background. Billy's `run_sql` tool lets an LLM emit free-form SELECTs
// against four tables. Tenant scoping was enforced entirely by a regex in
// internal/billy/sqlguard.go that required an `org_id` token to *exist*
// somewhere in the string. That is not a boundary: every one of these is
// accepted by the guard and returns every tenant's rows —
//
//	WHERE org_id = '$ORG_ID' OR 1=1
//	WHERE 1=1 OR org_id = '$ORG_ID'
//	FROM policies p JOIN events e ON 1=1 WHERE p.org_id = '$ORG_ID'
//	WHERE NOT org_id = '$ORG_ID'
//	WHERE CASE WHEN org_id = '$ORG_ID' THEN true ELSE true END
//
// and the attacker controls the string, because a package README reaches
// the model as untrusted text (internal/billy/untrusted.go). A regex cannot
// win that argument: the guard's lexer diverges from Postgres (comments are
// stripped before string literals; dollar-quoting is not modelled), and a
// pure-Go SQL parser would just be a second dialect with the same bug class.
//
// So the boundary moves into the database, where the predicate is not a
// string the model can shape:
//
//  1. a `billy_ro` role with COLUMN-level SELECT on exactly four tables,
//  2. ENABLE + FORCE ROW LEVEL SECURITY with an org-scoped policy, and
//  3. `SET LOCAL chainsaw.org_id` inside a per-query transaction.
//
// With all three, every bypass above returns zero foreign rows regardless of
// what the guard misses. The guard stays as defence in depth (A2), not as the
// boundary.

// BillyRORole is the Postgres role Billy's read pool must authenticate as.
// It is deliberately a constant and not configurable: the startup check
// (VerifyBillyRole) and the migration that grants privileges have to agree
// on one name, and an operator-supplied name would let a typo silently
// resolve to a role with no RLS policy — i.e. back to today's behaviour.
const BillyRORole = "billy_ro"

// OrgScopeGUC is the session variable the RLS policy reads. Postgres requires
// custom GUCs to be qualified (`prefix.name`), and `current_setting(name, true)`
// returns NULL when it has never been set on the connection — so an unscoped
// connection matches no row rather than every row. That is the fail-closed
// half of this design and the reason the policy uses the missing_ok form.
const OrgScopeGUC = "chainsaw.org_id"

// billyReadableTables is the exact set of tables Billy may read. Order is
// fixed so the generated DDL is stable across boots.
var billyReadableTables = []string{"events", "policies", "repositories", "package_metadata"}

// BillyReadableColumns is the column-level grant list for BillyRORole.
//
// It MIRRORS `allowedColumns` in internal/billy/tools.go, which is the
// guard-side allowlist. The two lists cannot share a declaration — core/
// is the public open-core module and must not import internal/ — so
// internal/billy/rls_grant_sync_test.go asserts they stay identical, with
// the deliberate exceptions listed below. Change one, change the other, or
// that test fails.
//
// Consequence worth knowing: `SELECT *` needs privilege on EVERY column, so
// under these grants it is refused by Postgres ("permission denied for table
// events") on all four tables. The SQL guard accepts `*` today — `*` is not
// an identifier, so the column-extraction regex never sees it. That is a
// message-quality problem, not a safety one: the model gets a database error
// instead of a guard rejection telling it to name its columns. The fix
// belongs in the guard (A2), not here.
//
// `repositories.remote_url` (userinfo credentials —
// https://user:token@registry.example.com) and `remote_headers` (upstream
// auth headers) are absent here on purpose. The guard also excludes them as
// of A2, so the two lists agree — but the grant is the half that holds if
// the guard regresses, because Postgres, not a regex, is refusing the
// column. `format_options`, `scanner_payload`, `parameter_hash` and friends
// are absent from both lists for the reason they always were: Billy has no
// business reading them.
var BillyReadableColumns = map[string][]string{
	"events": {
		"id", "org_id", "recorded_at", "repository", "format", "logical_path",
		"method", "client_id", "action", "outcome", "status_code",
		"package_name", "package_version", "version_requested",
		"version_resolved", "cache_status", "bytes_upstream", "bytes_to_client",
		"failure_reason", "rule_id", "latency_ms", "requesting_ip",
		"request_user_agent", "requesting_country", "scanner", "severity",
	},
	"policies": {
		"id", "org_id", "name", "description", "precedence", "mode", "status",
		"created_at", "updated_at", "identifier", "conditions", "policy_scope",
	},
	"repositories": {
		"org_id", "name", "format", "type", "enabled", "anonymous_access",
		// remote_url deliberately omitted — see the doc comment above.
		"remote_proxy_url", "remote_skip_tls", "remote_timeout_seconds",
		"cache_negative_ttl_seconds", "client_configuration_guide_template",
		"public_base_url", "created_at", "updated_at",
	},
	"package_metadata": {
		"org_id", "repository", "package", "version", "license_spdx",
		"package_release_date", "version_release_date", "sha256_hash",
		"upstream_url", "internal_package", "created_at", "updated_at",
	},
}

// BillyGrantExceptions names columns that the SQL guard allows but that the
// database deliberately does NOT grant — the guard being the wider of the
// two. Empty today: `remote_url` was the one entry, and A2 removed it from
// the guard's allowlist as well, so the lists now agree exactly.
//
// The map stays because the asymmetry is legitimate and will recur: the DB
// grant is the boundary and may be narrower than the guard on purpose. The
// drift test in internal/billy fails on a stale entry, so an exception left
// here after the guard catches up cannot go unnoticed.
var BillyGrantExceptions = map[string][]string{}

// rlsPolicyOrgIsolation is the org-scoped SELECT policy. It applies to
// PUBLIC — every role, including roles that do not exist yet — so a new
// read-only role added later is scoped by default instead of being wide
// open until someone remembers to write a policy for it.
const rlsPolicyOrgIsolation = "chainsaw_org_isolation"

// rlsPolicyWriterAll is the escape hatch for the application's own writer
// role. FORCE ROW LEVEL SECURITY (mandatory here — without it the role that
// owns the tables bypasses every policy, and that role is the one the
// migration runs as) subjects the owner to RLS too, which would otherwise
// turn every application read into zero rows and every write into a policy
// violation. So the writer gets an explicit permissive `USING (true)`
// policy, and permissive policies OR together.
//
// The policy names exactly two roles: `current_user` at migration time and
// the table owner when a restore left those different. current_user is the
// right anchor because migrations are not a separate step — pgstore.Open
// runs migrate() on the application's own DSN, so the migrating role IS the
// application writer, by construction. Nothing else is enumerated; see the
// inline comment in billyRLSStatements for why the wider sweep was dropped.
const rlsPolicyWriterAll = "chainsaw_writer_all"

// billyRLSStatements returns the idempotent DDL that installs the Billy
// tenant boundary. Appended to migrateSchema's statement list.
//
// Every statement is safe to re-run:
//   - ENABLE/FORCE ROW LEVEL SECURITY are no-ops when already set.
//   - Policies are DROP IF EXISTS + CREATE inside one DO block, so the
//     drop and the re-create are in the same implicit transaction and
//     there is never a window where the table is unprotected.
//   - Grants revoke first (including per-column, which a table-level
//     REVOKE does not reach), so removing a column from
//     BillyReadableColumns actually withdraws it on the next boot.
//   - Role creation is best-effort: a writer role without CREATEROLE
//     raises a notice instead of failing the boot. The startup check in
//     VerifyBillyRole is what makes a missing role loud, at the point
//     where it matters.
func billyRLSStatements() []string {
	stmts := make([]string, 0, 2)

	var b strings.Builder
	b.WriteString(`DO $chainsaw_rls$
DECLARE
	tbl       text;
	writer    text := current_user;
	tbl_owner text;
	role_list text;
BEGIN
	FOREACH tbl IN ARRAY ARRAY[`)
	for i, t := range billyReadableTables {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("'" + t + "'")
	}
	b.WriteString(`] LOOP
		IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = tbl) THEN
			CONTINUE;
		END IF;
		EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tbl);
		EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', tbl);

		-- Exactly two roles keep unrestricted access: the migrating role
		-- (which IS the application writer — migrate() runs from Open() on
		-- the app's own DSN) and the table owner, when a restore left those
		-- different. Nothing else is enumerated, deliberately: an earlier
		-- draft also swept in every role holding table-level SELECT, so an
		-- operator's reporting role would keep working — but that makes the
		-- policy fail-OPEN for any role someone grants SELECT to later,
		-- which is the same shape of mistake this whole change exists to
		-- remove. Any additional cross-tenant reader must be added to this
		-- policy on purpose; see docs/CONFIG_REFERENCE.md B2. Superusers
		-- bypass RLS outright, so operator psql access is unaffected.
		SELECT tableowner INTO tbl_owner FROM pg_tables WHERE schemaname = 'public' AND tablename = tbl;
		IF tbl_owner IS NOT NULL AND tbl_owner <> writer AND tbl_owner <> '` + BillyRORole + `' THEN
			role_list := quote_ident(writer) || ', ' || quote_ident(tbl_owner);
		ELSE
			role_list := quote_ident(writer);
		END IF;

		EXECUTE format('DROP POLICY IF EXISTS ` + rlsPolicyWriterAll + ` ON public.%I', tbl);
		IF role_list IS NOT NULL THEN
			EXECUTE format('CREATE POLICY ` + rlsPolicyWriterAll + ` ON public.%I FOR ALL TO %s USING (true) WITH CHECK (true)', tbl, role_list);
		END IF;

		EXECUTE format('DROP POLICY IF EXISTS ` + rlsPolicyOrgIsolation + ` ON public.%I', tbl);
		EXECUTE format(
			'CREATE POLICY ` + rlsPolicyOrgIsolation + ` ON public.%I FOR SELECT USING (org_id = current_setting(%L, true))',
			tbl, '` + OrgScopeGUC + `');
	END LOOP;
END
$chainsaw_rls$`)
	stmts = append(stmts, b.String())

	var g strings.Builder
	g.WriteString(`DO $chainsaw_billy_grants$
DECLARE
	tbl text;
	col text;
BEGIN
	IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '` + BillyRORole + `') THEN
		BEGIN
			CREATE ROLE ` + BillyRORole + ` NOLOGIN NOBYPASSRLS;
		EXCEPTION WHEN insufficient_privilege THEN
			RAISE NOTICE 'chainsaw: cannot CREATE ROLE ` + BillyRORole + ` (writer lacks CREATEROLE); create it manually — see docs/CONFIG_REFERENCE.md B2';
			RETURN;
		END;
	END IF;

	EXECUTE 'GRANT USAGE ON SCHEMA public TO ` + BillyRORole + `';

	FOREACH tbl IN ARRAY ARRAY[`)
	for i, t := range billyReadableTables {
		if i > 0 {
			g.WriteString(", ")
		}
		g.WriteString("'" + t + "'")
	}
	g.WriteString(`] LOOP
		IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = tbl) THEN
			CONTINUE;
		END IF;
		-- Table-level first, then every column: a table-level REVOKE does
		-- not withdraw column-level grants, so both are needed for this to
		-- converge on exactly the list below.
		EXECUTE format('REVOKE ALL PRIVILEGES ON TABLE public.%I FROM ` + BillyRORole + `', tbl);
		FOR col IN
			SELECT column_name FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = tbl
		LOOP
			EXECUTE format('REVOKE ALL PRIVILEGES (%I) ON TABLE public.%I FROM ` + BillyRORole + `', col, tbl);
		END LOOP;
	END LOOP;
`)
	tables := make([]string, 0, len(BillyReadableColumns))
	for t := range BillyReadableColumns {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	for _, t := range tables {
		cols := append([]string(nil), BillyReadableColumns[t]...)
		quoted := make([]string, len(cols))
		for i, c := range cols {
			quoted[i] = `"` + c + `"`
		}
		// Guarded on the table existing so a fresh database mid-migration
		// (or a future table rename) degrades to a no-op, not a boot failure.
		g.WriteString(`
	IF EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = '` + t + `') THEN
		EXECUTE 'GRANT SELECT (` + strings.Join(quoted, ", ") + `) ON TABLE public.` + t + ` TO ` + BillyRORole + `';
	END IF;
`)
	}
	g.WriteString(`END
$chainsaw_billy_grants$`)
	stmts = append(stmts, g.String())

	return stmts
}

// ErrBillySharesWriterRole is returned when the Billy read pool authenticates
// as the same Postgres role as the writer. That role holds the
// chainsaw_writer_all policy, so RLS would let it read every tenant — i.e.
// the whole boundary silently degrades to the pre-RLS behaviour. This is the
// most likely way this change gets undone: someone copies
// CHAINSAW_DATABASE_URL into CHAINSAW_BILLY_DATABASE_URL and nothing appears
// to be wrong.
var ErrBillySharesWriterRole = errors.New("billy read-only DSN resolves to the same Postgres role as the writer: row-level security would not apply")

// ErrBillyRoleBypassesRLS is returned when the Billy role is a superuser or
// carries BYPASSRLS. Either attribute disables every policy for that role,
// which is the same silent degradation by a different route.
var ErrBillyRoleBypassesRLS = errors.New("billy read-only role is a superuser or has BYPASSRLS: row-level security would not apply")

// CurrentRole returns `current_user` for a pool. Note this is the effective
// role after any SET ROLE, which is what RLS actually keys on.
func CurrentRole(ctx context.Context, db *sql.DB) (string, error) {
	if db == nil {
		return "", fmt.Errorf("nil database handle")
	}
	var role string
	if err := db.QueryRowContext(ctx, `SELECT current_user`).Scan(&role); err != nil {
		return "", fmt.Errorf("read current_user: %w", err)
	}
	return role, nil
}

// VerifyBillyRole is the startup check for item 4 of A1. It fails when the
// Billy pool would not actually be subject to row-level security — because
// it shares the writer's role, or because its role bypasses RLS outright.
//
// Callers must treat a non-nil error as fatal for the Billy feature (do not
// fall back to the writer pool); see internal/server/server.go.
func VerifyBillyRole(ctx context.Context, billyDB, writerDB *sql.DB) error {
	billyRole, err := CurrentRole(ctx, billyDB)
	if err != nil {
		return fmt.Errorf("billy pool: %w", err)
	}
	if writerDB != nil {
		writerRole, err := CurrentRole(ctx, writerDB)
		if err != nil {
			return fmt.Errorf("writer pool: %w", err)
		}
		if strings.EqualFold(billyRole, writerRole) {
			return fmt.Errorf("%w (both are %q)", ErrBillySharesWriterRole, billyRole)
		}
	}

	var super, bypass bool
	err = billyDB.QueryRowContext(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&super, &bypass)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// current_user always has a pg_roles row; treat the impossible as fatal.
		return fmt.Errorf("%w: no pg_roles row for %q", ErrBillyRoleBypassesRLS, billyRole)
	case err != nil:
		return fmt.Errorf("read role attributes for %q: %w", billyRole, err)
	case super || bypass:
		return fmt.Errorf("%w (role %q: superuser=%t bypassrls=%t)", ErrBillyRoleBypassesRLS, billyRole, super, bypass)
	}

	// Mechanism 3: the tables must actually have RLS switched on. Checked
	// before the policy sweep because an unprotected table has no policies to
	// find, so the sweep would come back clean and say nothing.
	unprotected, err := UnprotectedBillyTables(ctx, billyDB)
	if err != nil {
		return fmt.Errorf("check row-level security for %q: %w", billyRole, err)
	}
	if len(unprotected) > 0 {
		return fmt.Errorf("%w (role %q, tables: %s)", ErrBillyTablesUnprotected, billyRole, strings.Join(unprotected, ", "))
	}

	// Mechanism 2: no permissive policy other than the org-isolation one may
	// apply to this role — including through role membership, which no
	// attribute on the role reflects.
	coverage, err := UnrestrictedPolicyCoverage(ctx, billyDB)
	if err != nil {
		return fmt.Errorf("check policy coverage for %q: %w", billyRole, err)
	}
	if len(coverage) > 0 {
		names := make([]string, len(coverage))
		for i, c := range coverage {
			names[i] = c.String()
		}
		return fmt.Errorf("%w (role %q is covered by: %s)", ErrBillyInheritsUnrestrictedPolicy, billyRole, strings.Join(names, "; "))
	}
	return nil
}

// WarnUnlessWriterIsLeastPrivilege reports whether the application's OWN
// database role bypasses row-level security, and returns a ready-to-log
// explanation when it does.
//
// This is P9-23, and it is deliberately NOT fatal. The writer is supposed to
// read across tenants — that is what the chainsaw_writer_all policy is for —
// so a bypassing writer is a blast-radius problem, not a correctness one, and
// making it fatal would refuse to boot every existing deployment. What it
// must not be is silent: while the writer holds SUPERUSER or BYPASSRLS,
// chainsaw_writer_all is never exercised, so the day the role is demoted is
// the first day that policy runs in anger. See docs/plan_qa_phase9_remediation.md
// P9-23 for the migration shape and why it needs its own wave.
//
// Returns ok=true when the writer is already least-privilege.
func WarnUnlessWriterIsLeastPrivilege(ctx context.Context, writerDB *sql.DB) (ok bool, detail string, err error) {
	p, err := DescribeRoleRLSPosture(ctx, writerDB)
	if err != nil {
		return false, "", err
	}
	if !p.BypassesRLS() {
		return true, "", nil
	}
	return false, fmt.Sprintf(
		"application database role %q bypasses row-level security (superuser=%t bypassrls=%t). "+
			"An application compromise is an unrestricted database role, and the %s policy is moot until this is fixed. "+
			"Remediation is P9-23: create a least-privilege owner role and repoint CHAINSAW_DATABASE_URL — do NOT demote this role in place if it is the cluster's only superuser.",
		p.Role, p.Superuser, p.BypassRLS, rlsPolicyWriterAll), nil
}

// OpenBillyReadOnly opens the dedicated Billy read pool from billyDSN and
// refuses to return it unless VerifyBillyRole passes. On failure the pool is
// closed, so a caller that ignores the error cannot accidentally hold a
// usable unscoped handle.
func OpenBillyReadOnly(ctx context.Context, billyDSN string, writerDB *sql.DB) (*sql.DB, error) {
	db, err := OpenReadOnly(billyDSN)
	if err != nil {
		return nil, err
	}
	if err := VerifyBillyRole(ctx, db, writerDB); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// ScopedRows is *sql.Rows plus ownership of the transaction that carries the
// org scope. Closing it closes the rows and then ends the transaction, which
// is what discards the SET LOCAL before the connection returns to the pool.
//
// It embeds *sql.Rows, so Columns/Next/Scan/Err at the call site are
// unchanged — the whole migration of a call site is the Query line.
type ScopedRows struct {
	*sql.Rows
	tx *sql.Tx
}

// Close closes the rows, then rolls back the read-only transaction. Rollback
// (not Commit) because nothing was written and a rollback cannot fail in a
// way the caller could act on. Double Close is safe: sql.Tx.Rollback after
// the transaction has ended returns sql.ErrTxDone, which is swallowed.
func (r *ScopedRows) Close() error {
	if r == nil {
		return nil
	}
	var err error
	if r.Rows != nil {
		err = r.Rows.Close()
	}
	if r.tx != nil {
		if rbErr := r.tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) && err == nil {
			err = rbErr
		}
	}
	return err
}

// QueryOrgScoped runs query inside a read-only transaction whose
// chainsaw.org_id GUC is set to orgID, so the RLS policy installed by
// billyRLSStatements restricts every row the query can see.
//
// SET LOCAL, not SET. The Billy pool is shared across orgs; a session-level
// GUC survives the connection's return to the pool and would then scope the
// NEXT org's query to the PREVIOUS org — a cross-tenant read introduced by
// the fix itself. `set_config(name, value, is_local => true)` is the
// SET LOCAL equivalent that accepts a bind parameter; the literal
// `SET LOCAL chainsaw.org_id = ...` form does not, and would put orgID back
// into a SQL string.
//
// The pool already runs with default_transaction_read_only=on (OpenReadOnly),
// so the explicit BEGIN costs a round trip and nothing else.
//
// The caller MUST Close the returned rows; that is what ends the
// transaction. A caller that leaks them leaks a connection, which the
// 5-connection pool will surface quickly.
func QueryOrgScoped(ctx context.Context, db *sql.DB, orgID, query string, args ...any) (*ScopedRows, error) {
	if db == nil {
		return nil, fmt.Errorf("nil database handle")
	}
	// An empty org id would set the GUC to '' and match nothing, which is
	// fail-closed but indistinguishable from "the tenant has no rows".
	// Callers reaching here without a tenant are a bug; say so.
	if strings.TrimSpace(orgID) == "" {
		return nil, fmt.Errorf("org-scoped query requires a non-empty org id")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin org-scoped transaction: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT set_config($1, $2, true)`, OrgScopeGUC, orgID); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("set %s: %w", OrgScopeGUC, err)
	}
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return &ScopedRows{Rows: rows, tx: tx}, nil
}

// ---------------------------------------------------------------------------
// P9-22 / P9-23 — the checks that make the boundary's absence loud.
//
// The two errors above (ErrBillySharesWriterRole, ErrBillyRoleBypassesRLS)
// cover the two ways this design was expected to be undone: point Billy at
// the writer's DSN, or give its role SUPERUSER/BYPASSRLS. Both are checks on
// role ATTRIBUTES, and both were measured passing on a connection that was
// nonetheless completely unscoped.
//
// They are not sufficient, because RLS binds a role through three
// independent mechanisms and the attribute check only sees one of them:
//
//  1. the role's own SUPERUSER / BYPASSRLS attributes  — covered above;
//  2. the POLICIES that name the role, including policies naming a role it
//     is merely a MEMBER of. Postgres matches a policy's role list with
//     pg_has_role(..., 'USAGE'), so `GRANT chainsaw TO billy_ro` silently
//     hands billy_ro the chainsaw_writer_all policy, whose qual is `true`.
//     Permissive policies OR together, so the effective predicate collapses
//     to `true` and every tenant is visible — while rolsuper and
//     rolbypassrls both still report false and the startup check passes.
//     This is measured, not theorised: a two-tenant fixture that returns one
//     row before the GRANT returns both rows after it, with no attribute
//     change (TestVerifyBillyRole_RejectsInheritedWriterPolicy);
//  3. whether ROW LEVEL SECURITY is enabled on the table at all. The
//     documented incident rollback in docs/MIGRATIONS.md is
//     `ALTER TABLE … DISABLE ROW LEVEL SECURITY`, which is exactly the state
//     nothing else here would notice.
//
// So VerifyBillyRole now checks all three. Each is a query the Billy pool can
// run as itself — pg_class and pg_policy are world-readable — which matters,
// because the question "is THIS connection scoped" has to be answered on the
// connection in question, not on the writer's.

// ErrBillyInheritsUnrestrictedPolicy is mechanism 2 above: the Billy role is
// covered by a permissive policy other than the org-isolation one, either by
// being named in it directly or by holding membership in a role that is.
var ErrBillyInheritsUnrestrictedPolicy = errors.New("billy read-only role is covered by an unrestricted row-level policy (directly or via role membership): row-level security would not scope its reads")

// ErrBillyTablesUnprotected is mechanism 3: a Billy-readable table exists but
// has row-level security switched off, so no policy on it applies to anyone.
var ErrBillyTablesUnprotected = errors.New("row-level security is not enabled on every billy-readable table: reads on those tables are unscoped")

// PolicyCoverage is one (table, policy, role) triple whose policy applies to
// the connection it was read on. Role is "PUBLIC" for a policy that names no
// role explicitly.
type PolicyCoverage struct {
	Table  string
	Policy string
	Role   string
}

func (c PolicyCoverage) String() string {
	return fmt.Sprintf("%s.%s (via %s)", c.Table, c.Policy, c.Role)
}

// billyTableLiteralList renders billyReadableTables as a SQL list literal.
// The values are a package constant, never operator or model input, so the
// interpolation is not a parameter in disguise.
func billyTableLiteralList() string {
	quoted := make([]string, len(billyReadableTables))
	for i, t := range billyReadableTables {
		quoted[i] = "'" + t + "'"
	}
	return strings.Join(quoted, ", ")
}

// UnrestrictedPolicyCoverage returns every PERMISSIVE policy on the
// Billy-readable tables, other than the org-isolation policy itself, that
// applies to db's current role.
//
// Only permissive policies are considered: Postgres OR-combines those, so any
// one of them with a wide qual defeats the scope. Restrictive policies AND
// together and can only ever narrow what is visible, so one appearing here
// would be a false alarm.
//
// A policy's role list stores OID 0 for PUBLIC, which no pg_roles row
// matches — so PUBLIC is tested explicitly rather than through the join, or a
// second `TO PUBLIC USING (true)` policy would be invisible to this check.
//
// 'MEMBER', not 'USAGE'. Postgres matches a policy's role list with USAGE, so
// USAGE is what reproduces its behaviour exactly — but a NOINHERIT member of
// a policy's role has USAGE false and can still reach the policy by issuing
// SET ROLE, which changes current_user to the covered role. MEMBER is true in
// both cases. The check is therefore deliberately one notch stricter than
// Postgres's own matching: the false positive it can raise is a role that
// holds NOINHERIT membership in a writer role and never uses it, which is a
// configuration worth failing on anyway.
func UnrestrictedPolicyCoverage(ctx context.Context, db *sql.DB) ([]PolicyCoverage, error) {
	if db == nil {
		return nil, fmt.Errorf("nil database handle")
	}
	rows, err := db.QueryContext(ctx, `
		SELECT c.relname,
		       p.polname,
		       CASE WHEN pr.roleoid = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(pr.roleoid) END
		  FROM pg_policy p
		  JOIN pg_class c ON c.oid = p.polrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		  CROSS JOIN LATERAL unnest(p.polroles) AS pr(roleoid)
		 WHERE n.nspname = 'public'
		   AND c.relname IN (`+billyTableLiteralList()+`)
		   AND p.polpermissive
		   AND p.polname <> $1
		   AND (pr.roleoid = 0 OR pg_has_role(current_user, pr.roleoid, 'MEMBER'))
		 ORDER BY 1, 2, 3`, rlsPolicyOrgIsolation)
	if err != nil {
		return nil, fmt.Errorf("read policy coverage: %w", err)
	}
	defer rows.Close()

	var out []PolicyCoverage
	for rows.Next() {
		var c PolicyCoverage
		if err := rows.Scan(&c.Table, &c.Policy, &c.Role); err != nil {
			return nil, fmt.Errorf("scan policy coverage: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read policy coverage: %w", err)
	}
	return out, nil
}

// UnprotectedBillyTables returns the Billy-readable tables that exist in the
// database but do not have row-level security enabled.
//
// A table that does not exist is not reported: billyRLSStatements skips
// missing tables too, and a deployment mid-migration would otherwise fail a
// check about a table nothing can read yet.
func UnprotectedBillyTables(ctx context.Context, db *sql.DB) ([]string, error) {
	if db == nil {
		return nil, fmt.Errorf("nil database handle")
	}
	rows, err := db.QueryContext(ctx, `
		SELECT c.relname
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = 'public'
		   AND c.relkind = 'r'
		   AND c.relname IN (`+billyTableLiteralList()+`)
		   AND NOT c.relrowsecurity
		 ORDER BY 1`)
	if err != nil {
		return nil, fmt.Errorf("read row-security flags: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("scan row-security flags: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read row-security flags: %w", err)
	}
	return out, nil
}

// RoleRLSPosture records whether a role is exempt from row-level security by
// attribute. Either attribute makes every policy on every table a no-op for
// that role.
type RoleRLSPosture struct {
	Role      string
	Superuser bool
	BypassRLS bool
}

// BypassesRLS reports whether the role skips row-level security outright.
func (p RoleRLSPosture) BypassesRLS() bool { return p.Superuser || p.BypassRLS }

// DescribeRoleRLSPosture reads the RLS-relevant attributes of db's current
// role. Unlike VerifyBillyRole it renders no judgement — the application's
// own writer legitimately reads across tenants, so the caller decides whether
// the answer is a problem. See WarnUnlessWriterIsLeastPrivilege.
func DescribeRoleRLSPosture(ctx context.Context, db *sql.DB) (RoleRLSPosture, error) {
	var p RoleRLSPosture
	if db == nil {
		return p, fmt.Errorf("nil database handle")
	}
	err := db.QueryRowContext(ctx,
		`SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&p.Role, &p.Superuser, &p.BypassRLS)
	if err != nil {
		return p, fmt.Errorf("read role attributes: %w", err)
	}
	return p, nil
}
