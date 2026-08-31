package pgstore

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// P0-A / A1 — the tests that make the claim "RLS is the boundary" checkable.
//
// The point of this file is TestBillyRLS_BypassQueriesReturnOnlyOwnOrg: it
// takes the five query shapes the SQL guard demonstrably accepts today and
// runs them, unmodified, through the production execution path
// (QueryOrgScoped on a non-writer role) against a two-tenant fixture. Every
// one of them must come back with tenant A's rows and nothing else. Without
// that test, the migration in rls.go is an assertion, not a result.
//
// These are DB-backed. Set CHAINSAW_TEST_REQUIRE_DB=1 so an unreachable
// Postgres FAILS instead of skipping — a skipped test still prints "ok" for
// the package, which is exactly how a boundary quietly stops being tested.

const (
	rlsOrgA = "org-rls-tenant-a"
	rlsOrgB = "org-rls-tenant-b"
)

// rlsTestEnv is a migrated scratch database plus a throwaway, non-superuser
// login role that stands in for billy_ro.
//
// Why a throwaway role and not billy_ro itself: Postgres roles are
// CLUSTER-wide, not per-database. billy_ro is created NOLOGIN by the
// migration and giving it a LOGIN password would mutate the developer's
// whole cluster from a unit test. The org-isolation policy is written
// against PUBLIC (see rls.go), so every role except the writer and the
// table owner is scoped identically — which is the property under test.
// billy_ro's own column grants are asserted separately, from the admin
// connection, in TestBillyRLS_ColumnGrantsExcludeRemoteURL.
type rlsTestEnv struct {
	adminDSN string
	roleDSN  string
	store    *Store
}

func newRLSTestEnv(t *testing.T) *rlsTestEnv {
	t.Helper()

	baseDSN := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if baseDSN == "" {
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != "" {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but CHAINSAW_DATABASE_URL is empty")
		}
		t.Skip("CHAINSAW_DATABASE_URL not set")
	}

	scratchDSN, dropScratch := provisionScratchDatabase(t, baseDSN)
	t.Cleanup(dropScratch)

	store, err := Open(scratchDSN)
	if err != nil {
		t.Fatalf("open scratch store (this runs the RLS migration): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	role := fmt.Sprintf("chainsaw_rls_probe_%d", time.Now().UnixNano())
	password := "probe-pw"
	// NOSUPERUSER NOBYPASSRLS is not decoration: either attribute makes every
	// policy in this file a no-op, and the test would pass for the wrong reason.
	if _, err := store.DB().Exec(fmt.Sprintf(
		`CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOBYPASSRLS NOINHERIT`, role, password)); err != nil {
		t.Skipf("create probe role (does the test role have CREATEROLE?): %v", err)
	}
	t.Cleanup(func() {
		// Privileges must go before the role does.
		for _, tbl := range billyReadableTables {
			_, _ = store.DB().Exec(fmt.Sprintf(`REVOKE ALL ON TABLE public.%s FROM %s`, tbl, role))
		}
		_, _ = store.DB().Exec(fmt.Sprintf(`DROP ROLE IF EXISTS %s`, role))
	})
	for _, tbl := range billyReadableTables {
		if _, err := store.DB().Exec(fmt.Sprintf(`GRANT SELECT ON TABLE public.%s TO %s`, tbl, role)); err != nil {
			t.Fatalf("grant SELECT on %s to probe role: %v", tbl, err)
		}
	}

	roleDSN, err := swapCredentials(scratchDSN, role, password)
	if err != nil {
		t.Fatalf("rewrite DSN for probe role: %v", err)
	}

	return &rlsTestEnv{adminDSN: scratchDSN, roleDSN: roleDSN, store: store}
}

// swapCredentials rewrites the userinfo of a URL-form Postgres DSN, keeping
// host, database and every query parameter (sslmode in particular).
func swapCredentials(dsn, user, password string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" {
		return "", fmt.Errorf("dsn is not in URL form")
	}
	u.User = url.UserPassword(user, password)
	return u.String(), nil
}

// seedTwoTenants writes one event, one policy, one repository and one
// package_metadata row for each of two orgs.
func (e *rlsTestEnv) seedTwoTenants(t *testing.T) {
	t.Helper()
	db := e.store.DB()
	for _, org := range []string{rlsOrgA, rlsOrgB} {
		if _, err := db.Exec(
			`INSERT INTO events (org_id, recorded_at, status_code, package_name, action)
			 VALUES ($1, CURRENT_TIMESTAMP, 200, $2, 'download')`,
			org, "pkg-"+org); err != nil {
			t.Fatalf("seed events for %s: %v", org, err)
		}
		if _, err := db.Exec(
			`INSERT INTO policies (id, org_id, name, mode) VALUES ($1, $2, $3, 'block')`,
			"pol-"+org, org, "policy-"+org); err != nil {
			t.Fatalf("seed policies for %s: %v", org, err)
		}
		if _, err := db.Exec(
			`INSERT INTO repositories (org_id, name, format, type, remote_url, remote_headers)
			 VALUES ($1, 'npm-proxy', 'npm', 'remote', $2, $3)`,
			org, "https://user:s3cr3t@registry."+org+".example/", `{"Authorization":"Bearer leak-`+org+`"}`); err != nil {
			t.Fatalf("seed repositories for %s: %v", org, err)
		}
		if _, err := db.Exec(
			`INSERT INTO package_metadata (org_id, repository, package, version)
			 VALUES ($1, 'npm-proxy', $2, '1.0.0')`,
			org, "pkg-"+org); err != nil {
			t.Fatalf("seed package_metadata for %s: %v", org, err)
		}
	}
}

// openProbePool opens the probe role's pool the way production opens Billy's.
func (e *rlsTestEnv) openProbePool(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenReadOnly(e.roleDSN)
	if err != nil {
		t.Fatalf("open probe read-only pool: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func scopedStrings(ctx context.Context, t *testing.T, db *sql.DB, orgID, query string, args ...any) []string {
	t.Helper()
	rows, err := QueryOrgScoped(ctx, db, orgID, query, args...)
	if err != nil {
		t.Fatalf("QueryOrgScoped(%q): %v", query, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v sql.NullString
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan (%q): %v", query, err)
		}
		out = append(out, v.String)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows.Err (%q): %v", query, err)
	}
	return out
}

// TestBillyRLS_BypassQueriesReturnOnlyOwnOrg is the test this whole change
// exists to pass. Each query below is ALLOWED by the SQL guard at HEAD — the
// guard only requires an org_id token to exist somewhere in the string — and
// each one returns every tenant's rows without RLS.
func TestBillyRLS_BypassQueriesReturnOnlyOwnOrg(t *testing.T) {
	env := newRLSTestEnv(t)
	env.seedTwoTenants(t)
	probe := env.openProbePool(t)
	ctx := context.Background()

	// Sanity: the fixture really does contain both tenants. If this is 1 the
	// test below proves nothing.
	var total int
	if err := env.store.DB().QueryRow(`SELECT count(*) FROM events`).Scan(&total); err != nil {
		t.Fatalf("count events as writer: %v", err)
	}
	if total != 2 {
		t.Fatalf("fixture: expected 2 events across both tenants, got %d — the writer's own RLS policy may be missing", total)
	}

	cases := []struct {
		name  string
		query string
		want  []string
	}{
		{
			name:  "trailing OR 1=1",
			query: `SELECT package_name FROM events WHERE org_id = '` + rlsOrgA + `' OR 1=1`,
			want:  []string{"pkg-" + rlsOrgA},
		},
		{
			name:  "leading 1=1 OR",
			query: `SELECT package_name FROM events WHERE 1=1 OR org_id = '` + rlsOrgA + `'`,
			want:  []string{"pkg-" + rlsOrgA},
		},
		{
			// The one that needs no OR at all, and is currently blessed by a
			// passing guard test (sqlguard_test.go TestGuardSQLAcceptsJoin...).
			name:  "JOIN ON 1=1",
			query: `SELECT e.package_name FROM policies p JOIN events e ON 1=1 WHERE p.org_id = '` + rlsOrgA + `'`,
			want:  []string{"pkg-" + rlsOrgA},
		},
		{
			name:  "NOT org_id =",
			query: `SELECT package_name FROM events WHERE NOT org_id = '` + rlsOrgA + `'`,
			want:  nil,
		},
		{
			name:  "CASE WHEN ... ELSE true",
			query: `SELECT package_name FROM events WHERE CASE WHEN org_id = '` + rlsOrgA + `' THEN true ELSE true END`,
			want:  []string{"pkg-" + rlsOrgA},
		},
		{
			// Not one of the five, but the shape that matters most: an
			// unqualified read of a whole table.
			name:  "unqualified select",
			query: `SELECT package_name FROM events`,
			want:  []string{"pkg-" + rlsOrgA},
		},
		{
			name:  "policies unqualified",
			query: `SELECT name FROM policies`,
			want:  []string{"policy-" + rlsOrgA},
		},
		{
			name:  "package_metadata unqualified",
			query: `SELECT package FROM package_metadata`,
			want:  []string{"pkg-" + rlsOrgA},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scopedStrings(ctx, t, probe, rlsOrgA, tc.query)
			for _, v := range got {
				if strings.Contains(v, rlsOrgB) {
					t.Fatalf("cross-tenant read: %q leaked %q (all rows: %v)", tc.query, v, got)
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("query %q returned %d rows %v, want %d %v", tc.query, len(got), got, len(tc.want), tc.want)
			}
		})
	}
}

// TestBillyRLS_UnscopedConnectionSeesNothing pins the fail-closed half:
// current_setting(..., true) is NULL on a connection nobody scoped, and
// `org_id = NULL` is NULL, which is not true. A policy written without the
// missing_ok argument would ERROR instead, and an error is a worse failure
// mode than an empty result only if you assume someone reads the log.
func TestBillyRLS_UnscopedConnectionSeesNothing(t *testing.T) {
	env := newRLSTestEnv(t)
	env.seedTwoTenants(t)
	probe := env.openProbePool(t)

	var n int
	if err := probe.QueryRow(`SELECT count(*) FROM events`).Scan(&n); err != nil {
		t.Fatalf("unscoped count: %v", err)
	}
	if n != 0 {
		t.Fatalf("unscoped connection saw %d events, want 0", n)
	}
}

// TestBillyRLS_GUCDoesNotLeakAcrossPooledConnections is the SET LOCAL half.
// With MaxOpenConns pinned to 1 every acquisition reuses the same physical
// connection, so a session-level SET here would be visible to the next
// caller — scoping tenant B's query to tenant A.
func TestBillyRLS_GUCDoesNotLeakAcrossPooledConnections(t *testing.T) {
	env := newRLSTestEnv(t)
	env.seedTwoTenants(t)
	ctx := context.Background()

	probe, err := openReadOnlyWithPool(env.roleDSN, PoolConfig{
		MaxOpenConns:     1,
		MaxIdleConns:     1,
		ConnMaxLifetime:  time.Hour,
		ConnMaxIdleTime:  time.Hour,
		StatementTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("open single-connection probe pool: %v", err)
	}
	defer probe.Close()

	got := scopedStrings(ctx, t, probe, rlsOrgA, `SELECT package_name FROM events`)
	if len(got) != 1 {
		t.Fatalf("scoped read returned %v, want exactly tenant A's row", got)
	}

	// Same physical connection, no scope set.
	var guc sql.NullString
	if err := probe.QueryRowContext(ctx, `SELECT current_setting($1, true)`, OrgScopeGUC).Scan(&guc); err != nil {
		t.Fatalf("read GUC after scoped query: %v", err)
	}
	if guc.Valid && guc.String != "" {
		t.Fatalf("%s leaked onto the recycled connection as %q — SET LOCAL was not used, or the transaction was committed without discarding it", OrgScopeGUC, guc.String)
	}

	var n int
	if err := probe.QueryRowContext(ctx, `SELECT count(*) FROM events`).Scan(&n); err != nil {
		t.Fatalf("post-scope unscoped count: %v", err)
	}
	if n != 0 {
		t.Fatalf("recycled connection still saw %d rows, want 0", n)
	}
}

// TestVerifyBillyRole_RejectsWriterRole is item 4: without this check the
// whole change silently degrades the first time someone copies the writer
// DSN into the Billy env var.
func TestVerifyBillyRole_RejectsWriterRole(t *testing.T) {
	env := newRLSTestEnv(t)
	ctx := context.Background()

	// Same DSN as the writer — the exact misconfiguration.
	if _, err := OpenBillyReadOnly(ctx, env.adminDSN, env.store.DB()); err == nil {
		t.Fatal("OpenBillyReadOnly accepted the writer's own DSN")
	} else if !strings.Contains(err.Error(), "same Postgres role") {
		t.Fatalf("wrong rejection reason: %v", err)
	}

	// The probe role is distinct and non-superuser: this one must pass.
	db, err := OpenBillyReadOnly(ctx, env.roleDSN, env.store.DB())
	if err != nil {
		t.Fatalf("OpenBillyReadOnly rejected a correctly separated role: %v", err)
	}
	defer db.Close()
}

// TestVerifyBillyRole_RejectsBypassRLSRole covers the other silent
// degradation: a role that is correctly separated but carries BYPASSRLS (or
// is a superuser) is subject to no policy at all.
func TestVerifyBillyRole_RejectsBypassRLSRole(t *testing.T) {
	env := newRLSTestEnv(t)
	ctx := context.Background()

	role := fmt.Sprintf("chainsaw_rls_bypass_%d", time.Now().UnixNano())
	if _, err := env.store.DB().Exec(fmt.Sprintf(
		`CREATE ROLE %s LOGIN PASSWORD 'probe-pw' NOSUPERUSER BYPASSRLS`, role)); err != nil {
		t.Skipf("create BYPASSRLS role (needs superuser): %v", err)
	}
	defer func() { _, _ = env.store.DB().Exec(fmt.Sprintf(`DROP ROLE IF EXISTS %s`, role)) }()

	dsn, err := swapCredentials(env.adminDSN, role, "probe-pw")
	if err != nil {
		t.Fatalf("rewrite DSN: %v", err)
	}
	if _, err := OpenBillyReadOnly(ctx, dsn, env.store.DB()); err == nil {
		t.Fatal("OpenBillyReadOnly accepted a BYPASSRLS role")
	} else if !strings.Contains(err.Error(), "BYPASSRLS") {
		t.Fatalf("wrong rejection reason: %v", err)
	}
}

// TestBillyRLS_ColumnGrantsExcludeRemoteURL asserts the grants the migration
// installed on the real billy_ro role. Column-level grants are what make the
// credential-bearing columns unreadable regardless of what the SQL guard
// lets through: repositories.remote_url routinely carries userinfo
// (https://user:token@host) and remote_headers holds upstream auth headers,
// and run_sql is not role-gated within an org.
func TestBillyRLS_ColumnGrantsExcludeRemoteURL(t *testing.T) {
	env := newRLSTestEnv(t)
	db := env.store.DB()

	var exists bool
	if err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)`, BillyRORole).Scan(&exists); err != nil {
		t.Fatalf("look up %s: %v", BillyRORole, err)
	}
	if !exists {
		t.Skipf("%s was not created by the migration (writer lacks CREATEROLE)", BillyRORole)
	}

	granted := func(table, column string) bool {
		t.Helper()
		var ok bool
		if err := db.QueryRow(
			`SELECT has_column_privilege($1, $2, $3, 'SELECT')`,
			BillyRORole, "public."+table, column).Scan(&ok); err != nil {
			t.Fatalf("has_column_privilege(%s.%s): %v", table, column, err)
		}
		return ok
	}

	for table, cols := range BillyReadableColumns {
		for _, col := range cols {
			if !granted(table, col) {
				t.Errorf("%s lacks SELECT on %s.%s but it is in BillyReadableColumns", BillyRORole, table, col)
			}
		}
	}

	// The columns that must stay unreadable even though the table is allowed.
	for _, tc := range []struct{ table, column string }{
		{"repositories", "remote_url"},
		{"repositories", "remote_headers"},
		{"repositories", "format_options"},
		{"events", "scanner_payload"},
		{"events", "prev_value"},
		{"events", "new_value"},
		{"policies", "parameter_hash"},
	} {
		if granted(tc.table, tc.column) {
			t.Errorf("%s can SELECT %s.%s — the column-level grant is too wide", BillyRORole, tc.table, tc.column)
		}
	}

	// And no privileges at all on a table outside the four.
	var anyUsers bool
	if err := db.QueryRow(
		`SELECT has_table_privilege($1, 'public.users', 'SELECT')`, BillyRORole).Scan(&anyUsers); err != nil {
		t.Fatalf("has_table_privilege(users): %v", err)
	}
	if anyUsers {
		t.Errorf("%s can SELECT from users", BillyRORole)
	}
}

// TestBillyRLSStatements_Idempotent re-runs the migration. "Idempotent" is
// the load-bearing property of this project's migration story
// (docs/MIGRATIONS.md) and DROP POLICY / CREATE POLICY is the part of this
// change most likely to break it.
func TestBillyRLSStatements_Idempotent(t *testing.T) {
	env := newRLSTestEnv(t)
	env.seedTwoTenants(t)

	for i := 0; i < 3; i++ {
		for _, stmt := range billyRLSStatements() {
			if _, err := env.store.DB().Exec(stmt); err != nil {
				t.Fatalf("re-run %d of RLS DDL failed: %v", i, err)
			}
		}
	}

	// Still exactly one policy of each name per table, and the boundary
	// still holds afterwards.
	for _, tbl := range billyReadableTables {
		var n int
		if err := env.store.DB().QueryRow(
			`SELECT count(*) FROM pg_policies WHERE schemaname='public' AND tablename=$1`, tbl).Scan(&n); err != nil {
			t.Fatalf("count policies on %s: %v", tbl, err)
		}
		if n != 2 {
			t.Fatalf("%s has %d policies after re-running the migration, want 2", tbl, n)
		}
		var rls, force bool
		if err := env.store.DB().QueryRow(
			`SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid = ('public.'||$1)::regclass`,
			tbl).Scan(&rls, &force); err != nil {
			t.Fatalf("read RLS flags for %s: %v", tbl, err)
		}
		if !rls || !force {
			t.Fatalf("%s: ENABLE=%t FORCE=%t, want both true (FORCE is what stops the owner bypassing)", tbl, rls, force)
		}
	}

	probe := env.openProbePool(t)
	got := scopedStrings(context.Background(), t, probe, rlsOrgA, `SELECT package_name FROM events WHERE org_id = '`+rlsOrgA+`' OR 1=1`)
	if len(got) != 1 {
		t.Fatalf("after re-running the migration the bypass returned %v, want tenant A only", got)
	}
}

// TestBillyRLS_WriterStillReadsEveryTenant is the regression this change is
// most likely to cause. FORCE ROW LEVEL SECURITY applies to the table owner
// too; without the chainsaw_writer_all policy every application read would
// silently become zero rows.
func TestBillyRLS_WriterStillReadsEveryTenant(t *testing.T) {
	env := newRLSTestEnv(t)
	env.seedTwoTenants(t)

	for _, q := range []string{
		`SELECT count(*) FROM events`,
		`SELECT count(*) FROM policies`,
		`SELECT count(*) FROM repositories`,
		`SELECT count(*) FROM package_metadata`,
	} {
		var n int
		if err := env.store.DB().QueryRow(q).Scan(&n); err != nil {
			t.Fatalf("writer %q: %v", q, err)
		}
		if n < 2 {
			t.Fatalf("writer %q returned %d rows, want both tenants — the writer policy is missing or FORCE RLS locked the app out", q, n)
		}
	}

	// And the writer can still write.
	if _, err := env.store.DB().Exec(
		`INSERT INTO events (org_id, recorded_at, status_code, action) VALUES ($1, CURRENT_TIMESTAMP, 200, 'download')`,
		rlsOrgA); err != nil {
		t.Fatalf("writer INSERT under FORCE RLS: %v", err)
	}
}

// TestQueryOrgScoped_ParameterisedQuery mirrors the production shape exactly:
// executeRunSQL rewrites the model's `$ORG_ID` placeholder to `$1` and binds
// orgID, so the query QueryOrgScoped receives already carries a positional
// parameter. The GUC is set by a separate `set_config($1, $2, true)` Exec, so
// this checks the two statements' parameter numbering do not collide.
func TestQueryOrgScoped_ParameterisedQuery(t *testing.T) {
	env := newRLSTestEnv(t)
	env.seedTwoTenants(t)
	probe := env.openProbePool(t)

	got := scopedStrings(context.Background(), t, probe, rlsOrgA,
		`SELECT package_name FROM events WHERE org_id = $1 LIMIT 50`, rlsOrgA)
	if len(got) != 1 || got[0] != "pkg-"+rlsOrgA {
		t.Fatalf("parameterised scoped query returned %v, want [pkg-%s]", got, rlsOrgA)
	}

	// The same bound parameter naming a FOREIGN tenant still yields nothing:
	// RLS is evaluated on top of the predicate, not instead of it.
	foreign := scopedStrings(context.Background(), t, probe, rlsOrgA,
		`SELECT package_name FROM events WHERE org_id = $1 LIMIT 50`, rlsOrgB)
	if len(foreign) != 0 {
		t.Fatalf("query bound to tenant B under tenant A's scope returned %v, want none", foreign)
	}
}

// TestQueryOrgScoped_RejectsEmptyOrg — an empty org id would set the GUC to
// ” and quietly match nothing, which reads like "this tenant has no data".
func TestQueryOrgScoped_RejectsEmptyOrg(t *testing.T) {
	env := newRLSTestEnv(t)
	probe := env.openProbePool(t)
	if _, err := QueryOrgScoped(context.Background(), probe, "  ", `SELECT 1`); err == nil {
		t.Fatal("QueryOrgScoped accepted an empty org id")
	}
}
