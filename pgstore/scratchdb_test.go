package pgstore

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// provisionScratchDatabase creates a private, empty database on the same
// server as baseDSN and returns a DSN pointing at it plus a cleanup that
// drops it.
//
// Why this exists: a test that needs `DROP SCHEMA public CASCADE` cannot
// safely share a database with anything, and `go test ./...` runs packages in
// parallel against one CHAINSAW_DATABASE_URL. The destructive upgrade-path
// test used to wipe that shared database mid-run, which surfaced as
// `relation "users" does not exist` in whichever unrelated package happened
// to be opening a store at that moment. The Makefile documented "use a
// throwaway database", but a comment cannot enforce itself.
//
// Skips rather than fails when the role lacks CREATEDB: the point is to make
// the destructive test safe, and a test that cannot get a private database
// must not fall back to wiping the shared one.
func provisionScratchDatabase(t *testing.T, baseDSN string) (string, func()) {
	t.Helper()

	// CHAINSAW_TEST_REQUIRE_DB turns "cannot reach Postgres" into a failure.
	//
	// Callers already fail when the DSN is EMPTY under that flag, but an
	// unreachable server slipped through as a skip — and a skipped test still
	// reports its package "ok". That happened for real on 2026-08-26: the
	// Phase-2 DROP test reported ok while the container was simply not
	// running, which is exactly the outcome the flag exists to prevent.
	//
	// A missing CREATEDB privilege still SKIPS below, deliberately: the point
	// of this helper is to keep a destructive test off the shared database,
	// and a test that cannot get a private one must not fall back to wiping it.
	fatalIfRequired := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != "" {
			t.Fatalf(format, args...)
		}
		t.Skipf(format, args...)
	}

	admin, err := sql.Open("pgx", baseDSN)
	if err != nil {
		fatalIfRequired("scratch db: open base DSN: %v", err)
	}
	defer admin.Close()
	if err := admin.Ping(); err != nil {
		fatalIfRequired("scratch db: Postgres unreachable: %v", err)
	}

	// Unique per run. Postgres identifiers cap at 63 bytes and the name is
	// built only from a fixed prefix plus digits, so no quoting is needed —
	// but it is still interpolated, because CREATE DATABASE does not accept
	// a placeholder for the database name.
	name := fmt.Sprintf("chainsaw_scratch_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil {
		// Most likely cause is a role without CREATEDB. Skipping is the
		// correct outcome — see the doc comment.
		t.Skipf("scratch db: CREATE DATABASE (does the test role have CREATEDB?): %v", err)
	}

	drop := func() {
		// A new connection: the caller's pool is closed by its own cleanup,
		// and Postgres refuses to drop a database with live sessions.
		a2, err := sql.Open("pgx", baseDSN)
		if err != nil {
			t.Logf("scratch db: reopen for drop: %v", err)
			return
		}
		defer a2.Close()
		if _, err := a2.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`); err != nil {
			// WITH (FORCE) needs PG13+. Fall back, then give up loudly
			// rather than silently leaking a database per run.
			if _, err2 := a2.Exec(`DROP DATABASE IF EXISTS ` + name); err2 != nil {
				t.Logf("scratch db: leaked %s (drop failed: %v / %v)", name, err, err2)
			}
		}
	}

	scratch, err := swapDatabaseName(baseDSN, name)
	if err != nil {
		drop()
		t.Skipf("scratch db: rewrite DSN: %v", err)
	}
	return scratch, drop
}

// swapDatabaseName rewrites the database component of a Postgres DSN,
// preserving user, host, port and every query parameter (sslmode in
// particular — dropping it turns a working local DSN into a TLS error).
func swapDatabaseName(dsn, name string) (string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", fmt.Errorf("parse dsn: %w", err)
	}
	if u.Scheme == "" {
		// key=value form (host=... dbname=...) — not worth a parser here;
		// the callers that matter all use URL form.
		return "", fmt.Errorf("dsn is not in URL form")
	}
	u.Path = "/" + strings.TrimPrefix(name, "/")
	return u.String(), nil
}
