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

// scratchMigratedStore opens a fresh scratch database, migrated once, and
// returns the store plus a raw connection to the same database.
func scratchMigratedStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" || u.Host == "" {
		t.Skipf("CHAINSAW_DATABASE_URL is not a URL DSN (%v)", err)
	}
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	dbName := fmt.Sprintf("chainsaw_migexec_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE "` + dbName + `"`); err != nil {
		t.Skipf("cannot create a scratch database (%v)", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP DATABASE IF EXISTS "` + dbName + `" WITH (FORCE)`) })
	scratch := *u
	scratch.Path = "/" + dbName
	store, err := Open(scratch.String())
	if err != nil {
		t.Fatalf("first migration: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	raw, err := sql.Open("pgx", scratch.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	return store, raw
}

// A second boot against a migrated database used to drop and re-add the
// intelligence_reports primary key and rebuild its indexes, under ACCESS
// EXCLUSIVE. Behind a long reader (pg_dump holds ACCESS SHARE for the whole
// dump) that waited forever and queued every query behind it. Re-migrating
// while a reader holds the table must now finish, and the PK must survive.
func TestRemigrateDoesNotWaitBehindAReader(t *testing.T) {
	store, raw := scratchMigratedStore(t)
	var pkBefore int64
	if err := raw.QueryRow(`SELECT oid FROM pg_constraint WHERE conname = 'intelligence_reports_pkey'`).Scan(&pkBefore); err != nil {
		t.Fatal(err)
	}

	reader, err := raw.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	if _, err := reader.Exec(`LOCK TABLE intelligence_reports, intelligence_latest_probes, running_artifacts IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- store.migrate() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("re-migration failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("re-migration blocked behind an ACCESS SHARE reader")
	}
	reader.Rollback()

	var pkAfter int64
	if err := raw.QueryRow(`SELECT oid FROM pg_constraint WHERE conname = 'intelligence_reports_pkey'`).Scan(&pkAfter); err != nil {
		t.Fatalf("primary key missing after re-migration: %v", err)
	}
	if pkAfter != pkBefore {
		t.Fatal("re-migration rebuilt intelligence_reports' primary key; it must leave it alone once org_id is gone")
	}
}

// DDL that does have to run must give up rather than hang: a failed boot
// leaves the old pod serving, a hung one queues its traffic.
func TestMigrationDDLTimesOutInsteadOfHanging(t *testing.T) {
	store, raw := scratchMigratedStore(t)
	oldTimeout, oldRetries, oldPause := migLockTimeout, migLockRetries, migLockRetryPause
	migLockTimeout, migLockRetries, migLockRetryPause = "200ms", 1, 10*time.Millisecond
	t.Cleanup(func() { migLockTimeout, migLockRetries, migLockRetryPause = oldTimeout, oldRetries, oldPause })

	// policies has an unconditional ALTER COLUMN in ensurePolicyColumns.
	holder, err := raw.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback()
	if _, err := holder.Exec(`LOCK TABLE policies IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- store.migrate() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("migration claimed success while a required lock was held")
		}
		if !strings.Contains(err.Error(), "lock") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("migration hung on a held lock instead of timing out")
	}
}
