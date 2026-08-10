package pgstore

// migrate_concurrency_test.go pins the advisory lock that serializes
// Store.migrate (see the comment on migrate in migrate.go).
//
// The bug it guards: migrate's DDL is idempotent (CREATE TABLE / CREATE
// INDEX ... IF NOT EXISTS) but NOT concurrency-safe. The existence check
// is not atomic with the create, so two sessions creating the same
// object at the same time both pass the check and the loser dies on
// pg_class's unique index (SQLSTATE 23505,
// pg_class_relname_nsp_index). Every pgstore.Open runs migrate, so this
// fires whenever openers race: N proxy replicas booting together, or N
// Go test binaries / t.Parallel tests against one CI database. In CI it
// showed up as a DB-suite failure count that moved between runs on an
// identical tree.

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// migrateRaceOpeners is how many Opens run at once. Four is enough to
// lose the pg_class race reliably while keeping the test to a few
// seconds — each opener applies the full DDL list, and the lock makes
// them run one after another.
const migrateRaceOpeners = 4

// TestMigrateConcurrentOpensOnFreshDatabase opens several Stores at
// once against a database that has never been migrated.
//
// The scratch database is the load-bearing part. On an already-migrated
// database every IF NOT EXISTS short-circuits and there is nothing to
// race, so running this against the shared CI database (which the rest
// of the suite has long since migrated) would pass with the lock
// removed. Creating a fresh database re-opens the window.
func TestMigrateConcurrentOpensOnFreshDatabase(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" || u.Host == "" {
		t.Skipf("CHAINSAW_DATABASE_URL is not a URL DSN (%v); cannot derive a scratch database", err)
	}

	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open admin connection: %v", err)
	}
	// Registered before the DROP below so it runs AFTER it — t.Cleanup
	// is LIFO, and a plain `defer admin.Close()` would fire first and
	// leave the scratch database behind ("sql: database is closed").
	t.Cleanup(func() { admin.Close() })

	// Generated from a literal prefix plus a timestamp, so the
	// identifier is [a-z0-9_] by construction and safe to interpolate —
	// CREATE DATABASE does not accept a bind parameter.
	dbName := fmt.Sprintf("chainsaw_migrate_race_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE "` + dbName + `"`); err != nil {
		t.Skipf("cannot create a scratch database (%v); the test role needs CREATEDB", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP DATABASE IF EXISTS "` + dbName + `"`); err != nil {
			t.Logf("drop scratch database %s: %v", dbName, err)
		}
	})

	scratch := *u
	scratch.Path = "/" + dbName
	scratchDSN := scratch.String()

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		stores []*Store
		errs   []error
		start  = make(chan struct{})
	)
	for i := 0; i < migrateRaceOpeners; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // widen the race window: all openers go at once
			store, err := Open(scratchDSN)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			stores = append(stores, store)
		}()
	}
	close(start)
	wg.Wait()

	// Close every store before the cleanup DROP DATABASE — Postgres
	// refuses to drop a database with live connections.
	for _, s := range stores {
		s.Close()
	}

	for _, err := range errs {
		t.Errorf("concurrent Open on a fresh database failed: %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("%d/%d concurrent Opens failed — the migration advisory lock in migrate() is missing or ineffective",
			len(errs), migrateRaceOpeners)
	}
}
