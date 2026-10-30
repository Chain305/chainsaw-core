package pgstore

// Boot-time migration execution.
//
// Every pgstore.Open runs the whole idempotent DDL list. Postgres takes a
// statement's table lock BEFORE checking its IF [NOT] EXISTS clause, so on an
// already-migrated database each boot still took an ACCESS EXCLUSIVE lock per
// ALTER TABLE and a SHARE lock per CREATE INDEX, on every table, with no
// lock_timeout. Behind a long reader (the hourly pg_dump holds ACCESS SHARE
// on every table for the length of the dump) one of those waited, every later
// query on that table queued behind it, and a deploy during a backup stalled
// the old pod's traffic. Statements also ran on pool connections, not on the
// connection holding the migration advisory lock.
//
// While migrate() runs, migExec instead:
//   - runs every statement on the advisory-lock connection, under
//     lock_timeout (migLockTimeout), retrying lock_not_available a bounded
//     number of times, then failing the boot. A failed boot keeps the old
//     pod serving; a hung one stalls it.
//   - skips the statements whose IF [NOT] EXISTS clause the catalog already
//     answers (ADD COLUMN, CREATE [UNIQUE] INDEX, DROP COLUMN / INDEX /
//     CONSTRAINT), so an up-to-date database takes no DDL lock for them.
//     The catalog snapshot is re-read after any statement that drops
//     something or runs a DO block, so a skip is never based on stale state.
// Outside migrate() it is plain s.db.Exec.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// Tunables are vars so tests can shorten them.
var (
	migLockTimeout    = "5s"
	migLockRetries    = 20
	migLockRetryPause = time.Second
)

const pgLockNotAvailable = "55P03"

type migSession struct {
	conn        *sql.Conn
	columns     map[string]bool // table.column
	indexes     map[string]bool // index name
	constraints map[string]bool // table.constraint
}

var (
	reAddColumn      = regexp.MustCompile(`(?is)^\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?"?(\w+)"?\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+"?(\w+)"?\s`)
	reDropColumn     = regexp.MustCompile(`(?is)^\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?"?(\w+)"?\s+DROP\s+COLUMN\s+IF\s+EXISTS\s+"?(\w+)"?\s*;?\s*$`)
	reDropConstraint = regexp.MustCompile(`(?is)^\s*ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?"?(\w+)"?\s+DROP\s+CONSTRAINT\s+IF\s+EXISTS\s+"?(\w+)"?\s*;?\s*$`)
	reCreateIndex    = regexp.MustCompile(`(?is)^\s*CREATE\s+(?:UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\s+"?(\w+)"?\s`)
	reDropIndex      = regexp.MustCompile(`(?is)^\s*DROP\s+INDEX\s+IF\s+EXISTS\s+"?(\w+)"?\s*;?\s*$`)
	// A second action in the same ALTER TABLE makes the statement more than
	// the one clause the skip rule reasons about.
	reMultiAction    = regexp.MustCompile(`(?i),\s*(?:ADD|ALTER|DROP|RENAME|SET|VALIDATE)\b`)
	reMutatesCatalog = regexp.MustCompile(`(?is)^\s*DO\b|\bDROP\b|\bRENAME\b`)
)

func (m *migSession) load(ctx context.Context) error {
	m.columns, m.indexes, m.constraints = map[string]bool{}, map[string]bool{}, map[string]bool{}
	rows, err := m.conn.QueryContext(ctx, `SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var t, c string
		if err := rows.Scan(&t, &c); err != nil {
			rows.Close()
			return err
		}
		m.columns[strings.ToLower(t+"."+c)] = true
	}
	rows.Close()
	rows, err = m.conn.QueryContext(ctx, `SELECT indexname FROM pg_indexes WHERE schemaname = 'public'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		m.indexes[strings.ToLower(n)] = true
	}
	rows.Close()
	rows, err = m.conn.QueryContext(ctx, `SELECT c.relname, k.conname FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var t, k string
		if err := rows.Scan(&t, &k); err != nil {
			rows.Close()
			return err
		}
		m.constraints[strings.ToLower(t+"."+k)] = true
	}
	rows.Close()
	return rows.Err()
}

// alreadyApplied reports whether the catalog already answers stmt's
// IF [NOT] EXISTS clause, so running it would only take a lock.
func (m *migSession) alreadyApplied(stmt string) bool {
	if reMultiAction.MatchString(stmt) && !reCreateIndex.MatchString(stmt) {
		return false
	}
	if g := reAddColumn.FindStringSubmatch(stmt); g != nil {
		return m.columns[strings.ToLower(g[1]+"."+g[2])]
	}
	if g := reCreateIndex.FindStringSubmatch(stmt); g != nil {
		return m.indexes[strings.ToLower(g[1])]
	}
	if g := reDropColumn.FindStringSubmatch(stmt); g != nil {
		return !m.columns[strings.ToLower(g[1]+"."+g[2])]
	}
	if g := reDropConstraint.FindStringSubmatch(stmt); g != nil {
		return !m.constraints[strings.ToLower(g[1]+"."+g[2])]
	}
	if g := reDropIndex.FindStringSubmatch(stmt); g != nil {
		return !m.indexes[strings.ToLower(g[1])]
	}
	return false
}

// applied records what a statement that ran created, and re-reads the
// catalog after anything that may have removed objects.
func (m *migSession) applied(ctx context.Context, stmt string) error {
	if g := reAddColumn.FindStringSubmatch(stmt); g != nil && !reMultiAction.MatchString(stmt) {
		m.columns[strings.ToLower(g[1]+"."+g[2])] = true
		return nil
	}
	if g := reCreateIndex.FindStringSubmatch(stmt); g != nil {
		m.indexes[strings.ToLower(g[1])] = true
		return nil
	}
	if reMutatesCatalog.MatchString(stmt) {
		return m.load(ctx)
	}
	return nil
}

func (s *Store) migExec(query string, args ...any) (sql.Result, error) {
	return s.migExecContext(context.Background(), query, args...)
}

func (s *Store) migExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	m := s.mig
	if m == nil {
		return s.db.ExecContext(ctx, query, args...)
	}
	if len(args) == 0 && m.alreadyApplied(query) {
		return driverRowsAffected(0), nil
	}
	var (
		res sql.Result
		err error
	)
	for attempt := 0; ; attempt++ {
		res, err = m.conn.ExecContext(ctx, query, args...)
		var pgErr *pgconn.PgError
		if err == nil || !errors.As(err, &pgErr) || pgErr.Code != pgLockNotAvailable || attempt >= migLockRetries {
			break
		}
		time.Sleep(migLockRetryPause)
	}
	if err != nil {
		return res, err
	}
	if err := m.applied(ctx, query); err != nil {
		return res, fmt.Errorf("refresh migration catalog: %w", err)
	}
	return res, nil
}

type driverRowsAffected int64

func (driverRowsAffected) LastInsertId() (int64, error)   { return 0, errors.New("not supported") }
func (r driverRowsAffected) RowsAffected() (int64, error) { return int64(r), nil }
