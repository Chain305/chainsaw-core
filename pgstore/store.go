package pgstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type Store struct {
	db     *sql.DB
	readDB *sql.DB
}

func Open(dsn string) (*Store, error) {
	return OpenWithConfig(dsn, "", defaultPoolConfig(), defaultPoolConfig())
}

// OpenWithConfig opens the writable pool from dsn and (optionally) a
// read pool from readDSN. When readDSN is empty the read pool aliases
// the writable pool — preserving the prior single-pool behaviour.
func OpenWithConfig(dsn, readDSN string, writePool, readPool PoolConfig) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("database DSN is required")
	}
	writePool = writePool.applyDefaults()
	readPool = readPool.applyDefaults()

	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database DSN: %w", err)
	}
	if writePool.StatementTimeout > 0 {
		if config.RuntimeParams == nil {
			config.RuntimeParams = make(map[string]string)
		}
		config.RuntimeParams["statement_timeout"] = fmt.Sprintf("%d", writePool.StatementTimeout.Milliseconds())
	}
	connector := stdlib.GetConnector(*config)
	db := sql.OpenDB(&rewriteConnector{base: connector})
	db.SetMaxOpenConns(writePool.MaxOpenConns)
	db.SetMaxIdleConns(writePool.MaxIdleConns)
	db.SetConnMaxLifetime(writePool.ConnMaxLifetime)
	db.SetConnMaxIdleTime(writePool.ConnMaxIdleTime)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if strings.TrimSpace(readDSN) != "" {
		readDB, err := openReadOnlyWithPool(readDSN, readPool)
		if err != nil {
			db.Close()
			return nil, err
		}
		store.readDB = readDB
	}
	return store, nil
}

func (s *Store) DB() *sql.DB {
	return s.db
}

// ReadDB returns the read-only pool when configured, else falls back
// to the writable pool. Consumers should use this for queries that
// don't require read-after-write consistency (artifact metadata,
// event listings, dashboards). For UI flows that read a row they
// just wrote in the same request, use [Store.DB] explicitly.
//
// Audit (M-ARCH-02, 2026-04-16) — `grep -rn '\.DB()' internal/`
// currently shows ~55 files routing through the primary pool. Paths
// that COULD run against the replica but still go to the primary
// today include:
//
//   - internal/server/dashboard.go         (trend / traffic listings)
//   - internal/server/violations_query.go  (violation listing pagination)
//   - internal/server/analytics.go         (usage dashboards, org lookups)
//   - internal/events/log.go (read methods) (event feed listing)
//   - internal/events/bom.go               (BOM listing aggregations)
//   - internal/server/usage.go             (usage rollup dashboards)
//   - internal/server/health.go            (db_health / liveness probes)
//   - internal/server/dashboard.go#traffic queries (registry graphs)
//
// The three files in the M-ARCH-02 "trivially safe" shortlist
// (violations_query.go, dashboard.go registry-traffic, events/log.go
// list methods) have been migrated to ReadDB() — see each file for
// the inline rationale. The remainder are left on the primary
// because they either mix read+write within the same handler
// (auth flows, onboarding, paddle webhooks) or intentionally need
// read-after-write consistency.
func (s *Store) ReadDB() *sql.DB {
	if s == nil || s.db == nil {
		return nil
	}
	if s.readDB != nil {
		return s.readDB
	}
	return s.db
}

// provenance-coverage
// HasAttestation reports whether the attestations table has any verified
// row for the given (ecosystem, name, version) coordinate. The table is
// universal (no org_id) so the query is keyed by package coordinate only;
// "installed in this org" is enforced upstream by the install-event scope.
// Any attestation_type counts as coverage — the report measures whether
// provenance exists, not which kind.
func (s *Store) HasAttestation(ctx context.Context, ecosystem, name, version string) (bool, error) {
	if s == nil || s.db == nil {
		return false, nil
	}
	db := s.db
	if s.readDB != nil {
		db = s.readDB
	}
	var exists bool
	err := db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM attestations
			WHERE ecosystem = $1 AND package_name = $2 AND version = $3)`,
		ecosystem, name, version,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has attestation %s/%s@%s: %w", ecosystem, name, version, err)
	}
	return exists, nil
}

// provenance-coverage end

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	if s.readDB != nil {
		if err := s.readDB.Close(); err != nil {
			firstErr = err
		}
	}
	if s.db != nil {
		if err := s.db.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Store) WithTx(ctx context.Context, fn func(*sql.Tx) error) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("store not initialized")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func currentTimestamp() time.Time {
	return time.Now().UTC()
}
