package pgstore

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// PoolConfig tunes the connection pools. The zero value resolves to
// the package defaults (see defaultPoolConfig).
type PoolConfig struct {
	MaxOpenConns     int
	MaxIdleConns     int
	ConnMaxLifetime  time.Duration
	ConnMaxIdleTime  time.Duration
	StatementTimeout time.Duration // 0 = unset
}

// defaultPoolConfig returns the connection-pool sizing used when an
// operator does not override via CHAINSAW_DB_* env vars.
//
// Wave-O perf baseline (2026-05-23): the previous default of 30 caused
// the pool-utilisation shedder (internal/server/pool_shed.go) to trip
// at sustained ~40 RPS — interactive in-flight count reached 27/30
// (90%) while pg_stat_activity itself showed only 5 idle + 1 active.
// PostgreSQL max_connections is 100 on the reference deploy; the 30
// ceiling was leaving ~70 connections of headroom on the floor while
// the proxy returned 503 "database pool exhausted, retry" to clients.
//
// Bumped to 50 (writable) / 25 idle. With reserved=10 background
// reservation in the shedder, the interactive ceiling is 40 active
// connections before the shedder trips — comfortably above the
// 40 RPS × ~600ms-per-request ≈ 24 concurrency the proxy actually
// sees at the previous breaking point. Three-replica fleets are still
// safe (3 × 50 = 150 < the headroom needed once max_connections is
// bumped on the PG side; for single-replica deploys 50 < 100 leaves
// 50 connections for psql, migrations, dashboard, and operator
// tools).
//
// Operators on small Postgres deploys (max_connections << 100) should
// still override via CHAINSAW_DB_MAX_OPEN_CONNS.
func defaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxOpenConns:    50,
		MaxIdleConns:    25,
		ConnMaxLifetime: 30 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
	}
}

// applyDefaults fills any zero field with the pre-Phase-5 default.
func (p PoolConfig) applyDefaults() PoolConfig {
	d := defaultPoolConfig()
	if p.MaxOpenConns == 0 {
		p.MaxOpenConns = d.MaxOpenConns
	}
	if p.MaxIdleConns == 0 {
		p.MaxIdleConns = d.MaxIdleConns
	}
	if p.ConnMaxLifetime == 0 {
		p.ConnMaxLifetime = d.ConnMaxLifetime
	}
	if p.ConnMaxIdleTime == 0 {
		p.ConnMaxIdleTime = d.ConnMaxIdleTime
	}
	return p
}

// OpenReadOnly opens a separate read-only connection pool from the given DSN.
// It sets default_transaction_read_only=on and statement_timeout=5s at the
// session level so that even if application-level validation is bypassed,
// Postgres itself blocks writes and long-running queries.
func OpenReadOnly(dsn string) (*sql.DB, error) {
	return openReadOnlyWithPool(dsn, PoolConfig{
		MaxOpenConns:     5,
		MaxIdleConns:     2,
		ConnMaxLifetime:  30 * time.Minute,
		ConnMaxIdleTime:  5 * time.Minute,
		StatementTimeout: 5 * time.Second,
	})
}

func openReadOnlyWithPool(dsn string, pool PoolConfig) (*sql.DB, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, fmt.Errorf("database DSN is required")
	}
	pool = pool.applyDefaults()
	if pool.StatementTimeout == 0 {
		pool.StatementTimeout = 5 * time.Second
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database DSN: %w", err)
	}
	if config.RuntimeParams == nil {
		config.RuntimeParams = make(map[string]string)
	}
	config.RuntimeParams["default_transaction_read_only"] = "on"
	config.RuntimeParams["statement_timeout"] = fmt.Sprintf("%d", pool.StatementTimeout.Milliseconds())

	connector := stdlib.GetConnector(*config)
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(pool.MaxOpenConns)
	db.SetMaxIdleConns(pool.MaxIdleConns)
	db.SetConnMaxLifetime(pool.ConnMaxLifetime)
	db.SetConnMaxIdleTime(pool.ConnMaxIdleTime)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping read-only database: %w", err)
	}
	return db, nil
}
