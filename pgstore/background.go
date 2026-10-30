package pgstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Background work (the scheduled refresher, dependency scans, cache warm)
// can run on its own connection pool, so a burst of it cannot take the
// connections installs need (docs/REPORTS.md#backend-perf-load-test-2026-10-29
// J.3). Callers mark a context with WithBackground; code that reads the
// pool through DBFor gets the background pool for it when one is
// configured, and the main pool otherwise.

type backgroundKey struct{}

// WithBackground marks ctx as background work for DBFor.
func WithBackground(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundKey{}, true)
}

// IsBackground reports whether ctx was marked by WithBackground.
func IsBackground(ctx context.Context) bool {
	v, _ := ctx.Value(backgroundKey{}).(bool)
	return v
}

// DBFor returns the background pool for a background-marked ctx when one
// is open, and the main pool otherwise.
func (s *Store) DBFor(ctx context.Context) *sql.DB {
	if s == nil {
		return nil
	}
	if s.bgDB != nil && ctx != nil && IsBackground(ctx) {
		return s.bgDB
	}
	return s.db
}

// OpenBackgroundPool opens the background pool against dsn (normally the
// main pool's DSN). A MaxOpenConns of 0 leaves background work on the main
// pool.
func (s *Store) OpenBackgroundPool(dsn string, cfg PoolConfig) error {
	if s == nil || cfg.MaxOpenConns <= 0 || strings.TrimSpace(dsn) == "" {
		return nil
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("parse background DSN: %w", err)
	}
	if cfg.StatementTimeout > 0 {
		if config.RuntimeParams == nil {
			config.RuntimeParams = make(map[string]string)
		}
		config.RuntimeParams["statement_timeout"] = fmt.Sprintf("%d", cfg.StatementTimeout.Milliseconds())
	}
	db := sql.OpenDB(&rewriteConnector{base: stdlib.GetConnector(*config)})
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(max(cfg.MaxOpenConns/2, 1))
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("ping background pool: %w", err)
	}
	s.bgDB = db
	return nil
}
