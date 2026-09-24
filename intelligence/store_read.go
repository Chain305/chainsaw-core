package intelligence

import (
	"context"
	"database/sql"
)

// The public package page reads intelligence_reports on the same writable pool
// the scans write through, so a scan storm that exhausts that pool takes the
// read down with it (2026-09-14, docs/PLANS_INTELLIGENCE.md#plan-scan-backpressure
// M1-C). pgstore already owns a separate read pool — Store.ReadDB, opened from
// CHAINSAW_DATABASE_READ_URL — and nothing in this package used it.
//
// It cannot simply become the default for Get. Get serves two contracts: the
// public lookup tolerates lag (worst case "not evaluated yet" on a page that
// polls), while the scan's cache-first read and xreplicaflight's peek read the
// row the caller or its leader JUST wrote, and a lagging replica would turn
// that into an extra fan-out or ErrLeaderCrashed. So the read pool is opt-in
// per request: a caller that can tolerate lag marks its context, and every
// other caller keeps reading the primary exactly as before.
//
// Opting in through the context rather than a new Service method keeps the
// Service interface — and its many fakes — unchanged, and keeps the choice at
// the one call site that knows its own consistency needs.

type lagTolerantReadKey struct{}

// WithLagTolerantRead marks ctx as able to tolerate a report read that lags
// the primary. Store.Get and Store.Search then read from the read pool, which
// falls back to the primary when no read DSN is configured.
func WithLagTolerantRead(ctx context.Context) context.Context {
	return context.WithValue(ctx, lagTolerantReadKey{}, true)
}

// IsLagTolerantRead reports whether ctx was marked by WithLagTolerantRead.
func IsLagTolerantRead(ctx context.Context) bool {
	on, _ := ctx.Value(lagTolerantReadKey{}).(bool)
	return on
}

// readerFor picks the pool for a read: the read pool when the caller opted in,
// the primary otherwise. Nil when the store has no database (tests).
func (s *Store) readerFor(ctx context.Context) *sql.DB {
	if s == nil || s.sql == nil {
		return nil
	}
	if IsLagTolerantRead(ctx) {
		return s.sql.ReadDB()
	}
	return s.sql.DB()
}
